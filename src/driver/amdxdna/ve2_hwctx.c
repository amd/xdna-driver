// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2025, Advanced Micro Devices, Inc.
 */
#include <drm/drm_cache.h>
#include <linux/dma-mapping.h>

#include "amdxdna_ctx.h"
#include "amdxdna_gem_of.h"
#include "ve2_of.h"
#include "ve2_mgmt.h"
#include "ve2_res_solver.h"

/*
 * struct ve2_dpu_data - interpretation of data payload for ERT_START_DPU
 *
 * @instruction_buffer:       address of instruction buffer
 * @instruction_buffer_size:  size of instruction buffer in bytes
 * @uc_index:                 microblaze controller index
 * @chained:                  number of following ve2_dpu_data elements
 *
 * The data payload for ERT_START_DPU is interpreted as fixed instruction
 * buffer address along with instruction count, followed by regular kernel
 * arguments.
 */
struct ve2_dpu_data {
	u64 instruction_buffer;		/* buffer address 2 words */
	u32 instruction_buffer_size;	/* size of buffer in bytes */
	u16 uc_index;			/* microblaze controller index */
	u16 chained;			/* number of following ve2_dpu_data elements */
};

static inline struct ve2_dpu_data *get_ve2_dpu_data_next(struct ve2_dpu_data *dpu_data)
{
	if (dpu_data->chained == 0)
		return NULL;

	return dpu_data + 1;
}

static int hsa_queue_reserve_slot(struct amdxdna_dev *xdna, struct amdxdna_ctx_priv *priv,
				  u64 *slot)
{
	struct ve2_hsa_queue *queue = &priv->hwctx_hsa_queue;
	struct host_queue_header *header = &queue->hsa_queue_p->hq_header;
	int ret;

	mutex_lock(&queue->hq_lock);
	if (header->write_index < header->read_index) {
		XDNA_ERR(xdna, "Error: HSA Queue read %llx before write %llx", header->read_index,
			 header->write_index);
		ret = -EINVAL;
	} else if ((header->write_index - header->read_index) < header->capacity) {
		*slot = header->write_index++;
		XDNA_DBG(xdna, "reserved slot %lld", *slot);
	} else {
		XDNA_ERR(xdna, "Error: HSQ Queue is full");
		ret = -EIO;
	}
	mutex_unlock(&queue->hq_lock);

	return ret;
}

static void ve2_job_release(struct kref *ref)
{
	struct amdxdna_sched_job *job;

	job = container_of(ref, struct amdxdna_sched_job, refcnt);
	amdxdna_sched_job_cleanup(job);
	kfree(job);
}

static void ve2_job_put(struct amdxdna_sched_job *job)
{
	kref_put(&job->refcnt, ve2_job_release);
}

static inline int ve2_hwctx_add_job(struct amdxdna_ctx *hwctx, struct amdxdna_sched_job *job,
				    u64 seq, u32 cmd_cnt)
{
	struct amdxdna_sched_job *other_job;
	int idx;

	hwctx->submitted += cmd_cnt;
	job->seq = seq;

	idx = get_job_idx(job->seq);
	// When pending list full, hwctx->submitted points to oldest fence
	other_job = hwctx->priv->pending[idx];
	if (other_job && other_job->fence)
		return -EAGAIN;

	if (other_job) {
		dma_fence_put(other_job->fence);
		ve2_job_put(other_job);
	}

	hwctx->priv->pending[idx] = job;
	kref_get(&job->refcnt);

	return 0;
}

static inline struct amdxdna_sched_job *ve2_hwctx_get_job(struct amdxdna_ctx *hwctx, u64 seq)
{
	return hwctx->priv->pending[get_job_idx(seq)];
}

static inline void ve2_hwctx_job_release(struct amdxdna_ctx *hwctx, struct amdxdna_sched_job *job)
{
	for (int i = 0; i < job->bo_cnt; i++) {
		if (!job->bos[i].obj)
			break;

		drm_gem_object_put(job->bos[i].obj);
	}
	drm_gem_object_put(to_gobj(job->cmd_bo));

	// Reset the pending list
	hwctx->priv->pending[get_job_idx(job->seq)] = NULL;
	if (job->fence)
		dma_fence_put(job->fence);
	kfree(job);
}

static inline struct host_queue_packet *hsa_queue_get_pkt(struct hsa_queue *queue, u64 slot)
{
	return &queue->hq_entry[slot & (queue->hq_header.capacity - 1)];
}

static inline int hsa_queue_pkt_is_valid(struct host_queue_packet *pkt)
{
	return pkt->xrt_header.common_header.type == HOST_QUEUE_PACKET_TYPE_VENDOR_SPECIFIC;
}

static void *get_host_queue_pkt(struct amdxdna_ctx *hwctx, u64 *seq)
{
	struct amdxdna_dev *xdna = hwctx->client->xdna;
	struct hsa_queue *queue = NULL;
	struct host_queue_packet *pkt;
	int ret;

	ret = hsa_queue_reserve_slot(xdna, hwctx->priv, seq);
	if (ret) {
		XDNA_ERR(xdna, "No slot available in Host queue");
		return NULL;
	}

	queue = (struct hsa_queue *)hwctx->priv->hwctx_hsa_queue.hsa_queue_p;
	if (!queue) {
		XDNA_ERR(xdna, "Invalid Host queue");
		return NULL;
	}

	pkt = hsa_queue_get_pkt(queue, *seq);
	if (hsa_queue_pkt_is_valid(pkt)) {
		XDNA_ERR(xdna, "pkt of slot %llx is already selected", *seq);
		return NULL;
	}

	return pkt;
}

static inline void hsa_queue_pkt_set_valid(struct host_queue_packet *pkt)
{
	pkt->xrt_header.common_header.type = HOST_QUEUE_PACKET_TYPE_VENDOR_SPECIFIC;
}

static inline void hsa_queue_pkt_set_invalid(struct host_queue_packet *pkt)
{
	pkt->xrt_header.common_header.type = HOST_QUEUE_PACKET_TYPE_INVALID;
}

static void ve2_free_hsa_queue(struct amdxdna_dev *xdna, struct ve2_hsa_queue *queue)
{
	struct platform_device *pdev = to_platform_device(xdna->ddev.dev);

	if (queue->hsa_queue_p) {
		dma_free_coherent(&pdev->dev, sizeof(struct hsa_queue), queue->hsa_queue_p,
				  queue->hsa_queue_mem.dma_addr);
		queue->hsa_queue_p = NULL;
	}
}

/*
 * Create hsa queue in kernel and initialize queue slots.
 */
static int ve2_create_host_queue(struct amdxdna_dev *xdna, struct ve2_hsa_queue *queue)
{
	struct platform_device *pdev = to_platform_device(xdna->ddev.dev);
	int nslots = HOST_QUEUE_ENTRY;
	dma_addr_t dma_handle;

	// Allocate a single contiguous block of memory
	queue->hsa_queue_p = dma_alloc_coherent(&pdev->dev,
						sizeof(struct hsa_queue) + sizeof(u64) * nslots,
						&dma_handle,
						GFP_KERNEL);
	if (!queue->hsa_queue_p)
		return -ENOMEM;

	// Set the base DMA address for hsa queue
	queue->hsa_queue_mem.dma_addr = dma_handle;

	// Calculate the address for hqc_mem within the allocated block
	queue->hq_complete.hqc_mem =
		(u64 *)((char *)queue->hsa_queue_p + sizeof(struct hsa_queue));
	queue->hq_complete.hqc_dma_addr = queue->hsa_queue_mem.dma_addr + sizeof(struct hsa_queue);
	queue->hsa_queue_p->hq_header.data_address = queue->hsa_queue_mem.dma_addr +
		sizeof(struct host_queue_header);

	// Set hsa queue slots to invalid
	for (int i = 0; i < nslots; i++) {
		struct host_queue_indirect_hdr *hdr = &queue->hsa_queue_p->hq_indirect_hdr[i];

		hsa_queue_pkt_set_invalid(hsa_queue_get_pkt(queue->hsa_queue_p, i));
		hdr->header.type = HOST_QUEUE_PACKET_TYPE_VENDOR_SPECIFIC;
		hdr->header.opcode = HOST_QUEUE_PACKET_EXEC_BUF;
		hdr->header.count = 0;
		hdr->header.distribute = 1;
		hdr->header.indirect = 1;

		for (int j = 0; j < HOST_INDIRECT_PKT_NUM; j++) {
			struct host_queue_indirect_pkt *pkt =
			       &queue->hsa_queue_p->hq_indirect_pkt[i][j];

			pkt->header.type = HOST_QUEUE_PACKET_TYPE_VENDOR_SPECIFIC;
			pkt->header.opcode = HOST_QUEUE_PACKET_EXEC_BUF;
			pkt->header.count = sizeof(struct exec_buf);
			pkt->header.distribute = 1;
			pkt->header.indirect = 0;
		}
	}

	WARN_ON(!is_power_of_2(nslots));
	queue->hsa_queue_p->hq_header.capacity = nslots;

	XDNA_DBG(xdna, "created ve2 hsq queue with capacity %d slots", nslots);
	return 0;
}

static int submit_command_indirect(struct amdxdna_ctx *hwctx, void *cmd_data, u64 *seq)
{
	struct amdxdna_ctx_priv *ve2_ctx = hwctx->priv;
	struct amdxdna_dev *xdna = hwctx->client->xdna;
	struct ve2_hsa_queue *hq_queue;
	struct xrt_packet_header *hdr;
	struct host_queue_packet *pkt;
	struct ve2_dpu_data *dpu;
	struct hsa_queue *queue;
	u64 slot_id = 0;
	int ret;

	dpu = (struct ve2_dpu_data *)cmd_data;
	ret = hsa_queue_reserve_slot(xdna, hwctx->priv, &slot_id);
	if (ret)
		return ret;

	hq_queue = (struct ve2_hsa_queue *)&ve2_ctx->hwctx_hsa_queue;
	queue = (struct hsa_queue *)hq_queue->hsa_queue_p;
	pkt = hsa_queue_get_pkt(queue, slot_id);
	if (hsa_queue_pkt_is_valid(pkt)) {
		XDNA_ERR(xdna, "pkt of slot %llx is already selected", slot_id);
		return -EINVAL;
	}

	*seq = slot_id;
	slot_id = slot_id & (queue->hq_header.capacity - 1);

	hdr = &pkt->xrt_header;
	hdr->common_header.opcode = HOST_QUEUE_PACKET_EXEC_BUF;
	hdr->common_header.count = sizeof(struct host_indirect_packet_entry);
	hdr->common_header.distribute = 1;
	hdr->common_header.indirect = 1;
	hdr->completion_signal = (u64)(hq_queue->hq_complete.hqc_dma_addr + slot_id * sizeof(u64));

	struct host_queue_indirect_hdr *indirect_hdr =
		(struct host_queue_indirect_hdr *)&queue->hq_indirect_hdr[slot_id];
	u32 total_cmds = dpu->chained + 1;

	indirect_hdr->header.count = total_cmds * sizeof(struct host_indirect_packet_entry);
	indirect_hdr->header.indirect = 1;
	indirect_hdr->header.distribute = 1;
	u64 m_indirect_hdr_paddr = (u64)(queue->hq_header.data_address +
		((u64)&queue->hq_indirect_hdr[slot_id] - (u64)&queue->hq_entry));

	struct host_indirect_packet_entry *hp = (struct host_indirect_packet_entry *)pkt->data;

	hp->host_addr_low = lower_32_bits((u64)m_indirect_hdr_paddr);
	hp->host_addr_high = upper_32_bits((u64)m_indirect_hdr_paddr);
	hp->uc_index = 0;

	struct host_indirect_packet_entry *hp_hdr =
		(struct host_indirect_packet_entry *)indirect_hdr->data;

	for (int i = 0; dpu && (i < total_cmds); i++, hp_hdr++, dpu = get_ve2_dpu_data_next(dpu)) {
		struct host_queue_indirect_pkt *indirect_data =
			(struct host_queue_indirect_pkt *)&queue->hq_indirect_pkt[slot_id][i];
		u64 m_indirect_data_paddr = (u64)(queue->hq_header.data_address +
				((u64)&queue->hq_indirect_pkt[slot_id][i] - (u64)&queue->hq_entry));

		XDNA_DBG(xdna, "\nIndirect packet id %d\n", i);
		XDNA_DBG(xdna, "        uc index %d\n", dpu->uc_index);
		XDNA_DBG(xdna, "        dpu instruction_buffer %llx\n",
			 (u64)dpu->instruction_buffer);

		hp_hdr->host_addr_low = lower_32_bits((u64)m_indirect_data_paddr);
		hp_hdr->host_addr_high = upper_32_bits((u64)m_indirect_data_paddr);
		hp_hdr->uc_index = dpu->uc_index;

		struct host_queue_indirect_pkt *cebp = indirect_data;

		cebp->payload.dpu_control_code_host_addr_low =
			lower_32_bits(dpu->instruction_buffer);
		cebp->payload.dpu_control_code_host_addr_high =
			upper_32_bits(dpu->instruction_buffer);
		cebp->payload.cu_index = 0;
		cebp->payload.args_len = 0;
		cebp->payload.args_host_addr_low = 0;
		cebp->payload.args_host_addr_high = 0;
	}

	hsa_queue_pkt_set_valid(pkt);

	return 0;
}

static int submit_command(struct amdxdna_ctx *hwctx, void *cmd_data, u64 *seq)
{
	struct amdxdna_ctx_priv *ve2_ctx = hwctx->priv;
	struct amdxdna_dev *xdna = hwctx->client->xdna;
	struct ve2_hsa_queue *hq_queue;
	struct ve2_dpu_data *dpu_cmd;
	struct xrt_packet_header *hdr;
	struct host_queue_packet *pkt;
	struct exec_buf *ebp;
	u64 slot_id = 0;

	hq_queue = (struct ve2_hsa_queue *)&ve2_ctx->hwctx_hsa_queue;
	if (!cmd_data) {
		XDNA_ERR(xdna, "Invalid command requested");
		return -EINVAL;
	}

	pkt = (struct host_queue_packet *)get_host_queue_pkt(hwctx, &slot_id);
	if (!pkt) {
		XDNA_ERR(xdna, "Getting host queue packet failed");
		return -EINVAL;
	}

	*seq = slot_id;
	XDNA_DBG(xdna, "pkt %p of slot %llx is selected", (void *)pkt, slot_id);
	slot_id = slot_id & (hq_queue->hsa_queue_p->hq_header.capacity - 1);

	hdr = &pkt->xrt_header;
	hdr->common_header.opcode = HOST_QUEUE_PACKET_EXEC_BUF;
	hdr->completion_signal =
		(u64)(hq_queue->hq_complete.hqc_dma_addr + slot_id * sizeof(u64));

	hdr->common_header.count = sizeof(struct exec_buf);
	hdr->common_header.distribute = 0;
	hdr->common_header.indirect = 0;

	dpu_cmd = (struct ve2_dpu_data *)cmd_data;
	ebp = (struct exec_buf *)pkt->data;
	ebp->cu_index = 0;
	ebp->dpu_control_code_host_addr_high = upper_32_bits(dpu_cmd->instruction_buffer);
	ebp->dpu_control_code_host_addr_low = lower_32_bits(dpu_cmd->instruction_buffer);
	ebp->args_len = 0;
	ebp->args_host_addr_low = 0;
	ebp->args_host_addr_high = 0;
	XDNA_DBG(xdna, "dpu instruction addr: 0x%llx", dpu_cmd->instruction_buffer);

	hsa_queue_pkt_set_valid(pkt);

	return 0;
}

static int ve2_submit_cmd_single(struct amdxdna_ctx *hwctx, struct amdxdna_sched_job *job, u64 *seq)
{
	struct amdxdna_dev *xdna = hwctx->client->xdna;
	struct amdxdna_gem_obj *cmd_bo = job->cmd_bo;
	u32 cmd_data_len;
	void *cmd_data;
	int ret;

	cmd_data = amdxdna_cmd_get_payload(cmd_bo, &cmd_data_len);
	if (!cmd_data) {
		XDNA_ERR(xdna, "Invalid command received in single cmd submit");
		return -EINVAL;
	}

	if (get_ve2_dpu_data_next(cmd_data))
		ret = submit_command_indirect(hwctx, cmd_data, seq);
	else
		ret = submit_command(hwctx, cmd_data, seq);
	if (ret) {
		XDNA_ERR(xdna, "Submit single command failed, error %d", ret);
		return ret;
	}

	return ve2_hwctx_add_job(hwctx, job, *seq, 1);
}

static int ve2_submit_cmd_chain(struct amdxdna_ctx *hwctx, struct amdxdna_sched_job *job, u64 *seq)
{
	struct amdxdna_dev *xdna = hwctx->client->xdna;
	struct amdxdna_gem_obj *cmd_bo = job->cmd_bo;
	struct amdxdna_cmd_chain *cmd_chain;
	u32 cmd_chain_len;
	int ret;

	cmd_chain = amdxdna_cmd_get_payload(cmd_bo, &cmd_chain_len);
	if (!cmd_chain || cmd_chain_len < struct_size(cmd_chain, data, cmd_chain->command_count)) {
		XDNA_ERR(xdna, "Invalid command received in cmd chain submit");
		return -EINVAL;
	}

	for (int i = 0; i < cmd_chain->command_count; i++) {
		u32 boh = (u32)(cmd_chain->data[i]);
		struct amdxdna_gem_obj *abo;
		void *cmd_data;
		u32 cmd_data_len;

		abo = amdxdna_gem_get_obj(hwctx->client, boh, AMDXDNA_BO_CMD);
		if (!abo) {
			XDNA_ERR(xdna, "Failed to find cmd BO %d", boh);
			return -ENOENT;
		}

		cmd_data = amdxdna_cmd_get_payload(abo, &cmd_data_len);
		if (!cmd_data) {
			XDNA_ERR(xdna, "Invalid command data received");
			amdxdna_gem_put_obj(abo);
			return -EINVAL;
		}

		if (get_ve2_dpu_data_next(cmd_data))
			ret = submit_command_indirect(hwctx, cmd_data, seq);
		else
			ret = submit_command(hwctx, cmd_data, seq);
		if (ret) {
			XDNA_ERR(xdna, "Submit chain command(%d) failed, error %d", i, ret);
			amdxdna_gem_put_obj(abo);
			return ret;
		}

		amdxdna_gem_put_obj(abo);
	}

	return ve2_hwctx_add_job(hwctx, job, *seq, cmd_chain->command_count);
}

int ve2_cmd_submit(struct amdxdna_ctx *hwctx, struct amdxdna_sched_job *job, u32 *syncobj_hdls,
		   u64 *syncobj_points, u32 syncobj_cnt, u64 *seq)
{
	struct amdxdna_dev *xdna = hwctx->client->xdna;
	struct amdxdna_gem_obj *cmd_bo = job->cmd_bo;
	int ret;
	u32 op;

	op = amdxdna_cmd_get_op(cmd_bo);
	if (op != ERT_START_DPU && op != ERT_CMD_CHAIN) {
		XDNA_WARN(xdna, "Unsupported ERT cmd: %d received", op);
		return -EINVAL;
	}

	if (op == ERT_CMD_CHAIN)
		ret = ve2_submit_cmd_chain(hwctx, job, seq);
	else
		ret = ve2_submit_cmd_single(hwctx, job, seq);

	if (ret) {
		XDNA_ERR(xdna, "Failed to submit a command. ret %d\n", ret);
		return ret;
	}

	//TODO: return value will be handled in future commit.
	notify_fw_cmd_ready(hwctx);

	return 0;
}

/*
 * Handling interrupt notification based on read_index and write_index.
 */
static inline bool check_read_index(struct amdxdna_ctx_priv *priv_ctx, struct amdxdna_ctx *hwctx,
				    struct amdxdna_dev *xdna, u64 seq)
{
	struct ve2_hsa_queue *queue = &priv_ctx->hwctx_hsa_queue;
	u32 print_interval = 300;
	static u64 counter;
	u64 *read_index;

	mutex_lock(&queue->hq_lock);
	read_index = (u64 *)((char *)priv_ctx->hwctx_hsa_queue.hsa_queue_p +
		HSA_QUEUE_READ_INDEX_OFFSET);
	if (counter % print_interval == 0) {
		XDNA_DBG(xdna, "read idx addr (0x%llx)", (u64)read_index);
		XDNA_WARN(xdna, "hwctx [%p] check read idx (%lld) > cmd idx (%lld)", hwctx,
			  *read_index, seq);
	}
	counter++;
	mutex_unlock(&queue->hq_lock);

	return ((*read_index) > seq);
}

int ve2_cmd_wait(struct amdxdna_ctx *hwctx, u64 seq, u32 timeout)
{
	struct amdxdna_ctx_priv *priv_ctx = hwctx->priv;
	struct amdxdna_client *client = hwctx->client;
	struct amdxdna_dev *xdna = client->xdna;
	struct amdxdna_sched_job *job;
	unsigned long timeout_jiffies;
	int ret;

	/*
	 * NOTE: this is simplified hwctx which has no col_entry list for different ctx
	 * sharing the same lead col.
	 * The current version assumes one hwctx is 1:1 mapping with one lead cert col
	 */
	timeout_jiffies = msecs_to_jiffies(timeout);
	if (timeout_jiffies)
		ret = wait_event_interruptible_timeout(priv_ctx->waitq,
						       check_read_index(priv_ctx, hwctx, xdna, seq),
						       timeout_jiffies);
	else
		ret = wait_event_interruptible(priv_ctx->waitq,
					       check_read_index(priv_ctx, hwctx, xdna, seq));

	XDNA_DBG(xdna, "wait_event returned %d (timeout_jiffies=%lu)", ret, timeout_jiffies);

	if (ret == -ERESTARTSYS)
		return ret;

	if ((!timeout_jiffies && !ret) || ret > 0) {
		job = ve2_hwctx_get_job(hwctx, seq);
		if (unlikely(!job)) {
			ret = 0;
			goto out;
		}

		if (timeout_jiffies && !ret) {
			amdxdna_cmd_set_state(job->cmd_bo, ERT_CMD_STATE_TIMEOUT);
			XDNA_ERR(xdna, "Requested command [%d] TIMEOUT!!", (int)seq);
		} else {
			amdxdna_cmd_set_state(job->cmd_bo, ERT_CMD_STATE_COMPLETED);
		}

		ve2_hwctx_job_release(hwctx, job);

		if (!timeout_jiffies) {
			ret = 0;
			goto out;
		}
	}

	/*
	 * wait_event_interruptible_timeout() returns 0 when the condition evaluated to false
	 * after the timeout elapsed. So, return -ETIME in this case
	 */
	if (timeout_jiffies && !ret)
		ret = -ETIME;

out:
	XDNA_INFO(xdna, "Requested command [%d] finished with ret %d", (int)seq, ret);

	/* 0 is success, others are timeout */
	return ret > 0 ? 0 : ret;
}

int ve2_hwctx_init(struct amdxdna_ctx *hwctx)
{
	struct amdxdna_client *client = hwctx->client;
	struct amdxdna_dev *xdna = client->xdna;
	struct amdxdna_ctx_priv *priv = NULL;
	int ret;

	priv = kzalloc(sizeof(*priv), GFP_KERNEL);
	if (!priv)
		return -ENOMEM;

	hwctx->priv = priv;
	init_waitqueue_head(&priv->waitq);

	/* one host_queue entry per hwctx */
	ret = ve2_create_host_queue(xdna, &priv->hwctx_hsa_queue);
	if (ret)
		goto free_priv;

	ret = ve2_mgmt_create_partition(xdna, hwctx);
	if (ret)
		goto free_hsa_queue;

	return 0;

free_hsa_queue:
	ve2_free_hsa_queue(xdna, &hwctx->priv->hwctx_hsa_queue);
free_priv:
	kfree(hwctx->priv);

	return ret;
}

void ve2_hwctx_fini(struct amdxdna_ctx *hwctx)
{
	struct amdxdna_client *client = hwctx->client;
	struct amdxdna_dev *xdna = client->xdna;
	struct amdxdna_sched_job *job;
	int idx;

	for (idx = 0; idx < HWCTX_MAX_CMDS; idx++) {
		job = hwctx->priv->pending[idx];
		if (!job)
			continue;

		ve2_hwctx_job_release(hwctx, job);
	}

	ve2_get_firmware_status(hwctx);

	ve2_mgmt_destroy_partition(hwctx);
	ve2_free_hsa_queue(xdna, &hwctx->priv->hwctx_hsa_queue);
	kfree(hwctx->priv);
}

static int ve2_update_handshake_pkt(struct amdxdna_ctx *hwctx, u64 paddr, u8 buf_type,
				    u32 buf_sz, u32 col, bool attach)
{
	struct device *aie_dev = hwctx->priv->aie_part;
	struct handshake hs = { 0 };
	int ret;

	WARN_ON(!aie_dev);

	switch (buf_type) {
	case AMDXDNA_FW_BUF_DEBUG:
		if (attach) {
			hs.dbg_buf.dbg_buf_addr_high = upper_32_bits(paddr);
			hs.dbg_buf.dbg_buf_addr_low = lower_32_bits(paddr);
			hs.dbg_buf.size = buf_sz;
		}
		ret = aie_partition_write_privileged_mem(aie_dev, CERT_HANDSHAKE_OFF(col) +
							 offsetof(struct handshake,
								  dbg_buf.dbg_buf_addr_high),
							 sizeof(hs.dbg_buf), (void *)&hs.dbg_buf);
		break;
	case AMDXDNA_FW_BUF_TRACE:
		if (attach) {
			hs.trace.dtrace_addr_high = upper_32_bits(paddr);
			hs.trace.dtrace_addr_low = lower_32_bits(paddr);
		}
		ret = aie_partition_write_privileged_mem(aie_dev, CERT_HANDSHAKE_OFF(col) +
							 offsetof(struct handshake,
								  trace.dtrace_addr_high),
							 sizeof(hs.trace), (void *)&hs.trace);
		break;
	case AMDXDNA_FW_BUF_LOG:
		if (attach) {
			hs.log_addr_high = upper_32_bits(paddr);
			hs.log_addr_low = lower_32_bits(paddr);
			hs.log_buf_size = buf_sz;
		}
		ret = aie_partition_write_privileged_mem(aie_dev, CERT_HANDSHAKE_OFF(col) +
							 offsetof(struct handshake, log_addr_high),
							 sizeof(hs.log_addr_high) +
							 sizeof(hs.log_addr_high) +
							 sizeof(hs.log_buf_size),
							 (void *)&hs.log_addr_high);
		break;
	default:
		ret = -EOPNOTSUPP;
		break;
	}

	return ret;
}

int ve2_hwctx_config(struct amdxdna_ctx *hwctx, u32 type, u64 mdata_hdl, void *buf, u32 size)
{
	struct amdxdna_dev *xdna = hwctx->client->xdna;
	struct amdxdna_client *client = hwctx->client;
	struct amdxdna_gem_obj *abo, *mdata_abo;
	struct fw_buffer_metadata *mdata;
	u32 prev_buf_sz;
	u64 buf_paddr;
	u32 buf_sz;
	int ret;

	mdata_abo = amdxdna_gem_get_obj(client, mdata_hdl, AMDXDNA_BO_DEV);
	if (!mdata_abo || !mdata_abo->mem.kva) {
		XDNA_ERR(xdna, "Get metadata bo %lld failed for type %d", mdata_hdl, type);
		return -EINVAL;
	}

	mdata = (struct fw_buffer_metadata *)(mdata_abo->mem.kva);
	if (!mdata) {
		XDNA_ERR(xdna, "No metadata defined for bo %lld type %d", mdata_hdl, type);
		amdxdna_gem_put_obj(mdata_abo);
		return -EINVAL;
	}

	/* Update fw's handshake shared memory with debug/trace buffer details */
	switch (type) {
	case DRM_AMDXDNA_CTX_ASSIGN_DBG_BUF:
		abo = amdxdna_gem_get_obj(client, mdata->bo_handle, AMDXDNA_BO_DEV);
		if (!abo || !abo->mem.kva) {
			XDNA_ERR(xdna, "Get bo %lld failed for type %d", mdata->bo_handle, type);
			amdxdna_gem_put_obj(mdata_abo);
			return -EINVAL;
		}

		for (u32 col = 0; col < hwctx->num_col; col++) {
			buf_sz = mdata->uc_info[col].size;
			if (buf_sz == 0)
				continue;
			buf_paddr = abo->mem.dev_addr + prev_buf_sz;
			ret = ve2_update_handshake_pkt(hwctx, mdata->buf_type, buf_paddr, buf_sz,
						       col, true);
			if (ret < 0) {
				XDNA_ERR(xdna, "hwctx config req %d with flag %d failed, err %d",
					 type, mdata->buf_type, ret);
				amdxdna_gem_put_obj(abo);
				amdxdna_gem_put_obj(mdata_abo);
				return ret;
			}
			prev_buf_sz += buf_sz;
		}
		XDNA_DBG(xdna, "Attached %d BO %lld to %s, ret %d", mdata->buf_type,
			 mdata->bo_handle, hwctx->name, ret);

		amdxdna_gem_put_obj(abo);
		amdxdna_gem_put_obj(mdata_abo);
		break;
	case DRM_AMDXDNA_CTX_REMOVE_DBG_BUF:
		for (u32 col = 0; col < hwctx->num_col; col++) {
			ret = ve2_update_handshake_pkt(hwctx, mdata->buf_type, 0, 0, col, false);
			if (ret < 0) {
				XDNA_ERR(xdna, "Detach Debug BO %lld from %s failed ret %d",
					 mdata->bo_handle, hwctx->name, ret);
				amdxdna_gem_put_obj(mdata_abo);
				return ret;
			}
		}
		XDNA_DBG(xdna, "Detached Debug BO %lld from %s, ret %d", mdata->bo_handle,
			 hwctx->name, ret);

		amdxdna_gem_put_obj(mdata_abo);
		break;
	default:
		XDNA_DBG(xdna, "%s Not supported type %d", __func__, type);
		ret = -EOPNOTSUPP;
		amdxdna_gem_put_obj(mdata_abo);
		break;
	}

	return ret;
}

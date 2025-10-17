// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2025, Advanced Micro Devices, Inc.
 */
#include <drm/drm_cache.h>
#include <linux/dma-mapping.h>
#include <linux/dma-buf.h>

#include "amdxdna_ctx.h"
#include "amdxdna_gem.h"
#include "ve2_of.h"
#include "ve2_mgmt.h"
#include "ve2_res_solver.h"

int enable_polling;
module_param(enable_polling, int, 0644);
MODULE_PARM_DESC(enable_polling, "Enable polling mode. Polling mode disabled by default.");

int verbosity;
module_param(verbosity, int, 0644);
MODULE_PARM_DESC(verbosity, "[Debug] Enabling verbosity. default is 0");

int partition_size = 4;
module_param(partition_size, int, 0644);
MODULE_PARM_DESC(partition_size, "Test only option: default partition size");

unsigned int ve2_hwctx_limit;
module_param(ve2_hwctx_limit, uint, 0400);
MODULE_PARM_DESC(ve2_hwctx_limit, "[Debug] Maximum number of hwctx. 0 = Use default");

int start_col;
module_param(start_col, int, 0644);
MODULE_PARM_DESC(start_col, "Test only option: lead column set to start_col");

int max_col;
module_param(max_col, int, 0644);
MODULE_PARM_DESC(max_col, "Max column supported by this driver");

#define CTX_TIMER	(nsecs_to_jiffies(1))

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

	mutex_lock(&queue->hq_lock);
	if (header->write_index < header->read_index) {
		XDNA_ERR(xdna, "HSA Queue read %llx before write %llx",
			 header->read_index, header->write_index);
		mutex_unlock(&queue->hq_lock);
		return -EINVAL;
	} else if ((header->write_index - header->read_index) < header->capacity) {
		*slot = header->write_index;
		XDNA_DBG(xdna, "slot %lld", *slot);
	} else {
		XDNA_ERR(xdna, "HSQ Queue is full");
		mutex_unlock(&queue->hq_lock);
		return -EIO;
	}

	mutex_unlock(&queue->hq_lock);
	return 0;
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

/**
 * ve2_hwctx_add_job - Add a job to the hardware context's pending list.
 * @hwctx: Pointer to the hardware context.
 * @job: Pointer to the job to be added.
 * @seq: Sequence number associated with the job.
 * @cmd_cnt: Number of commands submitted with this job.
 *
 * Returns 0 on success, or a negative error code if the job cannot be added.
 */
static inline int ve2_hwctx_add_job(struct amdxdna_ctx *hwctx, struct amdxdna_sched_job *job,
				    u64 seq, u32 cmd_cnt)
{
	struct amdxdna_dev *xdna = hwctx->client->xdna;
	int idx;

	mutex_lock(&hwctx->priv->privctx_lock);
	hwctx->submitted += cmd_cnt;
	job->seq = seq;

	idx = get_job_idx(job->seq);
	if (hwctx->priv->pending[idx]) {
		XDNA_ERR(xdna, "No more room for new command!!!");
		mutex_unlock(&hwctx->priv->privctx_lock);
		return -EINVAL;
	}

	hwctx->priv->pending[idx] = job;
	kref_get(&job->refcnt);
	hwctx->priv->state = AMDXDNA_HWCTX_STATE_ACTIVE;
	mutex_unlock(&hwctx->priv->privctx_lock);

	return 0;
}

static inline struct amdxdna_sched_job *ve2_hwctx_get_job(struct amdxdna_ctx *hwctx, u64 seq)
{
	return hwctx->priv->pending[get_job_idx(seq)];
}

static inline void ve2_hwctx_job_release(struct amdxdna_ctx *hwctx, struct amdxdna_sched_job *job)
{
	struct amdxdna_ctx_priv *priv_ctx = hwctx->priv;
	struct amdxdna_gem_obj *cmd_bo = job->cmd_bo;
	struct amdxdna_cmd_chain *cmd_chain;
	u32 op, cmd_cnt;

	op = amdxdna_cmd_get_op(cmd_bo);
	if (op == ERT_CMD_CHAIN) {
		cmd_chain = amdxdna_cmd_get_payload(cmd_bo, NULL);
		cmd_cnt = cmd_chain->command_count;
	} else {
		cmd_cnt = 1;
	}
	hwctx->completed += cmd_cnt;
	if (hwctx->completed == hwctx->submitted)
		priv_ctx->state = AMDXDNA_HWCTX_STATE_IDLE;

	for (int i = 0; i < job->bo_cnt; i++) {
		if (!job->bos[i].obj)
			break;

		drm_gem_object_put(job->bos[i].obj);
	}
	drm_gem_object_put(to_gobj(job->cmd_bo));

	mutex_lock(&hwctx->priv->privctx_lock);
	// Reset the pending list
	hwctx->priv->pending[get_job_idx(job->seq)] = NULL;
	ve2_job_put(job);
	mutex_unlock(&hwctx->priv->privctx_lock);
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
		dma_free_coherent(&pdev->dev,
				  sizeof(struct hsa_queue) + sizeof(u64) * HOST_QUEUE_ENTRY,
				  queue->hsa_queue_p,
				  queue->hsa_queue_mem.dma_addr);
		queue->hsa_queue_p = NULL;
	}
}

void packet_dump(struct amdxdna_dev *xdna, struct hsa_queue *queue, u64 slot_id)
{
	if (slot_id >= HOST_QUEUE_ENTRY) {
		XDNA_ERR(xdna, "Invalid slot_id: %llu\n", slot_id);
		return;
	}

	/* Print physical addresses */
	XDNA_DBG(xdna, "hsa dma_addr data 0x%llx\n", queue->hq_header.data_address);

	/* Print host_queue_packet */
	struct host_queue_packet *pkt = &queue->hq_entry[slot_id];

	XDNA_DBG(xdna, "Packet Dump for slot_id %llu:\n", slot_id);
	XDNA_DBG(xdna, "xrt_header.common_header.opcode: %u\n",
		 pkt->xrt_header.common_header.opcode);
	XDNA_DBG(xdna, "xrt_header.common_header.count: %u\n",
		 pkt->xrt_header.common_header.count);
	XDNA_DBG(xdna, "xrt_header.common_header.distribute: %u\n",
		 pkt->xrt_header.common_header.distribute);
	XDNA_DBG(xdna, "xrt_header.common_header.indirect: %u\n",
		 pkt->xrt_header.common_header.indirect);
	XDNA_DBG(xdna, "xrt_header.completion_signal: %llx\n",
		 pkt->xrt_header.completion_signal);
	for (int i = 0; i < 12; i++)
		XDNA_DBG(xdna, "\tdata[%d]: %x\n", i, (u32)pkt->data[i]);

	/* Print physical address of host_queue_packet */
	u64 pkt_paddr = queue->hq_header.data_address + ((u64)pkt - (u64)queue->hq_entry);

	XDNA_DBG(xdna, "Physical address of host_queue_packet: 0x%llx\n", pkt_paddr);

	/* Print host_queue_indirect_hdr */
	struct host_queue_indirect_hdr *indirect_hdr = &queue->hq_indirect_hdr[slot_id];
	int total_entry = indirect_hdr->header.count / sizeof(struct host_indirect_packet_entry);

	XDNA_DBG(xdna, "indirect_hdr.header.opcode: %u\n", indirect_hdr->header.opcode);
	XDNA_DBG(xdna, "indirect_hdr.header.count: %u\n", indirect_hdr->header.count);
	XDNA_DBG(xdna, "indirect_hdr.header.distribute: %u\n", indirect_hdr->header.distribute);
	XDNA_DBG(xdna, "indirect_hdr.header.indirect: %u\n", indirect_hdr->header.indirect);
	XDNA_DBG(xdna, "Total packet Entry %d\n", total_entry);
	for (int i = 0; i < 2 * total_entry; i += 2) {
		XDNA_DBG(xdna, "\tindirect_hdr.data[%d]: %x, indirect_hdr.data[%d]: %x\n",
			 i, (u32)indirect_hdr->data[i], i + 1,
			 (u32)(indirect_hdr->data[i + 1] & 0x1FFFFFF));
		XDNA_DBG(xdna, "Retrieved dpu_uc_index: %u\n",
			 (indirect_hdr->data[i + 1] >> 25) & 0x7F);
	}

	/* Print physical address of host_queue_indirect_hdr */
	u64 indirect_hdr_paddr = queue->hq_header.data_address +
			((u64)indirect_hdr - (u64)queue->hq_entry);
	XDNA_DBG(xdna, "Physical addr of host_queue_indirect_hdr: 0x%llx\n", indirect_hdr_paddr);

	/* Print host_queue_indirect_pkt */
	for (int i = 0; i < total_entry; i++) {
		struct host_queue_indirect_pkt *indirect_pkt = &queue->hq_indirect_pkt[slot_id][i];

		/* Print physical address of host_queue_indirect_pkt */
		u64 indirect_pkt_paddr = queue->hq_header.data_address +
			((u64)indirect_pkt - (u64)queue->hq_entry);

		XDNA_DBG(xdna, "\nPhysical address of indirect_pkt[%d]: 0x%llx\n", i,
			 indirect_pkt_paddr);
		XDNA_DBG(xdna, "\t\tindirect_pkt[%d].header.opcode: %u\n",
			 i, indirect_pkt->header.opcode);
		XDNA_DBG(xdna, "\t\tindirect_pkt[%d].header.count: %u\n",
			 i, indirect_pkt->header.count);
		XDNA_DBG(xdna, "\t\tindirect_pkt[%d].header.distribute: %u\n",
			 i, indirect_pkt->header.distribute);
		XDNA_DBG(xdna, "\t\tindirect_pkt[%d].header.indirect: %u\n",
			 i, indirect_pkt->header.indirect);
		XDNA_DBG(xdna, "\t\tindirect_pkt[%d].payload.cu_index: %u\n",
			 i, indirect_pkt->payload.cu_index);
		XDNA_DBG(xdna, "\t\tindirect_pkt[%d].payload.dpu_control_code_host_addr_low: %x\n",
			 i, (u32)indirect_pkt->payload.dpu_control_code_host_addr_low);
		XDNA_DBG(xdna, "\t\tindirect_pkt[%d].payload.dpu_control_code_host_addr_high: %x\n",
			 i, (u32)indirect_pkt->payload.dpu_control_code_host_addr_high);
		XDNA_DBG(xdna, "\t\tindirect_pkt[%d].payload.args_len: %u\n",
			 i, indirect_pkt->payload.args_len);
		XDNA_DBG(xdna, "\t\tindirect_pkt[%d].payload.args_host_addr_low: %x\n",
			 i, (u32)indirect_pkt->payload.args_host_addr_low);
		XDNA_DBG(xdna, "\t\tindirect_pkt[%d].payload.args_host_addr_high: %x\n",
			 i, (u32)indirect_pkt->payload.args_host_addr_high);
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

	/* Allocate a single contiguous block of memory */
	queue->hsa_queue_p = dma_alloc_coherent(&pdev->dev,
						sizeof(struct hsa_queue) + sizeof(u64) * nslots,
						&dma_handle,
						GFP_KERNEL);
	if (!queue->hsa_queue_p)
		return -ENOMEM;

	/* Set the base DMA address for hsa queue */
	queue->hsa_queue_mem.dma_addr = dma_handle;

	/* Calculate the address for hqc_mem within the allocated block */
	queue->hq_complete.hqc_mem =
		(u64 *)((char *)queue->hsa_queue_p + sizeof(struct hsa_queue));
	queue->hq_complete.hqc_dma_addr = queue->hsa_queue_mem.dma_addr + sizeof(struct hsa_queue);
	queue->hsa_queue_p->hq_header.data_address = queue->hsa_queue_mem.dma_addr +
		sizeof(struct host_queue_header);

	/* Set hsa queue slots to invalid */
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
	XDNA_DBG(xdna, "slot %llx is selected", slot_id);
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

	/* Enable for debug purpose */
	if (verbosity >= VERBOSITY_LEVEL_DBG)
		packet_dump(xdna, queue, slot_id);

	hsa_queue_pkt_set_valid(pkt);
	/* Update write index here */
	update_ctx_write_index(hwctx, 1);

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
#define XRT_PKT_OPCODE(p) ((p)->xrt_header.common_header.opcode)
	XDNA_DBG(xdna, "Queue packet opcode: %u\n", XRT_PKT_OPCODE(pkt));

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
	/* Update write index here */
	update_ctx_write_index(hwctx, 1);

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

		abo = amdxdna_gem_get_obj(hwctx->client, boh, AMDXDNA_BO_SHARE);
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

	if (hwctx->priv->misc_intrpt_flag) {
		XDNA_ERR(xdna, "Failed to submit a command, because of misc interrupt\n");
		return -EINVAL;
	}

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

	XDNA_DBG(xdna, "Command submitted with temporal sharing enabled");
	ve2_mgmt_schedule_cmd(xdna, hwctx, *seq);

	return 0;
}

/*
 * Handle interrupt notification based on read_index and write_index.
 */
static inline bool check_read_index(struct amdxdna_ctx *hwctx,
				    u64 seq, u32 print_interval)
{
	struct amdxdna_ctx_priv *priv_ctx = hwctx->priv;
	static u64 counter;
	u64 *read_index;

	if (!hwctx || !priv_ctx || !priv_ctx->hwctx_hsa_queue.hsa_queue_p)
		return false;

	if (priv_ctx->misc_intrpt_flag)
		return true;

	read_index = (u64 *)((char *)priv_ctx->hwctx_hsa_queue.hsa_queue_p +
			HSA_QUEUE_READ_INDEX_OFFSET);

	if (counter % print_interval == 0) {
		struct amdxdna_dev *xdna = hwctx->client->xdna;

		XDNA_DBG(xdna, "read index address: 0x%llx", (u64)read_index);
		XDNA_WARN(xdna, "hwctx [%p] check read idx (%llu) > cmd idx (%llu)",
			  hwctx, *read_index, seq);
	}

	counter++;
	return (*read_index > seq);
}

static void ve2_dump_ctx(struct amdxdna_dev *xdna, struct amdxdna_ctx *hwctx)
{
	struct amdxdna_ctx_priv *priv_ctx = hwctx->priv;
	struct device *aie_dev = priv_ctx->aie_dev;
	struct amdxdna_ctx_health_data_aie4 *r;
	struct handshake *hs = NULL;
	int ret = 0;

	r = kzalloc(sizeof(*r) + priv_ctx->num_col * sizeof(struct uc_health_info), GFP_KERNEL);
	if (!r) {
		XDNA_ERR(xdna, "No memory for struct amdxdna_ctx_health_data_aie4\n");
		return;
	}

	for (u32 col = 0; col < priv_ctx->num_col; col++) {
		hs = kzalloc(sizeof(*hs), GFP_KERNEL);
		if (!hs) {
			XDNA_ERR(xdna, "No memory for handshake.\n");
			return;
		}
		ret = ve2_partition_read_privileged_mem(aie_dev, col,
							offsetof(struct handshake, mpaie_alive),
							sizeof(struct handshake), (void *)hs);

		if (ret < 0) {
			XDNA_ERR(xdna, "aie_partition_read failed with ret=%d\n", ret);
			kfree(hs);
			kfree(r);
			return;
		}

		r->uc_info[col].uc_idx = hwctx->start_col + col;
		r->uc_info[col].page_idx = hs->vm.abs_page_index;
		r->uc_info[col].offset = hs->vm.ppc;
		r->uc_info[col].uc_idle_status = hs->cert_idle_status;
		r->uc_info[col].misc_status = hs->misc_status;
		r->uc_info[col].uc_pc = hs->exception.pc;
		r->uc_info[col].uc_ear = hs->exception.ear;
		r->uc_info[col].uc_esr = hs->exception.esr;
		r->uc_info[col].fw_state = hs->vm.fw_state;
		kfree(hs);
	}

	hwctx->health_data.version = AMDXDNA_CTX_HEALTH_DATA_V1;
	hwctx->health_data.npu_gen = AMDXDNA_NPU_GEN_AIE4;
	hwctx->health_data.aie4.ctx_state = priv_ctx->state;
	hwctx->health_data.aie4.num_uc = priv_ctx->num_col;
	memcpy(hwctx->health_data.aie4.uc_info, r->uc_info, priv_ctx->num_col *
	       sizeof(struct uc_health_info));

	kfree(r);
}

int ve2_cmd_wait(struct amdxdna_ctx *hwctx, u64 seq, u32 timeout)
{
	struct amdxdna_ctx_priv *priv_ctx = hwctx->priv;
	struct amdxdna_dev *xdna = hwctx->client->xdna;
	struct amdxdna_sched_job *job;
	u32 print_interval = 300;
	unsigned long wait_jifs;
	int ret = 0;

	/*
	 * NOTE: this is simplified hwctx which has no col_entry list for different ctx
	 * sharing the same lead col.
	 * The current version assumes one hwctx is 1:1 mapping with one lead cert col
	 */
	wait_jifs = msecs_to_jiffies(timeout);
	mutex_lock(&priv_ctx->hwctx_hsa_queue.hq_lock);
	if (wait_jifs)
		ret = wait_event_interruptible_timeout(priv_ctx->waitq,
						       check_read_index(hwctx, seq, print_interval),
						       wait_jifs);
	else
		ret = wait_event_interruptible(priv_ctx->waitq,
					       check_read_index(hwctx, seq, print_interval));
	mutex_unlock(&priv_ctx->hwctx_hsa_queue.hq_lock);

	XDNA_DBG(xdna, "wait_event returned %d (timeout_jiffies=%lu)", ret, wait_jifs);

	if ((!wait_jifs && !ret) || ret > 0) {
		job = ve2_hwctx_get_job(hwctx, seq);
		if (unlikely(!job)) {
			ret = 0;
			goto out;
		}

		/*
		 * amdxdna_cmd_set_state(job->cmd_bo,
		 *                       priv_ctx->hwctx_hsa_queue.hq_complete.hqc_mem[seq]);
		 */
		/*
		 * below check need to be removed once we have a clean solution
		 * to use completion signal
		 */
		if (priv_ctx->misc_intrpt_flag || (wait_jifs && !ret)) {
			XDNA_ERR(xdna, "cmd timeout. misc_intr_flag=%u timeout_jiffies=%lu ret=%d",
				 priv_ctx->misc_intrpt_flag, wait_jifs, ret);
			void *cmd_data;
			u32 data_total;

			ve2_dump_ctx(xdna, hwctx);

			cmd_data = amdxdna_cmd_get_data(job->cmd_bo, &data_total);
			size_t total_size = sizeof(struct amdxdna_ctx_health_data) +
					priv_ctx->num_col * sizeof(struct uc_health_info);
			if (unlikely(data_total < sizeof(hwctx->health_data)))
				XDNA_WARN(xdna, "%s: data_total: %u, sizeof(health): %lu", __func__,
					  data_total, total_size);

			data_total = min(data_total, total_size);
			memcpy(cmd_data, &hwctx->health_data, total_size);
			hwctx->health_reported = true;
			amdxdna_cmd_set_state(job->cmd_bo, ERT_CMD_STATE_TIMEOUT);
		} else {
			amdxdna_cmd_set_state(job->cmd_bo, ERT_CMD_STATE_COMPLETED);
		}

		ve2_hwctx_job_release(hwctx, job);

		if (!wait_jifs)
			return 0;
	}

	/*
	 * wait_event_interruptible_timeout() returns 0 when the condition evaluated to false
	 * after the timeout elapsed. So, return -ETIME in this case
	 */
	if (!ret)
		ret = -ETIME;

out:
	XDNA_DBG(xdna, "wait_cmd ret:%d", ret);
	/* 0 is success, others are timeout */
	return ret > 0 ? 0 : ret;
}

void ve2_free_firmware_slots(struct amdxdna_dev_hdl *xdna_hdl, u32 max_cols)
{
	u32 col;

	for (col = 0; col < max_cols; col++) {
		kfree(xdna_hdl->fw_slots[col]);
		xdna_hdl->fw_slots[col] = NULL;
	}
}

static void timeout_cb(struct timer_list *t)
{
	struct amdxdna_ctx_priv *priv = from_timer(priv, t, event_timer);

	wake_up_interruptible_all(&priv->waitq);
	mod_timer(&priv->event_timer, jiffies + CTX_TIMER);
}

static void ve2_clear_firmware_status(struct amdxdna_dev *xdna, struct amdxdna_ctx *hwctx)
{
	struct amdxdna_ctx_priv *priv = hwctx->priv;
	struct ve2_firmware_status *fs;

	for (u32 col = priv->start_col; col < priv->start_col + priv->num_col; col++) {
		fs = xdna->dev_handle->fw_slots[col];
		fs->state = 0;
		fs->abs_page_index = 0;
		fs->ppc = 0;
		fs->idle_status = 0;
		fs->misc_status = 0;
	}
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

	ret = ve2_xrs_request(xdna, hwctx);
	if (ret)
		goto free_hsa_queue;

	if (enable_polling) {
		XDNA_INFO(xdna, "Running in timer mode");
		timer_setup(&priv->event_timer, timeout_cb, 0);
		mod_timer(&priv->event_timer, jiffies + CTX_TIMER);
	} else {
		XDNA_INFO(xdna, "Running in interrupt mode");
	}

	if (verbosity >= VERBOSITY_LEVEL_DBG)
		ve2_clear_firmware_status(xdna, hwctx);

	priv->state = AMDXDNA_HWCTX_STATE_IDLE;

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

	if (enable_polling)
		del_timer_sync(&hwctx->priv->event_timer);

	if (verbosity >= VERBOSITY_LEVEL_DBG)
		ve2_get_firmware_status(hwctx);

	ve2_mgmt_destroy_partition(hwctx);
	ve2_free_hsa_queue(xdna, &hwctx->priv->hwctx_hsa_queue);
	kfree(hwctx->priv);
	XDNA_DBG(xdna, "Destroyed hwctx %p, total cmds submitted (%llu), completed(%llu)",
		 hwctx, hwctx->submitted, hwctx->completed);
}

static int ve2_update_handshake_pkt(struct amdxdna_ctx *hwctx, u8 buf_type, u64 paddr,
				    u32 buf_sz, u32 col, bool attach)
{
	struct amdxdna_ctx_priv *nhwctx = hwctx->priv;

	switch (buf_type) {
	case AMDXDNA_FW_BUF_DEBUG:
		nhwctx->hwctx_config[hwctx->start_col + col].debug_buf_addr = paddr;
		nhwctx->hwctx_config[hwctx->start_col + col].debug_buf_size = buf_sz;
		break;

	case AMDXDNA_FW_BUF_TRACE:
		nhwctx->hwctx_config[hwctx->start_col + col].dtrace_addr = paddr;
		break;

	case AMDXDNA_FW_BUF_LOG:
		nhwctx->hwctx_config[hwctx->start_col + col].log_buf_addr = paddr;
		nhwctx->hwctx_config[hwctx->start_col + col].log_buf_size = buf_sz;
		break;

	default:
		struct amdxdna_dev *xdna = hwctx->client->xdna;

		XDNA_ERR(xdna, "Invalid Request");
		return -EOPNOTSUPP;
	}

	return 0;
}

static void ve2_hwctx_config_op_timeout(struct amdxdna_ctx *hwctx, u32 op_timeout)
{
	struct amdxdna_ctx_priv *nhwctx = hwctx->priv;

	for (u32 col = 0; col < hwctx->num_col; col++)
		nhwctx->hwctx_config[hwctx->start_col + col].opcode_timeout_config = op_timeout;
}

int ve2_hwctx_config(struct amdxdna_ctx *hwctx, u32 type, u64 mdata_hdl, void *buf, u32 size)
{
	struct amdxdna_dev *xdna = hwctx->client->xdna;
	struct amdxdna_client *client = hwctx->client;
	struct amdxdna_gem_obj *abo, *mdata_abo;
	struct fw_buffer_metadata *mdata;
	u32 prev_buf_sz = 0;
	u32 op_timeout;
	u64 buf_paddr;
	u32 buf_sz;
	int ret;

	/* Update fw's handshake shared memory with debug/trace buffer details */
	switch (type) {
	case DRM_AMDXDNA_HWCTX_ASSIGN_DBG_BUF:
		mdata_abo = amdxdna_gem_get_obj(client, mdata_hdl, AMDXDNA_BO_SHARE);
		if (!mdata_abo || !mdata_abo->dma_buf) {
			XDNA_ERR(xdna, "Get metadata bo %lld failed for type %d", mdata_hdl, type);
			return -EINVAL;
		}
		mdata = (struct fw_buffer_metadata *)(amdxdna_gem_vmap(mdata_abo));
		if (!mdata) {
			XDNA_ERR(xdna, "No metadata defined for bo %lld type %d", mdata_hdl, type);
			amdxdna_gem_put_obj(mdata_abo);
			return -EINVAL;
		}

		abo = amdxdna_gem_get_obj(client, mdata->bo_handle, AMDXDNA_BO_SHARE);
		if (!abo) {
			XDNA_ERR(xdna, "Get bo %lld failed for type %d", mdata->bo_handle, type);
			amdxdna_gem_put_obj(mdata_abo);
			return -EINVAL;
		}

		for (u32 col = 0; col < hwctx->num_col; col++) {
			buf_sz = mdata->uc_info[col].size;
			if (buf_sz == 0)
				continue;
			buf_paddr = amdxdna_gem_dev_addr(abo) + prev_buf_sz;
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

	case DRM_AMDXDNA_HWCTX_REMOVE_DBG_BUF:
		mdata_abo = amdxdna_gem_get_obj(client, mdata_hdl, AMDXDNA_BO_SHARE);
		if (!mdata_abo || !mdata_abo->dma_buf) {
			XDNA_ERR(xdna, "Get metadata bo %lld failed for type %d", mdata_hdl, type);
			return -EINVAL;
		}
		mdata = (struct fw_buffer_metadata *)(amdxdna_gem_vmap(mdata_abo));
		if (!mdata) {
			XDNA_ERR(xdna, "No metadata defined for bo %lld type %d", mdata_hdl, type);
			amdxdna_gem_put_obj(mdata_abo);
			return -EINVAL;
		}
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

	case DRM_AMDXDNA_HWCTX_CONFIG_OPCODE_TIMEOUT:
		if (copy_from_user(&op_timeout, (u32 __user *)(uintptr_t)mdata_hdl, sizeof(u32))) {
			XDNA_ERR(xdna, "hwctx config req %d failed", type);
			return -EFAULT;
		}

		ve2_hwctx_config_op_timeout(hwctx, op_timeout);
		XDNA_DBG(xdna, "Configured opcode timeout %u on hwctx %s",
			 op_timeout, hwctx->name);
		break;

	default:
		XDNA_DBG(xdna, "%s Not supported type %d", __func__, type);
		ret = -EOPNOTSUPP;
		if (mdata_abo)
			amdxdna_gem_put_obj(mdata_abo);
		break;
	}

	return ret;
}

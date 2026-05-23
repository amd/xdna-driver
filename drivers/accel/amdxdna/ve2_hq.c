// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2026, Advanced Micro Devices, Inc.
 *
 * VE2 host queue: DMA HSA queue, ERT_START_DPU / ERT_CMD_CHAIN submit, cmd wait.
 */

#include <linux/dma-mapping.h>
#include <linux/errno.h>
#include <linux/slab.h>
#include <linux/wait.h>

#include "amdxdna_ctx.h"
#include "amdxdna_drv.h"
#include "amdxdna_gem.h"
#include "ve2_aie.h"
#include "ve2_aux.h"
#include "ve2_hq.h"
#include "ve2_hwctx.h"
#include "ve2_trace.h"

struct ve2_dpu_data {
	u64 dtrace_buffer;
	u64 instruction_buffer;
	u32 instruction_buffer_size;
	u16 uc_index;
	u16 chained;
};

static inline struct ve2_dpu_data *ve2_dpu_data_next(struct ve2_dpu_data *dpu)
{
	if (!dpu || !dpu->chained)
		return NULL;

	return dpu + 1;
}

struct ve2_hwctx_priv *ve2_hw_priv(struct amdxdna_hwctx *hwctx)
{
	if (!hwctx || !hwctx->priv)
		return NULL;

	return hwctx->priv->hw_priv;
}

static void ve2_hq_release_job(struct kref *ref)
{
	struct amdxdna_sched_job *job =
		container_of(ref, struct amdxdna_sched_job, refcnt);

	amdxdna_sched_job_cleanup(job);
	kfree(job);
}

static void ve2_hq_job_put(struct amdxdna_sched_job *job)
{
	kref_put(&job->refcnt, ve2_hq_release_job);
}

static int ve2_hq_add_job(struct amdxdna_hwctx *hwctx, struct amdxdna_sched_job *job,
			  u64 seq, u32 cmd_cnt)
{
	struct amdxdna_dev *xdna = hwctx->client->xdna;
	struct ve2_hwctx_priv *vp = ve2_hw_priv(hwctx);
	int idx;

	if (!vp)
		return -EINVAL;

	mutex_lock(&vp->privctx_lock);
	vp->submitted += cmd_cnt;
	job->seq = seq;

	idx = get_job_idx(job->seq);
	if (vp->pending[idx]) {
		mutex_unlock(&vp->privctx_lock);
		XDNA_ERR(xdna, "No room for new command");
		return -EINVAL;
	}

	vp->pending[idx] = job;
	vp->state = AMDXDNA_HWCTX_STATE_ACTIVE;
	mutex_unlock(&vp->privctx_lock);

	return 0;
}

static struct amdxdna_sched_job *ve2_hq_get_job(struct amdxdna_hwctx *hwctx, u64 seq)
{
	struct ve2_hwctx_priv *vp = ve2_hw_priv(hwctx);

	if (!vp)
		return NULL;

	return vp->pending[get_job_idx(seq)];
}

static void ve2_hq_job_release_locked(struct amdxdna_hwctx *hwctx,
				      struct amdxdna_sched_job *job)
{
	struct ve2_hwctx_priv *vp = ve2_hw_priv(hwctx);
	struct amdxdna_gem_obj *cmd_bo = job->cmd_bo;
	struct amdxdna_cmd_chain *cmd_chain;
	u32 cmd_cnt = 1;
	u32 op;

	if (!vp)
		return;

	op = amdxdna_cmd_get_op(cmd_bo);
	if (op == ERT_CMD_CHAIN) {
		cmd_chain = amdxdna_cmd_get_payload(cmd_bo, NULL);
		if (cmd_chain)
			cmd_cnt = cmd_chain->command_count;
	}

	vp->completed += cmd_cnt;
	if (vp->completed == vp->submitted)
		vp->state = AMDXDNA_HWCTX_STATE_IDLE;

	mutex_lock(&vp->privctx_lock);
	vp->pending[get_job_idx(job->seq)] = NULL;
	ve2_hq_job_put(job);
	mutex_unlock(&vp->privctx_lock);
}

static bool ve2_hq_slot_available(struct amdxdna_hwctx *hwctx)
{
	struct ve2_hwctx_priv *vp = ve2_hw_priv(hwctx);
	struct ve2_hsa_queue *queue;
	struct host_queue_header *header;
	u32 capacity;
	u64 outstanding;
	u32 slot_idx;
	bool available;

	if (!vp || !vp->hsa_queue.hsa_queue_p)
		return false;

	queue = &vp->hsa_queue;
	header = &queue->hsa_queue_p->hq_header;
	capacity = header->capacity;

	mutex_lock(&queue->hq_lock);
	hsa_queue_sync_read_index_for_read(queue);
	outstanding = queue->reserved_write_index - header->read_index;
	if (outstanding >= capacity) {
		mutex_unlock(&queue->hq_lock);
		return false;
	}

	slot_idx = queue->reserved_write_index % capacity;
	mutex_lock(&vp->privctx_lock);
	available = !vp->pending[slot_idx];
	mutex_unlock(&vp->privctx_lock);
	mutex_unlock(&queue->hq_lock);

	return available;
}

static int ve2_hq_wait_slot(struct amdxdna_hwctx *hwctx, u32 timeout_ms)
{
	struct ve2_hwctx_priv *vp = ve2_hw_priv(hwctx);
	unsigned long timeout_jiffies = msecs_to_jiffies(timeout_ms);
	long ret;

	if (!vp)
		return -EINVAL;

	ret = wait_event_interruptible_timeout(vp->waitq, ve2_hq_slot_available(hwctx),
					       timeout_jiffies);
	if (ret == 0)
		return -ETIMEDOUT;

	if (ret < 0)
		return ret;

	return 0;
}

static struct host_queue_packet *
ve2_hq_reserve_slot(struct amdxdna_dev *xdna, struct ve2_hwctx_priv *vp, u64 *slot)
{
	struct ve2_hsa_queue *queue = &vp->hsa_queue;
	struct host_queue_header *header = &queue->hsa_queue_p->hq_header;
	u32 capacity = header->capacity;
	u32 slot_idx;
	u64 outstanding;

	mutex_lock(&queue->hq_lock);
	hsa_queue_sync_read_index_for_read(queue);

	if (queue->reserved_write_index < header->read_index) {
		mutex_unlock(&queue->hq_lock);
		return ERR_PTR(-EINVAL);
	}

	outstanding = queue->reserved_write_index - header->read_index;
	if (outstanding >= capacity) {
		mutex_unlock(&queue->hq_lock);
		return ERR_PTR(-EBUSY);
	}

	slot_idx = queue->reserved_write_index % capacity;
	mutex_lock(&vp->privctx_lock);
	if (vp->pending[slot_idx]) {
		mutex_unlock(&vp->privctx_lock);
		mutex_unlock(&queue->hq_lock);
		return ERR_PTR(-EBUSY);
	}
	mutex_unlock(&vp->privctx_lock);

	*slot = queue->reserved_write_index++;
	queue->hq_complete.hqc_mem[slot_idx] = ERT_CMD_STATE_NEW;
	hsa_queue_sync_completion_for_write(queue, slot_idx);
	mutex_unlock(&queue->hq_lock);

	return &queue->hsa_queue_p->hq_entry[slot_idx];
}

static void ve2_hq_commit_slot(struct amdxdna_hwctx *hwctx, u64 seq)
{
	struct ve2_hwctx_priv *vp = ve2_hw_priv(hwctx);
	struct ve2_hsa_queue *queue;
	struct host_queue_header *header;
	u32 capacity;
	u32 slot_idx;
	struct host_queue_packet *pkt;

	if (!vp)
		return;

	queue = &vp->hsa_queue;
	header = &queue->hsa_queue_p->hq_header;
	capacity = header->capacity;
	slot_idx = seq % capacity;
	pkt = &queue->hsa_queue_p->hq_entry[slot_idx];

	mutex_lock(&queue->hq_lock);
	pkt->xrt_header.common_header.type = HOST_QUEUE_PACKET_TYPE_VENDOR_SPECIFIC;
	hsa_queue_sync_packet_for_write(queue, slot_idx);

	queue->hq_complete.hqc_mem[slot_idx] = ERT_CMD_STATE_SUBMITTED;
	hsa_queue_sync_completion_for_write(queue, slot_idx);

	while (header->write_index < queue->reserved_write_index) {
		u32 next_idx = header->write_index % capacity;

		hsa_queue_sync_completion_for_read(queue, next_idx);
		if (queue->hq_complete.hqc_mem[next_idx] != ERT_CMD_STATE_SUBMITTED)
			break;
		header->write_index++;
	}
	hsa_queue_sync_write_index_for_write(queue);
	mutex_unlock(&queue->hq_lock);
}

static int ve2_hq_submit_direct(struct amdxdna_hwctx *hwctx, void *cmd_data, u64 *seq,
				bool last_cmd)
{
	struct amdxdna_dev *xdna = hwctx->client->xdna;
	struct ve2_hwctx_priv *vp = ve2_hw_priv(hwctx);
	struct ve2_dpu_data *dpu = cmd_data;
	struct host_queue_packet *pkt;
	struct xrt_packet_header *hdr;
	struct exec_buf *ebp;
	u64 slot_id = 0;

	pkt = ve2_hq_reserve_slot(xdna, vp, &slot_id);
	if (IS_ERR(pkt))
		return PTR_ERR(pkt);

	*seq = slot_id;
	slot_id &= vp->hsa_queue.hsa_queue_p->hq_header.capacity - 1;

	hdr = &pkt->xrt_header;
	hdr->common_header.opcode = HOST_QUEUE_PACKET_EXEC_BUF;
	hdr->common_header.chain_flag = last_cmd ? LAST_CMD : NOT_LAST_CMD;
	hdr->completion_signal = (u64)(vp->hsa_queue.hq_complete.hqc_dma_addr +
				       slot_id * sizeof(u64));
	hdr->common_header.count = sizeof(struct exec_buf);
	hdr->common_header.distribute = 0;
	hdr->common_header.indirect = 0;

	ebp = (struct exec_buf *)pkt->data;
	ebp->dpu_control_code_host_addr_high = upper_32_bits(dpu->instruction_buffer);
	ebp->dpu_control_code_host_addr_low = lower_32_bits(dpu->instruction_buffer);
	ebp->dtrace_buf_host_addr_high = upper_32_bits(dpu->dtrace_buffer);
	ebp->dtrace_buf_host_addr_low = lower_32_bits(dpu->dtrace_buffer);
	ebp->args_len = 0;
	ebp->args_host_addr_low = 0;
	ebp->args_host_addr_high = 0;

	hsa_queue_sync_packet_for_write(&vp->hsa_queue, slot_id);
	ve2_hq_commit_slot(hwctx, *seq);

	return 0;
}

static int ve2_hq_submit_indirect(struct amdxdna_hwctx *hwctx, void *cmd_data, u64 *seq,
				  bool last_cmd)
{
	struct amdxdna_dev *xdna = hwctx->client->xdna;
	struct ve2_hwctx_priv *vp = ve2_hw_priv(hwctx);
	struct ve2_dpu_data *dpu = cmd_data;
	struct hsa_queue *queue = vp->hsa_queue.hsa_queue_p;
	struct host_queue_packet *pkt;
	struct host_queue_indirect_hdr *indirect_hdr;
	struct host_indirect_packet_entry *hp, *hp_hdr;
	u64 slot_id = 0;
	u32 total_cmds;
	u32 i;

	pkt = ve2_hq_reserve_slot(xdna, vp, &slot_id);
	if (IS_ERR(pkt))
		return PTR_ERR(pkt);

	*seq = slot_id;
	slot_id &= queue->hq_header.capacity - 1;

	pkt->xrt_header.common_header.opcode = HOST_QUEUE_PACKET_EXEC_BUF;
	pkt->xrt_header.common_header.chain_flag = last_cmd ? LAST_CMD : NOT_LAST_CMD;
	pkt->xrt_header.common_header.count = sizeof(struct host_indirect_packet_entry);
	pkt->xrt_header.common_header.distribute = 1;
	pkt->xrt_header.common_header.indirect = 1;
	pkt->xrt_header.completion_signal =
		(u64)(vp->hsa_queue.hq_complete.hqc_dma_addr + slot_id * sizeof(u64));

	indirect_hdr = &queue->hq_indirect_hdr[slot_id];
	total_cmds = dpu->chained + 1;
	indirect_hdr->header.count = total_cmds * sizeof(struct host_indirect_packet_entry);
	indirect_hdr->header.indirect = 1;
	indirect_hdr->header.distribute = 1;

	hp = (struct host_indirect_packet_entry *)pkt->data;
	hp->host_addr_low = lower_32_bits(queue->hq_header.data_address +
		((u64)&queue->hq_indirect_hdr[slot_id] - (u64)&queue->hq_entry));
	hp->host_addr_high = upper_32_bits(queue->hq_header.data_address +
		((u64)&queue->hq_indirect_hdr[slot_id] - (u64)&queue->hq_entry));
	hp->uc_index = 0;

	hp_hdr = (struct host_indirect_packet_entry *)indirect_hdr->data;
	for (i = 0; dpu && i < total_cmds; i++, hp_hdr++, dpu = ve2_dpu_data_next(dpu)) {
		struct host_queue_indirect_pkt *indirect_data =
			&queue->hq_indirect_pkt[dpu->uc_index][slot_id];
		u64 paddr = queue->hq_header.data_address +
			((u64)&queue->hq_indirect_pkt[dpu->uc_index][slot_id] -
			 (u64)&queue->hq_entry);

		hp_hdr->host_addr_low = lower_32_bits(paddr);
		hp_hdr->host_addr_high = upper_32_bits(paddr);
		hp_hdr->uc_index = dpu->uc_index;

		indirect_data->payload.dpu_control_code_host_addr_low =
			lower_32_bits(dpu->instruction_buffer);
		indirect_data->payload.dpu_control_code_host_addr_high =
			upper_32_bits(dpu->instruction_buffer);
		indirect_data->payload.dtrace_buf_host_addr_low =
			lower_32_bits(dpu->dtrace_buffer);
		indirect_data->payload.dtrace_buf_host_addr_high =
			upper_32_bits(dpu->dtrace_buffer);
		indirect_data->payload.args_len = 0;
		indirect_data->payload.args_host_addr_low = 0;
		indirect_data->payload.args_host_addr_high = 0;
		hsa_queue_sync_indirect_pkt_for_write(&vp->hsa_queue, dpu->uc_index, slot_id);
	}

	hsa_queue_sync_packet_for_write(&vp->hsa_queue, slot_id);
	hsa_queue_sync_indirect_hdr_for_write(&vp->hsa_queue, slot_id);
	ve2_hq_commit_slot(hwctx, *seq);

	return 0;
}

static int ve2_hq_push_cmd(struct amdxdna_hwctx *hwctx, void *cmd_data, u64 *seq,
			   bool last_cmd)
{
	int ret;

	while (true) {
		if (ve2_dpu_data_next(cmd_data))
			ret = ve2_hq_submit_indirect(hwctx, cmd_data, seq, last_cmd);
		else
			ret = ve2_hq_submit_direct(hwctx, cmd_data, seq, last_cmd);

		if (ret != -EBUSY)
			break;

		ret = ve2_hq_wait_slot(hwctx, VE2_RETRY_TIMEOUT_MS);
		if (ret)
			return ret == -ETIMEDOUT ? -EAGAIN : ret;
	}

	return ret;
}

static int ve2_hq_submit_single(struct amdxdna_hwctx *hwctx, struct amdxdna_sched_job *job,
				u64 *seq)
{
	struct amdxdna_dev *xdna = hwctx->client->xdna;
	void *cmd_data;
	u32 cmd_data_len;
	int ret;

	cmd_data = amdxdna_cmd_get_payload(job->cmd_bo, &cmd_data_len);
	if (!cmd_data) {
		XDNA_ERR(xdna, "Invalid command payload");
		return -EINVAL;
	}

	ret = ve2_hq_push_cmd(hwctx, cmd_data, seq, true);
	if (ret)
		return ret;

	return ve2_hq_add_job(hwctx, job, *seq, 1);
}

static int ve2_hq_submit_chain(struct amdxdna_hwctx *hwctx, struct amdxdna_sched_job *job,
			       u64 *seq)
{
	struct amdxdna_dev *xdna = hwctx->client->xdna;
	struct amdxdna_cmd_chain *cmd_chain;
	u32 cmd_chain_len;
	u32 start_idx = 0;
	u32 total_submitted = 0;
	int ret;

	cmd_chain = amdxdna_cmd_get_payload(job->cmd_bo, &cmd_chain_len);
	if (!cmd_chain ||
	    cmd_chain_len < struct_size(cmd_chain, data, cmd_chain->command_count)) {
		XDNA_ERR(xdna, "Invalid command chain");
		return -EINVAL;
	}

	while (start_idx < cmd_chain->command_count) {
		u32 submitted = 0;
		u32 i = start_idx;

		for (; i < cmd_chain->command_count; i++) {
			struct amdxdna_gem_obj *abo;
			void *cmd_data;
			u32 cmd_data_len;
			bool last_cmd = (i == cmd_chain->command_count - 1);

			abo = amdxdna_gem_get_obj(hwctx->client, (u32)cmd_chain->data[i],
						  AMDXDNA_BO_SHARE);
			if (!abo)
				return -ENOENT;

			cmd_data = amdxdna_cmd_get_payload(abo, &cmd_data_len);
			if (!cmd_data) {
				amdxdna_gem_put_obj(abo);
				return -EINVAL;
			}

			ret = ve2_hq_push_cmd(hwctx, cmd_data, seq, last_cmd);
			amdxdna_gem_put_obj(abo);

			if (ret == -EBUSY) {
				total_submitted += submitted;
				start_idx += submitted;
				ret = ve2_hq_wait_slot(hwctx, VE2_RETRY_TIMEOUT_MS);
				if (ret)
					return ret == -ETIMEDOUT ? -EAGAIN : ret;
				break;
			}
			if (ret)
				return ret;

			submitted++;
		}

		if (i == cmd_chain->command_count) {
			total_submitted += submitted;
			break;
		}
	}

	return ve2_hq_add_job(hwctx, job, *seq, cmd_chain->command_count);
}

int ve2_hq_alloc(struct amdxdna_hwctx *hwctx)
{
	struct amdxdna_dev *xdna = hwctx->client->xdna;
	struct ve2_hwctx_priv *vp = ve2_hw_priv(hwctx);
	struct ve2_hsa_queue *queue;
	struct device *alloc_dev;
	dma_addr_t dma_handle;
	size_t alloc_size;
	unsigned int r;
	int slot, uc;

	if (!vp)
		return -EINVAL;

	queue = &vp->hsa_queue;
	alloc_size = sizeof(struct hsa_queue) + sizeof(u64) * HOST_QUEUE_ENTRY;

	for (r = 0; r < AMDXDNA_MAX_MEM_REGIONS; r++) {
		alloc_dev = xdna->cma_region_devs[r];
		if ((vp->mem_bitmap & (1U << r)) && alloc_dev) {
			queue->hsa_queue_p = dma_alloc_coherent(alloc_dev, alloc_size,
								&dma_handle, GFP_KERNEL);
			if (queue->hsa_queue_p) {
				queue->alloc_dev = alloc_dev;
				break;
			}
		}
	}

	if (!queue->hsa_queue_p) {
		queue->hsa_queue_p = dma_alloc_coherent(xdna->ddev.dev, alloc_size,
							&dma_handle, GFP_KERNEL);
		if (!queue->hsa_queue_p)
			return -ENOMEM;
		queue->alloc_dev = xdna->ddev.dev;
	}

	mutex_init(&queue->hq_lock);
	queue->reserved_write_index = 0;
	queue->hsa_queue_mem.dma_addr = dma_handle;
	queue->hq_complete.hqc_mem =
		(u64 *)((char *)queue->hsa_queue_p + sizeof(struct hsa_queue));
	queue->hq_complete.hqc_dma_addr = dma_handle + sizeof(struct hsa_queue);
	queue->hsa_queue_p->hq_header.data_address =
		dma_handle + sizeof(struct host_queue_header);
	queue->hsa_queue_p->hq_header.capacity = HOST_QUEUE_ENTRY;

	for (slot = 0; slot < HOST_QUEUE_ENTRY; slot++) {
		struct host_queue_indirect_hdr *hdr = &queue->hsa_queue_p->hq_indirect_hdr[slot];

		hsa_queue_pkt_set_invalid(hsa_queue_get_pkt(queue->hsa_queue_p, slot));
		hdr->header.type = HOST_QUEUE_PACKET_TYPE_VENDOR_SPECIFIC;
		hdr->header.opcode = HOST_QUEUE_PACKET_EXEC_BUF;
		hdr->header.count = 0;
		hdr->header.distribute = 1;
		hdr->header.indirect = 1;

		for (uc = 0; uc < HOST_INDIRECT_PKT_NUM; uc++) {
			struct host_queue_indirect_pkt *pkt =
				&queue->hsa_queue_p->hq_indirect_pkt[uc][slot];

			pkt->header.type = HOST_QUEUE_PACKET_TYPE_VENDOR_SPECIFIC;
			pkt->header.opcode = HOST_QUEUE_PACKET_EXEC_BUF;
			pkt->header.count = sizeof(struct exec_buf);
			pkt->header.distribute = 1;
			pkt->header.indirect = 0;
		}
	}

	dma_sync_single_for_device(queue->alloc_dev, dma_handle, sizeof(struct hsa_queue),
				   DMA_TO_DEVICE);

	vp->start_col = hwctx->start_col;
	vp->num_col = hwctx->num_col;

	XDNA_DBG(xdna, "Host queue alloc dma=0x%llx capacity=%u",
		 (u64)dma_handle, HOST_QUEUE_ENTRY);

	return 0;
}

static void ve2_hq_drain_pending(struct amdxdna_hwctx *hwctx)
{
	struct ve2_hwctx_priv *vp = ve2_hw_priv(hwctx);
	int i;

	if (!vp)
		return;

	mutex_lock(&vp->privctx_lock);
	for (i = 0; i < HWCTX_MAX_CMDS; i++) {
		struct amdxdna_sched_job *job = vp->pending[i];

		if (!job)
			continue;

		vp->pending[i] = NULL;
		mutex_unlock(&vp->privctx_lock);
		ve2_hq_job_put(job);
		mutex_lock(&vp->privctx_lock);
	}
	mutex_unlock(&vp->privctx_lock);
}

void ve2_hq_free(struct amdxdna_hwctx *hwctx)
{
	struct ve2_hwctx_priv *vp = ve2_hw_priv(hwctx);
	struct ve2_hsa_queue *queue;
	size_t alloc_size;

	if (!vp)
		return;

	ve2_hq_drain_pending(hwctx);

	queue = &vp->hsa_queue;
	if (!queue->hsa_queue_p)
		return;

	alloc_size = sizeof(struct hsa_queue) + sizeof(u64) * HOST_QUEUE_ENTRY;
	dma_free_coherent(queue->alloc_dev, alloc_size, queue->hsa_queue_p,
			  queue->hsa_queue_mem.dma_addr);
	queue->hsa_queue_p = NULL;
	mutex_destroy(&queue->hq_lock);
}

int ve2_hq_cmd_submit(struct amdxdna_hwctx *hwctx, struct amdxdna_sched_job *job, u64 *seq)
{
	struct amdxdna_dev *xdna = hwctx->client->xdna;
	struct ve2_hwctx_link *link = hwctx->aux_ctx_priv;
	struct amdxdna_gem_obj *cmd_bo = job->cmd_bo;
	u32 op;
	int ret;

	if (!ve2_hw_priv(hwctx))
		return -EINVAL;

	op = amdxdna_cmd_get_op(cmd_bo);
	VE2_TRACE(xdna, "cmd_submit ENTER pid=%d hwctx=%p op=%u start_col=%u",
		  hwctx->client->pid, hwctx, op, hwctx->start_col);
	if (op != ERT_START_DPU && op != ERT_CMD_CHAIN) {
		XDNA_WARN(xdna, "Unsupported ERT opcode %u", op);
		return -EINVAL;
	}

	if (op == ERT_CMD_CHAIN)
		ret = ve2_hq_submit_chain(hwctx, job, seq);
	else
		ret = ve2_hq_submit_single(hwctx, job, seq);

	if (ret) {
		if (ret == -EAGAIN)
			return -ERESTARTSYS;
		return ret;
	}

	if (!link || !link->aie_ctx)
		return -EINVAL;

	ret = ve2_aie_kick_cmd(link->aie_ctx, *seq + 1);
	if (ret < 0) {
		struct ve2_hwctx_priv *vp = ve2_hw_priv(hwctx);
		u32 op = amdxdna_cmd_get_op(cmd_bo);
		u32 cmd_cnt = 1;

		if (op == ERT_CMD_CHAIN) {
			struct amdxdna_cmd_chain *chain = amdxdna_cmd_get_payload(cmd_bo, NULL);

			if (chain)
				cmd_cnt = chain->command_count;
		}
		if (vp) {
			struct amdxdna_sched_job *job;

			mutex_lock(&vp->privctx_lock);
			job = vp->pending[get_job_idx(*seq)];
			vp->pending[get_job_idx(*seq)] = NULL;
			vp->submitted -= cmd_cnt;
			mutex_unlock(&vp->privctx_lock);
			if (job)
				ve2_hq_job_put(job);
		}
		XDNA_ERR(xdna, "cmd_submit kick failed ret=%d", ret);
		return ret;
	}
	VE2_TRACE(xdna, "cmd_submit DONE seq=%llu", *seq);
	return 0;
}

static bool ve2_hq_read_index_done(struct amdxdna_hwctx *hwctx, u64 seq)
{
	struct ve2_hwctx_priv *vp = ve2_hw_priv(hwctx);
	u64 read_index;

	if (!vp || !vp->hsa_queue.hsa_queue_p)
		return false;

	read_index = *(u64 *)((char *)vp->hsa_queue.hsa_queue_p + HSA_QUEUE_READ_INDEX_OFFSET);
	hsa_queue_sync_read_index_for_read(&vp->hsa_queue);

	return read_index > seq;
}

static bool ve2_hq_wait_done(struct amdxdna_hwctx *hwctx, u64 seq)
{
	struct ve2_hwctx_priv *vp = ve2_hw_priv(hwctx);

	if (vp && vp->misc_intrpt_flag)
		return true;

	return ve2_hq_read_index_done(hwctx, seq);
}

static bool ve2_hq_hqc_has_terminal_state(struct ve2_hwctx_priv *vp, u64 seq)
{
	u32 capacity = vp->hsa_queue.hsa_queue_p->hq_header.capacity;
	u32 slot = seq % capacity;
	enum ert_cmd_state state;

	hsa_queue_sync_completion_for_read(&vp->hsa_queue, slot);
	state = (enum ert_cmd_state)((u32)vp->hsa_queue.hq_complete.hqc_mem[slot] & 0xF);

	return state == ERT_CMD_STATE_COMPLETED ||
	       state == ERT_CMD_STATE_ERROR ||
	       state == ERT_CMD_STATE_ABORT;
}

static void ve2_hq_process_completion(struct amdxdna_hwctx *hwctx,
				      struct amdxdna_sched_job *job, u64 seq)
{
	struct amdxdna_dev *xdna = hwctx->client->xdna;
	struct ve2_hwctx_priv *vp = ve2_hw_priv(hwctx);
	u32 capacity = vp->hsa_queue.hsa_queue_p->hq_header.capacity;
	u32 slot = seq % capacity;
	u32 comp;
	enum ert_cmd_state state;

	hsa_queue_sync_completion_for_read(&vp->hsa_queue, slot);
	comp = (u32)vp->hsa_queue.hq_complete.hqc_mem[slot];
	state = (enum ert_cmd_state)(comp & 0xF);

	if (state < ERT_CMD_STATE_NEW || state > ERT_CMD_STATE_NORESPONSE) {
		XDNA_WARN(xdna, "state %u at hqc_mem[%u] raw 0x%x", state, slot, comp);
		return;
	}

	if ((state == ERT_CMD_STATE_ERROR || state == ERT_CMD_STATE_ABORT) &&
	    amdxdna_cmd_get_op(job->cmd_bo) == ERT_CMD_CHAIN) {
		struct amdxdna_cmd_chain *cc = amdxdna_cmd_get_payload(job->cmd_bo, NULL);
		enum ert_cmd_state slot_state = state;
		u32 fail_cmd_idx = 0;
		u32 start_slot;
		u32 cmd_count;
		int i;

		if (!cc) {
			amdxdna_cmd_set_state(job->cmd_bo, state);
			return;
		}

		cmd_count = cc->command_count;
		start_slot = (seq - cmd_count + 1) % capacity;

		for (i = cmd_count; i > 0; i--) {
			u32 idx = (start_slot + i - 1) % capacity;

			hsa_queue_sync_completion_for_read(&vp->hsa_queue, idx);
			comp = (u32)vp->hsa_queue.hq_complete.hqc_mem[idx];
			slot_state = (enum ert_cmd_state)(comp & 0xF);
			if (slot_state != ERT_CMD_STATE_ABORT) {
				fail_cmd_idx = i - 1;
				break;
			}
		}

		cc->error_index = fail_cmd_idx;
		if (cc->error_index >= cmd_count)
			cc->error_index = 0;

		amdxdna_cmd_set_state(job->cmd_bo, slot_state);
	} else {
		amdxdna_cmd_set_state(job->cmd_bo, state);
	}
}

static void ve2_hq_handle_timeout(struct amdxdna_hwctx *hwctx,
				  struct amdxdna_sched_job *job, u64 seq)
{
	(void)hwctx;
	(void)seq;

	if (job && job->cmd_bo)
		amdxdna_cmd_set_state(job->cmd_bo, ERT_CMD_STATE_TIMEOUT);
}

int ve2_hq_cmd_wait(struct amdxdna_hwctx *hwctx, u64 seq, u32 timeout_ms)
{
	struct amdxdna_dev *xdna = hwctx->client->xdna;
	struct ve2_hwctx_priv *vp = ve2_hw_priv(hwctx);
	struct amdxdna_sched_job *job;
	unsigned long wait_jifs = msecs_to_jiffies(timeout_ms);
	long ret = 0;

	if (!vp)
		return -EINVAL;

	VE2_TRACE(xdna, "cmd_wait ENTER pid=%d seq=%llu timeout_ms=%u misc=%d polling=%d",
		  hwctx->client->pid, seq, timeout_ms, vp->misc_intrpt_flag, enable_polling);

	if (wait_jifs)
		ret = wait_event_interruptible_timeout(vp->waitq,
						       ve2_hq_wait_done(hwctx, seq),
						       wait_jifs);
	else
		ret = wait_event_interruptible(vp->waitq,
					       ve2_hq_wait_done(hwctx, seq));

	VE2_TRACE(xdna, "cmd_wait woke pid=%d seq=%llu wait_ret=%ld read_done=%d misc=%d",
		  hwctx->client->pid, seq, ret,
		  ve2_hq_read_index_done(hwctx, seq), vp->misc_intrpt_flag);

	mutex_lock(&vp->hsa_queue.hq_lock);
	if ((!wait_jifs && !ret) || ret > 0) {
		mutex_lock(&vp->privctx_lock);
		job = ve2_hq_get_job(hwctx, seq);
		if (job)
			kref_get(&job->refcnt);
		mutex_unlock(&vp->privctx_lock);

		if (!job) {
			ret = 0;
			goto out;
		}

		if (vp->misc_intrpt_flag || (wait_jifs && !ret)) {
			if (vp->misc_intrpt_flag && ve2_hq_hqc_has_terminal_state(vp, seq))
				ve2_hq_process_completion(hwctx, job, seq);
			else
				ve2_hq_handle_timeout(hwctx, job, seq);
		} else {
			ve2_hq_process_completion(hwctx, job, seq);
		}

		ve2_hq_job_release_locked(hwctx, job);
		ve2_hq_job_put(job);

		if (!wait_jifs) {
			mutex_unlock(&vp->hsa_queue.hq_lock);
			return 0;
		}
	}

	if (!ret)
		ret = -ETIME;

out:
	mutex_unlock(&vp->hsa_queue.hq_lock);
	VE2_TRACE(xdna, "cmd_wait EXIT pid=%d seq=%llu ret=%ld", hwctx->client->pid, seq,
		  ret > 0 ? 0L : ret);

	return ret > 0 ? 0 : ret;
}

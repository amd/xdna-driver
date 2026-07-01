// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2026, Advanced Micro Devices, Inc.
 *
 * VE2 DRM hardware context: XRS, host queue, and command submit/wait path
 * (ERT_START_DPU).
 */

#include <linux/dma-mapping.h>
#include <linux/errno.h>
#include <linux/module.h>
#include <linux/overflow.h>
#include <linux/slab.h>
#include <linux/timer.h>
#include <linux/wait.h>

#include "drm/amdxdna_accel.h"

#include "amdxdna_ctx.h"
#include "amdxdna_drv.h"
#include "amdxdna_gem.h"
#include "ve2_aux.h"
#include "ve2_hwctx.h"
#include "ve2_mgmt.h"

int enable_polling;
module_param(enable_polling, int, 0644);
MODULE_PARM_DESC(enable_polling, "Enables host-queue polling timer mode. Polling mode disabled by default.");

#define CTX_TIMER		(msecs_to_jiffies(1))	/* 1ms */
#define VE2_RETRY_TIMEOUT_MS	5000	/* max wait for a free host-queue slot */

/*
 * struct ve2_dpu_data - payload interpretation for ERT_START_DPU.
 * @dtrace_buffer:		dtrace buffer address
 * @instruction_buffer:		control-code (instruction) buffer address
 * @instruction_buffer_size:	size of the instruction buffer in bytes
 * @uc_index:			target micro-controller index
 * @chained:			number of ve2_dpu_data elements that follow
 *
 * A command targeting a single UC carries one ve2_dpu_data. A command spanning
 * multiple UCs carries @chained additional contiguous ve2_dpu_data entries and
 * is submitted via the indirect/distributed host-queue packet path.
 */
struct ve2_dpu_data {
	u64 dtrace_buffer;
	u64 instruction_buffer;
	u32 instruction_buffer_size;
	u16 uc_index;
	u16 chained;
};

static inline struct ve2_dpu_data *get_ve2_dpu_data_next(struct ve2_dpu_data *dpu_data)
{
	if (dpu_data->chained == 0)
		return NULL;

	return dpu_data + 1;
}

static void ve2_job_release(struct kref *ref)
{
	struct amdxdna_sched_job *job =
		container_of(ref, struct amdxdna_sched_job, refcnt);

	amdxdna_sched_job_cleanup(job);
	kfree(job);
}

static void ve2_job_put(struct amdxdna_sched_job *job)
{
	kref_put(&job->refcnt, ve2_job_release);
}

static int ve2_hwctx_add_job(struct amdxdna_hwctx *hwctx, struct amdxdna_sched_job *job,
			     u64 seq, u32 cmd_cnt)
{
	struct amdxdna_dev *xdna = hwctx->client->xdna;
	struct amdxdna_ctx_priv *vp = ve2_hw_priv(hwctx);
	int idx;

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

static struct amdxdna_sched_job *ve2_hwctx_get_job(struct amdxdna_hwctx *hwctx, u64 seq)
{
	struct amdxdna_ctx_priv *vp = ve2_hw_priv(hwctx);

	return vp->pending[get_job_idx(seq)];
}

static void ve2_hwctx_job_release(struct amdxdna_hwctx *hwctx, struct amdxdna_sched_job *job)
{
	struct amdxdna_ctx_priv *vp = ve2_hw_priv(hwctx);
	u32 cmd_cnt = 1;

	if (amdxdna_cmd_get_op(job->cmd_bo) == ERT_CMD_CHAIN) {
		struct amdxdna_cmd_chain *cmd_chain = amdxdna_cmd_get_payload(job->cmd_bo, NULL);

		if (cmd_chain)
			cmd_cnt = cmd_chain->command_count;
	}

	guard(mutex)(&vp->privctx_lock);
	vp->completed += cmd_cnt;
	if (vp->completed == vp->submitted)
		vp->state = AMDXDNA_HWCTX_STATE_IDLE;
	vp->pending[get_job_idx(job->seq)] = NULL;
	ve2_job_put(job);
}

static struct host_queue_packet *
hsa_queue_reserve_slot(struct amdxdna_dev *xdna, struct amdxdna_ctx_priv *vp, u64 *slot)
{
	struct ve2_hsa_queue *queue = &vp->hsa_queue;
	struct host_queue_header *header = &queue->hsa_queue_p->hq_header;
	u32 capacity = header->capacity;
	u64 outstanding;
	u32 slot_idx;

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

	/*
	 * Runlist optimization: Slot availability is determined by read_index only.
	 * Host uses read_index; no INVALID state check. Ring buffer math ensures
	 * we never overwrite when outstanding < capacity.
	 *
	 * Additionally, we must ensure the pending slot is free before reusing.
	 * Pending is cleared in ve2_cmd_wait when the waiting thread runs, which
	 * can lag behind read_index advance. Without this check, multi-threaded
	 * submit can hit "No more room" in ve2_hwctx_add_job.
	 */
	mutex_lock(&vp->privctx_lock);
	if (vp->pending[get_job_idx(queue->reserved_write_index)]) {
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

static void hsa_queue_commit_slot(struct amdxdna_hwctx *hwctx, u64 seq)
{
	struct amdxdna_ctx_priv *vp = ve2_hw_priv(hwctx);
	struct host_queue_header *header;
	struct host_queue_packet *pkt;
	struct ve2_hsa_queue *queue;
	u32 capacity;
	u32 slot_idx;

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

/*
 * ve2_check_slot_available - Check if a queue slot is available
 * @hwctx: Hardware context
 *
 * Returns true if at least one slot is available, false otherwise.
 * This is used as the condition for wait_event_interruptible_timeout.
 *
 */
static bool ve2_check_slot_available(struct amdxdna_hwctx *hwctx)
{
	struct amdxdna_ctx_priv *vp = ve2_hw_priv(hwctx);
	struct ve2_hsa_queue *queue = &vp->hsa_queue;
	struct host_queue_header *header = &queue->hsa_queue_p->hq_header;
	u32 capacity = header->capacity;
	u64 outstanding;
	bool available;

	mutex_lock(&queue->hq_lock);
	hsa_queue_sync_read_index_for_read(queue);
	outstanding = queue->reserved_write_index - header->read_index;
	if (outstanding >= capacity) {
		mutex_unlock(&queue->hq_lock);
		return false;
	}

	mutex_lock(&vp->privctx_lock);
	available = !vp->pending[get_job_idx(queue->reserved_write_index)];
	mutex_unlock(&vp->privctx_lock);
	mutex_unlock(&queue->hq_lock);

	return available;
}

/*
 * ve2_wait_for_retry_slot - Wait for a queue slot to become available
 * @hwctx: Hardware context
 * @timeout_ms: Maximum time to wait in milliseconds
 *
 * This function uses wait_event_interruptible_timeout to sleep until
 * a slot becomes available. The IRQ handler will wake us up when
 * commands complete and slots are freed.
 *
 * Returns:
 *   0 on success (slot available)
 *   -ETIMEDOUT if timeout expired
 *   negative error code if interrupted
 */

static int ve2_wait_for_retry_slot(struct amdxdna_hwctx *hwctx, u32 timeout_ms)
{
	struct amdxdna_ctx_priv *vp = ve2_hw_priv(hwctx);
	long ret;

	ret = wait_event_interruptible_timeout(vp->waitq, ve2_check_slot_available(hwctx),
					       msecs_to_jiffies(timeout_ms));
	if (ret == 0) {
		XDNA_ERR(hwctx->client->xdna,
			 "Timeout error in waiting for cmd slots, hwctx_id=%u pid=%u timeout=%u ms",
			 hwctx->id, hwctx->client->pid, timeout_ms);
		return -ETIMEDOUT;
	}
	if (ret < 0) {
		XDNA_WARN(hwctx->client->xdna,
			  "Wait for command slot interrupted: hwctx_id=%u pid=%u ret=%ld",
			  hwctx->id, hwctx->client->pid, ret);
		return ret;
	}

	return 0;
}

static int submit_command(struct amdxdna_hwctx *hwctx, void *cmd_data, u64 *seq, bool last_cmd)
{
	struct amdxdna_ctx_priv *vp = ve2_hw_priv(hwctx);
	struct amdxdna_dev *xdna = hwctx->client->xdna;
	struct ve2_dpu_data *dpu = cmd_data;
	struct host_queue_packet *pkt;
	struct xrt_packet_header *hdr;
	struct exec_buf *ebp;
	u64 slot_id = 0;

	pkt = hsa_queue_reserve_slot(xdna, vp, &slot_id);
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
	hsa_queue_commit_slot(hwctx, *seq);

	return 0;
}

static int submit_command_indirect(struct amdxdna_hwctx *hwctx, void *cmd_data, u64 *seq,
				   bool last_cmd)
{
	struct amdxdna_ctx_priv *vp = ve2_hw_priv(hwctx);
	struct amdxdna_dev *xdna = hwctx->client->xdna;
	struct ve2_dpu_data *dpu = cmd_data;
	struct host_queue_indirect_hdr *indirect_hdr;
	struct host_indirect_packet_entry *hp;
	struct host_indirect_packet_entry *hp_hdr;
	struct host_queue_packet *pkt;
	struct xrt_packet_header *hdr;
	struct ve2_dpu_data *d;
	struct hsa_queue *queue;
	u64 hdr_paddr;
	u32 total_cmds;
	u64 slot_id = 0;
	u32 slot_idx;
	int i;

	/* Validate the whole UC list up-front so a bad command never leaks a slot. */
	total_cmds = dpu->chained + 1;
	if (total_cmds > HOST_INDIRECT_PKT_NUM) {
		XDNA_ERR(xdna, "Too many chained UC entries %u (max %u)",
			 total_cmds, HOST_INDIRECT_PKT_NUM);
		return -EINVAL;
	}
	for (i = 0, d = dpu; d && i < total_cmds; i++, d = get_ve2_dpu_data_next(d)) {
		if (d->uc_index >= HOST_INDIRECT_PKT_NUM) {
			XDNA_ERR(xdna, "Invalid UC index %u (max %u)", d->uc_index,
				 HOST_INDIRECT_PKT_NUM);
			return -EINVAL;
		}
	}

	pkt = hsa_queue_reserve_slot(xdna, vp, &slot_id);
	if (IS_ERR(pkt))
		return PTR_ERR(pkt);

	queue = vp->hsa_queue.hsa_queue_p;
	*seq = slot_id;
	slot_idx = slot_id & (queue->hq_header.capacity - 1);

	hdr = &pkt->xrt_header;
	hdr->common_header.opcode = HOST_QUEUE_PACKET_EXEC_BUF;
	hdr->common_header.chain_flag = last_cmd ? LAST_CMD : NOT_LAST_CMD;
	hdr->common_header.count = sizeof(struct host_indirect_packet_entry);
	hdr->common_header.distribute = 1;
	hdr->common_header.indirect = 1;
	hdr->completion_signal = (u64)(vp->hsa_queue.hq_complete.hqc_dma_addr +
				       slot_idx * sizeof(u64));

	indirect_hdr = &queue->hq_indirect_hdr[slot_idx];
	indirect_hdr->header.count = total_cmds * sizeof(struct host_indirect_packet_entry);
	indirect_hdr->header.indirect = 1;
	indirect_hdr->header.distribute = 1;

	hdr_paddr = (u64)queue->hq_header.data_address +
		    ((u64)&queue->hq_indirect_hdr[slot_idx] - (u64)&queue->hq_entry);

	/* The top-level entry in the host-queue packet points at the indirect header. */
	hp = (struct host_indirect_packet_entry *)pkt->data;
	hp->host_addr_low = lower_32_bits(hdr_paddr);
	hp->host_addr_high = upper_32_bits(hdr_paddr);
	hp->uc_index = 0;

	hp_hdr = (struct host_indirect_packet_entry *)indirect_hdr->data;

	for (i = 0; dpu && i < total_cmds;
	     i++, hp_hdr++, dpu = get_ve2_dpu_data_next(dpu)) {
		u16 uc = dpu->uc_index;
		struct host_queue_indirect_pkt *ipkt;
		struct exec_buf *ebp;
		u64 pkt_paddr;

		ipkt = &queue->hq_indirect_pkt[uc][slot_idx];
		pkt_paddr = (u64)queue->hq_header.data_address +
			    ((u64)&queue->hq_indirect_pkt[uc][slot_idx] - (u64)&queue->hq_entry);

		hp_hdr->host_addr_low = lower_32_bits(pkt_paddr);
		hp_hdr->host_addr_high = upper_32_bits(pkt_paddr);
		hp_hdr->uc_index = uc;

		ebp = &ipkt->payload;
		ebp->dpu_control_code_host_addr_high = upper_32_bits(dpu->instruction_buffer);
		ebp->dpu_control_code_host_addr_low = lower_32_bits(dpu->instruction_buffer);
		ebp->dtrace_buf_host_addr_high = upper_32_bits(dpu->dtrace_buffer);
		ebp->dtrace_buf_host_addr_low = lower_32_bits(dpu->dtrace_buffer);
		ebp->args_len = 0;
		ebp->args_host_addr_low = 0;
		ebp->args_host_addr_high = 0;

		hsa_queue_sync_indirect_pkt_for_write(&vp->hsa_queue, uc, slot_idx);
	}

	hsa_queue_sync_packet_for_write(&vp->hsa_queue, slot_idx);
	hsa_queue_sync_indirect_hdr_for_write(&vp->hsa_queue, slot_idx);
	hsa_queue_commit_slot(hwctx, *seq);

	return 0;
}

/*
 * Reserve and commit a single command into the host queue. When the queue is
 * momentarily full (-EBUSY), block until the completion IRQ frees a slot and
 * retry, rather than failing the submission back to user space.
 */
static int submit_command_retry(struct amdxdna_hwctx *hwctx, void *cmd_data, u64 *seq,
				bool last_cmd)
{
	struct amdxdna_dev *xdna = hwctx->client->xdna;
	int ret;

	while (true) {
		if (get_ve2_dpu_data_next(cmd_data))
			ret = submit_command_indirect(hwctx, cmd_data, seq, last_cmd);
		else
			ret = submit_command(hwctx, cmd_data, seq, last_cmd);
		if (ret != -EBUSY)
			return ret;

		ret = ve2_wait_for_retry_slot(hwctx, VE2_RETRY_TIMEOUT_MS);
		if (ret == -ETIMEDOUT) {
			XDNA_DBG(xdna, "Submit timeout: no slot available after %ums",
				 VE2_RETRY_TIMEOUT_MS);
			return -EAGAIN;
		}
		if (ret < 0) {
			XDNA_ERR(xdna, "Submit interrupted while waiting for slot");
			return ret;
		}
	}
}

static int ve2_submit_cmd_single(struct amdxdna_hwctx *hwctx, struct amdxdna_sched_job *job,
				 u64 *seq)
{
	struct amdxdna_dev *xdna = hwctx->client->xdna;
	u32 cmd_data_len;
	void *cmd_data;
	int ret;

	cmd_data = amdxdna_cmd_get_payload(job->cmd_bo, &cmd_data_len);
	if (!cmd_data) {
		XDNA_ERR(xdna, "Invalid command payload");
		return -EINVAL;
	}

	ret = submit_command_retry(hwctx, cmd_data, seq, true);
	if (ret < 0)
		return ret;

	return ve2_hwctx_add_job(hwctx, job, *seq, 1);
}

static int ve2_create_host_queue(struct amdxdna_hwctx *hwctx)
{
	struct amdxdna_dev *xdna = hwctx->client->xdna;
	struct amdxdna_ctx_priv *vp = ve2_hw_priv(hwctx);
	struct ve2_hsa_queue *queue;
	dma_addr_t dma_handle;
	size_t alloc_size;
	int slot;

	if (!vp)
		return -EINVAL;

	queue = &vp->hsa_queue;
	alloc_size = sizeof(struct hsa_queue) + sizeof(u64) * HOST_QUEUE_ENTRY;

	queue->hsa_queue_p = dma_alloc_coherent(xdna->ddev.dev, alloc_size,
						&dma_handle, GFP_KERNEL);
	if (!queue->hsa_queue_p)
		return -ENOMEM;
	queue->alloc_dev = xdna->ddev.dev;

	mutex_init(&queue->hq_lock);
	queue->reserved_write_index = 0;
	queue->hsa_queue_dma_addr = dma_handle;
	queue->hq_complete.hqc_mem =
		(u64 *)((char *)queue->hsa_queue_p + sizeof(struct hsa_queue));
	queue->hq_complete.hqc_dma_addr = dma_handle + sizeof(struct hsa_queue);
	queue->hsa_queue_p->hq_header.data_address =
		dma_handle + sizeof(struct host_queue_header);
	queue->hsa_queue_p->hq_header.capacity = HOST_QUEUE_ENTRY;

	/* Set hsa queue slots to invalid and initialize indirect regions */
	for (slot = 0; slot < HOST_QUEUE_ENTRY; slot++) {
		struct host_queue_indirect_hdr *ihdr =
			&queue->hsa_queue_p->hq_indirect_hdr[slot];
		int uc;

		hsa_queue_pkt_set_invalid(hsa_queue_get_pkt(queue->hsa_queue_p, slot));

		ihdr->header.type = HOST_QUEUE_PACKET_TYPE_VENDOR_SPECIFIC;
		ihdr->header.opcode = HOST_QUEUE_PACKET_EXEC_BUF;
		ihdr->header.count = 0;
		ihdr->header.distribute = 1;
		ihdr->header.indirect = 1;

		for (uc = 0; uc < HOST_INDIRECT_PKT_NUM; uc++) {
			struct host_queue_indirect_pkt *ipkt =
				&queue->hsa_queue_p->hq_indirect_pkt[uc][slot];

			ipkt->header.type = HOST_QUEUE_PACKET_TYPE_VENDOR_SPECIFIC;
			ipkt->header.opcode = HOST_QUEUE_PACKET_EXEC_BUF;
			ipkt->header.count = sizeof(struct exec_buf);
			ipkt->header.distribute = 1;
			ipkt->header.indirect = 0;
		}
	}

	dma_sync_single_for_device(queue->alloc_dev, dma_handle, sizeof(struct hsa_queue),
				   DMA_TO_DEVICE);

	XDNA_DBG(xdna, "Host queue alloc dma=0x%llx capacity=%u", (u64)dma_handle,
		 HOST_QUEUE_ENTRY);

	return 0;
}

static void ve2_drain_pending(struct amdxdna_hwctx *hwctx)
{
	struct amdxdna_ctx_priv *vp = ve2_hw_priv(hwctx);
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
		ve2_job_put(job);
		mutex_lock(&vp->privctx_lock);
	}
	mutex_unlock(&vp->privctx_lock);
}

static void ve2_free_hsa_queue(struct amdxdna_hwctx *hwctx)
{
	struct amdxdna_ctx_priv *vp = ve2_hw_priv(hwctx);
	struct ve2_hsa_queue *queue;
	size_t alloc_size;

	if (!vp)
		return;

	ve2_drain_pending(hwctx);

	queue = &vp->hsa_queue;
	if (!queue->hsa_queue_p)
		return;

	alloc_size = sizeof(struct hsa_queue) + sizeof(u64) * HOST_QUEUE_ENTRY;
	dma_free_coherent(queue->alloc_dev, alloc_size, queue->hsa_queue_p,
			  queue->hsa_queue_dma_addr);
	queue->hsa_queue_p = NULL;
	mutex_destroy(&queue->hq_lock);
}

static void ve2_hwctx_poll_timer(struct timer_list *t)
{
	struct amdxdna_ctx_priv *vp = from_timer(vp, t, event_timer);

	wake_up_interruptible_all(&vp->waitq);
	mod_timer(&vp->event_timer, jiffies + CTX_TIMER);
}

/**
 * ve2_hwctx_init - XRS request (column list + partition), host queue, timer.
 */
int ve2_hwctx_init(struct amdxdna_hwctx *hwctx)
{
	struct amdxdna_client *client = hwctx->client;
	struct amdxdna_dev *xdna = client->xdna;
	struct amdxdna_hwctx_priv *priv;
	struct amdxdna_dev_hdl *hdl;
	struct amdxdna_ctx_priv *vp;
	int ret;

	hdl = ve2_dev_hdl(xdna);
	if (!hdl)
		return -ENODEV;

	priv = kzalloc(sizeof(*priv), GFP_KERNEL);
	if (!priv)
		return -ENOMEM;

	vp = kzalloc(sizeof(*vp), GFP_KERNEL);
	if (!vp) {
		kfree(priv);
		return -ENOMEM;
	}

	hwctx->priv = priv;
	priv->hw_priv = vp;

	init_waitqueue_head(&priv->job_free_wq);
	mutex_init(&vp->privctx_lock);
	init_waitqueue_head(&vp->waitq);

	/* VE2: num_tiles is the number of AIE columns (not a 2D tile count). */
	if (!hwctx->num_tiles) {
		XDNA_ERR(xdna, "Number of columns is zero");
		ret = -EINVAL;
		goto free_priv;
	}

	ret = ve2_xrs_request(xdna, hwctx);
	if (ret) {
		XDNA_ERR(xdna, "XRS resource request failed, ret %d", ret);
		goto free_priv;
	}

	ve2_auto_select_mem_bitmap(xdna, hwctx);

	/* Allocate per-column config array (zero-initialised = no buffers attached). */
	vp->hwctx_config = kcalloc(hwctx->num_col, sizeof(*vp->hwctx_config), GFP_KERNEL);
	if (!vp->hwctx_config) {
		ret = -ENOMEM;
		goto destroy_partition;
	}

	ret = ve2_create_host_queue(hwctx);
	if (ret) {
		XDNA_ERR(xdna, "Host queue alloc failed, ret %d", ret);
		goto free_hwctx_config;
	}

	if (!hwctx->max_opc)	/* default to max number of commands */
		hwctx->max_opc = HWCTX_MAX_CMDS;

	if (enable_polling) {
		timer_setup(&vp->event_timer, ve2_hwctx_poll_timer, 0);
		mod_timer(&vp->event_timer, jiffies + CTX_TIMER);
		XDNA_DBG(xdna, "hwctx %p: polling mode enabled", hwctx);
	} else {
		XDNA_DBG(xdna, "hwctx %p: interrupt mode", hwctx);
	}
	return 0;

free_hwctx_config:
	kfree(vp->hwctx_config);
	vp->hwctx_config = NULL;
destroy_partition:
	ve2_mgmt_destroy_partition(hwctx);
free_priv:
	mutex_destroy(&vp->privctx_lock);
	kfree(vp);
	kfree(priv);
	hwctx->priv = NULL;
	return ret;
}

/**
 * ve2_hwctx_fini - Release resources from ve2_hwctx_init(); caller holds @xdna->dev_lock.
 */
void ve2_hwctx_fini(struct amdxdna_hwctx *hwctx)
{
	struct amdxdna_hwctx_priv *priv = hwctx->priv;
	struct amdxdna_ctx_priv *vp;

	if (!priv)
		return;

	vp = priv->hw_priv;

	ve2_mgmt_destroy_partition(hwctx);
	ve2_free_hsa_queue(hwctx);

	if (vp) {
		if (enable_polling)
			del_timer_sync(&vp->event_timer);
		kfree(vp->hwctx_config);
		vp->hwctx_config = NULL;
		mutex_destroy(&vp->privctx_lock);
		kfree(vp);
		priv->hw_priv = NULL;
	}

	kfree(priv);
	hwctx->priv = NULL;
}

/*
 * ve2_submit_cmd_chain - Submit an ERT_CMD_CHAIN (runlist) job.
 */
static int ve2_submit_cmd_chain(struct amdxdna_hwctx *hwctx, struct amdxdna_sched_job *job,
				u64 *seq)
{
	struct amdxdna_dev *xdna = hwctx->client->xdna;
	struct amdxdna_gem_obj *cmd_bo = job->cmd_bo;
	struct amdxdna_cmd_chain *cmd_chain;
	u32 cmd_chain_len;
	int ret;

	cmd_chain = amdxdna_cmd_get_payload(cmd_bo, &cmd_chain_len);
	if (!cmd_chain ||
	    cmd_chain_len < struct_size(cmd_chain, data, cmd_chain->command_count)) {
		XDNA_ERR(xdna, "Invalid command chain payload");
		return -EINVAL;
	}

	if (!cmd_chain->command_count) {
		XDNA_ERR(xdna, "Empty command chain");
		return -EINVAL;
	}

	for (u32 i = 0; i < cmd_chain->command_count; i++) {
		u32 boh = (u32)cmd_chain->data[i];
		bool last_cmd = (i == cmd_chain->command_count - 1);
		struct amdxdna_gem_obj *abo;
		u32 cmd_data_len;
		void *cmd_data;

		abo = amdxdna_gem_get_obj(hwctx->client, boh, AMDXDNA_BO_SHARE);
		if (!abo) {
			XDNA_ERR(xdna, "Failed to find cmd BO %u in chain", boh);
			return -ENOENT;
		}

		cmd_data = amdxdna_cmd_get_payload(abo, &cmd_data_len);
		if (!cmd_data) {
			XDNA_ERR(xdna, "Invalid command data in chain");
			amdxdna_gem_put_obj(abo);
			return -EINVAL;
		}

		ret = submit_command_retry(hwctx, cmd_data, seq, last_cmd);
		amdxdna_gem_put_obj(abo);
		if (ret) {
			XDNA_ERR(xdna, "Submit chain cmd %u/%u failed: %d", i,
				 cmd_chain->command_count, ret);
			return ret;
		}
	}

	return ve2_hwctx_add_job(hwctx, job, *seq, cmd_chain->command_count);
}

int ve2_cmd_submit(struct amdxdna_hwctx *hwctx, struct amdxdna_sched_job *job, u64 *seq)
{
	struct amdxdna_ctx_priv *vp = ve2_hw_priv(hwctx);
	struct amdxdna_dev *xdna = hwctx->client->xdna;
	struct amdxdna_gem_obj *cmd_bo = job->cmd_bo;
	int ret;
	u32 op;

	op = amdxdna_cmd_get_op(cmd_bo);
	if (op != ERT_START_DPU && op != ERT_CMD_CHAIN) {
		XDNA_WARN(xdna, "Unsupported ERT opcode %u", op);
		return -EINVAL;
	}

	if (op == ERT_CMD_CHAIN)
		ret = ve2_submit_cmd_chain(hwctx, job, seq);
	else
		ret = ve2_submit_cmd_single(hwctx, job, seq);
	if (ret) {
		if (ret == -EAGAIN)
			return -ERESTARTSYS;
		return ret;
	}

	if (!vp->mgmtctx) {
		struct amdxdna_sched_job *pjob;

		mutex_lock(&vp->privctx_lock);
		pjob = vp->pending[get_job_idx(*seq)];
		vp->pending[get_job_idx(*seq)] = NULL;
		vp->submitted--;
		mutex_unlock(&vp->privctx_lock);
		if (pjob)
			ve2_job_put(pjob);
		XDNA_ERR(xdna, "cmd_submit: no management context");
		return -EINVAL;
	}

	ret = ve2_mgmt_schedule_cmd(hwctx->client->xdna, hwctx, *seq + 1);
	if (ret < 0) {
		u32 cmd_cnt = 1;
		struct amdxdna_sched_job *pjob;

		mutex_lock(&vp->privctx_lock);
		pjob = vp->pending[get_job_idx(*seq)];
		vp->pending[get_job_idx(*seq)] = NULL;
		vp->submitted -= cmd_cnt;
		mutex_unlock(&vp->privctx_lock);
		if (pjob)
			ve2_job_put(pjob);
		XDNA_ERR(xdna, "cmd_submit kick failed ret=%d", ret);
		return ret;
	}
	return 0;
}

static bool check_read_index(struct amdxdna_hwctx *hwctx, u64 seq)
{
	struct amdxdna_ctx_priv *vp = ve2_hw_priv(hwctx);
	u64 read_index;

	if (!vp)
		return false;

	if (vp->misc_intrpt_flag)
		return true;

	hsa_queue_sync_read_index_for_read(&vp->hsa_queue);
	read_index = *(u64 *)((char *)vp->hsa_queue.hsa_queue_p + HSA_QUEUE_READ_INDEX_OFFSET);

	return read_index > seq;
}

/*
 * Check whether CERT already wrote a terminal completion state to the HQC slot
 * for the last sub-command (or single command) at @seq. Used to tell a real
 * completion (incl. an errored one) apart from a stall/timeout when a MISC
 * interrupt wakes the waiter.
 */
static bool ve2_hqc_has_terminal_state(struct amdxdna_ctx_priv *vp, u64 seq)
{
	struct ve2_hsa_queue *queue = &vp->hsa_queue;
	u32 capacity = queue->hsa_queue_p->hq_header.capacity;
	u32 slot = seq % capacity;
	u64 *hqc_mem = queue->hq_complete.hqc_mem;
	enum ert_cmd_state state;

	hsa_queue_sync_completion_for_read(queue, slot);
	state = (enum ert_cmd_state)((u32)hqc_mem[slot] & 0xF);

	return state == ERT_CMD_STATE_COMPLETED ||
	       state == ERT_CMD_STATE_ERROR ||
	       state == ERT_CMD_STATE_ABORT;
}

static void ve2_process_hqc_completion(struct amdxdna_hwctx *hwctx, struct amdxdna_sched_job *job,
				       u64 seq)
{
	struct amdxdna_ctx_priv *vp = ve2_hw_priv(hwctx);
	u32 capacity = vp->hsa_queue.hsa_queue_p->hq_header.capacity;
	struct amdxdna_dev *xdna = hwctx->client->xdna;
	u64 *hqc_mem = vp->hsa_queue.hq_complete.hqc_mem;
	u32 slot = seq % capacity;
	enum ert_cmd_state state;
	u32 comp;

	hsa_queue_sync_completion_for_read(&vp->hsa_queue, slot);
	comp = (u32)hqc_mem[slot];
	state = (enum ert_cmd_state)(comp & 0xF);

	if (state < ERT_CMD_STATE_NEW || state > ERT_CMD_STATE_NORESPONSE) {
		XDNA_WARN(xdna, "state %u at hqc_mem[%u] raw 0x%x", state, slot, comp);
		return;
	}

	/*
	 * For a failed command chain, the last sub-command's slot reflects the
	 * chain result but not where it failed. When a runlist fails at command
	 * K, the firmware aborts the commands after K and marks K itself
	 * ERROR/ABORT, so scan the per-sub-command completion slots backwards
	 * and report the first non-ABORT command as the failing index.
	 */
	if ((state == ERT_CMD_STATE_ERROR || state == ERT_CMD_STATE_ABORT) &&
	    amdxdna_cmd_get_op(job->cmd_bo) == ERT_CMD_CHAIN) {
		struct amdxdna_cmd_chain *cc = amdxdna_cmd_get_payload(job->cmd_bo, NULL);
		enum ert_cmd_state slot_state = state;
		u32 fail_cmd_idx = 0;
		u32 cmd_count;
		u32 start_slot;
		int i;

		if (!cc) {
			XDNA_WARN(xdna, "Failed to get chain payload, seq %llu", seq);
			amdxdna_cmd_set_state(job->cmd_bo, state);
			return;
		}

		cmd_count = cc->command_count;
		start_slot = (seq - cmd_count + 1) % capacity;

		for (i = cmd_count; i > 0; i--) {
			u32 idx = (start_slot + i - 1) % capacity;

			hsa_queue_sync_completion_for_read(&vp->hsa_queue, idx);
			comp = (u32)hqc_mem[idx];
			slot_state = (enum ert_cmd_state)(comp & 0xF);
			if (slot_state != ERT_CMD_STATE_ABORT) {
				fail_cmd_idx = i - 1;
				break;
			}
		}

		if (fail_cmd_idx >= cmd_count)
			fail_cmd_idx = 0;
		cc->error_index = fail_cmd_idx;

		XDNA_ERR(xdna, "Chain error at index %u (slot %u) state %d err_code 0x%x",
			 fail_cmd_idx, (start_slot + fail_cmd_idx) % capacity, slot_state,
			 slot_state == ERT_CMD_STATE_ERROR ? (comp >> 4) : 0);
		amdxdna_cmd_set_state(job->cmd_bo, slot_state);
		return;
	}

	amdxdna_cmd_set_state(job->cmd_bo, state);
}

static void ve2_handle_timeout(struct amdxdna_hwctx *hwctx, struct amdxdna_sched_job *job, u64 seq)
{
	struct amdxdna_ctx_priv *vp = ve2_hw_priv(hwctx);
	struct amdxdna_dev *xdna = hwctx->client->xdna;

	if (amdxdna_cmd_get_op(job->cmd_bo) == ERT_CMD_CHAIN) {
		struct amdxdna_cmd_chain *cc = amdxdna_cmd_get_payload(job->cmd_bo, NULL);
		u32 fail_cmd_idx = 0;
		u32 rl_read_idx = 0;
		int ret;

		if (cc && vp->mgmtctx) {
			ret = ve2_partition_read_privileged_mem(vp->mgmtctx,
								offsetof(struct handshake,
									 runlist_read_idx),
								sizeof(rl_read_idx), &rl_read_idx);
			if (ret >= 0)
				fail_cmd_idx = rl_read_idx;
			if (fail_cmd_idx >= cc->command_count)
				fail_cmd_idx = 0;
			cc->error_index = fail_cmd_idx;
			XDNA_ERR(xdna, "Chain timeout at index %u, runlist_read_idx %u",
				 fail_cmd_idx, rl_read_idx);
		}
	}

	amdxdna_cmd_set_state(job->cmd_bo, ERT_CMD_STATE_TIMEOUT);
}

int ve2_cmd_wait(struct amdxdna_hwctx *hwctx, u64 seq, u32 timeout_ms)
{
	struct amdxdna_ctx_priv *vp = ve2_hw_priv(hwctx);
	struct amdxdna_sched_job *job;
	unsigned long wait_jifs = msecs_to_jiffies(timeout_ms);
	bool timed_out;
	long ret = 0;

	if (wait_jifs)
		ret = wait_event_interruptible_timeout(vp->waitq,
						       check_read_index(hwctx, seq),
						       wait_jifs);
	else
		ret = wait_event_interruptible(vp->waitq,
					       check_read_index(hwctx, seq));

	/* Interrupted by a signal; the command stays in flight for retry. */
	if (ret < 0)
		return ret;

	/* Timed wait expired with the completion condition still unmet. */
	timed_out = wait_jifs && ret == 0;

	mutex_lock(&vp->hsa_queue.hq_lock);

	mutex_lock(&vp->privctx_lock);
	job = ve2_hwctx_get_job(hwctx, seq);
	if (job)
		kref_get(&job->refcnt);
	mutex_unlock(&vp->privctx_lock);

	/* Already completed and released by another waiter. */
	if (!job) {
		mutex_unlock(&vp->hsa_queue.hq_lock);
		return 0;
	}

	/*
	 * Treat as a timeout when the timed wait expired, or when a MISC
	 * interrupt woke us but CERT has not written a terminal completion
	 * state (a stall). Otherwise process the (possibly errored) completion.
	 */
	if (timed_out || (vp->misc_intrpt_flag && !ve2_hqc_has_terminal_state(vp, seq)))
		ve2_handle_timeout(hwctx, job, seq);
	else
		ve2_process_hqc_completion(hwctx, job, seq);

	ve2_hwctx_job_release(hwctx, job);
	ve2_job_put(job);

	mutex_unlock(&vp->hsa_queue.hq_lock);

	return 0;
}

/* ---- ctx_config ---------------------------------------------------------- */

static int ve2_update_handshake_pkt(struct amdxdna_hwctx *hwctx, u8 buf_type, u64 paddr, u32 sz,
				    u32 col)
{
	struct amdxdna_ctx_priv *vp = ve2_hw_priv(hwctx);

	switch (buf_type) {
	case AMDXDNA_FW_BUF_DEBUG:
		vp->hwctx_config[col].debug_buf_addr = paddr;
		vp->hwctx_config[col].debug_buf_size = sz;
		break;
	case AMDXDNA_FW_BUF_TRACE:
		vp->hwctx_config[col].dtrace_addr = paddr;
		break;
	case AMDXDNA_FW_BUF_LOG:
		vp->hwctx_config[col].log_buf_addr = paddr;
		vp->hwctx_config[col].log_buf_size = sz;
		break;
	default:
		struct amdxdna_dev *xdna = hwctx->client->xdna;

		XDNA_ERR(xdna, "Unknown fw buf_type %u", buf_type);
		return -EOPNOTSUPP;
	}
	return 0;
}

static int ve2_config_assign_dbg_buf(struct amdxdna_hwctx *hwctx, u64 mdata_hdl, bool attach)
{
	struct amdxdna_client *client = hwctx->client;
	struct amdxdna_fw_buffer_metadata *mdata;
	struct amdxdna_dev *xdna = client->xdna;
	struct amdxdna_gem_obj *mdata_abo, *abo;
	u32 col, prev_sz = 0;
	u64 base_paddr = 0;
	int ret = 0;

	mdata_abo = amdxdna_gem_get_obj(client, mdata_hdl, AMDXDNA_BO_SHARE);
	if (!mdata_abo) {
		XDNA_ERR(xdna, "Failed to get metadata BO %llu", mdata_hdl);
		return -EINVAL;
	}

	mdata = (struct amdxdna_fw_buffer_metadata *)(amdxdna_gem_vmap(mdata_abo));
	if (!mdata) {
		XDNA_ERR(xdna, "Failed to vmap metadata BO %llu", mdata_hdl);
		ret = -EINVAL;
		goto put_mdata;
	}

	if (struct_size(mdata, uc_info, hwctx->num_col) > mdata_abo->mem.size) {
		XDNA_ERR(xdna, "%s: metadata BO too small for %u uc entries (BO size %zu)",
			 __func__, hwctx->num_col, mdata_abo->mem.size);
		ret = -EINVAL;
		goto put_mdata;
	}

	abo = NULL;
	if (attach) {
		if (!mdata->bo_handle) {
			XDNA_DBG(xdna, "No payload BO to attach (buf_type=%u)",
				 mdata->buf_type);
			goto put_mdata;
		}

		abo = amdxdna_gem_get_obj(client, (u32)mdata->bo_handle, AMDXDNA_BO_SHARE);
		if (!abo) {
			XDNA_ERR(xdna, "Failed to get payload BO %llu", mdata->bo_handle);
			ret = -EINVAL;
			goto put_mdata;
		}
		base_paddr = amdxdna_gem_dev_addr(abo);
	}

	for (col = 0; col < hwctx->num_col && col < mdata->num_ucs; col++) {
		u32 sz = attach ? mdata->uc_info[col].size : 0;
		u64 paddr = attach ? (base_paddr + prev_sz) : 0;

		if (sz == 0 && attach)
			continue;

		ret = ve2_update_handshake_pkt(hwctx, mdata->buf_type, paddr, sz, col);
		if (ret) {
			XDNA_ERR(xdna, "col %u config failed: buf_type=%u ret=%d",
				 col, mdata->buf_type, ret);
			break;
		}
		prev_sz += sz;
	}

	if (abo)
		amdxdna_gem_put_obj(abo);
put_mdata:
	amdxdna_gem_put_obj(mdata_abo);
	return ret;
}

int ve2_hwctx_config(struct amdxdna_hwctx *hwctx, u32 type, u64 value, void *buf, u32 size)
{
	struct amdxdna_ctx_priv *vp = ve2_hw_priv(hwctx);
	struct amdxdna_dev *xdna = hwctx->client->xdna;
	u32 op_timeout;
	u32 col;

	if (!vp || !vp->hwctx_config)
		return -EINVAL;

	switch (type) {
	case DRM_AMDXDNA_HWCTX_ASSIGN_DBG_BUF:
		return ve2_config_assign_dbg_buf(hwctx, value, true);

	case DRM_AMDXDNA_HWCTX_REMOVE_DBG_BUF:
		return ve2_config_assign_dbg_buf(hwctx, value, false);

	case DRM_AMDXDNA_HWCTX_CONFIG_OPCODE_TIMEOUT:
		if (copy_from_user(&op_timeout, u64_to_user_ptr(value), sizeof(u32))) {
			XDNA_ERR(xdna, "Failed to copy opcode timeout from user");
			return -EFAULT;
		}
		for (col = 0; col < hwctx->num_col; col++)
			vp->hwctx_config[col].opcode_timeout_config = op_timeout;
		XDNA_DBG(xdna, "hwctx %p: opcode timeout set to %u", hwctx, op_timeout);
		return 0;

	default:
		XDNA_ERR(xdna, "Unsupported config type %u", type);
		return -EOPNOTSUPP;
	}
}

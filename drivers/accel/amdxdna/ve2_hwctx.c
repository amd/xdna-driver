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

struct ve2_dpu_data {
	u64 dtrace_buffer;
	u64 instruction_buffer;
};

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

	guard(mutex)(&vp->privctx_lock);
	vp->completed++;
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

	*slot = queue->reserved_write_index++;
	queue->hq_complete.hqc_mem[slot_idx] = ERT_CMD_STATE_NEW;
	hsa_queue_sync_completion_for_write(queue, slot_idx);
	mutex_unlock(&queue->hq_lock);

	return &queue->hsa_queue_p->hq_entry[slot_idx];
}

static void hsa_queue_commit_slot(struct amdxdna_hwctx *hwctx, u64 seq)
{
	struct amdxdna_ctx_priv *vp = ve2_hw_priv(hwctx);
	struct ve2_hsa_queue *queue;
	struct host_queue_header *header;
	u32 capacity;
	u32 slot_idx;
	struct host_queue_packet *pkt;

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

static int submit_command(struct amdxdna_hwctx *hwctx, void *cmd_data, u64 *seq,
			  bool last_cmd)
{
	struct amdxdna_dev *xdna = hwctx->client->xdna;
	struct amdxdna_ctx_priv *vp = ve2_hw_priv(hwctx);
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

static int ve2_submit_cmd_single(struct amdxdna_hwctx *hwctx, struct amdxdna_sched_job *job,
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

	ret = submit_command(hwctx, cmd_data, seq, true);
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

	/* Basic tests use direct ERT_START_DPU packets only; mark all slots invalid. */
	for (slot = 0; slot < HOST_QUEUE_ENTRY; slot++)
		hsa_queue_pkt_set_invalid(hsa_queue_get_pkt(queue->hsa_queue_p, slot));

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

	ret = ve2_create_host_queue(hwctx);
	if (ret) {
		XDNA_ERR(xdna, "Host queue alloc failed, ret %d", ret);
		goto destroy_partition;
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
		mutex_destroy(&vp->privctx_lock);
		kfree(vp);
		priv->hw_priv = NULL;
	}

	kfree(priv);
	hwctx->priv = NULL;
}

int ve2_cmd_submit(struct amdxdna_hwctx *hwctx, struct amdxdna_sched_job *job, u64 *seq)
{
	struct amdxdna_dev *xdna = hwctx->client->xdna;
	struct amdxdna_ctx_priv *vp = ve2_hw_priv(hwctx);
	struct amdxdna_gem_obj *cmd_bo = job->cmd_bo;
	u32 op;
	int ret;

	op = amdxdna_cmd_get_op(cmd_bo);
	if (op != ERT_START_DPU) {
		XDNA_WARN(xdna, "Unsupported ERT opcode %u", op);
		return -EINVAL;
	}

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

static void ve2_process_hqc_completion(struct amdxdna_hwctx *hwctx,
				       struct amdxdna_sched_job *job, u64 seq)
{
	struct amdxdna_dev *xdna = hwctx->client->xdna;
	struct amdxdna_ctx_priv *vp = ve2_hw_priv(hwctx);
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

	amdxdna_cmd_set_state(job->cmd_bo, state);
}

int ve2_cmd_wait(struct amdxdna_hwctx *hwctx, u64 seq, u32 timeout_ms)
{
	struct amdxdna_ctx_priv *vp = ve2_hw_priv(hwctx);
	struct amdxdna_sched_job *job;
	unsigned long wait_jifs = msecs_to_jiffies(timeout_ms);
	long ret = 0;

	if (wait_jifs)
		ret = wait_event_interruptible_timeout(vp->waitq,
						       check_read_index(hwctx, seq),
						       wait_jifs);
	else
		ret = wait_event_interruptible(vp->waitq,
					       check_read_index(hwctx, seq));
	mutex_lock(&vp->hsa_queue.hq_lock);
	if ((!wait_jifs && !ret) || ret > 0) {
		mutex_lock(&vp->privctx_lock);
		job = ve2_hwctx_get_job(hwctx, seq);
		if (job)
			kref_get(&job->refcnt);
		mutex_unlock(&vp->privctx_lock);

		if (!job) {
			ret = 0;
			goto out;
		}

		if (vp->misc_intrpt_flag || (wait_jifs && !ret)) {
			if (vp->misc_intrpt_flag)
				ve2_process_hqc_completion(hwctx, job, seq);
			else
				amdxdna_cmd_set_state(job->cmd_bo, ERT_CMD_STATE_TIMEOUT);
		} else {
			ve2_process_hqc_completion(hwctx, job, seq);
		}

		ve2_hwctx_job_release(hwctx, job);
		ve2_job_put(job);

		if (!wait_jifs) {
			mutex_unlock(&vp->hsa_queue.hq_lock);
			return 0;
		}
	}

	if (!ret)
		ret = -ETIME;

out:
	mutex_unlock(&vp->hsa_queue.hq_lock);
	return ret > 0 ? 0 : ret;
}

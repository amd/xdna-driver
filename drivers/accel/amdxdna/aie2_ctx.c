// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2024-2026, Advanced Micro Devices, Inc.
 */

#include "drm/amdxdna_accel.h"
#include <drm/drm_device.h>
#include <drm/drm_gem.h>
#include <drm/drm_gem_shmem_helper.h>
#include <drm/drm_print.h>
#include <drm/drm_syncobj.h>
#include <linux/hmm.h>
#include <linux/types.h>
#include <linux/xarray.h>
#include "trace/events/amdxdna.h"

#include "aie2_msg_priv.h"
#include "aie2_pci.h"
#include "amdxdna_solver.h"
#include "amdxdna_ctx.h"
#include "amdxdna_gem.h"
#include "amdxdna_mailbox.h"
#include "amdxdna_pci_drv.h"
#include "amdxdna_pm.h"

static bool force_cmdlist = true;
module_param(force_cmdlist, bool, 0600);
MODULE_PARM_DESC(force_cmdlist, "Force use command list (Default true)");

uint tdr_timeout_ms = 2000;
module_param(tdr_timeout_ms, uint, 0400);
MODULE_PARM_DESC(tdr_timeout_ms, "TDR (Timeout Detection and Recovery) timeout in milliseconds (0 = disable)");

bool tdr_dump_only;
module_param(tdr_dump_only, bool, 0600);
MODULE_PARM_DESC(tdr_dump_only, "Only dump health info on timeout, skip recovery (default: false)");

struct aie2_ctx_health {
	struct amdxdna_ctx_health header;
	u32 txn_op_idx;
	u32 ctx_pc;
	u32 fatal_error_type;
	u32 fatal_error_exception_type;
	u32 fatal_error_exception_pc;
	u32 fatal_error_app_module;
};

static inline void aie2_tdr_signal(struct amdxdna_dev *xdna)
{
	WRITE_ONCE(xdna->dev_handle->tdr_status, AIE2_TDR_SIGNALED);
}

#ifdef HAVE_6_17_drm_gpu_sched_stat_no_hang
static bool aie2_tdr_detect(struct amdxdna_dev *xdna)
{
	struct amdxdna_dev_hdl *ndev = xdna->dev_handle;

	if (READ_ONCE(ndev->tdr_status) == AIE2_TDR_WAIT) {
		XDNA_ERR(xdna, "TDR timeout detected");
		return true;
	}

	WRITE_ONCE(ndev->tdr_status, AIE2_TDR_WAIT);
	return false;
}
#endif

static void aie2_job_release(struct kref *ref)
{
	struct amdxdna_sched_job *job;

	job = container_of(ref, struct amdxdna_sched_job, refcnt);
	amdxdna_sched_job_cleanup(job);
	atomic64_inc(&job->hwctx->job_free_cnt);
	wake_up(&job->hwctx->priv->job_free_wq);
	if (job->out_fence)
		dma_fence_put(job->out_fence);
	kfree(job->aie2_job_health);
	kfree(job);
}

static void aie2_job_put(struct amdxdna_sched_job *job)
{
	kref_put(&job->refcnt, aie2_job_release);
}

/* The bad_job is used in aie2_sched_job_timedout, otherwise, set it to NULL */
static void aie2_hwctx_stop(struct amdxdna_dev *xdna, struct amdxdna_hwctx *hwctx,
			    struct drm_sched_job *bad_job)
{
	drm_sched_stop(&hwctx->priv->sched, bad_job);
	aie2_destroy_context(xdna->dev_handle, hwctx);
#ifdef HAVE_6_13_drm_sched_start_errno
	drm_sched_start(&hwctx->priv->sched, 0);
#elif defined(HAVE_6_10_drm_sched_start_full_recovery)
	drm_sched_start(&hwctx->priv->sched, true);
#else
	drm_sched_start(&hwctx->priv->sched);
#endif
}

/*
 * Drop pin + ref on every heap chunk this hwctx previously pinned via
 * aie2_hwctx_heap_expand(). Acquires client->mm_lock internally to
 * serialize the walk against concurrent chunk additions; callers must
 * NOT hold mm_lock. Unlike aie2_hwctx_{renotify,heap_expand}_heap()
 * (which are paired under a single mm_lock acquisition in
 * aie2_hwctx_map_heap()), release_heap is always called standalone.
 */
static void aie2_hwctx_release_heap(struct amdxdna_hwctx *hwctx)
{
	struct amdxdna_client *client = hwctx->client;
	struct amdxdna_gem_obj *last;
	struct amdxdna_gem_obj *chunk;

	guard(mutex)(&client->mm_lock);

	last = hwctx->priv->last_pinned_chunk;
	if (!last)
		return;

	list_for_each_entry(chunk, &client->dev_heap_chunks, heap_chunk_node) {
		amdxdna_gem_unpin(chunk);
		drm_gem_object_put(to_gobj(chunk));
		if (chunk == last)
			break;
	}
	hwctx->priv->last_pinned_chunk = NULL;
}

static int aie2_hwctx_renotify_heap(struct amdxdna_hwctx *hwctx)
{
	struct amdxdna_gem_obj *last = hwctx->priv->last_pinned_chunk;
	struct amdxdna_client *client = hwctx->client;
	struct amdxdna_dev *xdna = client->xdna;
	struct amdxdna_gem_obj *chunk;
	bool first = true;
	u64 addr;
	int ret;

	drm_WARN_ON(&xdna->ddev, !mutex_is_locked(&client->mm_lock));

	if (!last)
		return 0;

	list_for_each_entry(chunk, &client->dev_heap_chunks, heap_chunk_node) {
		addr = amdxdna_obj_dma_addr(chunk);
		if (first)
			ret = aie2_map_host_buf(xdna->dev_handle,
						hwctx->fw_ctx_id,
						addr, chunk->mem.size);
		else
			ret = aie2_add_host_buf(xdna->dev_handle,
						hwctx->fw_ctx_id,
						addr, chunk->mem.size);
		if (ret) {
			XDNA_ERR(xdna,
				 "Renotify FW hwctx %s for chunk size 0x%lx failed, ret %d",
				 hwctx->name, chunk->mem.size, ret);
			return ret;
		}
		first = false;
		if (chunk == last)
			break;
	}

	return 0;
}

static int aie2_hwctx_map_heap(struct amdxdna_hwctx *hwctx)
{
	struct amdxdna_client *client = hwctx->client;
	struct amdxdna_dev *xdna = client->xdna;
	int ret;

	drm_WARN_ON(&xdna->ddev, !mutex_is_locked(&xdna->dev_lock));

	/*
	 * Called from hwctx create and from restart (suspend/resume and TDR).
	 * The per-hwctx FW context is brand-new on both paths and has no
	 * host_buf state, so on restart we must first re-notify FW for every
	 * chunk that this hwctx previously pinned (kernel pins/refs are
	 * preserved across restart). aie2_hwctx_heap_expand() then continues
	 * from list_prepare_entry(last_pinned_chunk), pinning + notifying any
	 * chunks added since.
	 *
	 * On hwctx create last_pinned_chunk is NULL: renotify is a no-op and
	 * expand walks from the list head with first_pin = true, issuing
	 * aie2_map_host_buf() for chunk 0 and aie2_add_host_buf() afterward.
	 */
	mutex_lock(&client->mm_lock);
	ret = aie2_hwctx_renotify_heap(hwctx);
	if (ret)
		goto unlock;
	ret = aie2_hwctx_heap_expand(hwctx);
unlock:
	mutex_unlock(&client->mm_lock);

	return ret;
}

static int aie2_hwctx_restart(struct amdxdna_dev *xdna, struct amdxdna_hwctx *hwctx)
{
	int ret;

	ret = aie2_create_context(xdna->dev_handle, hwctx);
	if (ret) {
		XDNA_ERR(xdna, "Create hwctx failed, ret %d", ret);
		goto out;
	}

	ret = aie2_hwctx_map_heap(hwctx);
	if (ret) {
		XDNA_ERR(xdna, "Map host buf failed, ret %d", ret);
		goto out;
	}

	ret = aie2_config_cu(hwctx, NULL);
	if (ret) {
		XDNA_ERR(xdna, "Config cu failed, ret %d", ret);
		goto out;
	}

out:
	XDNA_DBG(xdna, "%s restarted, ret %d", hwctx->name, ret);
	return ret;
}

static struct dma_fence *aie2_cmd_get_out_fence(struct amdxdna_hwctx *hwctx, u64 seq)
{
	struct dma_fence *fence, *out_fence = NULL;
	int ret;

	fence = drm_syncobj_fence_get(hwctx->priv->syncobj);
	if (!fence)
		return NULL;

	ret = dma_fence_chain_find_seqno(&fence,  seq);
	if (ret)
		goto out;

	out_fence = dma_fence_get(dma_fence_chain_contained(fence));

out:
	dma_fence_put(fence);
	return out_fence;
}

static void aie2_hwctx_wait_for_idle(struct amdxdna_hwctx *hwctx)
{
	struct dma_fence *fence;

	fence = aie2_cmd_get_out_fence(hwctx, hwctx->priv->seq - 1);
	if (!fence)
		return;

	/* Wait up to 2 seconds for fw to finish all pending requests */
	dma_fence_wait_timeout(fence, false, msecs_to_jiffies(2000));
	dma_fence_put(fence);
}

static int aie2_hwctx_suspend_cb(struct amdxdna_hwctx *hwctx, void *arg)
{
	struct amdxdna_dev *xdna = hwctx->client->xdna;

	aie2_hwctx_wait_for_idle(hwctx);
	aie2_hwctx_stop(xdna, hwctx, NULL);

	return 0;
}

void aie2_hwctx_suspend(struct amdxdna_client *client)
{
	struct amdxdna_dev *xdna = client->xdna;

	/*
	 * Command timeout is unlikely. But if it happens, it doesn't
	 * break the system. aie2_hwctx_stop() will destroy mailbox
	 * and abort all commands.
	 */
	drm_WARN_ON(&xdna->ddev, !mutex_is_locked(&xdna->dev_lock));
	amdxdna_hwctx_walk(client, NULL, aie2_hwctx_suspend_cb);
}

static int aie2_hwctx_resume_cb(struct amdxdna_hwctx *hwctx, void *arg)
{
	struct amdxdna_dev *xdna = hwctx->client->xdna;

	return aie2_hwctx_restart(xdna, hwctx);
}

int aie2_hwctx_resume(struct amdxdna_client *client)
{
	/*
	 * The resume path cannot guarantee that mailbox channel can be
	 * regenerated. If this happen, when submit message to this
	 * mailbox channel, error will return.
	 */
	return amdxdna_hwctx_walk(client, NULL, aie2_hwctx_resume_cb);
}

static void
aie2_sched_notify(struct amdxdna_sched_job *job)
{
	struct dma_fence *fence = job->fence;

	trace_xdna_job(&job->base, job->hwctx->name, "signaling fence",
		       job->seq, job->drv_cmd ? job->drv_cmd->opcode : DEFAULT_IO);

	aie2_tdr_signal(job->hwctx->client->xdna);
	job->hwctx->priv->completed++;
	dma_fence_signal(fence);

	up(&job->hwctx->priv->job_sem);
	job->job_done = true;
	mmput_async(job->mm);
	aie2_job_put(job);
}

static void aie2_log_health_report(struct amdxdna_dev *xdna,
				   struct app_health_report *report)
{
	XDNA_ERR(xdna, "Firmware timeout state capture:");
	XDNA_ERR(xdna, "\tVersion: %d.%d", report->major, report->minor);
	XDNA_ERR(xdna, "\tReport size: 0x%x", report->size);
	XDNA_ERR(xdna, "\tContext ID: %d", report->context_id);
	XDNA_ERR(xdna, "\tDPU PC: 0x%x", report->dpu_pc);
	XDNA_ERR(xdna, "\tTXN OP ID: 0x%x", report->txn_op_id);
	XDNA_ERR(xdna, "\tContext PC: 0x%x", report->ctx_pc);
	XDNA_ERR(xdna, "\tFatal error type: 0x%x", report->fatal_info.fatal_type);
	XDNA_ERR(xdna, "\tFatal error exception type: 0x%x", report->fatal_info.exception_type);
	XDNA_ERR(xdna, "\tFatal error exception PC: 0x%x", report->fatal_info.exception_pc);
	XDNA_ERR(xdna, "\tFatal error app module: 0x%x", report->fatal_info.app_module);
	XDNA_ERR(xdna, "\tFatal error task ID: %d", report->fatal_info.task_index);
	XDNA_ERR(xdna, "\tTimed out sub command ID: %d", report->run_list_id);
}

static void aie2_set_cmd_timeout(struct amdxdna_sched_job *job)
{
	struct aie2_ctx_health *aie2_health __free(kfree) = NULL;
	struct amdxdna_dev *xdna = job->hwctx->client->xdna;
	struct amdxdna_gem_obj *cmd_abo = job->cmd_bo;
	struct app_health_report *report = job->aie2_job_health;
	u32 fail_cmd_idx = 0;

	if (!report)
		goto set_timeout;

	aie2_log_health_report(xdna, report);

	fail_cmd_idx = report->run_list_id;
	aie2_health = kzalloc_obj(*aie2_health);
	if (!aie2_health)
		goto set_timeout;

	aie2_health->header.version = AMDXDNA_CMD_CTX_HEALTH_V1;
	aie2_health->header.npu_gen = AMDXDNA_CMD_CTX_HEALTH_AIE2;
	aie2_health->txn_op_idx = report->txn_op_id;
	aie2_health->ctx_pc = report->ctx_pc;
	aie2_health->fatal_error_type = report->fatal_info.fatal_type;
	aie2_health->fatal_error_exception_type = report->fatal_info.exception_type;
	aie2_health->fatal_error_exception_pc = report->fatal_info.exception_pc;
	aie2_health->fatal_error_app_module = report->fatal_info.app_module;

set_timeout:
	amdxdna_cmd_set_error(cmd_abo, job, fail_cmd_idx, ERT_CMD_STATE_TIMEOUT,
			      aie2_health, sizeof(*aie2_health));
}

static int
aie2_sched_resp_handler(void *handle, void __iomem *data, size_t size)
{
	struct amdxdna_sched_job *job = handle;
	struct amdxdna_gem_obj *cmd_abo;
	int ret = 0;
	u32 status;

	amdxdna_io_stats_job_done(job->hwctx->client);
	cmd_abo = job->cmd_bo;

	if (unlikely(job->job_timeout)) {
		aie2_set_cmd_timeout(job);
		ret = -EINVAL;
		goto out;
	}

	if (unlikely(!data) || unlikely(size != sizeof(u32))) {
		amdxdna_cmd_set_error(cmd_abo, job, 0, ERT_CMD_STATE_ABORT, NULL, 0);
		ret = -EINVAL;
		goto out;
	}

	status = readl(data);
	XDNA_DBG(job->hwctx->client->xdna, "Resp status 0x%x", status);
	if (status == AIE2_STATUS_SUCCESS)
		amdxdna_cmd_set_state(cmd_abo, ERT_CMD_STATE_COMPLETED);
	else
		amdxdna_cmd_set_error(cmd_abo, job, 0, ERT_CMD_STATE_ERROR, NULL, 0);

out:
	aie2_sched_notify(job);
	return ret;
}

static int
aie2_sched_drvcmd_resp_handler(void *handle, void __iomem *data, size_t size)
{
	struct amdxdna_sched_job *job = handle;
	int ret = 0;

	if (unlikely(!data))
		goto out;

	if (unlikely(size != sizeof(u32))) {
		ret = -EINVAL;
		goto out;
	}

	job->drv_cmd->result = readl(data);

out:
	aie2_sched_notify(job);
	return ret;
}

static int
aie2_sched_cmdlist_resp_handler(void *handle, void __iomem *data, size_t size)
{
	struct amdxdna_sched_job *job = handle;
	struct amdxdna_gem_obj *cmd_abo;
	struct amdxdna_dev *xdna;
	u32 fail_cmd_idx = 0;
	u32 fail_cmd_status;
	u32 cmd_status;
	int ret = 0;

	amdxdna_io_stats_job_done(job->hwctx->client);
	cmd_abo = job->cmd_bo;

	if (unlikely(job->job_timeout)) {
		aie2_set_cmd_timeout(job);
		ret = -EINVAL;
		goto out;
	}

	if (unlikely(!data) || unlikely(size != sizeof(u32) * 3)) {
		amdxdna_cmd_set_error(cmd_abo, job, 0, ERT_CMD_STATE_ABORT, NULL, 0);
		ret = -EINVAL;
		goto out;
	}

	cmd_status = readl(data + offsetof(struct cmd_chain_resp, status));
	xdna = job->hwctx->client->xdna;
	XDNA_DBG(xdna, "Status 0x%x", cmd_status);
	if (cmd_status == AIE2_STATUS_SUCCESS) {
		amdxdna_cmd_set_state(cmd_abo, ERT_CMD_STATE_COMPLETED);
		goto out;
	}

	/* Slow path to handle error, read from ringbuf on BAR */
	fail_cmd_idx = readl(data + offsetof(struct cmd_chain_resp, fail_cmd_idx));
	fail_cmd_status = readl(data + offsetof(struct cmd_chain_resp, fail_cmd_status));
	XDNA_DBG(xdna, "Failed cmd idx %d, status 0x%x",
		 fail_cmd_idx, fail_cmd_status);

	if (fail_cmd_status == AIE2_STATUS_SUCCESS) {
		amdxdna_cmd_set_error(cmd_abo, job, fail_cmd_idx, ERT_CMD_STATE_ABORT, NULL, 0);
		ret = -EINVAL;
	} else {
		amdxdna_cmd_set_error(cmd_abo, job, fail_cmd_idx, ERT_CMD_STATE_ERROR, NULL, 0);
	}

out:
	aie2_sched_notify(job);
	return ret;
}

static struct dma_fence *
aie2_sched_job_run(struct drm_sched_job *sched_job)
{
	struct amdxdna_sched_job *job = drm_job_to_xdna_job(sched_job);
	struct amdxdna_gem_obj *cmd_abo = job->cmd_bo;
	struct amdxdna_hwctx *hwctx = job->hwctx;
	struct dma_fence *fence;
	int ret;

	trace_xdna_job(sched_job, hwctx->name, "job run",
		       job->seq, job->drv_cmd ? job->drv_cmd->opcode : DEFAULT_IO);

	if (!hwctx->priv->mbox_chann)
		return NULL;

	if (!mmget_not_zero(job->mm))
		return ERR_PTR(-ESRCH);

	kref_get(&job->refcnt);
	fence = dma_fence_get(job->fence);

	if (job->drv_cmd) {
		switch (job->drv_cmd->opcode) {
		case SYNC_DEBUG_BO:
			ret = aie2_sync_bo(hwctx, job, aie2_sched_drvcmd_resp_handler);
			break;
		case ATTACH_DEBUG_BO:
		case DETACH_DEBUG_BO:
			ret = aie2_config_debug_bo(hwctx, job, aie2_sched_drvcmd_resp_handler);
			break;
		default:
			ret = -EINVAL;
			break;
		}
		goto out;
	}

	amdxdna_cmd_set_state(cmd_abo, ERT_CMD_STATE_NEW);

	if (amdxdna_cmd_get_op(cmd_abo) == ERT_CMD_CHAIN)
		ret = aie2_cmdlist_multi_execbuf(hwctx, job, aie2_sched_cmdlist_resp_handler);
	else if (force_cmdlist)
		ret = aie2_cmdlist_single_execbuf(hwctx, job, aie2_sched_cmdlist_resp_handler);
	else
		ret = aie2_execbuf(hwctx, job, aie2_sched_resp_handler);

out:
	if (ret) {
		dma_fence_put(job->fence);
		aie2_job_put(job);
		mmput(job->mm);
		fence = ERR_PTR(ret);
	} else {
		aie2_tdr_signal(hwctx->client->xdna);
		amdxdna_io_stats_job_start(job->hwctx->client);
	}
	trace_xdna_job(sched_job, hwctx->name, "sent to device",
		       job->seq, job->drv_cmd ? job->drv_cmd->opcode : DEFAULT_IO);

	return fence;
}

static void aie2_sched_job_free(struct drm_sched_job *sched_job)
{
	struct amdxdna_sched_job *job = drm_job_to_xdna_job(sched_job);
	struct amdxdna_hwctx *hwctx = job->hwctx;

	trace_xdna_job(sched_job, hwctx->name, "job free",
		       job->seq, job->drv_cmd ? job->drv_cmd->opcode : DEFAULT_IO);
	if (!job->job_done)
		up(&hwctx->priv->job_sem);

	drm_sched_job_cleanup(sched_job);
	aie2_job_put(job);
}

static enum drm_gpu_sched_stat
aie2_sched_job_timedout(struct drm_sched_job *sched_job)
{
	struct amdxdna_sched_job *job = drm_job_to_xdna_job(sched_job);
	struct amdxdna_hwctx *hwctx = job->hwctx;
	struct app_health_report *report;
	struct amdxdna_dev *xdna;
	int ret;

	xdna = hwctx->client->xdna;

	guard(mutex)(&xdna->dev_lock);

#ifdef HAVE_6_17_drm_gpu_sched_stat_no_hang
	if (!aie2_tdr_detect(xdna))
		return DRM_GPU_SCHED_STAT_NO_HANG;
#endif

	report = kzalloc_obj(*report);
	if (report) {
		ret = aie2_query_app_health(xdna->dev_handle, hwctx->fw_ctx_id, report);
		if (ret) {
			kfree(report);
			report = NULL;
		}
	}

#ifdef HAVE_6_17_drm_gpu_sched_stat_no_hang
	if (tdr_dump_only) {
		if (report) {
			aie2_log_health_report(xdna, report);
			kfree(report);
		}
		return DRM_GPU_SCHED_STAT_NO_HANG;
	}
#endif

	job->job_timeout = true;
	job->aie2_job_health = report;

	aie2_hwctx_stop(xdna, hwctx, sched_job);

	aie2_hwctx_restart(xdna, hwctx);

#ifdef HAVE_drm_gpu_sched_stat_reset
	return DRM_GPU_SCHED_STAT_RESET;
#else
	return DRM_GPU_SCHED_STAT_NOMINAL;
#endif
}

static const struct drm_sched_backend_ops sched_ops = {
	.run_job = aie2_sched_job_run,
	.free_job = aie2_sched_job_free,
	.timedout_job = aie2_sched_job_timedout,
};

static int aie2_hwctx_col_list(struct amdxdna_hwctx *hwctx)
{
	struct amdxdna_dev *xdna = hwctx->client->xdna;
	struct amdxdna_dev_hdl *ndev = xdna->dev_handle;
	bool natural_align;

	natural_align = (ndev->priv->col_align == COL_ALIGN_NATURE);
	return amdxdna_hwctx_col_list(hwctx, ndev->aie.metadata.core.row_count,
				      ndev->total_col, natural_align);
}

static int aie2_alloc_resource(struct amdxdna_hwctx *hwctx)
{
	struct amdxdna_dev *xdna = hwctx->client->xdna;

	if (AIE_FEATURE_ON(&xdna->dev_handle->aie, AIE2_TEMPORAL_ONLY)) {
		hwctx->num_unused_col = xdna->dev_handle->total_col - hwctx->num_col;
		hwctx->num_col = xdna->dev_handle->total_col;
		return aie2_create_context(xdna->dev_handle, hwctx);
	}

	return amdxdna_alloc_resource(hwctx, NULL);
}

static void aie2_release_resource(struct amdxdna_hwctx *hwctx)
{
	struct amdxdna_dev *xdna = hwctx->client->xdna;
	int ret;

	if (AIE_FEATURE_ON(&xdna->dev_handle->aie, AIE2_TEMPORAL_ONLY)) {
		ret = aie2_destroy_context(xdna->dev_handle, hwctx);
		if (ret && ret != -ENODEV)
			XDNA_ERR(xdna, "Destroy temporal only context failed, ret %d", ret);
	} else {
		amdxdna_release_resource(hwctx, NULL);
	}
}

static int aie2_ctx_syncobj_create(struct amdxdna_hwctx *hwctx)
{
	return amdxdna_ctx_syncobj_create(hwctx);
}

int aie2_hwctx_init(struct amdxdna_hwctx *hwctx)
{
	struct amdxdna_client *client = hwctx->client;
	struct amdxdna_dev *xdna = client->xdna;
	struct amdxdna_hwctx_priv *priv;
	struct aie2_hwctx_priv *aie2_priv;
	int ret;

	priv = kzalloc(sizeof(*priv), GFP_KERNEL);
	if (!priv)
		return -ENOMEM;

	aie2_priv = kzalloc(sizeof(*aie2_priv), GFP_KERNEL);
	if (!aie2_priv) {
		kfree(priv);
		return -ENOMEM;
	}
	priv->hw_priv = aie2_priv;

	ret = amdxdna_hwctx_priv_init(hwctx, priv, &sched_ops,
				      tdr_timeout_ms > 0 ? tdr_timeout_ms : 0);
	if (ret) {
		XDNA_ERR(xdna, "Initialize hwctx priv failed, ret %d", ret);
		kfree(aie2_priv);
		kfree(priv);
		return ret;
	}

	ret = aie2_hwctx_col_list(hwctx);
	if (ret) {
		XDNA_ERR(xdna, "Create col list failed, ret %d", ret);
		goto fini_priv;
	}

	ret = amdxdna_pm_resume_get_locked(xdna);
	if (ret)
		goto free_col_list;

	ret = aie2_alloc_resource(hwctx);
	if (ret) {
		XDNA_ERR(xdna, "Alloc hw resource failed, ret %d", ret);
		goto suspend_put;
	}

	ret = aie2_hwctx_map_heap(hwctx);
	if (ret) {
		XDNA_ERR(xdna, "Map host buffer failed, ret %d", ret);
		goto release_resource;
	}

	ret = aie2_ctx_syncobj_create(hwctx);
	if (ret) {
		XDNA_ERR(xdna, "Create syncobj failed, ret %d", ret);
		goto release_resource;
	}
	amdxdna_pm_suspend_put(xdna);

	init_waitqueue_head(&priv->job_free_wq);

	XDNA_DBG(xdna, "hwctx %s init completed", hwctx->name);

	return 0;

release_resource:
	aie2_release_resource(hwctx);
	aie2_hwctx_release_heap(hwctx);
suspend_put:
	amdxdna_pm_suspend_put(xdna);
free_col_list:
	kfree(hwctx->col_list);
fini_priv:
	amdxdna_hwctx_priv_fini(hwctx, priv);
	kfree(priv->hw_priv);
	kfree(priv);
	return ret;
}

void aie2_hwctx_fini(struct amdxdna_hwctx *hwctx)
{
	struct amdxdna_dev *xdna = hwctx->client->xdna;
	struct amdxdna_hwctx_priv *priv = hwctx->priv;

	XDNA_DBG(xdna, "%s sequence number %lld", hwctx->name, hwctx->priv->seq);
	aie2_hwctx_wait_for_idle(hwctx);

	/* Request fw to destroy hwctx and cancel the rest pending requests */
	drm_sched_stop(&hwctx->priv->sched, NULL);
	aie2_release_resource(hwctx);

	aie2_hwctx_release_heap(hwctx);
#ifdef HAVE_6_13_drm_sched_start_errno
	drm_sched_start(&hwctx->priv->sched, 0);
#elif defined(HAVE_6_10_drm_sched_start_full_recovery)
	drm_sched_start(&hwctx->priv->sched, true);
#else
	drm_sched_start(&hwctx->priv->sched);
#endif

	mutex_unlock(&xdna->dev_lock);
	drm_sched_entity_destroy(&hwctx->priv->entity);

	/* Wait for all submitted jobs to be completed or canceled */
	wait_event(hwctx->priv->job_free_wq,
		   atomic64_read(&hwctx->job_submit_cnt) ==
		   atomic64_read(&hwctx->job_free_cnt));
	mutex_lock(&xdna->dev_lock);

	amdxdna_ctx_syncobj_destroy(hwctx);
	amdxdna_hwctx_priv_fini(hwctx, priv);
	kfree(priv->hw_priv);
	kfree(priv);
	kfree(hwctx->cus);
}

static int aie2_config_cu_resp_handler(void *handle, void __iomem *data, size_t size)
{
	struct amdxdna_hwctx *hwctx = handle;

	amdxdna_pm_suspend_put(hwctx->client->xdna);
	return 0;
}

static int aie2_hwctx_cu_config(struct amdxdna_hwctx *hwctx, void *buf, u32 size)
{
	struct amdxdna_hwctx_param_config_cu *config = buf;
	struct amdxdna_dev *xdna = hwctx->client->xdna;
	u32 total_size;
	int ret;

	XDNA_DBG(xdna, "Config %d CU to %s", config->num_cus, hwctx->name);
	if (XDNA_MBZ_DBG(xdna, config->pad, sizeof(config->pad)))
		return -EINVAL;

	if (hwctx->cus) {
		XDNA_ERR(xdna, "Not support re-config CU");
		return -EINVAL;
	}

	if (!config->num_cus) {
		XDNA_ERR(xdna, "Number of CU is zero");
		return -EINVAL;
	}

	total_size = struct_size(config, cu_configs, config->num_cus);
	if (total_size > size) {
		XDNA_ERR(xdna, "CU config larger than size");
		return -EINVAL;
	}

	hwctx->cus = kmemdup(config, total_size, GFP_KERNEL);
	if (!hwctx->cus)
		return -ENOMEM;

	ret = amdxdna_pm_resume_get_locked(xdna);
	if (ret)
		goto free_cus;

	ret = aie2_config_cu(hwctx, aie2_config_cu_resp_handler);
	if (ret) {
		XDNA_ERR(xdna, "Config CU to firmware failed, ret %d", ret);
		goto pm_suspend_put;
	}

	wmb(); /* To avoid locking in command submit when check status */

	return 0;

pm_suspend_put:
	amdxdna_pm_suspend_put(xdna);
free_cus:
	kfree(hwctx->cus);
	hwctx->cus = NULL;
	return ret;
}

static void aie2_cmd_wait(struct amdxdna_hwctx *hwctx, u64 seq)
{
	struct dma_fence *out_fence = aie2_cmd_get_out_fence(hwctx, seq);

	if (!out_fence) {
		XDNA_ERR(hwctx->client->xdna, "Failed to get fence");
		return;
	}

	dma_fence_wait_timeout(out_fence, false, MAX_SCHEDULE_TIMEOUT);
	dma_fence_put(out_fence);
}

static int aie2_hwctx_cfg_debug_bo(struct amdxdna_hwctx *hwctx, u32 bo_hdl,
				   bool attach)
{
	struct amdxdna_client *client = hwctx->client;
	struct amdxdna_dev *xdna = client->xdna;
	struct amdxdna_drv_cmd cmd = { 0 };
	struct amdxdna_gem_obj *abo;
	u64 seq;
	int ret;

	abo = amdxdna_gem_get_obj(client, bo_hdl, AMDXDNA_BO_DEV);
	if (!abo) {
		XDNA_ERR(xdna, "Get bo %d failed", bo_hdl);
		return -EINVAL;
	}

	if (attach) {
		if (abo->assigned_hwctx != AMDXDNA_INVALID_CTX_HANDLE) {
			ret = -EBUSY;
			goto put_obj;
		}
		cmd.opcode = ATTACH_DEBUG_BO;
	} else {
		if (abo->assigned_hwctx != hwctx->id) {
			ret = -EINVAL;
			goto put_obj;
		}
		cmd.opcode = DETACH_DEBUG_BO;
	}

	ret = amdxdna_cmd_submit(client, &cmd, AMDXDNA_INVALID_BO_HANDLE,
				 &bo_hdl, 1, hwctx->id, &seq);
	if (ret) {
		XDNA_ERR(xdna, "Submit command failed");
		goto put_obj;
	}

	aie2_cmd_wait(hwctx, seq);
	if (cmd.result) {
		XDNA_ERR(xdna, "Response failure 0x%x", cmd.result);
		goto put_obj;
	}

	if (attach)
		abo->assigned_hwctx = hwctx->id;
	else
		abo->assigned_hwctx = AMDXDNA_INVALID_CTX_HANDLE;

	XDNA_DBG(xdna, "Config debug BO %d to %s", bo_hdl, hwctx->name);

put_obj:
	amdxdna_gem_put_obj(abo);
	return ret;
}

int aie2_hwctx_config(struct amdxdna_hwctx *hwctx, u32 type, u64 value, void *buf, u32 size)
{
	struct amdxdna_dev *xdna = hwctx->client->xdna;

	drm_WARN_ON(&xdna->ddev, !mutex_is_locked(&xdna->dev_lock));
	switch (type) {
	case DRM_AMDXDNA_HWCTX_CONFIG_CU:
		return aie2_hwctx_cu_config(hwctx, buf, size);
	case DRM_AMDXDNA_HWCTX_ASSIGN_DBG_BUF:
		return aie2_hwctx_cfg_debug_bo(hwctx, (u32)value, true);
	case DRM_AMDXDNA_HWCTX_REMOVE_DBG_BUF:
		return aie2_hwctx_cfg_debug_bo(hwctx, (u32)value, false);
	default:
		XDNA_DBG(xdna, "Not supported type %d", type);
		return -EOPNOTSUPP;
	}
}

int aie2_hwctx_sync_debug_bo(struct amdxdna_hwctx *hwctx, u32 debug_bo_hdl)
{
	struct amdxdna_client *client = hwctx->client;
	struct amdxdna_dev *xdna = client->xdna;
	struct amdxdna_drv_cmd cmd = { 0 };
	u64 seq;
	int ret;

	cmd.opcode = SYNC_DEBUG_BO;
	ret = amdxdna_cmd_submit(client, &cmd, AMDXDNA_INVALID_BO_HANDLE,
				 &debug_bo_hdl, 1, hwctx->id, &seq);
	if (ret) {
		XDNA_ERR(xdna, "Submit command failed");
		return ret;
	}

	aie2_cmd_wait(hwctx, seq);
	if (cmd.result) {
		XDNA_ERR(xdna, "Response failure 0x%x", cmd.result);
		return -EINVAL;
	}

	return 0;
}

static int aie2_populate_range(struct amdxdna_gem_obj *abo)
{
	struct amdxdna_dev *xdna = to_xdna_dev(to_gobj(abo)->dev);
	struct amdxdna_umap *mapp;
	unsigned long timeout;
	struct mm_struct *mm;
	bool found;
	int ret;

	timeout = jiffies + msecs_to_jiffies(HMM_RANGE_DEFAULT_TIMEOUT);
again:
	found = false;
	down_write(&xdna->notifier_lock);
	list_for_each_entry(mapp, &abo->mem.umap_list, node) {
		if (mapp->invalid) {
			found = true;
			break;
		}
	}

	if (!found) {
		abo->mem.map_invalid = false;
		up_write(&xdna->notifier_lock);
		return 0;
	}
	kref_get(&mapp->refcnt);
	up_write(&xdna->notifier_lock);

	XDNA_DBG(xdna, "populate memory range %lx %lx",
		 mapp->vma->vm_start, mapp->vma->vm_end);
	mm = mapp->notifier.mm;
	if (!mmget_not_zero(mm)) {
		amdxdna_umap_put(mapp);
		return -EFAULT;
	}

	mapp->range.notifier_seq = mmu_interval_read_begin(&mapp->notifier);
	mmap_read_lock(mm);
	ret = hmm_range_fault(&mapp->range);
	mmap_read_unlock(mm);
	if (ret) {
		if (time_after(jiffies, timeout)) {
			ret = -ETIME;
			goto put_mm;
		}

		if (ret == -EBUSY) {
			amdxdna_umap_put(mapp);
			goto again;
		}

		goto put_mm;
	}

	down_write(&xdna->notifier_lock);
	if (mmu_interval_read_retry(&mapp->notifier, mapp->range.notifier_seq)) {
		up_write(&xdna->notifier_lock);
		amdxdna_umap_put(mapp);
		goto again;
	}
	mapp->invalid = false;
	up_write(&xdna->notifier_lock);
	amdxdna_umap_put(mapp);
	goto again;

put_mm:
	amdxdna_umap_put(mapp);
	mmput(mm);
	return ret;
}

int aie2_cmd_submit(struct amdxdna_hwctx *hwctx, struct amdxdna_sched_job *job, u64 *seq)
{
	struct amdxdna_dev *xdna = hwctx->client->xdna;
	struct ww_acquire_ctx acquire_ctx;
	struct dma_fence_chain *chain;
	struct amdxdna_gem_obj *abo;
	unsigned long timeout = 0;
	int ret, i;

	ret = down_interruptible(&hwctx->priv->job_sem);
	if (ret) {
		XDNA_ERR(xdna, "Grab job sem failed, ret %d", ret);
		return ret;
	}

	chain = dma_fence_chain_alloc();
	if (!chain) {
		XDNA_ERR(xdna, "Alloc fence chain failed");
		ret = -ENOMEM;
		goto up_sem;
	}

#ifdef HAVE_6_17_drm_sched_job_init
	ret = drm_sched_job_init(&job->base, &hwctx->priv->entity, 1, hwctx,
				 hwctx->client->filp->client_id);
#else
	ret = drm_sched_job_init(&job->base, &hwctx->priv->entity, 1, hwctx);
#endif
	if (ret) {
		XDNA_ERR(xdna, "DRM job init failed, ret %d", ret);
		goto free_chain;
	}

retry:
	ret = drm_gem_lock_reservations(job->bos, job->bo_cnt, &acquire_ctx);
	if (ret) {
		XDNA_WARN(xdna, "Failed to lock BOs, ret %d", ret);
		goto cleanup_job;
	}

	for (i = 0; i < job->bo_cnt; i++) {
		ret = dma_resv_reserve_fences(job->bos[i]->resv, 1);
		if (ret) {
			XDNA_WARN(xdna, "Failed to reserve fences %d", ret);
			drm_gem_unlock_reservations(job->bos, job->bo_cnt, &acquire_ctx);
			goto cleanup_job;
		}
	}

	down_read(&xdna->notifier_lock);
	for (i = 0; i < job->bo_cnt; i++) {
		abo = to_xdna_obj(job->bos[i]);
		if (abo->mem.map_invalid) {
			up_read(&xdna->notifier_lock);
			drm_gem_unlock_reservations(job->bos, job->bo_cnt, &acquire_ctx);
			if (!timeout) {
				timeout = jiffies +
					msecs_to_jiffies(HMM_RANGE_DEFAULT_TIMEOUT);
			} else if (time_after(jiffies, timeout)) {
				ret = -ETIME;
				goto cleanup_job;
			}

			ret = aie2_populate_range(abo);
			if (ret)
				goto cleanup_job;
			goto retry;
		}
	}

	mutex_lock(&hwctx->priv->io_lock);
	drm_sched_job_arm(&job->base);
	job->out_fence = dma_fence_get(&job->base.s_fence->finished);
	for (i = 0; i < job->bo_cnt; i++)
		dma_resv_add_fence(job->bos[i]->resv, job->out_fence, DMA_RESV_USAGE_WRITE);
	job->seq = hwctx->priv->seq++;
	kref_get(&job->refcnt);
	drm_sched_entity_push_job(&job->base);

	*seq = job->seq;
	drm_syncobj_add_point(hwctx->priv->syncobj, chain, job->out_fence, *seq);
	mutex_unlock(&hwctx->priv->io_lock);

	up_read(&xdna->notifier_lock);
	drm_gem_unlock_reservations(job->bos, job->bo_cnt, &acquire_ctx);

	aie2_job_put(job);
	atomic64_inc(&hwctx->job_submit_cnt);

	return 0;

cleanup_job:
	drm_sched_job_cleanup(&job->base);
free_chain:
	dma_fence_chain_free(chain);
up_sem:
	up(&hwctx->priv->job_sem);
	job->job_done = true;
	return ret;
}

int aie2_hwctx_heap_expand(struct amdxdna_hwctx *hwctx)
{
	struct amdxdna_client *client = hwctx->client;
	struct amdxdna_dev *xdna = client->xdna;
	struct amdxdna_gem_obj *last = hwctx->priv->last_pinned_chunk;
	bool first_pin = !last;
	struct amdxdna_gem_obj *chunk;
	u64 addr;
	int ret;

	drm_WARN_ON(&xdna->ddev, !mutex_is_locked(&xdna->dev_lock));
	drm_WARN_ON(&xdna->ddev, !mutex_is_locked(&client->mm_lock));

	/*
	 * Start at the chunk just after last_pinned_chunk, or at the head
	 * of the list when nothing has been pinned yet for this hwctx.
	 * list_prepare_entry() yields a cursor whose .next points to the
	 * desired starting element, so list_for_each_entry_continue() then
	 * iterates correctly without a duplicate-entry hazard.
	 */
	chunk = list_prepare_entry(last, &client->dev_heap_chunks, heap_chunk_node);

	list_for_each_entry_continue(chunk, &client->dev_heap_chunks,
				     heap_chunk_node) {
		/*
		 * In PASID mode the device address comes from the chunk UVA
		 * (see amdxdna_obj_dma_addr()), so an un-mmapped chunk has
		 * no valid address yet and must be skipped; it will be
		 * picked up by a later expand() once userspace mmaps it.
		 *
		 * In non-PASID mode (IOVA / carved-out) the device address
		 * comes from abo->mem.dma_addr, which is set at chunk open
		 * time independently of mmap, so FW notification can
		 * proceed regardless of UVA state.
		 */
		if (amdxdna_pasid_on(client) &&
		    chunk->mem.uva == AMDXDNA_INVALID_ADDR) {
			XDNA_DBG(xdna,
				 "hwctx %s: chunk not yet mmapped, deferring FW notify",
				 hwctx->name);
			break;
		}

		ret = amdxdna_gem_pin(chunk);
		if (ret) {
			XDNA_ERR(xdna, "Pin chunk for hwctx %s failed, ret %d",
				 hwctx->name, ret);
			return ret;
		}
		drm_gem_object_get(to_gobj(chunk));

		addr = amdxdna_obj_dma_addr(chunk);
		if (first_pin)
			ret = aie2_map_host_buf(xdna->dev_handle,
						hwctx->fw_ctx_id,
						addr, chunk->mem.size);
		else
			ret = aie2_add_host_buf(xdna->dev_handle,
						hwctx->fw_ctx_id,
						addr, chunk->mem.size);
		if (ret) {
			XDNA_ERR(xdna,
				 "Notify FW hwctx %s for chunk size 0x%lx failed, ret %d",
				 hwctx->name, chunk->mem.size, ret);
			amdxdna_gem_unpin(chunk);
			drm_gem_object_put(to_gobj(chunk));
			return ret;
		}

		hwctx->priv->last_pinned_chunk = chunk;
		first_pin = false;
	}

	return 0;
}

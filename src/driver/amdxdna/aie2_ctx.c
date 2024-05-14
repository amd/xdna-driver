// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2024, Advanced Micro Devices, Inc.
 */

#include "amdxdna_ctx.h"
#include "amdxdna_gem.h"
#include "amdxdna_trace.h"
#include "aie2_pci.h"
#include "aie2_solver.h"
#include "aie2_msg_priv.h"

bool force_cmdlist;
module_param(force_cmdlist, bool, 0600);
MODULE_PARM_DESC(force_cmdlist, "Force use command list (Default false)");

#define HWCTX_MAX_TIMEOUT	16000 /* miliseconds */

static inline int
aie2_hwctx_add_job(struct amdxdna_hwctx *hwctx, struct amdxdna_sched_job *job)
{
	struct amdxdna_sched_job *other;
	int idx;

	idx = get_job_idx(hwctx->priv->seq);
	/* When pending list full, hwctx->seq points to oldest fence */
	other = hwctx->priv->pending[idx];
	if (other && other->fence)
		return -EAGAIN;

	if (other) {
		dma_fence_put(other->out_fence);
		amdxdna_job_put(other);
	}

	hwctx->priv->pending[idx] = job;
	job->seq = hwctx->priv->seq++;
	kref_get(&job->refcnt);

	return 0;
}

static inline struct amdxdna_sched_job *
aie2_hwctx_get_job(struct amdxdna_hwctx *hwctx, u64 seq)
{
	int idx;

	/* Special sequence number for oldest fence if exist */
	if (seq == AMDXDNA_INVALID_CMD_HANDLE) {
		idx = get_job_idx(hwctx->priv->seq);
		goto out;
	}

	if (seq >= hwctx->priv->seq)
		return ERR_PTR(-EINVAL);

	if (seq + HWCTX_MAX_CMDS < hwctx->priv->seq)
		return NULL;

	idx = get_job_idx(seq);

out:
	return hwctx->priv->pending[idx];
}

/* The bad_job is used in aie2_sched_job_timedout, otherwise, set it to NULL */
static void aie2_hwctx_stop(struct amdxdna_dev *xdna, struct amdxdna_hwctx *hwctx,
			    struct drm_sched_job *bad_job)
{
	drm_sched_stop(&hwctx->priv->sched, bad_job);
	aie2_destroy_context(xdna->dev_handle, hwctx);
}

static int aie2_hwctx_restart(struct amdxdna_dev *xdna, struct amdxdna_hwctx *hwctx)
{
	struct amdxdna_gem_obj *heap = hwctx->priv->heap;
	int ret;

	ret = aie2_create_context(xdna->dev_handle, hwctx);
	if (ret) {
		XDNA_ERR(xdna, "Create hwctx failed, ret %d", ret);
		goto out;
	}

	ret = aie2_map_host_buf(xdna->dev_handle, hwctx->fw_ctx_id,
				heap->mem.userptr, heap->mem.size);
	if (ret) {
		XDNA_ERR(xdna, "Map host buf failed, ret %d", ret);
		goto out;
	}

	if (hwctx->status != HWCTX_STAT_READY) {
		XDNA_DBG(xdna, "hwctx is not ready, status %d", hwctx->status);
		goto out;
	}

#ifdef AMDXDNA_DEVEL
	if (priv_load) {
		ret = aie2_legacy_config_cu(hwctx);
		if (ret) {
			XDNA_ERR(xdna, "Legacy config cu failed, ret %d", ret);
			goto out;
		}
		goto skip_config_cu;
	}
#endif
	ret = aie2_config_cu(hwctx);
	if (ret) {
		XDNA_ERR(xdna, "Config cu failed, ret %d", ret);
		goto out;
	}
#ifdef AMDXDNA_DEVEL
skip_config_cu:
#endif
out:
	drm_sched_start(&hwctx->priv->sched, true);
	XDNA_DBG(xdna, "%s restarted, ret %d", hwctx->name, ret);
	return ret;
}

void aie2_stop_ctx_by_col_map(struct amdxdna_client *client, u32 col_map)
{
	struct amdxdna_dev *xdna = client->xdna;
	struct amdxdna_hwctx *hwctx;
	int next = 0;

	drm_WARN_ON(&xdna->ddev, !mutex_is_locked(&xdna->dev_lock));
	mutex_lock(&client->hwctx_lock);
	idr_for_each_entry_continue(&client->hwctx_idr, hwctx, next) {
		/* check if the HW context uses the error column */
		if (!(col_map & amdxdna_hwctx_col_map(hwctx)))
			continue;

		aie2_hwctx_stop(xdna, hwctx, NULL);
		hwctx->old_status = hwctx->status;
		hwctx->status = HWCTX_STAT_STOP;
		XDNA_DBG(xdna, "Stop %s", hwctx->name);
	}
	mutex_unlock(&client->hwctx_lock);
}

void aie2_restart_ctx(struct amdxdna_client *client)
{
	struct amdxdna_dev *xdna = client->xdna;
	struct amdxdna_hwctx *hwctx;
	int next = 0;

	drm_WARN_ON(&xdna->ddev, !mutex_is_locked(&xdna->dev_lock));
	mutex_lock(&client->hwctx_lock);
	idr_for_each_entry_continue(&client->hwctx_idr, hwctx, next) {
		if (hwctx->status != HWCTX_STAT_STOP)
			continue;

		hwctx->status = hwctx->old_status;
		XDNA_DBG(xdna, "Resetting %s", hwctx->name);
		aie2_hwctx_restart(xdna, hwctx);
	}
	mutex_unlock(&client->hwctx_lock);
}

static int aie2_hwctx_wait_for_idle(struct amdxdna_hwctx *hwctx)
{
	struct amdxdna_sched_job *job;

	mutex_lock(&hwctx->priv->io_lock);
	if (!hwctx->priv->seq) {
		mutex_unlock(&hwctx->priv->io_lock);
		return 0;
	}

	job = aie2_hwctx_get_job(hwctx, hwctx->priv->seq - 1);
	if (IS_ERR_OR_NULL(job)) {
		mutex_unlock(&hwctx->priv->io_lock);
		XDNA_WARN(hwctx->client->xdna, "Corrupted pending list");
		return 0;
	}
	mutex_unlock(&hwctx->priv->io_lock);

	wait_event(hwctx->priv->job_free_wq, !job->fence);

	return 0;
}

void aie2_hwctx_suspend(struct amdxdna_hwctx *hwctx)
{
	struct amdxdna_dev *xdna = hwctx->client->xdna;

	/*
	 * Command timeout is unlikely. But if it happens, it doesn't
	 * break the system. aie2_hwctx_stop() will destroy mailbox
	 * and abort all commands.
	 */
	drm_WARN_ON(&xdna->ddev, !mutex_is_locked(&xdna->dev_lock));
	aie2_hwctx_wait_for_idle(hwctx);
	aie2_hwctx_stop(xdna, hwctx, NULL);
	hwctx->old_status = hwctx->status;
	hwctx->status = HWCTX_STAT_STOP;
}

void aie2_hwctx_resume(struct amdxdna_hwctx *hwctx)
{
	struct amdxdna_dev *xdna = hwctx->client->xdna;

	/*
	 * The resume path cannot guarantee that mailbox channel can be
	 * regenerated. If this happen, when submit message to this
	 * mailbox channel, error will return.
	 */
	drm_WARN_ON(&xdna->ddev, !mutex_is_locked(&xdna->dev_lock));
	hwctx->status = hwctx->old_status;
	aie2_hwctx_restart(xdna, hwctx);
}

static inline void
aie2_sched_notify(struct amdxdna_sched_job *job)
{
	dma_fence_signal(job->fence);
	trace_xdna_job(job->hwctx->name, "signaled fence", job->seq);
	dma_fence_put(job->fence);
	mmput(job->mm);
	amdxdna_job_put(job);
}

static int
aie2_sched_resp_handler(void *handle, const u32 *data, size_t size)
{
	struct amdxdna_sched_job *job = handle;
	u32 ret = 0;
	u32 status;

	if (unlikely(!data)) {
		amdxdna_cmd_set_state(job, 0, ERT_CMD_STATE_ABORT);
		goto out;
	}

	if (unlikely(size != sizeof(u32))) {
		amdxdna_cmd_set_state(job, 0, ERT_CMD_STATE_ABORT);
		ret = -EINVAL;
		goto out;
	}

	status = *data;
	XDNA_DBG(job->hwctx->client->xdna, "Resp status 0x%x", status);
	if (status == AIE2_STATUS_SUCCESS)
		amdxdna_cmd_set_state(job, 0, ERT_CMD_STATE_COMPLETED);
	else
		amdxdna_cmd_set_state(job, 0, ERT_CMD_STATE_ERROR);

out:
	aie2_sched_notify(job);
	return ret;
}

static int
aie2_sched_cmdlist_resp_handler(void *handle, const u32 *data, size_t size)
{
	struct amdxdna_sched_job *job = handle;
	struct cmd_chain_resp *resp;
	struct amdxdna_dev *xdna;
	u32 fail_cmd_status;
	u32 fail_cmd_idx;
	u32 ret = 0;

	if (unlikely(!data)) {
		amdxdna_cmd_set_state_in_range(job, 0, job->cmd_bo_cnt,
					       ERT_CMD_STATE_ABORT);
		goto out;
	}

	if (unlikely(size != sizeof(u32) * 3)) {
		amdxdna_cmd_set_state_in_range(job, 0, job->cmd_bo_cnt,
					       ERT_CMD_STATE_ABORT);
		ret = -EINVAL;
		goto out;
	}

	resp = (struct cmd_chain_resp *)data;
	xdna = job->hwctx->client->xdna;
	XDNA_DBG(xdna, "Status for all 0x%x", resp->status);
	if (resp->status == AIE2_STATUS_SUCCESS) {
		amdxdna_cmd_set_state_in_range(job, 0, job->cmd_bo_cnt,
					       ERT_CMD_STATE_COMPLETED);
		goto out;
	}

	/* Slow path to handle error, read from ringbuf on BAR */
	fail_cmd_idx = resp->fail_cmd_idx;
	fail_cmd_status = resp->fail_cmd_status;
	XDNA_DBG(xdna, "Failed cmd idx %d, status 0x%x",
		 fail_cmd_idx, fail_cmd_status);

	if (fail_cmd_idx > job->cmd_bo_cnt ||
	    fail_cmd_status == AIE2_STATUS_SUCCESS) {
		amdxdna_cmd_set_state_in_range(job, 0, job->cmd_bo_cnt,
					       ERT_CMD_STATE_ABORT);
		ret = -EINVAL;
		goto out;
	}

	amdxdna_cmd_set_state_in_range(job, 0, fail_cmd_idx, ERT_CMD_STATE_COMPLETED);
	amdxdna_cmd_set_state_in_range(job, fail_cmd_idx, job->cmd_bo_cnt,
				       ERT_CMD_STATE_ABORT);

out:
	aie2_sched_notify(job);
	return ret;
}

static struct dma_fence *
aie2_sched_job_run(struct drm_sched_job *sched_job)
{
	struct amdxdna_sched_job *job = drm_job_to_xdna_job(sched_job);
	struct amdxdna_hwctx *hwctx = job->hwctx;
	struct dma_fence *fence;
	int ret;

	if (!mmget_not_zero(job->mm))
		return ERR_PTR(-ESRCH);

	kref_get(&job->refcnt);
	fence = dma_fence_get(job->fence);

	amdxdna_cmd_init_all_state(job);
	if (force_cmdlist || job->cmd_bo_cnt > 1)
		ret = aie2_cmdlist(hwctx, job, job, aie2_sched_cmdlist_resp_handler);
	else
		ret = aie2_execbuf(hwctx, job, job, aie2_sched_resp_handler);
	if (ret) {
		dma_fence_put(job->fence);
		amdxdna_job_put(job);
		mmput(job->mm);
		fence = ERR_PTR(ret);
	}
	trace_xdna_job(hwctx->name, "sent to device", job->seq);

	return fence;
}

static void aie2_sched_job_free(struct drm_sched_job *sched_job)
{
	struct amdxdna_sched_job *job = drm_job_to_xdna_job(sched_job);
	struct amdxdna_hwctx *hwctx = job->hwctx;

	trace_xdna_job(hwctx->name, "job free", job->seq);
	drm_sched_job_cleanup(sched_job);
	job->fence = NULL;
	amdxdna_job_put(job);

	wake_up(&hwctx->priv->job_free_wq);
}

static enum drm_gpu_sched_stat
aie2_sched_job_timedout(struct drm_sched_job *sched_job)
{
	struct amdxdna_sched_job *job = drm_job_to_xdna_job(sched_job);
	struct amdxdna_hwctx *hwctx = job->hwctx;
	struct amdxdna_dev *xdna;

	xdna = hwctx->client->xdna;
	trace_xdna_job(hwctx->name, "job timedout", job->seq);
	mutex_lock(&xdna->dev_lock);
	aie2_hwctx_stop(xdna, hwctx, sched_job);

	aie2_hwctx_restart(xdna, hwctx);
	mutex_unlock(&xdna->dev_lock);

	return DRM_GPU_SCHED_STAT_NOMINAL;
}

const struct drm_sched_backend_ops sched_ops = {
	.run_job = aie2_sched_job_run,
	.free_job = aie2_sched_job_free,
	.timedout_job = aie2_sched_job_timedout,
};

static int aie2_hwctx_col_list(struct amdxdna_hwctx *hwctx)
{
	struct amdxdna_dev *xdna = hwctx->client->xdna;
	struct amdxdna_dev_hdl *ndev;
	int start, end, first, last;
	u32 width = 1, entries = 0;
	int i;

	if (!hwctx->num_tiles) {
		XDNA_ERR(xdna, "Number of tiles is zero");
		return -EINVAL;
	}

	ndev = xdna->dev_handle;
	if (unlikely(!ndev->metadata.core.row_count)) {
		XDNA_WARN(xdna, "Core tile row count is zero");
		return -EINVAL;
	}

	hwctx->num_col = hwctx->num_tiles / ndev->metadata.core.row_count;
	if (!hwctx->num_col || hwctx->num_col > ndev->total_col) {
		XDNA_ERR(xdna, "Invalid num_col %d", hwctx->num_col);
		return -EINVAL;
	}

	if (ndev->priv->col_align == COL_ALIGN_NATURE)
		width = hwctx->num_col;

#ifdef AMDXDNA_DEVEL
	if (start_col_index >= 0) {
		if (start_col_index + hwctx->num_col > ndev->total_col) {
			XDNA_ERR(xdna, "Invalid start_col_index %d, num col %d",
				 start_col_index, hwctx->num_col);
			return -EINVAL;
		}
		entries = 1;
		first = start_col_index;
		goto skip_list_cal;
	}
#endif
	/*
	 * In range [start, end], find out columns that is multiple of width.
	 *	'first' is the first column,
	 *	'last' is the last column,
	 *	'entries' is the total number of columns.
	 */
	start =  xdna->dev_info->first_col;
	end =  ndev->total_col - hwctx->num_col;
	if (start > 0 && end == 0) {
		XDNA_DBG(xdna, "Force start from col 0");
		start = 0;
	}
	first = start + (width - start % width) % width;
	last = end - end % width;
	if (last >= first)
		entries = (last - first) / width + 1;
	XDNA_DBG(xdna, "start %d end %d first %d last %d",
		 start, end, first, last);

	if (unlikely(!entries)) {
		XDNA_ERR(xdna, "Start %d end %d width %d",
			 start, end, width);
		return -EINVAL;
	}

#ifdef AMDXDNA_DEVEL
skip_list_cal:
#endif
	hwctx->col_list = kmalloc_array(entries, sizeof(*hwctx->col_list), GFP_KERNEL);
	if (!hwctx->col_list)
		return -ENOMEM;

	hwctx->col_list_len = entries;
	hwctx->col_list[0] = first;
	for (i = 1; i < entries; i++)
		hwctx->col_list[i] = hwctx->col_list[i - 1] + width;

	print_hex_dump_debug("col_list: ", DUMP_PREFIX_OFFSET, 16, 4, hwctx->col_list,
			     entries * sizeof(*hwctx->col_list), false);
	return 0;
}

static int aie2_alloc_resource(struct amdxdna_hwctx *hwctx)
{
	struct amdxdna_dev *xdna = hwctx->client->xdna;
	struct alloc_requests *xrs_req;
	int ret;

	xrs_req = kzalloc(sizeof(*xrs_req), GFP_KERNEL);
	if (!xrs_req)
		return -ENOMEM;

	xrs_req->cdo.start_cols = hwctx->col_list;
	xrs_req->cdo.cols_len = hwctx->col_list_len;
	xrs_req->cdo.ncols = hwctx->num_col;
	xrs_req->cdo.qos_cap.opc = hwctx->max_opc;

	xrs_req->rqos.gops = hwctx->qos.gops;
	xrs_req->rqos.fps = hwctx->qos.fps;
	xrs_req->rqos.dma_bw = hwctx->qos.dma_bandwidth;
	xrs_req->rqos.latency = hwctx->qos.latency;
	xrs_req->rqos.exec_time = hwctx->qos.frame_exec_time;
	xrs_req->rqos.priority = hwctx->qos.priority;

	xrs_req->rid = (uintptr_t)hwctx;

	ret = xrs_allocate_resource(xdna->xrs_hdl, xrs_req, hwctx);
	if (ret)
		XDNA_ERR(xdna, "Allocate AIE resource failed, ret %d", ret);

	kfree(xrs_req);
	return ret;
}

static void aie2_release_resource(struct amdxdna_hwctx *hwctx)
{
	struct amdxdna_dev *xdna = hwctx->client->xdna;
	int ret;

	ret = xrs_release_resource(xdna->xrs_hdl, (uintptr_t)hwctx);
	if (ret)
		XDNA_ERR(xdna, "Release AIE resource failed, ret %d", ret);
}

int aie2_hwctx_init(struct amdxdna_hwctx *hwctx)
{
	struct amdxdna_client *client = hwctx->client;
	struct amdxdna_dev *xdna = client->xdna;
	struct drm_gpu_scheduler *sched;
	struct amdxdna_hwctx_priv *priv;
	struct amdxdna_gem_obj *heap;
	int i, ret;

	priv = kzalloc(sizeof(*hwctx->priv), GFP_KERNEL);
	if (!priv)
		return -ENOMEM;
	hwctx->priv = priv;

	mutex_lock(&client->mm_lock);
	heap = client->dev_heap;
	if (!heap) {
		XDNA_ERR(xdna, "The client dev heap object not exist");
		mutex_unlock(&client->mm_lock);
		ret = -ENOENT;
		goto free_priv;
	}
	drm_gem_object_get(to_gobj(heap));
	mutex_unlock(&client->mm_lock);
	priv->heap = heap;

	ret = amdxdna_gem_pin(heap);
	if (ret) {
		XDNA_ERR(xdna, "Dev heap pin failed, ret %d", ret);
		goto put_heap;
	}

	for (i = 0; i < ARRAY_SIZE(priv->cmd_buf); i++) {
		struct amdxdna_gem_obj *abo;
		struct amdxdna_drm_create_bo args = {
			.flags = 0,
			.type = AMDXDNA_BO_DEV,
			.vaddr = 0,
			.size = MAX_CHAIN_CMDBUF_SIZE,
		};

		abo = amdxdna_drm_alloc_dev_bo(&xdna->ddev, &args, client->filp, true);
		if (!abo)
			goto free_cmd_bufs;

		XDNA_DBG(xdna, "Command buf %d addr 0x%llx size 0x%lx",
			 i, abo->mem.dev_addr, abo->mem.size);
		priv->cmd_buf[i] = abo;
	}

	sched = &priv->sched;
	mutex_init(&priv->io_lock);
	ret = drm_sched_init(sched, &sched_ops, NULL, DRM_SCHED_PRIORITY_COUNT,
			     HWCTX_MAX_CMDS, 0, msecs_to_jiffies(HWCTX_MAX_TIMEOUT),
			     NULL, NULL, hwctx->name, xdna->ddev.dev);
	if (ret) {
		XDNA_ERR(xdna, "Failed to init DRM scheduler. ret %d", ret);
		goto free_cmd_bufs;
	}

	ret = drm_sched_entity_init(&priv->entity, DRM_SCHED_PRIORITY_NORMAL,
				    &sched, 1, NULL);
	if (ret) {
		XDNA_ERR(xdna, "Failed to initial sched entiry. ret %d", ret);
		goto free_sched;
	}
	init_waitqueue_head(&priv->job_free_wq);

	ret = aie2_hwctx_col_list(hwctx);
	if (ret) {
		XDNA_ERR(xdna, "Create col list failed, ret %d", ret);
		goto free_entity;
	}

	ret = aie2_alloc_resource(hwctx);
	if (ret) {
		XDNA_ERR(xdna, "Alloc hw resource failed, ret %d", ret);
		goto free_col_list;
	}

	ret = aie2_map_host_buf(xdna->dev_handle, hwctx->fw_ctx_id,
				heap->mem.userptr, heap->mem.size);
	if (ret) {
		XDNA_ERR(xdna, "Map host buffer failed, ret %d", ret);
		goto release_resource;
	}
	hwctx->status = HWCTX_STAT_INIT;

	XDNA_DBG(xdna, "hwctx %s init completed", hwctx->name);

	return 0;

release_resource:
	aie2_release_resource(hwctx);
free_col_list:
	kfree(hwctx->col_list);
free_entity:
	drm_sched_entity_destroy(&priv->entity);
free_sched:
	drm_sched_fini(&priv->sched);
free_cmd_bufs:
	for (i = 0; i < ARRAY_SIZE(priv->cmd_buf); i++) {
		if (!priv->cmd_buf[i])
			continue;
		drm_gem_object_put(to_gobj(priv->cmd_buf[i]));
	}
	amdxdna_gem_unpin(heap);
put_heap:
	drm_gem_object_put(to_gobj(heap));
free_priv:
	kfree(priv);
	return ret;
}

void aie2_hwctx_fini(struct amdxdna_hwctx *hwctx)
{
	struct amdxdna_sched_job *job;
	struct amdxdna_dev *xdna;
	int idx;

	xdna = hwctx->client->xdna;
	drm_sched_wqueue_stop(&hwctx->priv->sched);

	/* Now, scheduler will not send command to device. */
	aie2_release_resource(hwctx);

	/*
	 * All submitted commands are aborted.
	 * Restart scheduler queues to cleanup jobs. The amdxdna_sched_job_run()
	 * will return NODEV if it is called.
	 */
	drm_sched_wqueue_start(&hwctx->priv->sched);

	aie2_hwctx_wait_for_idle(hwctx);
	drm_sched_entity_destroy(&hwctx->priv->entity);
	drm_sched_fini(&hwctx->priv->sched);

	for (idx = 0; idx < HWCTX_MAX_CMDS; idx++) {
		job = hwctx->priv->pending[idx];
		if (!job)
			continue;

		dma_fence_put(job->out_fence);
		amdxdna_job_put(job);
	}
	XDNA_DBG(xdna, "%s sequence number %lld", hwctx->name, hwctx->priv->seq);

	for (idx = 0; idx < ARRAY_SIZE(hwctx->priv->cmd_buf); idx++)
		drm_gem_object_put(to_gobj(hwctx->priv->cmd_buf[idx]));
	amdxdna_gem_unpin(hwctx->priv->heap);
	drm_gem_object_put(to_gobj(hwctx->priv->heap));
#ifdef AMDXDNA_DEVEL
	if (priv_load)
		aie2_unregister_pdis(hwctx);
#endif

	mutex_destroy(&hwctx->priv->io_lock);
	kfree(hwctx->col_list);
	kfree(hwctx->priv);
	kfree(hwctx->cus);
}

static int aie2_hwctx_cu_config(struct amdxdna_hwctx *hwctx, void *buf, u32 size)
{
	struct amdxdna_hwctx_param_config_cu *config = buf;
	struct amdxdna_dev *xdna = hwctx->client->xdna;
	u32 total_size;
	int ret;

	XDNA_DBG(xdna, "Config %d CU to %s", config->num_cus, hwctx->name);
	if (hwctx->status != HWCTX_STAT_INIT) {
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

#ifdef AMDXDNA_DEVEL
	if (priv_load) {
		ret = aie2_register_pdis(hwctx);
		if (ret) {
			XDNA_ERR(xdna, "Register PDIs failed, ret %d", ret);
			goto free_cus;
		}

		ret = aie2_legacy_config_cu(hwctx);
		if (ret) {
			XDNA_ERR(xdna, "Legacy config cu failed, ret %d", ret);
			aie2_unregister_pdis(hwctx);
			goto free_cus;
		}

		goto skip_config_cu;
	}
#endif
	ret = aie2_config_cu(hwctx);
	if (ret) {
		XDNA_ERR(xdna, "Configu CU to firmware failed, ret %d", ret);
		goto free_cus;
	}

#ifdef AMDXDNA_DEVEL
skip_config_cu:
#endif
	wmb(); /* To avoid locking in command submit when check status */
	hwctx->status = HWCTX_STAT_READY;

	return 0;

free_cus:
	kfree(hwctx->cus);
	hwctx->cus = NULL;
	return ret;
}

static int aie2_hwctx_attach_debug_bo(struct amdxdna_hwctx *hwctx, u32 bo_hdl)
{
	struct amdxdna_client *client = hwctx->client;
	struct amdxdna_gem_obj *abo = amdxdna_gem_get_obj(client, bo_hdl, AMDXDNA_BO_DEV);
	struct amdxdna_dev *xdna = client->xdna;
	int ret;

	// Debug BO has to be AMDXDNA_BO_DEV type
	if (!abo) {
		ret = -EINVAL;
		goto done;
	}

	/*
	 * There has to be no existing assigned dbg BO and the target
	 * BO (bo_hdl) has to exist and can't be already assigned to other ctx.
	 */
	if (amdxdna_gem_get_assigned_hwctx(client, hwctx->dbg_buf_bo) == hwctx->id)
		ret = hwctx->dbg_buf_bo == bo_hdl ? 0 : -EBUSY;
	else
		ret = amdxdna_gem_set_assigned_hwctx(client, bo_hdl, hwctx->id);

	amdxdna_gem_put_obj(abo);

done:
	if (ret == 0) {
		hwctx->dbg_buf_bo = bo_hdl;
		XDNA_DBG(xdna, "Attached debug BO %d to %s", bo_hdl, hwctx->name);
	} else {
		XDNA_ERR(xdna, "Failed to attach debug BO %d to %s: %d", bo_hdl, hwctx->name, ret);
	}
	return ret;
}

static int aie2_hwctx_detach_debug_bo(struct amdxdna_hwctx *hwctx, u32 bo_hdl)
{
	struct amdxdna_client *client = hwctx->client;
	struct amdxdna_dev *xdna = client->xdna;

	if ((hwctx->dbg_buf_bo != bo_hdl) ||
	    (amdxdna_gem_get_assigned_hwctx(client, bo_hdl) != hwctx->id)) {
		XDNA_ERR(xdna, "Debug BO %d isn't attached to %s", bo_hdl, hwctx->name);
		return -EINVAL;
	}

	hwctx->dbg_buf_bo = AMDXDNA_INVALID_BO_HANDLE;
	amdxdna_gem_clear_assigned_hwctx(client, bo_hdl);
	XDNA_DBG(xdna, "Detached debug BO %d from %s", bo_hdl, hwctx->name);
	return 0;
}

int aie2_hwctx_config(struct amdxdna_hwctx *hwctx, u32 type, u64 value, void *buf, u32 size)
{
	struct amdxdna_dev *xdna = hwctx->client->xdna;

	drm_WARN_ON(&xdna->ddev, !mutex_is_locked(&xdna->dev_lock));
	switch (type) {
	case DRM_AMDXDNA_HWCTX_CONFIG_CU:
		return aie2_hwctx_cu_config(hwctx, buf, size);
	case DRM_AMDXDNA_HWCTX_ASSIGN_DBG_BUF:
		return aie2_hwctx_attach_debug_bo(hwctx, (u32)value);
	case DRM_AMDXDNA_HWCTX_REMOVE_DBG_BUF:
		return aie2_hwctx_detach_debug_bo(hwctx, (u32)value);
	default:
		XDNA_DBG(xdna, "Not supported type %d", type);
		return -EOPNOTSUPP;
	}
}

int aie2_cmd_submit(struct amdxdna_hwctx *hwctx, struct amdxdna_sched_job *job, u64 *seq)
{
	struct amdxdna_dev *xdna = hwctx->client->xdna;
	struct ww_acquire_ctx acquire_ctx;
	int ret, i;

	ret = drm_sched_job_init(&job->base, &hwctx->priv->entity, 1, hwctx);
	if (ret) {
		XDNA_ERR(xdna, "DRM job init failed, ret %d", ret);
		return ret;
	}

	drm_sched_job_arm(&job->base);
	job->out_fence = dma_fence_get(&job->base.s_fence->finished);

	ret = drm_gem_lock_reservations(job->bos, job->bo_cnt, &acquire_ctx);
	if (ret) {
		XDNA_WARN(xdna, "Failed to reverve fence, ret %d", ret);
		goto put_fence;
	}

	for (i = 0; i < job->bo_cnt; i++) {
		ret = dma_resv_reserve_fences(job->bos[i]->resv, 1);
		if (ret) {
			XDNA_WARN(xdna, "Failed to reserve fences %d", ret);
			goto unlock_resv;
		}
	}

	for (i = 0; i < job->bo_cnt; i++)
		dma_resv_add_fence(job->bos[i]->resv, job->out_fence, DMA_RESV_USAGE_WRITE);
	drm_gem_unlock_reservations(job->bos, job->bo_cnt, &acquire_ctx);

	mutex_lock(&hwctx->priv->io_lock);
	ret = aie2_hwctx_add_job(hwctx, job);
	if (ret) {
		mutex_unlock(&hwctx->priv->io_lock);
		goto unlock_resv;
	}

	*seq = job->seq;
	drm_sched_entity_push_job(&job->base);
	mutex_unlock(&hwctx->priv->io_lock);

	return 0;

unlock_resv:
	drm_gem_unlock_reservations(job->bos, job->bo_cnt, &acquire_ctx);
put_fence:
	dma_fence_put(job->out_fence);
	drm_sched_job_cleanup(&job->base);
	return ret;
}

int aie2_cmd_wait(struct amdxdna_hwctx *hwctx, u64 seq, u32 timeout)
{
	signed long remaining = MAX_SCHEDULE_TIMEOUT;
	struct amdxdna_sched_job *job;
	struct dma_fence *out_fence;
	int ret;

	mutex_lock(&hwctx->priv->io_lock);
	job = aie2_hwctx_get_job(hwctx, seq);
	if (IS_ERR(job)) {
		mutex_unlock(&hwctx->priv->io_lock);
		ret = PTR_ERR(job);
		goto out;
	}

	if (unlikely(!job)) {
		mutex_unlock(&hwctx->priv->io_lock);
		ret = 0;
		goto out;
	}
	out_fence = dma_fence_get(job->out_fence);
	mutex_unlock(&hwctx->priv->io_lock);

	if (timeout)
		remaining = msecs_to_jiffies(timeout);

	remaining = dma_fence_wait_timeout(out_fence, true, remaining);
	if (!remaining)
		ret = -ETIME;
	else if (remaining < 0)
		ret = remaining; /* error code */
	else
		ret = 0;

	dma_fence_put(out_fence);
out:
	return ret;
}

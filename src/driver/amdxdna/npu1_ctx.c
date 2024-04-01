// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2024, Advanced Micro Devices, Inc.
 */

#include "amdxdna_ctx.h"
#include "amdxdna_gem.h"
#include "npu_common.h"
#include "npu1_pci.h"

static inline u64
npu1_hwctx_add_fence(struct amdxdna_hwctx *hwctx, struct dma_fence *fence)
{
	struct dma_fence *other;
	int idx;

	idx = hwctx->priv->seq & (HWCTX_MAX_CMDS - 1);
	/* When pending list full, hwctx->seq points to oldest fence */
	other = hwctx->priv->pending[idx];
	if (other && !dma_fence_is_signaled(other))
		return AMDXDNA_INVALID_CMD_HANDLE;

	if (other)
		dma_fence_put(other);

	hwctx->priv->pending[idx] = fence;

	return hwctx->priv->seq++;
}

static inline struct dma_fence *
npu1_hwctx_get_fence(struct amdxdna_hwctx *hwctx, u64 seq)
{
	struct dma_fence *fence;
	int idx;

	/* Special sequence number for oldest fence if exist */
	if (seq == AMDXDNA_INVALID_CMD_HANDLE) {
		idx = hwctx->priv->seq & (HWCTX_MAX_CMDS - 1);
		fence = hwctx->priv->pending[idx];
		if (fence)
			goto get_fence;

		goto out;
	}

	if (seq >= hwctx->priv->seq) {
		fence = ERR_PTR(-EINVAL);
		goto out;
	}

	if (seq + HWCTX_MAX_CMDS < hwctx->priv->seq) {
		fence = NULL;
		goto out;
	}

	idx = seq & (HWCTX_MAX_CMDS - 1);

get_fence:
	fence = dma_fence_get(hwctx->priv->pending[idx]);
out:
	return fence;
}

static void npu1_hwctx_stop(struct amdxdna_dev *xdna, struct amdxdna_hwctx *hwctx)
{
	drm_sched_stop(&hwctx->priv->sched, NULL);
	npu1_destroy_context(xdna->dev_handle, hwctx);
}

static int npu1_hwctx_restart(struct amdxdna_dev *xdna, struct amdxdna_hwctx *hwctx)
{
	struct amdxdna_gem_obj *heap = hwctx->priv->heap;
	int ret;

	ret = npu1_create_context(xdna->dev_handle, hwctx);
	if (ret) {
		XDNA_ERR(xdna, "Create hwctx failed, ret %d", ret);
		return ret;
	}

	ret = npu1_config_cu(xdna->dev_handle, hwctx->priv->mbox_chan, hwctx->xclbin);
	if (ret) {
		XDNA_ERR(xdna, "Config cu failed, ret %d", ret);
		return ret;
	}

	ret = npu1_map_host_buf(xdna->dev_handle, hwctx->fw_ctx_id,
				heap->mem.userptr, heap->mem.size);
	if (ret) {
		XDNA_ERR(xdna, "Map host buf failed, ret %d", ret);
		return ret;
	}

	return 0;
}

static int npu1_hwctx_col_match(struct amdxdna_hwctx *hwctx, u32 col_map)
{
	u32 start_col, end_col;

	start_col = hwctx->start_col;
	end_col = start_col + hwctx->num_col - 1;

	return col_map & GENMASK(end_col, start_col);
}

void npu1_stop_ctx_by_col_map(struct amdxdna_client *client, u32 col_map)
{
	struct amdxdna_dev *xdna = client->xdna;
	struct amdxdna_hwctx *hwctx;
	int next = 0;

	drm_WARN_ON(&xdna->ddev, !mutex_is_locked(&xdna->dev_lock));
	mutex_lock(&client->hwctx_lock);
	idr_for_each_entry_continue(&client->hwctx_idr, hwctx, next) {
		/* check if the HW context uses the error column */
		if (!npu1_hwctx_col_match(hwctx, col_map))
			continue;

		npu1_hwctx_stop(xdna, hwctx);
		hwctx->stopped = true;
		XDNA_DBG(xdna, "Stop %s.%d", hwctx->name, hwctx->id);
	}
	mutex_unlock(&client->hwctx_lock);
}

void npu1_restart_ctx(struct amdxdna_client *client)
{
	struct amdxdna_dev *xdna = client->xdna;
	struct amdxdna_hwctx *hwctx;
	int next = 0, ret;

	drm_WARN_ON(&xdna->ddev, !mutex_is_locked(&xdna->dev_lock));
	mutex_lock(&client->hwctx_lock);
	idr_for_each_entry_continue(&client->hwctx_idr, hwctx, next) {
		if (!hwctx->stopped)
			continue;

		XDNA_DBG(xdna, "Resetting %s.%d", hwctx->name, hwctx->id);
		ret = npu1_hwctx_restart(xdna, hwctx);
		if (ret)
			continue;

		drm_sched_start(&hwctx->priv->sched, true);
		hwctx->stopped = false;
		XDNA_DBG(xdna, "%s.%d restarted", hwctx->name, hwctx->id);
	}
	mutex_unlock(&client->hwctx_lock);
}

static int npu1_hwctx_wait_for_idle(struct amdxdna_hwctx *hwctx)
{
	struct dma_fence *out_fence;
	signed long remaining;

	spin_lock(&hwctx->priv->io_lock);
	if (!hwctx->priv->seq) {
		spin_unlock(&hwctx->priv->io_lock);
		return 0;
	}

	out_fence = npu1_hwctx_get_fence(hwctx, hwctx->priv->seq - 1);
	spin_unlock(&hwctx->priv->io_lock);
	if (!out_fence)
		return 0;

	if (dma_fence_is_signaled(out_fence)) {
		dma_fence_put(out_fence);
		return 0;
	}

	remaining = msecs_to_jiffies(HWCTX_MAX_TIMEOUT);
	remaining = dma_fence_wait_timeout(out_fence, false, remaining);
	dma_fence_put(out_fence);
	WARN_ONCE(!remaining, "Unexpected timeout %ld\n", remaining);

	return (remaining) ? -ETIME : 0;
}

void npu1_hwctx_suspend(struct amdxdna_hwctx *hwctx)
{
	struct amdxdna_dev *xdna = hwctx->client->xdna;

	/*
	 * Command timeout is unlikely. But if it happens, it doesn't
	 * break the system. npu1_hwctx_stop() will destroy mailbox
	 * and abort all commands.
	 */
	npu1_hwctx_wait_for_idle(hwctx);
	npu1_hwctx_stop(xdna, hwctx);
	npu1_unregister_pdis(xdna->dev_handle, hwctx->xclbin);
}

void npu1_hwctx_resume(struct amdxdna_hwctx *hwctx)
{
	struct amdxdna_dev *xdna = hwctx->client->xdna;

	/*
	 * The resume path cannot guarantee that mailbox channel can be
	 * regenerated. If this happen, when submit message to this
	 * mailbox channel, error will return.
	 */
	npu1_register_pdis(xdna->dev_handle, hwctx->xclbin);
	npu1_hwctx_restart(xdna, hwctx);
	drm_sched_start(&hwctx->priv->sched, true);
}

static void
npu1_sched_resp_handler(void *handle, const u32 *data, size_t size)
{
	struct amdxdna_sched_job *job = handle;
	u32 status;

	if (!data) {
		job->cmd->state = ERT_CMD_STATE_ABORT;
		goto out;
	}

	print_hex_dump_debug("resp data: ", DUMP_PREFIX_OFFSET, 16, 4, data, size, true);

	status = *data;
	if (status)
		job->cmd->state = ERT_CMD_STATE_ERROR;
	else
		job->cmd->state = ERT_CMD_STATE_COMPLETED;

out:
	dma_fence_signal(job->fence);
	dma_fence_put(job->fence);
	mmput(job->mm);
	amdxdna_job_put(job);
}

static struct dma_fence *
npu1_sched_job_run(struct drm_sched_job *sched_job)
{
	struct amdxdna_sched_job *job = drm_job_to_xdna_job(sched_job);
	struct amdxdna_hwctx *hwctx = job->hwctx;
	struct amdxdna_dev *xdna;
	struct dma_fence *fence;
	void *cmd_buf;
	u32 buf_len;
	int ret;

	xdna = hwctx->client->xdna;

	if (!mmget_not_zero(job->mm))
		return ERR_PTR(-ESRCH);

	kref_get(&job->refcnt);
	fence = dma_fence_get(job->fence);
	cmd_buf = &job->cmd->data[job->cmd->extra_cu_masks];
	buf_len = to_gobj(job->cmd_abo)->size -
		offsetof(struct amdxdna_cmd, data[job->cmd->extra_cu_masks]);
	ret = npu1_execbuf(xdna->dev_handle, hwctx->priv->mbox_chan, job->cu_idx,
			   cmd_buf, buf_len, job, npu1_sched_resp_handler);
	if (ret) {
		dma_fence_put(job->fence);
		amdxdna_job_put(job);
		mmput(job->mm);
		fence = ERR_PTR(ret);
	}

	return fence;
}

static void npu1_sched_job_free(struct drm_sched_job *sched_job)
{
	struct amdxdna_sched_job *job = drm_job_to_xdna_job(sched_job);

	drm_sched_job_cleanup(sched_job);
	amdxdna_job_put(job);
}

const struct drm_sched_backend_ops sched_ops = {
	.run_job = npu1_sched_job_run,
	.free_job = npu1_sched_job_free,
};

int npu1_hwctx_init(struct amdxdna_hwctx *hwctx)
{
	struct amdxdna_client *client = hwctx->client;
	struct amdxdna_dev *xdna = client->xdna;
	struct drm_gpu_scheduler *sched;
	struct amdxdna_gem_obj *heap;
	int ret;

	hwctx->priv = kzalloc(sizeof(*hwctx->priv), GFP_KERNEL);
	if (!hwctx->priv)
		return -ENOMEM;

	heap = amdxdna_gem_get_obj(&xdna->ddev, client->dev_heap,
				   AMDXDNA_BO_DEV_HEAP, client->filp);
	if (!heap) {
		ret = -EINVAL;
		XDNA_ERR(xdna, "Cannot get dev heap object, ret %d", ret);
		goto free_priv;
	}

	ret = amdxdna_gem_pin(heap);
	if (ret) {
		XDNA_ERR(xdna, "Dev heap pin failed, ret %d", ret);
		goto put_heap;
	}
	hwctx->priv->heap = heap;

	sched = &hwctx->priv->sched;
	spin_lock_init(&hwctx->priv->io_lock);
	ret = drm_sched_init(sched, &sched_ops, NULL, DRM_SCHED_PRIORITY_COUNT,
			     HWCTX_MAX_CMDS, 0, MAX_SCHEDULE_TIMEOUT, NULL,
			     NULL, hwctx->name, xdna->ddev.dev);
	if (ret) {
		XDNA_ERR(xdna, "Failed to init DRM scheduler. ret %d", ret);
		goto unpin;
	}

	ret = drm_sched_entity_init(&hwctx->priv->entity, DRM_SCHED_PRIORITY_NORMAL,
				    &sched, 1, NULL);
	if (ret) {
		XDNA_ERR(xdna, "Failed to initial sched entiry. ret %d", ret);
		goto free_sched;
	}

	ret = npu_alloc_resource(hwctx);
	if (ret) {
		XDNA_ERR(xdna, "Alloc hw resource failed, ret %d", ret);
		goto free_entity;
	}

	ret = npu1_config_cu(xdna->dev_handle, hwctx->priv->mbox_chan, hwctx->xclbin);
	if (ret) {
		XDNA_ERR(xdna, "Config CU failed, ret %d", ret);
		goto release_resource;
	}

	ret = npu1_map_host_buf(xdna->dev_handle, hwctx->fw_ctx_id,
				heap->mem.userptr, heap->mem.size);
	if (ret) {
		XDNA_ERR(xdna, "Map host buffer failed, ret %d", ret);
		goto release_resource;
	}

	XDNA_DBG(xdna, "hwctx %s init completed", hwctx->name);

	return 0;

release_resource:
	npu_release_resource(hwctx);
free_entity:
	drm_sched_entity_destroy(&hwctx->priv->entity);
free_sched:
	drm_sched_fini(&hwctx->priv->sched);
unpin:
	amdxdna_gem_unpin(heap);
put_heap:
	amdxdna_put_dev_heap(heap);
free_priv:
	kfree(hwctx->priv);
	return ret;
}

void npu1_hwctx_fini(struct amdxdna_hwctx *hwctx)
{
	struct amdxdna_dev *xdna;
	struct dma_fence *fence;
	int idx;

	xdna = hwctx->client->xdna;
	drm_sched_wqueue_stop(&hwctx->priv->sched);

	/* Now, scheduler will not send command to device. */
	npu_release_resource(hwctx);

	/*
	 * All submitted commands are aborted.
	 * Restart scheduler queues to cleanup jobs. The amdxdna_sched_job_run()
	 * will return NODEV if it is called.
	 */
	drm_sched_wqueue_start(&hwctx->priv->sched);

	amdxdna_xclbin_unload(xdna, hwctx->xclbin);
	drm_sched_entity_destroy(&hwctx->priv->entity);
	drm_sched_fini(&hwctx->priv->sched);

	for (idx = 0; idx < HWCTX_MAX_CMDS; idx++) {
		fence = hwctx->priv->pending[idx];
		if (!fence)
			continue;

		dma_fence_put(fence);
	}
	XDNA_DBG(xdna, "%s sequence number %lld", hwctx->name, hwctx->priv->seq);

	amdxdna_gem_unpin(hwctx->priv->heap);
	amdxdna_put_dev_heap(hwctx->priv->heap);
}

int npu1_cmd_submit(struct amdxdna_hwctx *hwctx, struct amdxdna_sched_job *job, u64 *seq)
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

	spin_lock(&hwctx->priv->io_lock);
	job->seq = npu1_hwctx_add_fence(job->hwctx, job->out_fence);
	if (job->seq == AMDXDNA_INVALID_CMD_HANDLE) {
		spin_unlock(&hwctx->priv->io_lock);
		ret = -EAGAIN;
		goto unlock_resv;
	}

	*seq = job->seq;
	drm_sched_entity_push_job(&job->base);
	spin_unlock(&hwctx->priv->io_lock);

	return 0;

unlock_resv:
	drm_gem_unlock_reservations(job->bos, job->bo_cnt, &acquire_ctx);
put_fence:
	dma_fence_put(job->out_fence);
	drm_sched_job_cleanup(&job->base);
	return ret;
}

int npu1_cmd_wait(struct amdxdna_hwctx *hwctx, u64 seq, u32 timeout)
{
	signed long remaining = MAX_SCHEDULE_TIMEOUT;
	struct dma_fence *out_fence;
	int ret;

	spin_lock(&hwctx->priv->io_lock);
	out_fence = npu1_hwctx_get_fence(hwctx, seq);
	spin_unlock(&hwctx->priv->io_lock);

	if (IS_ERR(out_fence)) {
		ret = PTR_ERR(out_fence);
		goto put_fence;
	}

	if (unlikely(!out_fence) || dma_fence_is_signaled(out_fence)) {
		ret = 0; /* This command already done */
		goto put_fence;
	}

	if (timeout)
		remaining = msecs_to_jiffies(timeout);

	remaining = dma_fence_wait_timeout(out_fence, true, remaining);
	if (!remaining)
		ret = -ETIME;
	else if (remaining < 0)
		ret = remaining; /* error code */
	else
		ret = 0;

put_fence:
	dma_fence_put(out_fence);
	return ret;
}

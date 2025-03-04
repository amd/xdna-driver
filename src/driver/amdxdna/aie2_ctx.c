// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2024-2025, Advanced Micro Devices, Inc.
 */

#include <linux/timekeeping.h>
#include <drm/drm_syncobj.h>

#include "amdxdna_ctx.h"
#include "amdxdna_gem.h"
#include "amdxdna_trace.h"
#include "aie2_pci.h"
#include "aie2_msg_priv.h"

bool force_cmdlist;
module_param(force_cmdlist, bool, 0600);
MODULE_PARM_DESC(force_cmdlist, "Force use command list (Default false)");

static void aie2_job_release(struct kref *ref)
{
	struct amdxdna_sched_job *job;
	struct amdxdna_ctx *ctx;

	job = container_of(ref, struct amdxdna_sched_job, refcnt);
	ctx = job->ctx;
	amdxdna_sched_job_cleanup(job);
	if (job->out_fence)
		dma_fence_put(job->out_fence);

	kfree(job);

	atomic64_inc(&ctx->job_free_cnt);
	wake_up(&ctx->priv->job_free_waitq);
}

static void aie2_job_put(struct amdxdna_sched_job *job)
{
	kref_put(&job->refcnt, aie2_job_release);
}

static const char *
aie2_fence_state2str(struct dma_fence *fence)
{
	if (!fence)
		return "not-exist";
	return dma_fence_is_signaled(fence) ? "signaled" : "unsignaled";
}

static void
aie2_ctx_dump(struct amdxdna_dev *xdna, struct amdxdna_ctx *ctx)
{
	u64 sub = ctx->submitted;
	u64 comp = ctx->completed;

	XDNA_ERR(xdna, "Dumping ctx %s, sub=%lld, comp=%lld", ctx->name, sub, comp);
	mutex_lock(&ctx->priv->io_lock);
	for (int i = 0; i < CTX_MAX_CMDS; i++) {
		struct amdxdna_sched_job *j;

		j = ctx->priv->pending[i];
		if (!j)
			continue;
		XDNA_ERR(xdna, "JOB[%d]:", i);
		XDNA_ERR(xdna, "\tseq: %lld", j->seq);
		XDNA_ERR(xdna, "\top: 0x%x", j->opcode);
		XDNA_ERR(xdna, "\tmsg: 0x%x", j->msg_id);
		XDNA_ERR(xdna, "\tfence: %s", aie2_fence_state2str(j->fence));
		XDNA_ERR(xdna, "\tout_fence: %s", aie2_fence_state2str(j->out_fence));
	}
	mutex_unlock(&ctx->priv->io_lock);
}

void aie2_dump_ctx(struct amdxdna_client *client)
{
	struct amdxdna_dev *xdna = client->xdna;
	struct amdxdna_ctx *ctx;
	unsigned long ctx_id;
	int idx;

	idx = srcu_read_lock(&client->ctx_srcu);
	amdxdna_for_each_ctx(client, ctx_id, ctx)
		aie2_ctx_dump(xdna, ctx);
	srcu_read_unlock(&client->ctx_srcu, idx);
}

static void aie2_ctx_wait_for_idle(struct amdxdna_ctx *ctx)
{
	struct dma_fence *fence;

	fence = aie2_cmd_get_out_fence(ctx, ctx->submitted - 1);
	if (!fence)
		return;

	dma_fence_wait_timeout(fence, false, msecs_to_jiffies(2000));
	dma_fence_put(fence);
}

void aie2_ctx_disconnect(struct amdxdna_ctx *ctx, bool wait)
{
	struct amdxdna_dev *xdna = ctx->client->xdna;

	/*
	 * Command timeout is unlikely. But if it happens, it doesn't
	 * break the system. aie2_hwctx_stop() will destroy mailbox
	 * and abort all commands.
	 */
	if (wait)
		aie2_ctx_wait_for_idle(ctx);
	mutex_lock(&xdna->dev_handle->aie2_lock);
	aie2_hwctx_stop(ctx);
	mutex_unlock(&xdna->dev_handle->aie2_lock);
}

int aie2_ctx_connect(struct amdxdna_ctx *ctx)
{
	struct amdxdna_dev *xdna = ctx->client->xdna;
	int ret;

	if (!ctx->cus)
		return -EINVAL;

	mutex_lock(&xdna->dev_handle->aie2_lock);
	ret = aie2_hwctx_start(ctx);
	if (ret)
		goto unlock_and_err;

#ifdef AMDXDNA_DEVEL
	if (priv_load) {
		ret = aie2_legacy_config_cu(ctx);
		if (ret) {
			XDNA_ERR(xdna, "Legacy config cu failed, ret %d", ret);
			goto failed;
		}
		goto skip_config_cu;
	}
#endif
	ret = aie2_config_cu(ctx);
	if (ret) {
		XDNA_ERR(xdna, "Config cu failed, ret %d", ret);
		goto failed;
	}
#ifdef AMDXDNA_DEVEL
skip_config_cu:
#endif
	mutex_unlock(&xdna->dev_handle->aie2_lock);
	return 0;

failed:
	aie2_hwctx_stop(ctx);
unlock_and_err:
	mutex_unlock(&xdna->dev_handle->aie2_lock);
	return ret;
}

static void
aie2_sched_notify(struct amdxdna_sched_job *job)
{
	struct amdxdna_ctx *ctx = job->ctx;
	struct dma_fence *fence = job->fence;
	int idx;

#ifdef AMDXDNA_DRM_USAGE
	amdxdna_update_stats(ctx->client, ktime_get(), false);
#endif
	ctx->completed++;
	trace_xdna_job(&job->base, ctx->name, "signaling fence", job->seq, job->opcode);
	job->job_done = true;
	dma_fence_signal(fence);
	aie2_rq_yield(ctx);
	idx = get_job_idx(job->seq);
	ctx->priv->pending[idx] = NULL;
	up(&job->ctx->priv->job_sem);
	dma_fence_put(fence);
	mmput_async(job->mm);
	aie2_job_put(job);
}

static int
aie2_sched_resp_handler(void *handle, void __iomem *data, size_t size)
{
	struct amdxdna_sched_job *job = handle;
	struct amdxdna_gem_obj *cmd_abo;
	u32 ret = 0;
	u32 status;

	cmd_abo = job->cmd_bo;

	if (unlikely(!data))
		goto out;

	if (unlikely(size != sizeof(u32))) {
		amdxdna_cmd_set_state(cmd_abo, ERT_CMD_STATE_ABORT);
		ret = -EINVAL;
		goto out;
	}

	status = readl(data);
	XDNA_DBG(job->ctx->client->xdna, "Response status 0x%x", status);
	if (status == AIE2_STATUS_SUCCESS)
		amdxdna_cmd_set_state(cmd_abo, ERT_CMD_STATE_COMPLETED);
	else
		amdxdna_cmd_set_state(cmd_abo, ERT_CMD_STATE_ERROR);

out:
	aie2_sched_notify(job);
	return ret;
}

static int
aie2_sched_nocmd_resp_handler(void *handle, void __iomem *data, size_t size)
{
	struct amdxdna_sched_job *job = handle;
	u32 ret = 0;
	u32 status;

	if (unlikely(!data))
		goto out;

	if (unlikely(size != sizeof(u32))) {
		ret = -EINVAL;
		goto out;
	}

	status = readl(data);
	XDNA_DBG(job->ctx->client->xdna, "Response status 0x%x", status);

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
	u32 fail_cmd_status;
	u32 fail_cmd_idx;
	u32 cmd_status;
	u32 ret = 0;

	cmd_abo = job->cmd_bo;
	if (unlikely(!data) || unlikely(size != sizeof(u32) * 3)) {
		amdxdna_cmd_set_state(cmd_abo, ERT_CMD_STATE_ABORT);
		ret = -EINVAL;
		goto out;
	}

	cmd_status = readl(data + offsetof(struct cmd_chain_resp, status));
	xdna = job->ctx->client->xdna;
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
		amdxdna_cmd_set_state(cmd_abo, ERT_CMD_STATE_ABORT);
		ret = -EINVAL;
		goto out;
	}
	amdxdna_cmd_set_state(cmd_abo, fail_cmd_status);

	if (amdxdna_cmd_get_op(cmd_abo) == ERT_CMD_CHAIN) {
		struct amdxdna_cmd_chain *cc = amdxdna_cmd_get_payload(cmd_abo, NULL);

		cc->error_index = fail_cmd_idx;
		if (cc->error_index >= cc->command_count)
			cc->error_index = 0;
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
	struct amdxdna_ctx *ctx = job->ctx;
	struct dma_fence *fence;
	int ret = 0;

	trace_xdna_job(sched_job, ctx->name, "job run", job->seq, job->opcode);

	if (!mmget_not_zero(job->mm))
		return ERR_PTR(-ESRCH);

	kref_get(&job->refcnt);
	fence = dma_fence_get(job->fence);

	switch (job->opcode) {
	case OP_SYNC_BO:
		ret = aie2_sync_bo(ctx, job, aie2_sched_nocmd_resp_handler);
		goto out;
	case OP_REG_DEBUG_BO:
	case OP_UNREG_DEBUG_BO:
		ret = aie2_config_debug_bo(ctx, job, aie2_sched_nocmd_resp_handler);
		goto out;
	case OP_NOOP:
		// Call notify since we did not really send it down
		aie2_sched_notify(job);
		goto out;
	}

	if (amdxdna_cmd_get_op(cmd_abo) == ERT_CMD_CHAIN)
		ret = aie2_cmdlist_multi_execbuf(ctx, job, aie2_sched_cmdlist_resp_handler);
	else if (force_cmdlist)
		ret = aie2_cmdlist_single_execbuf(ctx, job, aie2_sched_cmdlist_resp_handler);
	else
		ret = aie2_execbuf(ctx, job, aie2_sched_resp_handler);

out:
	if (ret) {
		dma_fence_put(job->fence);
		aie2_job_put(job);
		mmput(job->mm);
		fence = ERR_PTR(ret);
	}
#ifdef AMDXDNA_DRM_USAGE
	else
		amdxdna_update_stats(ctx->client, ktime_get(), true);
#endif

	return fence;
}

static void aie2_sched_job_free(struct drm_sched_job *sched_job)
{
	struct amdxdna_sched_job *job = drm_job_to_xdna_job(sched_job);
	struct amdxdna_ctx *ctx = job->ctx;

	trace_xdna_job(sched_job, ctx->name, "job free", job->seq, job->opcode);
	if (!job->job_done) {
		int idx;

		idx = get_job_idx(job->seq);
		/* No contention with submit, no lock */
		ctx->priv->pending[idx] = NULL;
		up(&ctx->priv->job_sem);
	}

	drm_sched_job_cleanup(sched_job);
	aie2_job_put(job);
}

const struct drm_sched_backend_ops sched_ops = {
	.run_job = aie2_sched_job_run,
	.free_job = aie2_sched_job_free,
};

static int aie2_ctx_syncobj_create(struct amdxdna_ctx *ctx)
{
	struct drm_syncobj *syncobj;
	struct amdxdna_dev *xdna;
	struct drm_file *filp;
	u32 hdl;
	int ret;

	xdna = ctx->client->xdna;
	filp = ctx->client->filp;
	ctx->priv->syncobj = NULL;
	ctx->syncobj_hdl = AMDXDNA_INVALID_FENCE_HANDLE;

	ret = drm_syncobj_create(&syncobj, 0, NULL);
	if (ret) {
		XDNA_ERR(xdna, "Create ctx syncobj failed, ret %d", ret);
		return ret;
	}
	ret = drm_syncobj_get_handle(filp, syncobj, &hdl);
	if (ret) {
		drm_syncobj_put(syncobj);
		XDNA_ERR(xdna, "Create ctx syncobj handle failed, ret %d", ret);
		return ret;
	}
	ctx->priv->syncobj = syncobj;
	ctx->syncobj_hdl = hdl;

	return 0;
}

static void aie2_ctx_syncobj_destroy(struct amdxdna_ctx *ctx)
{
	/*
	 * The syncobj_hdl is owned by user space and will be cleaned up
	 * separately.
	 */
	drm_syncobj_put(ctx->priv->syncobj);
}

static int aie2_ctx_col_list(struct amdxdna_ctx *ctx)
{
	struct amdxdna_dev *xdna = ctx->client->xdna;
	struct amdxdna_dev_hdl *ndev;
	int start, end, first, last;
	u32 width = 1, entries = 0;
	int i;

	if (!ctx->num_tiles) {
		XDNA_ERR(xdna, "Number of tiles is zero");
		return -EINVAL;
	}

	ndev = xdna->dev_handle;
	if (unlikely(!ndev->metadata.core.row_count)) {
		XDNA_WARN(xdna, "Core tile row count is zero");
		return -EINVAL;
	}

	ctx->num_col = ctx->num_tiles / ndev->metadata.core.row_count;
	if (!ctx->num_col || ctx->num_col > ndev->total_col) {
		XDNA_ERR(xdna, "Invalid num_col %d", ctx->num_col);
		return -EINVAL;
	}

	if (ndev->priv->col_align == COL_ALIGN_NATURE)
		width = ctx->num_col;

#ifdef AMDXDNA_DEVEL
	if (start_col_index >= 0) {
		if (start_col_index + ctx->num_col > ndev->total_col) {
			XDNA_ERR(xdna, "Invalid start_col_index %d, num col %d",
				 start_col_index, ctx->num_col);
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
	end =  ndev->total_col - ctx->num_col;
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
	ctx->col_list = kmalloc_array(entries, sizeof(*ctx->col_list), GFP_KERNEL);
	if (!ctx->col_list)
		return -ENOMEM;

	ctx->col_list_len = entries;
	ctx->col_list[0] = first;
	for (i = 1; i < entries; i++)
		ctx->col_list[i] = ctx->col_list[i - 1] + width;

	print_hex_dump_debug("col_list: ", DUMP_PREFIX_OFFSET, 16, 4, ctx->col_list,
			     entries * sizeof(*ctx->col_list), false);
	return 0;
}

int aie2_ctx_init(struct amdxdna_ctx *ctx)
{
	struct amdxdna_client *client = ctx->client;
	struct amdxdna_dev *xdna = client->xdna;
	struct amdxdna_ctx_priv *priv;
	struct amdxdna_gem_obj *heap;
	unsigned int wq_flags;
	int i, ret;

	priv = kzalloc(sizeof(*ctx->priv), GFP_KERNEL);
	if (!priv)
		return -ENOMEM;
	ctx->priv = priv;

	ret = aie2_ctx_col_list(ctx);
	if (ret) {
		XDNA_ERR(xdna, "Create col list failed, ret %d", ret);
		goto free_priv;
	}

	mutex_lock(&client->mm_lock);
	heap = client->dev_heap;
	if (!heap) {
		XDNA_ERR(xdna, "The client dev heap object not exist");
		mutex_unlock(&client->mm_lock);
		ret = -ENOENT;
		goto free_col_list;
	}
	drm_gem_object_get(to_gobj(heap));
	mutex_unlock(&client->mm_lock);
	priv->heap = heap;
	sema_init(&priv->job_sem, CTX_MAX_CMDS);

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

		abo = amdxdna_drm_create_dev_bo(&xdna->ddev, &args, client->filp);
		if (IS_ERR(abo)) {
			ret = PTR_ERR(abo);
			goto free_cmd_bufs;
		}

		XDNA_DBG(xdna, "Command buf %d addr 0x%llx size 0x%lx",
			 i, abo->mem.dev_addr, abo->mem.size);
		priv->cmd_buf[i] = abo;
	}

	mutex_init(&priv->io_lock);
	init_waitqueue_head(&priv->job_free_waitq);

	fs_reclaim_acquire(GFP_KERNEL);
	might_lock(&priv->io_lock);
	fs_reclaim_release(GFP_KERNEL);

	wq_flags = __WQ_ORDERED;
	if (!aie2_pm_is_turbo(xdna->dev_handle))
		wq_flags |= WQ_UNBOUND;
	priv->submit_wq = alloc_workqueue(ctx->name, wq_flags, 1);
	if (!priv->submit_wq) {
		XDNA_ERR(xdna, "Failed to alloc submit wq");
		goto free_cmd_bufs;
	}

	ret = aie2_ctx_syncobj_create(ctx);
	if (ret) {
		XDNA_ERR(xdna, "Create syncobj failed, ret %d", ret);
		goto free_wq;
	}

	ret = aie2_rq_add(&xdna->dev_handle->ctx_rq, ctx);
	if (ret) {
		XDNA_ERR(xdna, "Add ctx %s failed, ret %d", ctx->name, ret);
		goto destroy_syncobj;
	}
	init_rwsem(&priv->io_sem);
	atomic64_set(&priv->job_pending_cnt, 0);
	init_waitqueue_head(&priv->connect_waitq);

	XDNA_DBG(xdna, "ctx %s init completed", ctx->name);
	return 0;

destroy_syncobj:
	aie2_ctx_syncobj_destroy(ctx);
free_wq:
	destroy_workqueue(priv->submit_wq);
free_cmd_bufs:
	for (i = 0; i < ARRAY_SIZE(priv->cmd_buf); i++) {
		if (!priv->cmd_buf[i])
			continue;
		drm_gem_object_put(to_gobj(priv->cmd_buf[i]));
	}
	amdxdna_gem_unpin(heap);
put_heap:
	drm_gem_object_put(to_gobj(heap));
free_col_list:
	kfree(ctx->col_list);
free_priv:
	kfree(priv);
	return ret;
}

void aie2_ctx_fini(struct amdxdna_ctx *ctx)
{
	struct amdxdna_dev *xdna = ctx->client->xdna;
	int idx;

	aie2_rq_del(&xdna->dev_handle->ctx_rq, ctx);

	destroy_workqueue(ctx->priv->submit_wq);
	aie2_ctx_syncobj_destroy(ctx);
	for (idx = 0; idx < ARRAY_SIZE(ctx->priv->cmd_buf); idx++)
		drm_gem_object_put(to_gobj(ctx->priv->cmd_buf[idx]));
	amdxdna_gem_unpin(ctx->priv->heap);
	drm_gem_object_put(to_gobj(ctx->priv->heap));
#ifdef AMDXDNA_DEVEL
	if (priv_load) {
		mutex_lock(&xdna->dev_handle->aie2_lock);
		aie2_unregister_pdis(ctx);
		mutex_unlock(&xdna->dev_handle->aie2_lock);
	}
#endif

	XDNA_DBG(xdna, "%s total completed jobs %lld",
		 ctx->name, ctx->completed);
	mutex_destroy(&ctx->priv->io_lock);
	kfree(ctx->col_list);
	kfree(ctx->priv);
	kfree(ctx->cus);
}

static int aie2_ctx_cu_config(struct amdxdna_ctx *ctx, void *buf, u32 size)
{
	struct amdxdna_ctx_param_config_cu *config = buf;
	struct amdxdna_dev *xdna = ctx->client->xdna;
	u32 total_size;
	int ret;

	XDNA_DBG(xdna, "Config %d CU to %s", config->num_cus, ctx->name);
	if (ctx->cus) {
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

	ctx->cus = kmemdup(config, total_size, GFP_KERNEL);
	if (!ctx->cus)
		return -ENOMEM;

#ifdef AMDXDNA_DEVEL
	if (priv_load) {
		mutex_lock(&xdna->dev_handle->aie2_lock);
		ret = aie2_register_pdis(ctx);
		mutex_unlock(&xdna->dev_handle->aie2_lock);
		if (ret) {
			XDNA_ERR(xdna, "Register PDIs failed, ret %d", ret);
			goto free_cus;
		}
	}
#endif
	return 0;

free_cus:
	kfree(ctx->cus);
	ctx->cus = NULL;
	return ret;
}

static int aie2_ctx_attach_debug_bo(struct amdxdna_ctx *ctx, u32 bo_hdl)
{
	struct amdxdna_client *client = ctx->client;
	struct amdxdna_dev *xdna = client->xdna;
	struct amdxdna_gem_obj *abo;
	u64 seq;
	int ret;

	abo = amdxdna_gem_get_obj(client, bo_hdl, AMDXDNA_BO_DEV);
	if (!abo) {
		XDNA_ERR(xdna, "Get bo %d failed", bo_hdl);
		ret = -EINVAL;
		goto err_out;
	}

	ret = amdxdna_gem_set_assigned_ctx(client, bo_hdl, ctx->id);
	if (ret) {
		XDNA_ERR(xdna, "Failed to attach debug BO %d to %s: %d", bo_hdl, ctx->name, ret);
		goto put_obj;
	}

	ret = amdxdna_cmd_submit(client, OP_REG_DEBUG_BO, AMDXDNA_INVALID_BO_HANDLE,
				 &bo_hdl, 1, NULL, NULL, 0, ctx->id, &seq);
	if (ret) {
		XDNA_ERR(xdna, "Submit command failed");
		goto clear_ctx;
	}

	ret = amdxdna_cmd_wait(client, ctx->id, seq, 3000 /* ms */);
	if (ret)
		goto clear_ctx;
	XDNA_DBG(xdna, "Attached debug BO %d to %s", bo_hdl, ctx->name);
	amdxdna_gem_put_obj(abo);
	return 0;

clear_ctx:
	amdxdna_gem_clear_assigned_ctx(client, bo_hdl);
put_obj:
	amdxdna_gem_put_obj(abo);
err_out:
	return ret;
}

static int aie2_ctx_detach_debug_bo(struct amdxdna_ctx *ctx, u32 bo_hdl)
{
	struct amdxdna_client *client = ctx->client;
	struct amdxdna_dev *xdna = client->xdna;
	u64 seq;
	int ret;

	if (amdxdna_gem_get_assigned_ctx(client, bo_hdl) != ctx->id) {
		XDNA_ERR(xdna, "Debug BO %d isn't attached to %s", bo_hdl, ctx->name);
		return -EINVAL;
	}

	amdxdna_gem_clear_assigned_ctx(client, bo_hdl);

	ret = amdxdna_cmd_submit(client, OP_UNREG_DEBUG_BO, AMDXDNA_INVALID_BO_HANDLE,
				 &bo_hdl, 1, NULL, NULL, 0, ctx->id, &seq);
	if (unlikely(ret)) {
		XDNA_ERR(xdna, "Submit command failed");
		return ret;
	}

	ret = amdxdna_cmd_wait(client, ctx->id, seq, 3000 /* ms */);
	XDNA_DBG(xdna, "Detached debug BO %d from %s, ret %d", bo_hdl, ctx->name, ret);
	return ret;
}

int aie2_ctx_config(struct amdxdna_ctx *ctx, u32 type, u64 value, void *buf, u32 size)
{
	struct amdxdna_dev *xdna = ctx->client->xdna;

	switch (type) {
	case DRM_AMDXDNA_CTX_CONFIG_CU:
		return aie2_ctx_cu_config(ctx, buf, size);
	case DRM_AMDXDNA_CTX_ASSIGN_DBG_BUF:
		return aie2_ctx_attach_debug_bo(ctx, (u32)value);
	case DRM_AMDXDNA_CTX_REMOVE_DBG_BUF:
		return aie2_ctx_detach_debug_bo(ctx, (u32)value);
	default:
		XDNA_DBG(xdna, "Not supported type %d", type);
		return -EOPNOTSUPP;
	}
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

static int aie2_add_job_dependency(struct amdxdna_sched_job *job, u32 *syncobj_hdls,
				   u64 *syncobj_points, u32 syncobj_cnt)
{
	struct amdxdna_client *client = job->ctx->client;
	int ret = 0;
	u32 hdl;
	u64 pt;
	int i;

	for (i = 0; ret == 0 && i < syncobj_cnt; i++) {
		hdl = syncobj_hdls[i];
		pt = syncobj_points[i];
		ret = drm_sched_job_add_syncobj_dependency(&job->base, client->filp, hdl, pt);
		if (ret) {
			XDNA_ERR(client->xdna,
				 "Failed to add syncobj (%d@%lld) as dependency, ret %d",
				 hdl, pt, ret);
		}
	}
	return ret;
}

int aie2_cmd_submit(struct amdxdna_ctx *ctx, struct amdxdna_sched_job *job,
		    u32 *syncobj_hdls, u64 *syncobj_points, u32 syncobj_cnt, u64 *seq)
{
	struct amdxdna_dev *xdna = ctx->client->xdna;
	struct ww_acquire_ctx acquire_ctx;
	struct dma_fence_chain *chain;
	struct amdxdna_gem_obj *abo;
	unsigned long timeout = 0;
	int ret, i;

	ret = down_interruptible(&ctx->priv->job_sem);
	if (ret) {
		XDNA_ERR(xdna, "Grab job sem failed, ret %d", ret);
		return ret;
	}

	ret = aie2_rq_submit_enter(&xdna->dev_handle->ctx_rq, ctx);
	if (ret) {
		XDNA_ERR(xdna, "Submit enter failed, ret %d", ret);
		goto up_job_sem;
	}

	chain = dma_fence_chain_alloc();
	if (!chain) {
		ret = -ENOMEM;
		goto rq_yield;
	}

	ret = drm_sched_job_init(&job->base, &ctx->priv->entity, 1, ctx);
	if (ret) {
		XDNA_ERR(xdna, "DRM job init failed, ret %d", ret);
		goto free_chain;
	}

	ret = aie2_add_job_dependency(job, syncobj_hdls, syncobj_points, syncobj_cnt);
	if (ret) {
		XDNA_ERR(xdna, "Failed to add dependency, ret %d", ret);
		goto cleanup_job;
	}

retry:
	ret = amdxdna_lock_objects(job, &acquire_ctx);
	if (ret) {
		XDNA_WARN(xdna, "Failed to lock objects, ret %d", ret);
		goto cleanup_job;
	}

	for (i = 0; i < job->bo_cnt; i++) {
		ret = dma_resv_reserve_fences(job->bos[i].obj->resv, 1);
		if (ret) {
			XDNA_WARN(xdna, "Failed to reserve fences %d", ret);
			amdxdna_unlock_objects(job, &acquire_ctx);
			goto cleanup_job;
		}
	}

	down_read(&xdna->notifier_lock);
	for (i = 0; i < job->bo_cnt; i++) {
		abo = to_xdna_obj(job->bos[i].obj);
		if (abo->mem.map_invalid) {
			up_read(&xdna->notifier_lock);
			amdxdna_unlock_objects(job, &acquire_ctx);
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

	mutex_lock(&ctx->priv->io_lock);
	drm_sched_job_arm(&job->base);
	job->out_fence = dma_fence_get(&job->base.s_fence->finished);
	for (i = 0; i < job->bo_cnt; i++)
		dma_resv_add_fence(job->bos[i].obj->resv, job->out_fence, DMA_RESV_USAGE_WRITE);
	job->seq = ctx->submitted++;
	ctx->priv->pending[get_job_idx(job->seq)] = job;
	kref_get(&job->refcnt);
	drm_sched_entity_push_job(&job->base);

	*seq = job->seq;
	drm_syncobj_add_point(ctx->priv->syncobj, chain, job->out_fence, *seq);
	mutex_unlock(&ctx->priv->io_lock);

	up_read(&xdna->notifier_lock);
	amdxdna_unlock_objects(job, &acquire_ctx);
	aie2_rq_submit_exit(ctx);

	aie2_job_put(job);

	return 0;

cleanup_job:
	drm_sched_job_cleanup(&job->base);
free_chain:
	dma_fence_chain_free(chain);
rq_yield:
	aie2_rq_yield(ctx);
	aie2_rq_submit_exit(ctx);
up_job_sem:
	up(&ctx->priv->job_sem);
	job->job_done = true;
	return ret;
}

struct dma_fence *aie2_cmd_get_out_fence(struct amdxdna_ctx *ctx, u64 seq)
{
	struct dma_fence *fence, *out_fence = NULL;
	int ret;

	fence = drm_syncobj_fence_get(ctx->priv->syncobj);
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

int aie2_cmd_wait(struct amdxdna_ctx *ctx, u64 seq, u32 timeout)
{
	struct dma_fence *out_fence = aie2_cmd_get_out_fence(ctx, seq);
	signed long remaining = MAX_SCHEDULE_TIMEOUT;
	long ret;

	if (timeout)
		remaining = msecs_to_jiffies(timeout);
	ret = dma_fence_wait_timeout(out_fence, true, remaining);
	if (!ret)
		ret = -ETIME;
	else if (ret > 0)
		ret = 0;
	dma_fence_put(out_fence);
	return ret;
}

void aie2_hmm_invalidate(struct amdxdna_gem_obj *abo, unsigned long cur_seq)
{
	struct amdxdna_dev *xdna = to_xdna_dev(to_gobj(abo)->dev);
	struct drm_gem_object *gobj = to_gobj(abo);
	long ret;

	ret = dma_resv_wait_timeout(gobj->resv, DMA_RESV_USAGE_BOOKKEEP,
				    true, MAX_SCHEDULE_TIMEOUT);
	if (!ret || ret == -ERESTARTSYS)
		XDNA_ERR(xdna, "Failed to wait for bo, ret %ld", ret);
}

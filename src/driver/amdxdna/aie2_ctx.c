// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2024-2026, Advanced Micro Devices, Inc.
 */

#include <linux/timekeeping.h>
#include <drm/drm_syncobj.h>
#include <drm/drm_cache.h>

#include "amdxdna_ctx.h"
#include "amdxdna_gem.h"
#include "amdxdna_pm.h"
#include "amdxdna_trace.h"
#include "aie2_pci.h"
#include "aie2_msg_priv.h"

bool force_cmdlist = true;
module_param(force_cmdlist, bool, 0600);
MODULE_PARM_DESC(force_cmdlist, "Force use command list (Default true)");

static void aie2_job_release(struct kref *ref)
{
	struct amdxdna_sched_job *job;
	struct amdxdna_ctx *ctx;

	job = container_of(ref, struct amdxdna_sched_job, refcnt);
	ctx = job->ctx;
	amdxdna_sched_job_cleanup(job);
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

void aie2_dump_ctx(struct amdxdna_ctx *ctx)
{
	struct amdxdna_dev *xdna = ctx->client->xdna;
	struct amdxdna_mgmt_dma_hdl *dma_hdl;
	struct amdxdna_dev_hdl *ndev;
	struct app_health_report *r;
	u64 comp = ctx->completed;
	u64 sub = ctx->submitted;
	size_t size;
	int ret;

	ndev = xdna->dev_handle;
	XDNA_ERR(xdna, "Dumping ctx %s, hwctx %d, sub=%lld, comp=%lld",
		 ctx->name, ctx->priv->id, sub, comp);
	size = max_t(size_t, sizeof(*r), SZ_8K);
	dma_hdl = amdxdna_mgmt_buff_alloc(xdna, size, DMA_FROM_DEVICE);
	if (IS_ERR(dma_hdl)) {
		XDNA_WARN(xdna, "Allocate memory failed, skip get app health");
		return;
	}

	amdxdna_mgmt_buff_clflush(dma_hdl, 0, 0);
	mutex_lock(&ndev->aie2_lock);
	ret = aie2_get_app_health(ndev, dma_hdl, ctx->priv->id, size);
	mutex_unlock(&ndev->aie2_lock);
	if (!ret) {
		r = amdxdna_mgmt_buff_get_cpu_addr(dma_hdl, 0);

		print_hex_dump_debug("raw_report: ", DUMP_PREFIX_OFFSET, 16, 4, r, size, false);

		XDNA_ERR(xdna, "Firmware timeout state capture:");
		XDNA_ERR(xdna, "\tVersion: %d.%d", r->major, r->minor);
		XDNA_ERR(xdna, "\tReport size: 0x%x", r->size);
		XDNA_ERR(xdna, "\tContext ID: %d", r->context_id);
		XDNA_ERR(xdna, "\tDPU PC: 0x%x", r->dpu_pc);
		XDNA_ERR(xdna, "\tTXN OP ID: 0x%x", r->txn_op_id);
		XDNA_ERR(xdna, "\tContext PC: 0x%x", r->ctx_pc);
		XDNA_ERR(xdna, "\tFatal error type: 0x%x", r->fatal_info.fatal_type);
		XDNA_ERR(xdna, "\tFatal error exception type: 0x%x", r->fatal_info.exception_type);
		XDNA_ERR(xdna, "\tFatal error exception PC: 0x%x", r->fatal_info.exception_pc);
		XDNA_ERR(xdna, "\tFatal error app module: 0x%x", r->fatal_info.app_module);
		XDNA_ERR(xdna, "\tFatal error task ID: %d", r->fatal_info.task_index);

		ctx->health_data.version = AMDXDNA_CTX_HEALTH_DATA_V1;
		ctx->health_data.npu_gen = AMDXDNA_NPU_GEN_AIE2;
		ctx->health_data.aie2.fatal_error_exception_type = r->fatal_info.exception_type;
		ctx->health_data.aie2.fatal_error_exception_pc = r->fatal_info.exception_pc;
		ctx->health_data.aie2.fatal_error_app_module = r->fatal_info.app_module;
		ctx->health_data.aie2.fatal_error_type = r->fatal_info.fatal_type;
		ctx->health_data.aie2.txn_op_idx = r->txn_op_id;
		ctx->health_data.aie2.ctx_pc = r->ctx_pc;
		ctx->health_reported = false;
	}
	amdxdna_mgmt_buff_free(dma_hdl);

	mutex_lock(&ctx->io_lock);
	for (int i = 0; i < CTX_MAX_CMDS; i++) {
		struct amdxdna_sched_job *j;

		j = ctx->priv->pending[i];
		if (!j)
			continue;
		XDNA_ERR(xdna, "JOB[%d]:", i);
		XDNA_ERR(xdna, "\tseq: %lld", j->seq);
		XDNA_ERR(xdna, "\top: 0x%x", amdxdna_cmd_get_op(j->cmd_bo));
		XDNA_ERR(xdna, "\tmsg: 0x%x", j->msg_id);
		XDNA_ERR(xdna, "\tfence: %s", aie2_fence_state2str(j->fence));
		XDNA_ERR(xdna, "\tout_fence: %s", aie2_fence_state2str(j->out_fence));
	}
	mutex_unlock(&ctx->io_lock);
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
	ctx->priv->disconn_cnt++;
	mutex_unlock(&xdna->dev_handle->aie2_lock);
}

int aie2_ctx_connect(struct amdxdna_ctx *ctx)
{
	struct amdxdna_dev *xdna = ctx->client->xdna;
	int ret;

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
aie2_ctx_cmd_health_data(struct amdxdna_ctx *ctx, struct amdxdna_gem_obj *cmd_abo)
{
	void *cmd_data;
	u32 data_total;

	if (ctx->health_reported) {
		amdxdna_cmd_set_state(cmd_abo, ERT_CMD_STATE_ABORT);
		return;
	}

	cmd_data = amdxdna_cmd_get_data(cmd_abo, &data_total);
	if (unlikely(data_total < sizeof(ctx->health_data)))
		XDNA_WARN(ctx->client->xdna, "Large health data, truncated");

	data_total = min(data_total, sizeof(ctx->health_data));
	memcpy(cmd_data, &ctx->health_data, data_total);
	ctx->health_reported = true;

	amdxdna_cmd_set_state(cmd_abo, ERT_CMD_STATE_TIMEOUT);
}

static void
reset_tdr_timer(struct amdxdna_sched_job *job)
{
	struct amdxdna_ctx *ctx = job->ctx;
	struct amdxdna_dev_hdl *ndev = ctx->client->xdna->dev_handle;

	WRITE_ONCE(ndev->tdr.status, AIE2_TDR_SIGNALED);
}

static void
aie2_sched_notify(struct amdxdna_sched_job *job)
{
	struct amdxdna_ctx *ctx = job->ctx;
	int idx;

	amdxdna_pm_suspend_put(ctx->client->xdna);

	ctx->completed++;
	reset_tdr_timer(job);
	trace_xdna_job(&job->base, ctx->name, "signaling fence", job->seq, job->opcode);
	job->state = JOB_STATE_DONE;
	dma_fence_signal(job->fence);
	aie2_rq_yield(ctx);
	idx = get_job_idx(job->seq);
	ctx->priv->pending[idx] = NULL;
	up(&job->ctx->priv->job_sem);
	dma_fence_put(job->fence);
	job->fence = NULL;
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

	amdxdna_stats_account(job->ctx->client);
	cmd_abo = job->cmd_bo;

	if (unlikely(!data)) {
		aie2_ctx_cmd_health_data(job->ctx, cmd_abo);
		goto out;
	}

	if (unlikely(size != sizeof(u32))) {
		XDNA_WARN(job->ctx->client->xdna, "Abort cmd");
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

	amdxdna_stats_account(job->ctx->client);
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

	amdxdna_stats_account(job->ctx->client);
	xdna = job->ctx->client->xdna;
	cmd_abo = job->cmd_bo;
	if (unlikely(!data)) {
		if (amdxdna_cmd_get_op(cmd_abo) == ERT_CMD_CHAIN) {
			struct amdxdna_cmd_chain *cc = amdxdna_cmd_get_payload(cmd_abo, NULL);
			struct amdxdna_gem_obj *abo;
			u32 boh = cc->data[0];

			/*
			 * In the async callback/timeout case, driver sets the error index to 0,
			 * state to timeout, and dump the app health in the first subcmd BO.
			 */
			cc->error_index = 0;
			amdxdna_cmd_set_state(cmd_abo, ERT_CMD_STATE_TIMEOUT);
			abo = amdxdna_gem_get_obj(job->ctx->client, boh, AMDXDNA_BO_SHARE);
			if (!abo) {
				XDNA_ERR(xdna, "Failed to find cmd BO %d", boh);
				ret = -ENOENT;
				goto out;
			}
			amdxdna_cmd_set_state(abo, ERT_CMD_STATE_TIMEOUT);
			aie2_ctx_cmd_health_data(job->ctx, abo);
			amdxdna_gem_put_obj(abo);
		} else {
			/* Forced command chaining */
			aie2_ctx_cmd_health_data(job->ctx, cmd_abo);
		}
		ret = -EINVAL;
		goto out;
	}

	if (unlikely(size != sizeof(u32) * 3)) {
		amdxdna_cmd_set_state(cmd_abo, ERT_CMD_STATE_ABORT);
		ret = -EINVAL;
		goto out;
	}

	cmd_status = readl(data + offsetof(struct cmd_chain_resp, status));
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

	/*
	 * The firmware may error out even before it starts processing subcmds in the cmdlist.
	 * In such scenarios, the subcmd status returns with an uninitialized value of 0 i.e
	 * AIE2_STATUS_SUCCESS.
	 */
	if (fail_cmd_status == AIE2_STATUS_SUCCESS) {
		amdxdna_cmd_set_state(cmd_abo, ERT_CMD_STATE_ABORT);
		ret = -EINVAL;
		goto out;
	}
	amdxdna_cmd_set_state(cmd_abo, ERT_CMD_STATE_ERROR);

	if (amdxdna_cmd_get_op(cmd_abo) == ERT_CMD_CHAIN) {
		struct amdxdna_cmd_chain *cc = amdxdna_cmd_get_payload(cmd_abo, NULL);

		if (cc) {
			/*
			 * In the sync callback/command error case, driver only sets the
			 * error index to the index of the failing subcmd. It is the
			 * responsibility of XRT core to set the subcmd BO states to
			 * appropriate values.
			 */
			cc->error_index = fail_cmd_idx;
			if (cc->error_index >= cc->command_count)
				cc->error_index = 0;
		}
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
	int ret;

	trace_xdna_job(sched_job, ctx->name, "job run", job->seq, job->opcode);

	if (!mmget_not_zero(job->mm))
		return ERR_PTR(-ESRCH);

	ret = amdxdna_pm_resume_get(ctx->client->xdna);
	if (ret) {
		mmput(job->mm);
		return ERR_PTR(ret);
	}

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

	/*
	 * Transaction binaries are only supported with RAI 1.5 release onwards. Below
	 * implementation returns -EOPNOTSUPP error code for any older firmware versions.
	 */
	amdxdna_cmd_set_state(cmd_abo, ERT_CMD_STATE_NEW);

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
		amdxdna_pm_suspend_put(ctx->client->xdna);
	} else {
		if (job->opcode != OP_NOOP)
			amdxdna_stats_start(ctx->client);
	}

	return fence;
}

static void aie2_sched_job_free(struct drm_sched_job *sched_job)
{
	struct amdxdna_sched_job *job = drm_job_to_xdna_job(sched_job);
	struct amdxdna_ctx *ctx = job->ctx;

	trace_xdna_job(sched_job, ctx->name, "job free", job->seq, job->opcode);
	if (job->state != JOB_STATE_DONE) {
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

static bool is_valid_qos_dpm_params(struct amdxdna_qos_info *qos)
{
	/*
	 * gops is retrieved from the xmodel, so it's always set
	 * fps and latency are the configurable params from the application
	 */
	if (qos->gops > 0 && (qos->fps > 0 || qos->latency > 0))
		return true;

	return false;
}

static u32 capable_gops(u32 opc, u32 clk_mhz)
{
	return opc * clk_mhz / 1000;
}

static inline u32 request_gops(u32 gopw, u32 wps, u32 latency_ms, u32 factor)
{
	if (latency_ms)
		return gopw * max(wps, 1000 / latency_ms) * factor;
	else
		return gopw * wps * factor;
}

static void aie2_calc_ctx_dpm(struct amdxdna_dev_hdl *ndev, struct amdxdna_ctx *ctx)
{
	struct amdxdna_qos_info *qos = &ctx->qos;
	u32 req_gops;
	u32 level;

	if (!is_valid_qos_dpm_params(qos)) {
		XDNA_DBG(ndev->xdna, "Invalid QoS gops %d fps %d latency %d",
			 qos->gops, qos->fps, qos->latency);

		if (qos->priority == AMDXDNA_QOS_LOW_PRIORITY)
			ctx->priv->req_dpm_level =  0;
		else
			ctx->priv->req_dpm_level = ndev->max_dpm_level;
		return;
	}

	if (qos->priority == AMDXDNA_QOS_LOW_PRIORITY) {
		XDNA_DBG(ndev->xdna, "%s priority is %d, use DPM level 0",
			 ctx->name, qos->priority);
		ctx->priv->req_dpm_level =  0;
		return;
	}

	req_gops = request_gops(qos->gops, qos->fps, qos->latency,
				ndev->sys_eff_factor);
	if (!req_gops) {
		XDNA_WARN(ndev->xdna, "%s GOPS is zero, use max DPM level", ctx->name);
		ctx->priv->req_dpm_level = ndev->max_dpm_level;
		return;
	}

	/*
	 * Try to find a DPM level that can provide enough GOPS.
	 * If not able to find, use max_dpm_level.
	 */
	for (level = 0; level <= ndev->max_dpm_level; level++) {
		u32 clk_mhz, cap_gops;

		clk_mhz = ndev->priv->dpm_clk_tbl[level].hclk;
		cap_gops = capable_gops(ctx->max_opc, clk_mhz);
		if (req_gops <= cap_gops)
			break;
	}

	if (level > ndev->max_dpm_level) {
		XDNA_WARN(ndev->xdna, "%s GOPS too large, use max DPM level", ctx->name);
		level = ndev->max_dpm_level;
	}
	ctx->priv->req_dpm_level = level;
}

int aie2_ctx_init(struct amdxdna_ctx *ctx)
{
	struct amdxdna_client *client = ctx->client;
	struct amdxdna_dev *xdna = client->xdna;
	struct amdxdna_ctx_priv *priv;
	struct amdxdna_gem_obj *heap;
	struct amdxdna_dev_hdl *ndev;
	int i, ret;

	if (!ctx->num_tiles) {
		XDNA_ERR(xdna, "Number of tiles is zero");
		return -EINVAL;
	}

	ndev = xdna->dev_handle;
	if (unlikely(!ndev->metadata.core.row_count)) {
		XDNA_WARN(xdna, "Core tile row count is zero");
		return -EINVAL;
	}

	priv = kzalloc(sizeof(*ctx->priv), GFP_KERNEL);
	if (!priv)
		return -ENOMEM;
	ctx->priv = priv;

	ctx->priv->orig_num_col = ctx->num_tiles / ndev->metadata.core.row_count;
	ctx->max_opc = ndev->priv->col_opc * ctx->priv->orig_num_col;
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
			 i, amdxdna_gem_dev_addr(abo), abo->mem.size);
		priv->cmd_buf[i] = abo;
	}

	init_waitqueue_head(&priv->job_free_waitq);

	ret = amdxdna_ctx_syncobj_create(ctx);
	if (ret) {
		XDNA_ERR(xdna, "Create syncobj failed, ret %d", ret);
		goto free_cmd_bufs;
	}

	ret = aie2_rq_add(&xdna->dev_handle->ctx_rq, ctx);
	if (ret) {
		XDNA_ERR(xdna, "Add ctx %s failed, ret %d", ctx->name, ret);
		goto free_cmd_bufs;
	}
	init_rwsem(&priv->io_sem);
	atomic64_set(&priv->job_pending_cnt, 0);
	init_waitqueue_head(&priv->connect_waitq);

	aie2_calc_ctx_dpm(ndev, ctx);
	aie2_pm_add_dpm_level(ndev, ctx->priv->req_dpm_level);
	priv->active = true; /* Init context is counted as an activity */

	XDNA_DBG(xdna, "ctx %s init completed", ctx->name);
	return 0;

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
	amdxdna_ctx_syncobj_destroy(ctx);
	return ret;
}

void aie2_ctx_fini(struct amdxdna_ctx *ctx)
{
	struct amdxdna_dev *xdna = ctx->client->xdna;
	int idx;

	aie2_rq_del(&xdna->dev_handle->ctx_rq, ctx);
	if (!amdxdna_pm_resume_get(xdna)) {
		aie2_pm_del_dpm_level(xdna->dev_handle, ctx->priv->req_dpm_level);
		amdxdna_pm_suspend_put(xdna);
	}

	amdxdna_ctx_syncobj_destroy(ctx);
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
	kfree(ctx->priv);
	kfree(ctx->cus);
}

static int aie2_ctx_cu_config(struct amdxdna_ctx *ctx, void *buf, u32 size)
{
	struct amdxdna_hwctx_param_config_cu *config = buf;
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
	int ret;

	ret = amdxdna_pm_resume_get(xdna);
	if (ret)
		return ret;

	switch (type) {
	case DRM_AMDXDNA_HWCTX_CONFIG_CU:
		ret = aie2_ctx_cu_config(ctx, buf, size);
		break;
	case DRM_AMDXDNA_HWCTX_ASSIGN_DBG_BUF:
		ret = aie2_ctx_attach_debug_bo(ctx, (u32)value);
		break;
	case DRM_AMDXDNA_HWCTX_REMOVE_DBG_BUF:
		ret = aie2_ctx_detach_debug_bo(ctx, (u32)value);
		break;
	default:
		XDNA_DBG(xdna, "Not supported type %d", type);
		ret = -EOPNOTSUPP;
		break;
	}

	amdxdna_pm_suspend_put(xdna);
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

int aie2_cmd_submit(struct amdxdna_sched_job *job,
		    u32 *syncobj_hdls, u64 *syncobj_points, u32 syncobj_cnt, u64 *seq)
{
	struct amdxdna_ctx *ctx = job->ctx;
	struct ww_acquire_ctx acquire_ctx;
	struct dma_fence_chain *chain;
	struct amdxdna_dev *xdna;
	int ret, i;

	xdna = ctx->client->xdna;
	ret = down_killable(&ctx->priv->job_sem);
	if (ret)
		XDNA_ERR(xdna, "%s Grab job sem failed, ret %d", ctx->name, ret);

	ret = aie2_rq_submit_enter(&xdna->dev_handle->ctx_rq, ctx);
	if (ret) {
		if (ret != -ERESTARTSYS)
			XDNA_ERR(xdna, "Submit enter failed, ret %d", ret);
		goto up_job_sem;
	}

	chain = dma_fence_chain_alloc();
	if (!chain) {
		ret = -ENOMEM;
		goto rq_yield;
	}

#ifdef HAVE_6_17_drm_sched_job_init
	ret = drm_sched_job_init(&job->base, &ctx->priv->entity, 1, ctx,
				 ctx->client->filp->client_id);
#else
	ret = drm_sched_job_init(&job->base, &ctx->priv->entity, 1, ctx);
#endif
	if (ret) {
		XDNA_ERR(xdna, "DRM job init failed, ret %d", ret);
		goto free_chain;
	}

	ret = aie2_add_job_dependency(job, syncobj_hdls, syncobj_points, syncobj_cnt);
	if (ret) {
		XDNA_ERR(xdna, "Failed to add dependency, ret %d", ret);
		goto cleanup_job;
	}

	ret = amdxdna_lock_objects(job, &acquire_ctx);
	if (ret) {
		XDNA_WARN(xdna, "Failed to lock objects, ret %d", ret);
		goto cleanup_job;
	}

	mutex_lock(&ctx->io_lock);
	drm_sched_job_arm(&job->base);
	job->out_fence = dma_fence_get(&job->base.s_fence->finished);
	for (i = 0; i < job->bo_cnt; i++)
		dma_resv_add_fence(job->bos[i].obj->resv, job->out_fence, DMA_RESV_USAGE_WRITE);
	/*
	 * Resetting TDR timer before updating ctx->submitted to avoid
	 * racing with TDR detection.
	 */
	reset_tdr_timer(job);
	job->seq = ctx->submitted++;
	ctx->priv->pending[get_job_idx(job->seq)] = job;
	kref_get(&job->refcnt);
	drm_sched_entity_push_job(&job->base);

	*seq = job->seq;
	drm_syncobj_add_point(ctx->syncobj, chain, job->out_fence, *seq);
	mutex_unlock(&ctx->io_lock);

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
	job->state = JOB_STATE_DONE;
	return ret;
}

struct dma_fence *aie2_cmd_get_out_fence(struct amdxdna_ctx *ctx, u64 seq)
{
	struct dma_fence *fence, *out_fence = NULL;
	int ret;

	fence = drm_syncobj_fence_get(ctx->syncobj);
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

	if (!out_fence) {
		XDNA_ERR(ctx->client->xdna, "Invalid syncobj or sequence number");
		return -EINVAL;
	}

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
	struct drm_gem_object *gobj = to_gobj(abo);

	/*
	 * Must wait forever, otherwise, memory was unmapped then FW might crash.
	 * In case FW not response, TDR will terminal context execution and unref all BOs.
	 */
	dma_resv_wait_timeout(gobj->resv, DMA_RESV_USAGE_BOOKKEEP,
			      false /* non-interruptible */, MAX_SCHEDULE_TIMEOUT);
}

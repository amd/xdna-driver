// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2024-2026, Advanced Micro Devices, Inc.
 */
#include <linux/pm_runtime.h>
#include <drm/drm_syncobj.h>
#include <drm/drm_cache.h>

#include "amdxdna_ctx.h"
#include "amdxdna_gem.h"
#include "amdxdna_pm.h"
#include "amdxdna_trace.h"
#ifdef AMDXDNA_DEVEL
#include "amdxdna_devel.h"
#endif

#include "aie4_pci.h"
#include "aie4_message.h"
#include "aie4_solver.h"
#include "aie4_msg_priv.h"
#include "aie4_host_queue.h"

#define	NO_KMS			0
#define	KMS_REAL_CERT		1
#define	KMS_SIMULATING_CERT	2
int kernel_mode_submission = 1;
module_param(kernel_mode_submission, int, 0600);
MODULE_PARM_DESC(kernel_mode_submission,
		 "I/O submission, 0 - by user, 1 by driver (default), 2 - simulated cert for debugging");

static int aie4_alloc_resource(struct amdxdna_ctx *ctx)
{
	struct amdxdna_dev *xdna = ctx->client->xdna;
	struct alloc_requests *xrs_req;
	int ret;

	xrs_req = kzalloc(sizeof(*xrs_req), GFP_KERNEL);
	if (!xrs_req)
		return -ENOMEM;

	xrs_req->cdo.start_cols = ctx->col_list;
	xrs_req->cdo.cols_len = ctx->col_list_len;
	xrs_req->cdo.ncols = ctx->num_col;
	xrs_req->cdo.qos_cap.opc = ctx->max_opc;

	xrs_req->rqos.gops = ctx->qos.gops;
	xrs_req->rqos.fps = ctx->qos.fps;
	xrs_req->rqos.dma_bw = ctx->qos.dma_bandwidth;
	xrs_req->rqos.latency = ctx->qos.latency;
	xrs_req->rqos.exec_time = ctx->qos.frame_exec_time;
	xrs_req->rqos.priority = ctx->qos.priority;

	xrs_req->rid = (uintptr_t)ctx;

	ret = aie4_xrs_allocate_resource(xdna->dev_handle->xrs_hdl, xrs_req, ctx);
	if (ret)
		XDNA_ERR(xdna, "Allocate AIE resource failed, ret %d", ret);

	kfree(xrs_req);
	return ret;
}

static void aie4_release_resource(struct amdxdna_ctx *ctx)
{
	struct amdxdna_dev *xdna = ctx->client->xdna;
	int ret;

	ret = aie4_xrs_release_resource(xdna->dev_handle->xrs_hdl, (uintptr_t)ctx);
	if (ret)
		XDNA_ERR(xdna, "Release AIE resource failed, ret %d", ret);
}

static void aie4_ctx_col_list_fini(struct amdxdna_ctx *ctx)
{
	kfree(ctx->col_list);
}

static int aie4_ctx_col_list_init(struct amdxdna_ctx *ctx)
{
	u32 entries = 1;

	ctx->col_list = kmalloc_array(entries, sizeof(*ctx->col_list), GFP_KERNEL);
	if (!ctx->col_list)
		return -ENOMEM;

	ctx->col_list_len = entries;
	ctx->col_list[0] = 0;
	return 0;
}

static inline void aie4_ctx_umq_dump(struct amdxdna_ctx *ctx)
{
	const size_t indir_pkts_sz = CTX_MAX_CMDS * HSA_MAX_LEVEL1_INDIRECT_ENTRIES *
		sizeof(struct host_indirect_packet_data);
	const size_t pkts_sz = CTX_MAX_CMDS * sizeof(struct host_queue_packet);
	const size_t hdr_sz = sizeof(struct host_queue_header);
	void *umq_va = amdxdna_gem_vmap(ctx->priv->umq_bo);

	print_hex_dump_debug("raw_umq: ", DUMP_PREFIX_OFFSET, 16, 4,
			     umq_va, hdr_sz + pkts_sz + indir_pkts_sz, false);
}

static int aie4_ctx_umq_init(struct amdxdna_ctx *ctx)
{
	const size_t indir_pkts_sz = CTX_MAX_CMDS * HSA_MAX_LEVEL1_INDIRECT_ENTRIES *
		sizeof(struct host_indirect_packet_data);
	const size_t pkts_sz = CTX_MAX_CMDS * sizeof(struct host_queue_packet);
	struct amdxdna_dev *xdna = ctx->client->xdna;
	struct amdxdna_ctx_priv *priv = ctx->priv;
	struct host_queue_header *qhdr;
	struct amdxdna_gem_obj *umq_bo;
	size_t umq_sz;
	void *umq_va;
	int i;

	umq_bo = amdxdna_gem_get_obj(ctx->client, ctx->umq_bo, AMDXDNA_BO_SHARE);
	if (!umq_bo) {
		XDNA_ERR(xdna, "cannot find umq_bo handle %d", ctx->umq_bo);
		return -ENOENT;
	}
	priv->umq_bo = umq_bo;

	umq_va = amdxdna_gem_vmap(umq_bo);
	qhdr = umq_va;
	priv->umq_read_index = &qhdr->read_index;
	priv->umq_write_index = &qhdr->write_index;

	if (kernel_mode_submission == NO_KMS)
		return 0;

	/*
	 * Kernel mode submission requires driver to reinitialize the UMQ
	 * content to driver's need.
	 *
	 * Security notes:
	 * Since umq is shared b/w user and driver, the content can't be trusted
	 * and should not be read and used by driver at any time with below exceptions:
	 *   - read index: to tell if a command has been completed or not.
	 */
	priv->umq_pkts = umq_va + sizeof(*qhdr);
	priv->umq_indirect_pkts = umq_va + sizeof(*qhdr) + pkts_sz;
	priv->umq_indirect_pkts_dev_addr =
		amdxdna_gem_dev_addr(umq_bo) + sizeof(*qhdr) + pkts_sz;

	umq_sz = umq_bo->mem.size;
	if (umq_sz < sizeof(*qhdr) + pkts_sz + indir_pkts_sz) {
		XDNA_ERR(xdna, "umq BO size %ldB is too small", umq_sz);
		drm_gem_object_put(to_gobj(umq_bo));
		priv->umq_bo = NULL;
		return -EINVAL;
	}

	/* Init umq content */
	memset(umq_va, 0, umq_sz);
	priv->write_index = QUEUE_INDEX_START;
	qhdr->read_index = QUEUE_INDEX_START;
	qhdr->write_index = QUEUE_INDEX_START;
	qhdr->capacity = CTX_MAX_CMDS;
	qhdr->data_address = amdxdna_gem_dev_addr(umq_bo) + sizeof(*qhdr);
	for (i = 0; i < CTX_MAX_CMDS; i++)
		priv->umq_pkts[i].pkt_header.common_header.opcode = OPCODE_EXEC_BUF;
	for (i = 0; i < CTX_MAX_CMDS * HSA_MAX_LEVEL1_INDIRECT_ENTRIES; i++) {
		priv->umq_indirect_pkts[i].header.opcode = OPCODE_EXEC_BUF;
		priv->umq_indirect_pkts[i].header.count = sizeof(struct exec_buf);
		priv->umq_indirect_pkts[i].header.distribute = 1;
	}
	return 0;
}

static void aie4_ctx_umq_fini(struct amdxdna_ctx *ctx)
{
	if (ctx->priv && ctx->priv->umq_bo)
		drm_gem_object_put(to_gobj(ctx->priv->umq_bo));
}

static inline bool is_running_list_empty(struct amdxdna_ctx *ctx)
{
	bool is_empty;

	mutex_lock(&ctx->io_lock);
	is_empty = list_empty(&ctx->priv->running_job_list);
	mutex_unlock(&ctx->io_lock);
	return is_empty;
}

static inline struct amdxdna_sched_job *next_running_job(struct amdxdna_ctx *ctx)
{
	struct amdxdna_sched_job *job;

	mutex_lock(&ctx->io_lock);
	job = list_first_entry_or_null(&ctx->priv->running_job_list,
				       struct amdxdna_sched_job, list);
	if (job)
		list_del(&job->list);
	mutex_unlock(&ctx->io_lock);
	return job;
}

static void job_release(struct kref *ref)
{
	struct amdxdna_sched_job *job;

	job = container_of(ref, struct amdxdna_sched_job, refcnt);
	amdxdna_sched_job_cleanup(job);
}

static void job_done(struct amdxdna_sched_job *job)
{
	struct amdxdna_ctx *ctx = job->ctx;
	struct amdxdna_dev *xdna = ctx->client->xdna;

	XDNA_DBG(xdna, "%s job 0x%llx@%lld done, state %d",
		 ctx->name, (u64)job, job->seq, amdxdna_cmd_get_state(job->cmd_bo));
	job->state = JOB_STATE_DONE;
	trace_amdxdna_debug_point(ctx->name, job->seq, "signaling fence");
	dma_fence_signal(job->fence);
	mmput_async(job->mm);
	amdxdna_pm_suspend_put(xdna);
	kref_put(&job->refcnt, job_release);
}

static void job_complete(struct amdxdna_sched_job *job)
{
	struct amdxdna_ctx *ctx = job->ctx;
	struct amdxdna_dev *xdna = ctx->client->xdna;

	XDNA_DBG(xdna, "completing %s job %lld", ctx->name, job->seq);
	job_done(job);
}

static void job_abort(struct amdxdna_sched_job *job)
{
	struct amdxdna_gem_obj *cmd_abo = job->cmd_bo;
	struct amdxdna_ctx *ctx = job->ctx;
	struct amdxdna_dev *xdna = ctx->client->xdna;

	XDNA_ERR(xdna, "aborting %s job %lld", ctx->name, job->seq);

	amdxdna_cmd_set_state(cmd_abo, ERT_CMD_STATE_ABORT);
	job_done(job);
}

static void aie4_fill_health_data(struct amdxdna_gem_obj *cmd_abo,
				  struct amdxdna_ctx *ctx)
{
	struct amdxdna_ctx_health_data *health_data;
	struct aie4_msg_app_health_report *report;
	size_t hdr_size;
	u32 num_uc_copy;
	u32 data_total;

	health_data = amdxdna_cmd_get_data(cmd_abo, &data_total);
	health_data->version = AMDXDNA_CTX_HEALTH_DATA_V1;
	health_data->npu_gen = AMDXDNA_NPU_GEN_AIE4;

	/* Use health report cached when async context error was raised */
	if (ctx->priv->cached_health_valid && ctx->priv->cached_health_report) {
		report = ctx->priv->cached_health_report;
		health_data->aie4.ctx_state = report->ctx_status;
		hdr_size = offsetof(struct amdxdna_ctx_health_data, aie4.uc_info);
		num_uc_copy = 0;
		if (data_total > hdr_size) {
			num_uc_copy = min(report->num_uc,
					  (u32)((data_total - hdr_size) /
					      sizeof(struct uc_health_info)));
			if (num_uc_copy > 0)
				memcpy(health_data->aie4.uc_info, report->uc_info,
				       num_uc_copy * sizeof(struct uc_health_info));
		}
		health_data->aie4.num_uc = num_uc_copy;
	} else {
		health_data->aie4.ctx_state = 0;
		health_data->aie4.num_uc = 0;
	}
}

static void job_timeout(struct amdxdna_sched_job *job)
{
	struct amdxdna_ctx *ctx = job->ctx;
	struct amdxdna_dev *xdna = ctx->client->xdna;
	struct amdxdna_gem_obj *cmd_abo = job->cmd_bo;
	struct amdxdna_gem_obj *sub_cmd_abo;
	struct amdxdna_cmd_chain *payload;
	u32 boh, i = 0;

	XDNA_ERR(xdna, "timing out %s job %lld", ctx->name, job->seq);

	/* Single cmd. */
	if (job->state == JOB_STATE_SUBMITTED) {
		aie4_fill_health_data(cmd_abo, job->ctx);
		goto done;
	}

	/* Chained cmd. */
	/* TODO: 'i' should come from health data. */
	i = 0;
	payload = amdxdna_cmd_get_chained_payload(cmd_abo, NULL);
	if (payload) {
		boh = payload->data[i];
		payload->error_index = i;
		sub_cmd_abo = amdxdna_gem_get_obj(ctx->client, boh, AMDXDNA_BO_SHARE);
		if (!sub_cmd_abo) {
			XDNA_ERR(xdna, "Failed to find cmd BO %d", boh);
		} else {
			aie4_fill_health_data(sub_cmd_abo, job->ctx);
			amdxdna_gem_put_obj(sub_cmd_abo);
		}
	} else {
		XDNA_ERR(xdna, "Failed to find cmd BO payload");
	}

done:
	/*
	 * Ensure all ctx health data is updated before update state. Once state
	 * is updated, user space may treat cmd is completed.
	 */
	wmb();
	amdxdna_cmd_set_state(cmd_abo, ERT_CMD_STATE_TIMEOUT);
	job_done(job);
}

static inline void ring_doorbell(struct amdxdna_ctx *ctx)
{
	writel(0, ctx->priv->doorbell_addr);
}

static inline bool valid_queue_index(u64 read, u64 write, u32 capacity)
{
	return (write >= read) && ((write - read) <= capacity);
}

static inline u64 get_read_index(struct amdxdna_ctx *ctx)
{
	u64 wi = READ_ONCE(*ctx->priv->umq_write_index);
	u64 ri = READ_ONCE(*ctx->priv->umq_read_index);
	struct amdxdna_dev *xdna = ctx->client->xdna;

	/*
	 * CERT cannot update read index atomically. Driver may read half-updated
	 * read index. In case read index is not valid, wait for some time and
	 * retry once. It should allow CERT to complete the read index update.
	 */
	if (!valid_queue_index(ri, wi, CTX_MAX_CMDS)) {
		XDNA_WARN(xdna, "Invalid index, ri %lld, wi %lld", ri, wi);
		usleep_range(100, 200);
		ri = READ_ONCE(*ctx->priv->umq_read_index);
		if (!valid_queue_index(ri, wi, CTX_MAX_CMDS))
			XDNA_ERR(xdna, "Invalid index after retry, ri %lld, wi %lld", ri, wi);
	}
	return ri;
}

/* Publish cmd to CERT and return the assigned cmd ID. */
static inline u64 publish_cmd(struct amdxdna_ctx *ctx)
{
	u64 wi = ctx->priv->write_index++;

	/* Ensure the writes to the cmd slot are completed before notifying CERT. */
	wmb();
	WRITE_ONCE(*ctx->priv->umq_write_index, ctx->priv->write_index);
	return wi;
}

static inline bool check_cmd_done(struct amdxdna_ctx *ctx, u64 seq)
{
	u64 ri = get_read_index(ctx);

	XDNA_DBG(ctx->client->xdna, "checking if read_idx %lld > seq %lld", ri, seq);
	return ri > seq;
}

static inline int wait_till_seq_completed(struct amdxdna_ctx *ctx, u64 seq)
{
	struct amdxdna_ctx_priv *nctx = ctx->priv;
	struct cert_comp *cert_comp = nctx->cert_comp;

	wait_event(cert_comp->waitq,
		   ctx->priv->status != CTX_STATE_CONNECTED || check_cmd_done(ctx, seq));
	if (nctx->status != CTX_STATE_CONNECTED)
		return -EAGAIN; /* Ctx is not ready, come back later. */
	return 0;
}

static inline int wait_till_hsa_not_full(struct amdxdna_ctx *ctx)
{
	u64 wi = ctx->priv->write_index;

	if (wi < CTX_MAX_CMDS)
		return 0;
	return wait_till_seq_completed(ctx, wi - CTX_MAX_CMDS);
}

static inline void wait_till_job_done(struct amdxdna_sched_job *job)
{
	wait_till_seq_completed(job->ctx, job->seq);
}

static inline bool is_first_pending_job_submitting(struct amdxdna_ctx *ctx)
{
	struct amdxdna_sched_job *job;
	struct list_head *pl;
	bool ret;

	mutex_lock(&ctx->io_lock);

	pl = &ctx->priv->pending_job_list;
	if (list_empty(pl)) {
		ret = false;
	} else {
		job = list_first_entry(pl, struct amdxdna_sched_job, list);
		ret = (job->state == JOB_STATE_SUBMITTING);
	}

	mutex_unlock(&ctx->io_lock);
	return ret;
}

static void job_worker(struct work_struct *work)
{
	struct amdxdna_ctx_priv *priv;
	struct amdxdna_sched_job *job;
	struct amdxdna_dev *xdna;
	struct amdxdna_ctx *ctx;

	priv = container_of(work, struct amdxdna_ctx_priv, job_work);
	ctx = priv->ctx;
	xdna = ctx->client->xdna;

	while (!!(job = next_running_job(ctx))) {
		if (!priv->job_aborting)
			wait_till_job_done(job);
		trace_amdxdna_debug_point(ctx->name, job->seq, "job complete");

		if (get_read_index(ctx) > job->seq) {
			/* Job is completed (be it success or failure) normally by CERT. */
			job_complete(job);
		} else if (priv->job_aborting) {
			/* Mark job as aborted following a timeout. */
			job_abort(job);
		} else {
			/* Ctx has just failed, timeout this one. */
			job_timeout(job);
			/* Abort the rest. */
			priv->job_aborting = true;
		}
		ctx->completed++;
	}
	if (!priv->job_aborting)
		return;

	/*
	 * In case we need to abort jobs, after aborting all jobs in
	 * running queue, we also need to check if the first pending
	 * job should be aborted, if it is partially submitted already.
	 * The abort is completed when running queue is empty and first
	 * pending job has not started submitting.
	 */
	if (!is_first_pending_job_submitting(ctx)) {
		priv->job_aborting = false;

		/* TODO: we should recover the ctx in the async error handler. */
		*priv->umq_read_index = *priv->umq_write_index = priv->write_index;
		priv->status = CTX_STATE_CONNECTED;
		/*
		 * Notify user about aborted/timeout cmds.
		 * CERT did not get a chance to do so.
		 */
		wake_up_all(&priv->cert_comp->waitq);
		/* New job can be submitted. */
		wake_up_all(&ctx->priv->job_list_wq);
	}
}

/* CERT Simulation for debug only, remove later. */
static void cert_worker(struct work_struct *work)
{
	struct amdxdna_ctx_priv *priv;
	struct host_queue_packet *pkt;
	struct amdxdna_dev *xdna;
	u32 *ebuf_state;

	priv = container_of(work, struct amdxdna_ctx_priv, cert_work);
	xdna = priv->ctx->client->xdna;

	while (priv->status == CTX_STATE_CONNECTED &&
	       priv->cert_read_index < *priv->umq_write_index) {
		pkt = &priv->umq_pkts[priv->cert_read_index & (CTX_MAX_CMDS - 1)];
		ebuf_state = (u32 *)(uintptr_t)(pkt->pkt_header.completion_signal);
		XDNA_DBG(xdna, "Simulating CERT processing @%lld", priv->cert_read_index);
		if (priv->cert_read_index == priv->cert_timeout_seq) {
			/* Simulating timeout. */
			XDNA_DBG(xdna, "Simulating CERT timeout @%lld", priv->cert_read_index);
			priv->cert_read_index = *priv->umq_write_index;
			priv->status = CTX_STATE_DISCONNECTED;
			wake_up_all(&priv->cert_comp->waitq);
			priv->cert_timeout_seq = ~0UL;
			break;
		}
		msleep(300);
		if (priv->cert_read_index == priv->cert_error_seq) {
			/* Simulating error. */
			XDNA_DBG(xdna, "Simulating CERT error @%lld", priv->cert_read_index);
			*ebuf_state = ERT_CMD_STATE_ERROR;
		} else if (priv->cert_read_index > priv->cert_error_seq) {
			/* Simulating abort after error. */
			XDNA_DBG(xdna, "Simulating CERT abort after error @%lld",
				 priv->cert_read_index);
			*ebuf_state = ERT_CMD_STATE_ABORT;
		}
		++priv->cert_read_index;
		if (pkt->pkt_header.common_header.chain_flag == CHAIN_FLG_LAST_CMD) {
			/* Simulating success. */
			if (FIELD_GET(AMDXDNA_CMD_STATE, *ebuf_state) == ERT_CMD_STATE_NEW) {
				XDNA_DBG(xdna, "Simulating CERT success @%lld",
					 priv->cert_read_index - 1);
				*ebuf_state = ERT_CMD_STATE_COMPLETED;
			}
			*priv->umq_read_index = priv->cert_read_index;
			wake_up_all(&priv->cert_comp->waitq);
		}
	}
}

int aie4_ctx_init(struct amdxdna_ctx *ctx)
{
	struct amdxdna_dev *xdna = ctx->client->xdna;
	struct amdxdna_ctx_priv *priv = NULL;
	int ret;

	priv = kzalloc(sizeof(*priv), GFP_KERNEL);
	if (!priv)
		return -ENOMEM;

	ret = pm_runtime_resume_and_get(xdna->ddev.dev);
	if (ret) {
		XDNA_ERR(xdna, "Resume failed, ret %d", ret);
		goto free_priv;
	}
	ctx->priv = priv;
	priv->ctx = ctx;
	INIT_LIST_HEAD(&priv->pending_job_list);
	INIT_LIST_HEAD(&priv->running_job_list);
	init_waitqueue_head(&priv->job_list_wq);
	INIT_WORK(&priv->job_work, job_worker);
	priv->job_work_q = create_singlethread_workqueue(ctx->name);
	if (!priv->job_work_q) {
		XDNA_ERR(xdna, "Create job_work_q failed");
		goto fail;
	}

	/* CERT Simulation for debugging only, remove later. */
	INIT_WORK(&priv->cert_work, cert_worker);
	priv->cert_work_q = create_singlethread_workqueue(ctx->name);
	priv->cert_timeout_seq = ~0UL;
	priv->cert_error_seq = ~0UL;
	priv->cert_read_index = QUEUE_INDEX_START;

	ret = aie4_ctx_umq_init(ctx);
	if (ret)
		goto fail;

	/* col_list must be provided to the resolver */
	ret = aie4_ctx_col_list_init(ctx);
	if (ret)
		goto fail;

	/* resolver to call load->aie4_create_context */
	ret = aie4_alloc_resource(ctx);
	if (ret)
		goto fail;

	XDNA_DBG(xdna, "ctx %s init completed", ctx->name);
	return 0;

fail:
	aie4_ctx_col_list_fini(ctx);
	aie4_ctx_umq_fini(ctx);
	if (priv->cert_work_q) {
		cancel_work_sync(&priv->cert_work);
		destroy_workqueue(priv->cert_work_q);
	}
	if (priv->job_work_q) {
		cancel_work_sync(&priv->job_work);
		destroy_workqueue(priv->job_work_q);
	}
	amdxdna_ctx_syncobj_destroy(ctx);
	pm_runtime_mark_last_busy(xdna->ddev.dev);
	pm_runtime_put_autosuspend(xdna->ddev.dev);
free_priv:
	kfree(priv);
	return ret;
}

void aie4_ctx_fini(struct amdxdna_ctx *ctx)
{
	struct amdxdna_dev *xdna = ctx->client->xdna;
	struct amdxdna_ctx_priv *priv = ctx->priv;

	cancel_work_sync(&priv->cert_work);
	destroy_workqueue(priv->cert_work_q);

	/*
	 * TODO: this is temp hack. The hwctx should be destroyed on device
	 * before job_worker can be stopped. Otherwise, it is not safe to
	 * start releasing host data structure when it is still shared w/
	 * device. We have to apply this hack since, today,
	 * aie4_release_resource(ctx) also releases col_event which is used
	 * by job_worker, so...
	 */
	priv->status = CTX_STATE_DISCONNECTED;
	wake_up_all(&priv->cert_comp->waitq);
	cancel_work_sync(&priv->job_work);
	destroy_workqueue(priv->job_work_q);

	kfree(priv->cached_health_report);
	priv->cached_health_report = NULL;
	priv->cached_health_valid = false;
	/* only access hardware if device is active */
	if (!amdxdna_pm_resume_get(xdna)) {
		/* resolver to call unload->aie4_destroy_context */
		aie4_release_resource(ctx);
		amdxdna_pm_suspend_put(xdna);
	}

	aie4_ctx_col_list_fini(ctx);
	aie4_ctx_umq_fini(ctx);
	kfree(ctx->priv);
	pm_runtime_mark_last_busy(xdna->ddev.dev);
	pm_runtime_put_autosuspend(xdna->ddev.dev);
}

static inline void enqueue_pending_job(struct amdxdna_sched_job *job)
{
	struct amdxdna_ctx *ctx = job->ctx;

	mutex_lock(&ctx->io_lock);
	list_add_tail(&job->list, &ctx->priv->pending_job_list);
	job->state = JOB_STATE_PENDING;
	mutex_unlock(&ctx->io_lock);
}

static inline void cancel_pending_job(struct amdxdna_sched_job *job)
{
	struct amdxdna_ctx *ctx = job->ctx;

	mutex_lock(&ctx->io_lock);
	list_del(&job->list);
	job->state = JOB_STATE_INIT;
	mutex_unlock(&ctx->io_lock);
	wake_up_all(&ctx->priv->job_list_wq);
}

static inline bool is_first_pending_job(struct amdxdna_sched_job *job)
{
	struct amdxdna_ctx *ctx = job->ctx;
	bool is_first;

	mutex_lock(&ctx->io_lock);
	is_first = list_is_first(&job->list, &ctx->priv->pending_job_list);
	mutex_unlock(&ctx->io_lock);
	return is_first;
}

static inline void
fill_indirect_pkt(struct amdxdna_ctx_priv *priv, u64 slot_idx, u32 total_slots,
		  struct amdxdna_cmd_start_dpu *dpu, u16 entries)
{
	struct host_queue_packet *pkt = &priv->umq_pkts[slot_idx];
	struct host_indirect_packet_entry *hipe =
		(struct host_indirect_packet_entry *)(pkt->data);
	u16 i;

	for (i = 0; i < entries; i++, dpu++, hipe++) {
		struct host_indirect_packet_data *hipd;
		u64 indirect_pkt_dev_addr;
		u32 uci = dpu->uc_index;
		u32 idx;

		if (uci >= HSA_MAX_LEVEL1_INDIRECT_ENTRIES) {
			XDNA_ERR(priv->ctx->client->xdna, "Invalid uc index %d", uci);
			continue;
		}
		idx = uci * total_slots + slot_idx;
		hipd = &priv->umq_indirect_pkts[idx];
		indirect_pkt_dev_addr = priv->umq_indirect_pkts_dev_addr +
			sizeof(struct host_indirect_packet_data) * idx;

		/* Fill in indirect entry to point to indirect pkt. */
		hipe->host_addr_low = lower_32_bits(indirect_pkt_dev_addr);
		hipe_set_host_addr_high(&hipe->host_addr_high_uc_index,
					upper_32_bits(indirect_pkt_dev_addr));
		hipe_set_uc_index(&hipe->host_addr_high_uc_index, uci);

		/* Fill in indirect pkt. */
		hipd->payload.dpu_control_code_host_addr_low =
			lower_32_bits(dpu->instruction_buffer);
		hipd->payload.dpu_control_code_host_addr_high =
			upper_32_bits(dpu->instruction_buffer);
		hipd->payload.dtrace_buf_host_addr_low =
			lower_32_bits(dpu->dtrace_buffer);
		hipd->payload.dtrace_buf_host_addr_high =
			lower_16_bits(upper_32_bits(dpu->dtrace_buffer));
	}
	pkt->pkt_header.common_header.distribute = 1;
	pkt->pkt_header.common_header.indirect = 1;
	pkt->pkt_header.common_header.count = entries * sizeof(*hipe);
}

static inline void
fill_direct_pkt(struct amdxdna_ctx_priv *priv, u64 slot_idx,
		struct amdxdna_cmd_start_dpu *dpu)
{
	struct host_queue_packet *pkt = &priv->umq_pkts[slot_idx];
	struct exec_buf *ebuf = (struct exec_buf *)(pkt->data);

	memset(pkt->data, 0, sizeof(pkt->data));
	ebuf->dpu_control_code_host_addr_low = lower_32_bits(dpu->instruction_buffer);
	ebuf->dpu_control_code_host_addr_high = upper_32_bits(dpu->instruction_buffer);
	ebuf->dtrace_buf_host_addr_low = lower_32_bits(dpu->dtrace_buffer);
	ebuf->dtrace_buf_host_addr_high = lower_16_bits(upper_32_bits(dpu->dtrace_buffer));
	pkt->pkt_header.common_header.distribute = 0;
	pkt->pkt_header.common_header.indirect = 0;
	pkt->pkt_header.common_header.count = sizeof(*ebuf);
}

static int submit_one_cmd(struct amdxdna_ctx *ctx,
			  struct amdxdna_gem_obj *cmd_abo, bool last_of_chain, u64 *seq)
{
	struct amdxdna_dev *xdna = ctx->client->xdna;
	struct amdxdna_ctx_priv *priv = ctx->priv;
	struct amdxdna_cmd_start_dpu *dpu;
	struct host_queue_packet *pkt;
	u64 slot_idx;
	u16 chained;
	int ret;
	u32 op;

	/*
	 * Security notes:
	 * The cmd_abo is always shared b/w user and driver. Its content should
	 * never be trusted. Driver should cache key data and validate them after
	 * they are cached in local variable. Driver should only use the cached
	 * version and make sure it will not cause out-of-boundary access.
	 */
	op = amdxdna_cmd_get_op(cmd_abo);
	if (op != ERT_START_DPU) {
		XDNA_ERR(xdna, "Invalid exec buf op, %d", op);
		return -EINVAL;
	}

	dpu = amdxdna_cmd_get_payload(cmd_abo, NULL);
	chained = dpu->chained;
	if (chained >= HSA_MAX_LEVEL1_INDIRECT_ENTRIES) {
		XDNA_ERR(xdna, "Invalid DPU data");
		return -EINVAL;
	}

	mutex_unlock(&ctx->io_lock);
	ret = wait_till_hsa_not_full(ctx);
	mutex_lock(&ctx->io_lock);
	if (ret)
		return ret;

	slot_idx = ctx->priv->write_index & (CTX_MAX_CMDS - 1);
	if (chained)
		fill_indirect_pkt(priv, slot_idx, CTX_MAX_CMDS, dpu, chained + 1);
	else
		fill_direct_pkt(priv, slot_idx, dpu);

	pkt = &priv->umq_pkts[slot_idx];
	pkt->pkt_header.common_header.opcode = OPCODE_EXEC_BUF;
	pkt->pkt_header.common_header.chain_flag =
		last_of_chain ? CHAIN_FLG_LAST_CMD : CHAIN_FLG_NOT_LAST_CMD;
	if (kernel_mode_submission == KMS_REAL_CERT)
		pkt->pkt_header.completion_signal = amdxdna_gem_dev_addr(cmd_abo);
	else
		pkt->pkt_header.completion_signal = (uintptr_t)amdxdna_gem_vmap(cmd_abo);
	pkt->pkt_header.completion_signal += offsetof(struct amdxdna_cmd, header);
	pkt->pkt_header.common_header.reserved = 0x0; /* Remove after update CERT. */
	*seq = publish_cmd(ctx);
	/*aie4_ctx_umq_dump(ctx);*/
	if (kernel_mode_submission == KMS_REAL_CERT)
		ring_doorbell(ctx);
	else
		queue_work(priv->cert_work_q, &priv->cert_work);
	XDNA_DBG(xdna, "Submitted one cmd, %s seq %lld", ctx->name, *seq);
	return 0;
}

static int submit_job(struct amdxdna_sched_job *job)
{
	struct amdxdna_gem_obj *cmd_abo = job->cmd_bo;
	u32 op = amdxdna_cmd_get_op(cmd_abo);
	struct amdxdna_ctx *ctx = job->ctx;
	struct amdxdna_dev *xdna = ctx->client->xdna;
	struct amdxdna_cmd_chain *payload;
	u32 ccnt;
	int ret;
	u32 i;

	mutex_lock(&ctx->io_lock);

	if (job->opcode != OP_USER) {
		XDNA_ERR(xdna, "Invalid job opcode %d", job->opcode);
		ret = -EINVAL;
		goto done;
	}

	/* Single cmd. */
	if (op == ERT_START_DPU) {
		ret = submit_one_cmd(ctx, cmd_abo, true, &job->seq);
		if (!ret)
			job->state = JOB_STATE_SUBMITTED;
		goto done;
	}

	/* Cmd chain. */
	if (op != ERT_CMD_CHAIN) {
		XDNA_ERR(xdna, "Invalid cmd opcode %d", op);
		ret = -EINVAL;
		goto done;
	}
	payload = amdxdna_cmd_get_chained_payload(cmd_abo, &ccnt);
	if (!payload) {
		XDNA_ERR(xdna, "Invalid cmd payload for chained cmd");
		ret = -EINVAL;
		goto done;
	}
	for (i = 0; i < ccnt; i++) {
		u32 boh = (u32)(payload->data[i]);
		struct amdxdna_gem_obj *abo;

		abo = amdxdna_gem_get_obj(ctx->client, boh, AMDXDNA_BO_SHARE);
		if (!abo) {
			XDNA_ERR(xdna, "Failed to find cmd BO %d", boh);
			ret = -EINVAL;
			break;
		}
		ret = submit_one_cmd(ctx, abo, i + 1 == ccnt, &job->seq);
		amdxdna_gem_put_obj(abo);
		if (ret)
			break;
		job->state = JOB_STATE_SUBMITTING;
	}
	if (i == ccnt)
		job->state = JOB_STATE_SUBMITTED_CHAIN;

done:
	if (job->state == JOB_STATE_PENDING) {
		/* Did not send any cmd, no need to transfer to running list. */
		mutex_unlock(&ctx->io_lock);
		return ret;
	}
	/* Some/all cmds has been sent, transfer to running list to wait. */
	ctx->submitted++;
	list_move_tail(&job->list, &ctx->priv->running_job_list);
	mutex_unlock(&ctx->io_lock);
	trace_amdxdna_debug_point(ctx->name, job->seq, "job submitted");
	queue_work(ctx->priv->job_work_q, &ctx->priv->job_work);
	wake_up_all(&ctx->priv->job_list_wq);
	return 0;
}

int aie4_cmd_submit(struct amdxdna_sched_job *job,
		    u32 *syncobj_hdls, u64 *syncobj_points, u32 syncobj_cnt, u64 *seq)
{
	struct dma_fence_chain *chain = dma_fence_chain_alloc();
	struct amdxdna_ctx *ctx = job->ctx;
	struct amdxdna_dev *xdna = ctx->client->xdna;
	struct ww_acquire_ctx acquire_ctx;
	struct dma_fence *stub;
	size_t i;
	int ret;

	XDNA_DBG(xdna, "ctx %s job 0x%llx received", ctx->name, (u64)job);

	if (!chain)
		return -ENOMEM;

	enqueue_pending_job(job);
	/*
	 * After submit_job(), job may be completed right away before we return
	 * from this function call. Get a ref to make sure it is available for
	 * the rest of the code in this function after submit_job().
	 */
	kref_get(&job->refcnt);
	/* On AIE4 platform, out_fence is the hardware completion fence. */
	job->out_fence = dma_fence_get(job->fence);

wait_till_1st:
	ret = wait_event_killable(ctx->priv->job_list_wq,
				  (ctx->priv->status == CTX_STATE_CONNECTED) &&
				  is_first_pending_job(job));
	if (ret)
		goto fail_wait_till_1st;

	ret = amdxdna_lock_objects(job, &acquire_ctx);
	if (ret) {
		XDNA_WARN(xdna, "Failed to lock objects, ret %d", ret);
		goto fail_wait_till_1st;
	}

	if (!mmget_not_zero(job->mm)) {
		ret = -ESRCH;
		goto fail_mmget;
	}

	ret = amdxdna_pm_resume_get(xdna);
	if (ret)
		goto fail_pm_resume;

	for (i = 0; i < job->bo_cnt; i++) {
		dma_resv_add_fence(job->bos[i].obj->resv, job->out_fence,
				   DMA_RESV_USAGE_WRITE);
	}

	ret = submit_job(job);
	if (ret)
		goto fail_submit_job;

	*seq = job->seq;
	amdxdna_unlock_objects(job, &acquire_ctx);
	kref_put(&job->refcnt, job_release);
	return 0;

fail_submit_job:
	stub = dma_fence_get_stub();
	for (i = 0; i < job->bo_cnt; i++) {
		dma_resv_replace_fences(job->bos[i].obj->resv, job->out_fence->context,
					stub, DMA_RESV_USAGE_WRITE);
	}
	dma_fence_put(stub);
	amdxdna_pm_suspend_put(xdna);
fail_pm_resume:
	mmput(job->mm);
fail_mmget:
	amdxdna_unlock_objects(job, &acquire_ctx);
	if (ret == -EAGAIN)
		goto wait_till_1st;
fail_wait_till_1st:
	kref_put(&job->refcnt, job_release);
	cancel_pending_job(job);
	dma_fence_chain_free(chain);
	return ret;
}

void aie4_ctx_suspend(struct amdxdna_ctx *ctx, bool wait)
{
	struct amdxdna_dev *xdna = ctx->client->xdna;
	struct amdxdna_dev_hdl *ndev = ctx->client->xdna->dev_handle;

	drm_WARN_ON(&xdna->ddev, !mutex_is_locked(&ndev->aie4_lock));

	aie4_destroy_context(ndev, ctx, 1);

	ctx->priv->status = CTX_STATE_DISCONNECTED;
}

int aie4_ctx_resume(struct amdxdna_ctx *ctx)
{
	struct amdxdna_dev *xdna = ctx->client->xdna;
	struct amdxdna_dev_hdl *ndev = ctx->client->xdna->dev_handle;
	int ret;

	drm_WARN_ON(&xdna->ddev, !mutex_is_locked(&ndev->aie4_lock));

	if (!ctx->priv) {
		XDNA_DBG(xdna, "skip uninitialized ctx");
		return 0;
	}

	/* recreate existing ctx */
	ret = aie4_create_context(xdna->dev_handle, ctx);
	if (!ret)
		ctx->priv->status = CTX_STATE_CONNECTED;
	else
		XDNA_WARN(xdna, "Failed to resume %s status 0x%x ret %d",
			  ctx->name, ctx->priv->status, ret);
	return ret;
}

int aie4_cmd_wait(struct amdxdna_ctx *ctx, u64 seq, u32 timeout)
{
	unsigned long wait_jifs = MAX_SCHEDULE_TIMEOUT;
	struct amdxdna_ctx_priv *nctx = ctx->priv;
	struct cert_comp *cert_comp = nctx->cert_comp;
	long ret = 0;

	if (timeout)
		wait_jifs = msecs_to_jiffies(timeout);

	ret = wait_event_interruptible_timeout(cert_comp->waitq,
					       (nctx->status != CTX_STATE_CONNECTED ||
					       check_cmd_done(ctx, seq)),
					       wait_jifs);
	if (!ret)
		ret = -ETIME;
	else if (nctx->status != CTX_STATE_CONNECTED)
		ret = -EAGAIN; /* Ctx is not ready, come back later. */

	trace_amdxdna_debug_point(ctx->name, seq, "command wait done");
	return ret <= 0 ? ret : 0;
}

static int aie4_ctx_config_debug_bo(struct amdxdna_ctx *ctx, u32 bo_hdl, int attach)
{
	DECLARE_AIE4_MSG(aie4_msg_configure_hw_context, AIE4_MSG_OP_CONFIGURE_HW_CONTEXT);
	struct amdxdna_client *client = ctx->client;
	struct amdxdna_ctx_priv *nctx = ctx->priv;
	struct amdxdna_dev *xdna = client->xdna;
	struct amdxdna_dev_hdl *ndev = xdna->dev_handle;
	struct amdxdna_gem_obj *meta_bo;
	struct amdxdna_gem_obj *log_bo;
	struct fw_buffer_metadata *meta_buffer;
	u32 config_property;
	u32 prev_size;
	int ret;

	meta_bo = amdxdna_gem_get_obj(client, bo_hdl, AMDXDNA_BO_SHARE);
	if (!meta_bo) {
		XDNA_ERR(xdna, "Get meta_bo %d failed", bo_hdl);
		ret = -EINVAL;
		goto err_out;
	}

	nctx->meta_bo_hdl = attach ? bo_hdl : AMDXDNA_INVALID_BO_HANDLE;

	meta_buffer = (struct fw_buffer_metadata *)amdxdna_gem_vmap(meta_bo);

	switch (meta_buffer->buf_type) {
	case AMDXDNA_FW_BUF_LOG:
		/*
		 * TODO: remove the workaround, cert_log are now enabled from xrt.ini
		 * apply workaround here before xrt-smi can enable single file for cert_log
		 * so that kernel doesn't need to touch the kva anymore.
		 */
		config_property = AIE4_CONFIGURE_HW_CONTEXT_PROPERTY_CERT_LOG_BUFFER;
		log_bo = amdxdna_gem_get_obj(client, meta_buffer->bo_handle, AMDXDNA_BO_SHARE);
		break;
	case AMDXDNA_FW_BUF_DEBUG:
		config_property = AIE4_CONFIGURE_HW_CONTEXT_PROPERTY_CERT_DEBUG_BUFFER;
		log_bo = amdxdna_gem_get_obj(client, meta_buffer->bo_handle, AMDXDNA_BO_SHARE);
		break;
	case AMDXDNA_FW_BUF_TRACE:
		config_property = AIE4_CONFIGURE_HW_CONTEXT_PROPERTY_CERT_TRACE_BUFFER;
		log_bo = amdxdna_gem_get_obj(client, meta_buffer->bo_handle, AMDXDNA_BO_SHARE);
		break;
	case AMDXDNA_FW_BUF_DBG_Q:
		config_property = AIE4_CONFIGURE_HW_CONTEXT_PROPERTY_CERT_DEBUG_QUEUE;
		log_bo = amdxdna_gem_get_obj(client, meta_buffer->bo_handle, AMDXDNA_BO_SHARE);
		break;
	default:
		XDNA_ERR(xdna, "unsupported buffer type %d bo %lld",
			 meta_buffer->buf_type, meta_buffer->bo_handle);
		ret = -EOPNOTSUPP;
		goto put_meta_bo;
	}

	if (!log_bo) {
		XDNA_ERR(xdna, "Get log_bo %lld failed", meta_buffer->bo_handle);
		ret = -EINVAL;
		goto put_meta_bo;
	}
	XDNA_DBG(xdna, "Found bo %lld", meta_buffer->bo_handle);

	/* assign dev_addr + offse to firmware */
	prev_size = 0;
	for (int i = 0; i < meta_buffer->num_ucs; i++) {
		struct uc_info_entry *entry = &meta_buffer->uc_info[i];
		u32 index = entry->index;
		u64 off_addr;

		if (index >= MAX_NUM_CERTS) {
			XDNA_ERR(xdna, "got invalid index %d, stop", index);
			ret = -EINVAL;
			goto put_log_bo;
		}

		if (!attach) {
			XDNA_INFO(xdna, "clear index %d logging", index);
			req.cert_logging.info[index].paddr = 0;
			req.cert_logging.info[index].size = 0;
			continue;
		}

		off_addr = (u64)((char *)amdxdna_gem_dev_addr(log_bo) + prev_size);

		/* skip any empty entry */
		if (entry->size == 0)
			continue;
		prev_size += entry->size;

		req.cert_logging.info[index].paddr = off_addr;
		req.cert_logging.info[index].size = entry->size;

		XDNA_DBG(xdna, "request cert index %d, paddr 0x%llx, size %d",
			 index, off_addr, entry->size);
	}

	req.cert_logging.num = attach ? meta_buffer->num_ucs : 0;

	req.hw_context_id = ctx->priv->hw_ctx_id;
	req.property = config_property;

	mutex_lock(&ndev->aie4_lock);
	ret = aie4_send_msg_wait(ndev, &msg);
	mutex_unlock(&ndev->aie4_lock);

	XDNA_DBG(xdna, "Attach debug BO %d to %s, ret: %d", bo_hdl, ctx->name, ret);

put_log_bo:
	amdxdna_gem_put_obj(log_bo);
put_meta_bo:
	amdxdna_gem_put_obj(meta_bo);
err_out:
	return ret;
}

static int aie4_ctx_attach_debug_bo(struct amdxdna_ctx *ctx, u32 bo_hdl)
{
	return aie4_ctx_config_debug_bo(ctx, bo_hdl, 1);
}

static int aie4_ctx_detach_debug_bo(struct amdxdna_ctx *ctx, u32 bo_hdl)
{
	return aie4_ctx_config_debug_bo(ctx, bo_hdl, 0);
}

int aie4_parse_priority(u32 priority)
{
	switch (priority) {
	case AIE4_CONTEXT_PRIORITY_BAND_IDLE:
		return AMDXDNA_QOS_LOW_PRIORITY;
	case AIE4_CONTEXT_PRIORITY_BAND_NORMAL:
		return AMDXDNA_QOS_NORMAL_PRIORITY;
	case AIE4_CONTEXT_PRIORITY_BAND_FOCUS:
		return AMDXDNA_QOS_HIGH_PRIORITY;
	case AIE4_CONTEXT_PRIORITY_BAND_REAL_TIME:
		return AMDXDNA_QOS_REALTIME_PRIORITY;
	default:
		return 0;
	}
}

static int aie4_ctx_config_priority_band(struct amdxdna_ctx *ctx, u32 priority)
{
	DECLARE_AIE4_MSG(aie4_msg_configure_hw_context, AIE4_MSG_OP_CONFIGURE_HW_CONTEXT);
	struct amdxdna_dev *xdna = ctx->client->xdna;
	struct amdxdna_dev_hdl *ndev = xdna->dev_handle;
	int ret;

	if (priority >= AIE4_CONTEXT_PRIORITY_BAND_COUNT) {
		XDNA_ERR(xdna, "Invalid priority band %d", priority);
		return -EINVAL;
	}

	req.hw_context_id = ctx->priv->hw_ctx_id;
	req.property = AIE4_CONFIGURE_HW_CONTEXT_PROPERTY_PRIORITY_BAND;
	req.priority_band = priority;

	mutex_lock(&ndev->aie4_lock);
	ret = aie4_send_msg_wait(ndev, &msg);
	mutex_unlock(&ndev->aie4_lock);

	return ret;
}

static int aie4_ctx_config_scheduling(struct amdxdna_ctx *ctx, void *buf)
{
	DECLARE_AIE4_MSG(aie4_msg_configure_hw_context, AIE4_MSG_OP_CONFIGURE_HW_CONTEXT);
	struct amdxdna_hwctx_param_config_scheduling *scheduling = buf;
	struct amdxdna_dev *xdna = ctx->client->xdna;
	struct amdxdna_dev_hdl *ndev = xdna->dev_handle;
	int ret;

	if (scheduling->in_process_priority < -7 || scheduling->in_process_priority > 7) {
		XDNA_ERR(xdna, "Invalid in_process_priority %d", scheduling->in_process_priority);
		return -EINVAL;
	}

	req.hw_context_id = ctx->priv->hw_ctx_id;
	req.property = AIE4_CONFIGURE_HW_CONTEXT_PROPERTY_SCHEDULING;
	req.scheduling.quantum = scheduling->quantum;
	req.scheduling.in_process_priority = scheduling->in_process_priority;
	req.scheduling.realtime_band_priority_level = scheduling->realtime_band_priority_level;

	mutex_lock(&ndev->aie4_lock);
	ret = aie4_send_msg_wait(ndev, &msg);
	mutex_unlock(&ndev->aie4_lock);

	return ret;
}

static int aie4_ctx_config_dpm(struct amdxdna_ctx *ctx, void *buf)
{
	DECLARE_AIE4_MSG(aie4_msg_configure_hw_context, AIE4_MSG_OP_CONFIGURE_HW_CONTEXT);
	struct amdxdna_hwctx_param_config_dpm *dpm = buf;
	struct amdxdna_dev *xdna = ctx->client->xdna;
	struct amdxdna_dev_hdl *ndev = xdna->dev_handle;
	int ret;

	req.hw_context_id = ctx->priv->hw_ctx_id;
	req.property = AIE4_CONFIGURE_HW_CONTEXT_PROPERTY_DPM;
	req.dpm.egops = dpm->egops;
	req.dpm.fps = dpm->fps;
	req.dpm.data_movement = dpm->data_movement;
	req.dpm.latency_in_us = dpm->latency_in_us;

	mutex_lock(&ndev->aie4_lock);
	ret = aie4_send_msg_wait(ndev, &msg);
	mutex_unlock(&ndev->aie4_lock);

	return ret;
}

int aie4_ctx_config(struct amdxdna_ctx *ctx, u32 type, u64 value, void *buf, u32 size)
{
	struct amdxdna_dev *xdna = ctx->client->xdna;

	switch (type) {
	case DRM_AMDXDNA_HWCTX_ASSIGN_DBG_BUF:
		return aie4_ctx_attach_debug_bo(ctx, (u32)value);
	case DRM_AMDXDNA_HWCTX_REMOVE_DBG_BUF:
		return aie4_ctx_detach_debug_bo(ctx, (u32)value);
	case DRM_AMDXDNA_HWCTX_CONFIG_PRIORITY_BAND:
		return aie4_ctx_config_priority_band(ctx, (u32)value);
	case DRM_AMDXDNA_HWCTX_CONFIG_SCHEDULING:
		return aie4_ctx_config_scheduling(ctx, buf);
	case DRM_AMDXDNA_HWCTX_CONFIG_DPM:
		return aie4_ctx_config_dpm(ctx, buf);
	default:
		XDNA_DBG(xdna, "Not supported type %d", type);
		return -EOPNOTSUPP;
	}
}

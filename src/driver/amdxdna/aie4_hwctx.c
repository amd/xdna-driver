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

/*
 * UMQ cache-maintenance helpers.
 *
 * The UMQ BO is a userspace-supplied dma_buf shared with CERT.  It
 * can be backed by the amdxdna CMA exporter (cached, requires
 * dma_sync_single_for_*), by shmem pages, or by a foreign import.
 * amdxdna_gem_sync_range() picks the right mechanism per backing and
 * is a no-op on cache-coherent platforms, so these wrappers just
 * compute the right [offset, size) sub-window and let it route.
 */
static inline u64 umq_pkt_offset(u32 slot_idx)
{
	return sizeof(struct host_queue_header) +
	       slot_idx * sizeof(struct host_queue_packet);
}

static inline u64 umq_indirect_pkt_offset(u32 idx)
{
	return sizeof(struct host_queue_header) +
	       CTX_MAX_CMDS * sizeof(struct host_queue_packet) +
	       idx * sizeof(struct host_indirect_packet_data);
}

static inline void aie4_umq_sync_for_device(struct amdxdna_ctx_priv *priv,
					    u64 offset, u64 size)
{
	WARN_ON_ONCE(amdxdna_gem_sync_range(priv->umq_bo, offset, size,
					    DMA_TO_DEVICE));
}

static inline void aie4_umq_sync_for_cpu(struct amdxdna_ctx_priv *priv,
					 u64 offset, u64 size)
{
	WARN_ON_ONCE(amdxdna_gem_sync_range(priv->umq_bo, offset, size,
					    DMA_FROM_DEVICE));
}

static inline void aie4_umq_sync_read_index_for_cpu(struct amdxdna_ctx_priv *priv)
{
	aie4_umq_sync_for_cpu(priv,
			      offsetof(struct host_queue_header, read_index),
			      sizeof(*priv->umq_read_index));
}

static inline void aie4_umq_sync_read_index_for_device(struct amdxdna_ctx_priv *priv)
{
	aie4_umq_sync_for_device(priv,
				 offsetof(struct host_queue_header, read_index),
				 sizeof(*priv->umq_read_index));
}

static inline void aie4_umq_sync_write_index_for_device(struct amdxdna_ctx_priv *priv)
{
	aie4_umq_sync_for_device(priv,
				 offsetof(struct host_queue_header, write_index),
				 sizeof(*priv->umq_write_index));
}

static inline void aie4_umq_sync_pkt_for_device(struct amdxdna_ctx_priv *priv,
						u32 slot_idx)
{
	aie4_umq_sync_for_device(priv, umq_pkt_offset(slot_idx),
				 sizeof(struct host_queue_packet));
}

static inline void aie4_umq_sync_indirect_pkt_for_device(struct amdxdna_ctx_priv *priv,
							 u32 idx)
{
	aie4_umq_sync_for_device(priv, umq_indirect_pkt_offset(idx),
				 sizeof(struct host_indirect_packet_data));
}

int kernel_mode_submission = 1;
module_param(kernel_mode_submission, int, 0600);
MODULE_PARM_DESC(kernel_mode_submission, "I/O submission, 0 - by user, 1 by driver (default)");

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

	if (!kernel_mode_submission)
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
	/*
	 * Publish the freshly-initialized header, packet ring and indirect
	 * packet ring to CERT before any submit / doorbell.
	 */
	aie4_umq_sync_for_device(priv, 0, umq_sz);
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

/*
 * Invalidate the CPU-cached mappings of the cmd BO(s) that firmware/CERT
 * has just written completion state into via DMA, so the next userspace
 * read through the cached mmap returns the firmware-written value
 * instead of a stale line.
 *
 * The shim also invalidates cmd BOs in complete_command() before reading
 * completion state (KMS and UMS).  This path remains as defense in depth
 * on the success path and pairs with aie4_cmd_set_state_for_user() on
 * driver-initiated timeout/abort.
 *
 * For chained cmds, firmware writes per-sub-cmd completion state into
 * each sub-cmd BO's header (the parent runlist holder's state is
 * computed by userspace from the sub-cmd results), so the chain
 * payload must be walked and each sub-cmd BO synced too.
 */
static void aie4_cmd_bo_sync(struct amdxdna_ctx *ctx,
			     struct amdxdna_gem_obj *cmd_abo,
			     enum dma_data_direction dir)
{
	struct amdxdna_cmd_chain *payload;
	u32 ccnt;
	u32 i;

	if (!cmd_abo)
		return;

	amdxdna_gem_sync_range(cmd_abo, 0, cmd_abo->mem.size, dir);

	if (amdxdna_cmd_get_op(cmd_abo) != ERT_CMD_CHAIN)
		return;

	payload = amdxdna_cmd_get_chained_payload(cmd_abo, &ccnt);
	if (!payload)
		return;

	for (i = 0; i < ccnt; i++) {
		u32 boh = (u32)payload->data[i];
		struct amdxdna_gem_obj *sub_abo;

		sub_abo = amdxdna_gem_get_obj(ctx->client, boh, AMDXDNA_BO_SHARE);
		if (!sub_abo)
			continue;
		amdxdna_gem_sync_range(sub_abo, 0, sub_abo->mem.size, dir);
		amdxdna_gem_put_obj(sub_abo);
	}
}

static inline void aie4_cmd_bo_sync_for_cpu(struct amdxdna_ctx *ctx,
					    struct amdxdna_gem_obj *cmd_abo)
{
	aie4_cmd_bo_sync(ctx, cmd_abo, DMA_FROM_DEVICE);
}

static inline void aie4_cmd_bo_sync_for_device(struct amdxdna_ctx *ctx,
					       struct amdxdna_gem_obj *cmd_abo)
{
	aie4_cmd_bo_sync(ctx, cmd_abo, DMA_TO_DEVICE);
}

/*
 * Publish a driver-written completion state (timeout/abort) so userspace
 * sees it after its own cache invalidate: drop stale CPU lines, write
 * state via the kernel vmap, then flush the cmd BO (and health payload)
 * back to DDR.
 */
static void aie4_cmd_set_state_for_user(struct amdxdna_ctx *ctx,
					struct amdxdna_gem_obj *cmd_abo,
					enum ert_cmd_state state)
{
	aie4_cmd_bo_sync_for_cpu(ctx, cmd_abo);
	amdxdna_cmd_set_state(cmd_abo, state);
	aie4_cmd_bo_sync_for_device(ctx, cmd_abo);
}

static void job_done(struct amdxdna_sched_job *job)
{
	struct amdxdna_ctx *ctx = job->ctx;
	struct amdxdna_dev *xdna = ctx->client->xdna;

	/* Defense in depth before waking aie4_cmd_wait(); shim also syncs. */
	aie4_cmd_bo_sync_for_cpu(ctx, job->cmd_bo);

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

/*
 * When CERT does not respond, driver needs to update read index to let waiting
 * thread know the command is timed out/aborted.
 * Driver should never update read index when CERT is still alive.
 */
static inline void update_read_index(struct amdxdna_ctx *ctx, u64 idx)
{
	drm_WARN_ON(&ctx->client->xdna->ddev, ctx->priv->status == CTX_STATE_CONNECTED);

	/* Ensure the writes to the cmd bo are completed before notifying waiting thread. */
	wmb();
	WRITE_ONCE(*ctx->priv->umq_read_index, idx);
	/*
	 * On timeout/abort the CPU forges a read_index update that CERT (or a
	 * future reconnect of it) may observe; flush the cache line out.
	 */
	aie4_umq_sync_read_index_for_device(ctx->priv);
}

static void job_abort(struct amdxdna_sched_job *job)
{
	struct amdxdna_gem_obj *cmd_abo = job->cmd_bo;
	struct amdxdna_ctx *ctx = job->ctx;
	struct amdxdna_dev *xdna = ctx->client->xdna;

	XDNA_ERR(xdna, "aborting %s job %lld", ctx->name, job->seq);

	aie4_cmd_set_state_for_user(ctx, cmd_abo, ERT_CMD_STATE_ABORT);
	update_read_index(ctx, job->seq + 1);
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
	size_t min_size = offsetof(struct amdxdna_ctx_health_data, aie4.uc_info);

	health_data = amdxdna_cmd_get_data(cmd_abo, &data_total);
	if (!health_data || data_total < min_size) {
		XDNA_WARN(ctx->client->xdna,
			  "Health data buffer too small: data_total=%u min=%zu",
			  data_total, min_size);
		return;
	}

	health_data->version = AMDXDNA_CTX_HEALTH_DATA_V1;
	health_data->npu_gen = AMDXDNA_NPU_GEN_AIE4;

	/* Use async context error cached when async error was raised */
	/* Pairs with smp_store_release in aie4_ctx_cache_health_report. */
	if (smp_load_acquire(&ctx->priv->cached_ctx_error_valid)) {
		report = &ctx->priv->cached_ctx_error.app_health_report;
		health_data->aie4.ctx_state = aie4_health_get_ctx_status(report);
		health_data->aie4.ctx_error_type = ctx->priv->cached_ctx_error.error_type;
		hdr_size = offsetof(struct amdxdna_ctx_health_data, aie4.uc_info);
		num_uc_copy = 0;
		if (data_total > hdr_size) {
			u32 max_uc = (data_total - hdr_size) / sizeof(struct uc_health_info);

			num_uc_copy = min_t(u32, aie4_health_get_num_uc(report), max_uc);
			if (num_uc_copy > 0) {
				memcpy(health_data->aie4.uc_info, report->uc_info,
				       num_uc_copy * sizeof(struct uc_health_info));
			}
		}
		health_data->aie4.num_uc = num_uc_copy;
		/* Clear flag after payload write; release orders after our reads of
		 * cached_ctx_error.
		 */
		smp_store_release(&ctx->priv->cached_ctx_error_valid, false);
	} else {
		health_data->aie4.ctx_state = 0;
		health_data->aie4.ctx_error_type = 0;
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
		aie4_cmd_bo_sync_for_cpu(ctx, cmd_abo);
		aie4_fill_health_data(cmd_abo, job->ctx);
		goto done;
	}

	/* Chained cmd. */
	/* Pairs with smp_store_release in aie4_ctx_cache_health_report. */
	if (smp_load_acquire(&ctx->priv->cached_ctx_error_valid))
		i = aie4_health_runlist_read_idx(&ctx->priv->cached_ctx_error.app_health_report);
	payload = amdxdna_cmd_get_chained_payload(cmd_abo, NULL);
	if (payload) {
		boh = payload->data[i];
		payload->error_index = i;
		sub_cmd_abo = amdxdna_gem_get_obj(ctx->client, boh, AMDXDNA_BO_SHARE);
		if (!sub_cmd_abo) {
			XDNA_ERR(xdna, "Failed to find cmd BO %d", boh);
		} else {
			aie4_cmd_bo_sync_for_cpu(ctx, sub_cmd_abo);
			aie4_fill_health_data(sub_cmd_abo, job->ctx);
			aie4_cmd_bo_sync_for_device(ctx, sub_cmd_abo);
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
	aie4_cmd_set_state_for_user(ctx, cmd_abo, ERT_CMD_STATE_TIMEOUT);
	update_read_index(ctx, job->seq + 1);
	job_done(job);
}

static inline void ring_doorbell(struct amdxdna_ctx *ctx)
{
	struct amdxdna_dev *xdna = ctx->client->xdna;
	struct amdxdna_dev_hdl *ndev = xdna->dev_handle;
	int ret;

	if (ndev->xcomm_ops) {
		ret = ndev->xcomm_ops->ring_doorbell(ndev->xcomm_hdl,
						     ctx->priv->hw_ctx_id);
		XDNA_DBG(xdna, "ring_doorbell: ctx=%s hw_ctx_id=%u xcomm ret=%d",
			 ctx->name, ctx->priv->hw_ctx_id, ret);
		if (ret)
			XDNA_WARN(xdna,
				  "ring_doorbell failed: ctx=%s hw_ctx_id=%u ret=%d",
				  ctx->name, ctx->priv->hw_ctx_id, ret);
		return;
	}

	writel(0, ctx->priv->doorbell_addr);
	XDNA_DBG(xdna, "ring_doorbell: ctx=%s hw_ctx_id=%u MMIO %p",
		 ctx->name, ctx->priv->hw_ctx_id, ctx->priv->doorbell_addr);
}

static inline bool valid_queue_index(u64 read, u64 write, u32 capacity)
{
	return (write >= read) && ((write - read) <= capacity);
}

static inline u64 get_read_index(struct amdxdna_ctx *ctx)
{
	struct amdxdna_dev *xdna = ctx->client->xdna;
	u64 wi = READ_ONCE(*ctx->priv->umq_write_index);
	u64 ri;

	/* Invalidate the cached read_index line before reading what CERT wrote. */
	aie4_umq_sync_read_index_for_cpu(ctx->priv);
	ri = READ_ONCE(*ctx->priv->umq_read_index);

	/*
	 * CERT cannot update read index atomically. Driver may read half-updated
	 * read index. In case read index is not valid, wait for some time and
	 * retry once. It should allow CERT to complete the read index update.
	 */
	if (!valid_queue_index(ri, wi, CTX_MAX_CMDS)) {
		XDNA_WARN(xdna, "Invalid index, ri %lld, wi %lld", ri, wi);
		usleep_range(100, 200);
		aie4_umq_sync_read_index_for_cpu(ctx->priv);
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
	/* Flush the new write_index to memory before the doorbell wakes CERT. */
	aie4_umq_sync_write_index_for_device(ctx->priv);
	return wi;
}

static inline bool check_cmd_done(struct amdxdna_ctx *ctx, u64 seq)
{
	struct amdxdna_dev *xdna = ctx->client->xdna;
	u64 ri;
	u64 wi;

	if (ctx->priv->status != CTX_STATE_CONNECTED)
		return true;

	ri = get_read_index(ctx);

	if (ri > seq) {
		trace_amdxdna_debug_point(ctx->name, seq, "HSA poll completion");
		wi = READ_ONCE(*ctx->priv->umq_write_index);
		XDNA_DBG(xdna,
			 "HSA completion: ctx=%s read_index=%llu > seq=%llu write_index=%llu",
			 ctx->name, ri, seq, wi);
	}

	return ri > seq;
}

static struct cert_comp *aie4_ctx_get_cert_comp(struct amdxdna_ctx *ctx)
{
	struct amdxdna_dev_hdl *ndev = ctx->client->xdna->dev_handle;
	struct amdxdna_ctx_priv *priv = ctx->priv;
	struct cert_comp *cert_comp;

	mutex_lock(&ndev->aie4_lock);

	cert_comp = priv->cert_comp;
	if (cert_comp)
		kref_get(&cert_comp->kref);

	mutex_unlock(&ndev->aie4_lock);

	return cert_comp;
}

static void aie4_ctx_put_cert_comp(struct cert_comp *cert_comp)
{
	struct amdxdna_dev_hdl *ndev = cert_comp->ndev;

	mutex_lock(&ndev->aie4_lock);
	aie4_put_cert_comp_locked(cert_comp);
	mutex_unlock(&ndev->aie4_lock);
}

static inline int wait_till_seq_completed(struct amdxdna_ctx *ctx, u64 seq)
{
	struct cert_comp *cert_comp = aie4_ctx_get_cert_comp(ctx);

	if (!cert_comp)
		return -EAGAIN;

	wait_event(cert_comp->waitq, check_cmd_done(ctx, seq));
	aie4_ctx_put_cert_comp(cert_comp);
	return (ctx->priv->status != CTX_STATE_CONNECTED) ? -EAGAIN : 0;
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
	struct amdxdna_ctx_priv *priv = container_of(work, struct amdxdna_ctx_priv, job_work);
	struct amdxdna_ctx *ctx = priv->ctx;
	struct amdxdna_sched_job *job;

	while (!!(job = next_running_job(ctx))) {
		wait_till_job_done(job);
		trace_amdxdna_debug_point(ctx->name, job->seq, "job complete");

		if (get_read_index(ctx) > job->seq) {
			/* Job is completed (be it success or failure) normally by CERT. */
			job_complete(job);
		/* Pairs with smp_store_release in aie4_ctx_cache_health_report. */
		} else if (smp_load_acquire(&ctx->priv->cached_ctx_error_valid)) {
			/* CERT did not respond, timeout this one. */
			job_timeout(job);
		} else {
			/* Ctx is destroyed or previous cmd has timed out, abort job. */
			job_abort(job);
		}
		ctx->completed++;
	}
}

/*
 * Cleanup pending jobs which will also make HSA queue empty.
 */
void aie4_ctx_cleanup_pending_jobs(struct amdxdna_ctx *ctx)
{
	/* Can't really cleanup if jobs can still be submitted and completed by CERT. */
	drm_WARN_ON(&ctx->client->xdna->ddev, ctx->priv->status == CTX_STATE_CONNECTED);
	/* Make sure no job is till being submitted. */
	wait_event(ctx->priv->job_list_wq, !is_first_pending_job_submitting(ctx));
	/* Start job work to cleanup all pending jobs. */
	queue_work(ctx->priv->job_work_q, &ctx->priv->job_work);
	/* Wait for all pending jobs to be aborted by job_work. */
	flush_work(&ctx->priv->job_work);
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

	/* only access hardware if device is active */
	if (!amdxdna_pm_resume_get(xdna)) {
		/* resolver to call unload->aie4_destroy_context */
		aie4_release_resource(ctx);
		amdxdna_pm_suspend_put(xdna);
	}

	aie4_ctx_cleanup_pending_jobs(ctx);
	cancel_work_sync(&priv->job_work);
	destroy_workqueue(priv->job_work_q);
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
		/* Publish this indirect pkt slot before CERT can chase it. */
		aie4_umq_sync_indirect_pkt_for_device(priv, idx);
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
	 *
	 * Cache-maintenance: cmd_abo was last written by userspace (XRT) via
	 * its cached mmap, so dirty bytes still live in the user process's
	 * CPU cache.  Two consumers about to read from DDR need them
	 * published first: (a) our kernel vmap (amdxdna_cmd_get_op /
	 * get_payload below) - on a non-coherent platform the SHARE BO is
	 * backed by dma_alloc_noncoherent() and the kernel vmap is
	 * non-cached, so the read bypasses the CPU cache and goes straight
	 * to DDR; (b) CERT in the UMS-with-EXEC_CMD path, which DMAs the
	 * packet out of DDR.  DMA_TO_DEVICE expresses the access pattern
	 * (CPU wrote, something will read from DDR) regardless of whether
	 * that something is hardware DMA or a non-cached CPU mapping.
	 * amdxdna_gem_sync_range() is a no-op on cache-coherent platforms,
	 * so this is free where it is not needed.
	 */
	amdxdna_gem_sync_range(cmd_abo, 0, cmd_abo->mem.size, DMA_TO_DEVICE);

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
	pkt->pkt_header.completion_signal = amdxdna_gem_dev_addr(cmd_abo);
	pkt->pkt_header.completion_signal += offsetof(struct amdxdna_cmd, header);
	pkt->pkt_header.common_header.reserved = 0x0; /* Remove after update CERT. */
	/*
	 * Flush this packet slot before publish_cmd() bumps write_index.  Pair
	 * with the indirect-pkt flushes in fill_indirect_pkt() (chained path)
	 * so CERT sees a fully-formed packet when it follows the new
	 * write_index past this slot.
	 */
	aie4_umq_sync_pkt_for_device(priv, slot_idx);
	*seq = publish_cmd(ctx);
	aie4_ctx_umq_dump(ctx);
	ring_doorbell(ctx);
	XDNA_DBG(xdna, "Submitted one cmd, %s seq %lld", ctx->name, *seq);
	return 0;
}

static int submit_job(struct amdxdna_sched_job *job)
{
	struct amdxdna_gem_obj *cmd_abo = job->cmd_bo;
	struct amdxdna_ctx *ctx = job->ctx;
	struct amdxdna_dev *xdna = ctx->client->xdna;
	struct amdxdna_cmd_chain *payload;
	u32 ccnt;
	int ret;
	u32 op;
	u32 i;

	mutex_lock(&ctx->io_lock);

	if (job->opcode != OP_USER) {
		XDNA_ERR(xdna, "Invalid job opcode %d", job->opcode);
		ret = -EINVAL;
		goto done;
	}

	/*
	 * Flush user writes to the parent cmd BO before reading its op /
	 * chained payload via our kernel vmap below.  On a non-coherent
	 * platform that vmap is non-cached (dma_alloc_noncoherent() backing)
	 * and reads bypass the CPU cache, so the user's dirty lines must
	 * be in DDR first.  The per-cmd sync inside submit_one_cmd() covers
	 * the single-cmd parent and each sub-cmd in the chained path; this
	 * one covers the parent cmd BO whose chain header is consumed here
	 * in submit_job() itself.  A no-op on cache-coherent platforms.
	 */
	amdxdna_gem_sync_range(cmd_abo, 0, cmd_abo->mem.size, DMA_TO_DEVICE);
	op = amdxdna_cmd_get_op(cmd_abo);

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
	struct amdxdna_ctx *ctx = job->ctx;
	struct amdxdna_dev *xdna = ctx->client->xdna;
	struct ww_acquire_ctx acquire_ctx;
	struct dma_fence *stub;
	size_t i;
	int ret;

	XDNA_DBG(xdna, "ctx %s job 0x%llx received", ctx->name, (u64)job);

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
	return ret;
}

void aie4_ctx_suspend(struct amdxdna_ctx *ctx, bool wait)
{
	struct amdxdna_dev *xdna = ctx->client->xdna;
	struct amdxdna_dev_hdl *ndev = ctx->client->xdna->dev_handle;

	drm_WARN_ON(&xdna->ddev, !mutex_is_locked(&ndev->aie4_lock));
	aie4_destroy_context(ndev, ctx, 1);
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
	if (ret) {
		XDNA_WARN(xdna, "Failed to resume %s status 0x%x ret %d",
			  ctx->name, ctx->priv->status, ret);
	}
	return ret;
}

int aie4_cmd_wait(struct amdxdna_ctx *ctx, u64 seq, u32 timeout)
{
	unsigned long wait_jifs = timeout ? msecs_to_jiffies(timeout) : MAX_SCHEDULE_TIMEOUT;
	struct cert_comp *cert_comp = aie4_ctx_get_cert_comp(ctx);
	long ret = 0;

	if (!cert_comp)
		return -EAGAIN;

	ret = wait_event_interruptible_timeout(cert_comp->waitq,
					       check_cmd_done(ctx, seq),
					       wait_jifs);
	aie4_ctx_put_cert_comp(cert_comp);
	if (!ret)
		ret = -ETIME;
	else if (ret > 0 && ctx->priv->status != CTX_STATE_CONNECTED)
		ret = -EAGAIN; /* Ctx is not ready, come back later. */

	trace_amdxdna_debug_point(ctx->name, seq, "command wait done");
	return ret < 0 ? ret : 0;
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

	/*
	 * meta_bo was populated by userspace through its cached mmap to
	 * describe the firmware-side log/debug/trace buffer layout.  Flush
	 * those user writes back to DDR before we read the descriptor via
	 * our kernel vmap below: on a non-coherent platform the SHARE BO
	 * is backed by dma_alloc_noncoherent() and the kernel vmap is
	 * non-cached, so the load bypasses the CPU cache and would return
	 * stale fw_buffer_metadata without this clean.  DMA_TO_DEVICE is
	 * the right primitive because the access pattern (CPU wrote,
	 * something will read from DDR) is the same as a device DMA read,
	 * even though the actual reader here is the kernel's non-cached
	 * vmap.  No-op on cache-coherent platforms.
	 */
	amdxdna_gem_sync_range(meta_bo, 0, meta_bo->mem.size, DMA_TO_DEVICE);

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

	/*
	 * The maximum number of CERT uCs in a full-NPU context is
	 *   dev_info->num_col * dev_info->uc_per_col
	 * (both per-device-arch constants; see struct amdxdna_dev_info),
	 * and is additionally bounded by the firmware ABI array size in
	 * req.cert_logging.info[] (see struct
	 * aie4_msg_context_config_cert_logging). Use the tighter of the two.
	 */
	u32 max_certs = (u32)xdna->dev_info->num_col * xdna->dev_info->uc_per_col;

	if (max_certs > ARRAY_SIZE(req.cert_logging.info))
		max_certs = ARRAY_SIZE(req.cert_logging.info);

	/* assign dev_addr + offse to firmware */
	prev_size = 0;
	for (int i = 0; i < meta_buffer->num_ucs; i++) {
		struct uc_info_entry *entry = &meta_buffer->uc_info[i];
		u32 index = entry->index;
		u64 off_addr;

		if (index >= max_certs) {
			XDNA_ERR(xdna,
				 "invalid CERT index %u for buf_type %u (num_ucs=%u, num_col=%u, uc_per_col=%u, max=%u)",
				 index, meta_buffer->buf_type,
				 meta_buffer->num_ucs,
				 xdna->dev_info->num_col,
				 xdna->dev_info->uc_per_col, max_certs);
			ret = -EINVAL;
			goto put_log_bo;
		}

		if (!attach) {
			XDNA_DBG(xdna, "clear index %d logging", index);
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

int aie4_ctx_config(struct amdxdna_ctx *ctx, u32 type, u64 value, void *buf, u32 size)
{
	struct amdxdna_dev *xdna = ctx->client->xdna;

	switch (type) {
	case DRM_AMDXDNA_HWCTX_ASSIGN_DBG_BUF:
		return aie4_ctx_attach_debug_bo(ctx, (u32)value);
	case DRM_AMDXDNA_HWCTX_REMOVE_DBG_BUF:
		return aie4_ctx_detach_debug_bo(ctx, (u32)value);
	default:
		XDNA_DBG(xdna, "Not supported type %d", type);
		return -EOPNOTSUPP;
	}
}

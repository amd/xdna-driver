// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2025, Advanced Micro Devices, Inc.
 *
 * DRM Scheduler implementation for VE2 - Option E
 */

#include <linux/slab.h>
#include <drm/gpu_scheduler.h>

#include "amdxdna_ctx.h"
#include "ve2_of.h"
#include "ve2_mgmt.h"

/*
 * ===========================================================================
 * Context Switch Fence Implementation
 * ===========================================================================
 */

static const char *ve2_ctx_switch_fence_get_driver_name(struct dma_fence *fence)
{
	return "amdxdna";
}

static const char *ve2_ctx_switch_fence_get_timeline_name(struct dma_fence *fence)
{
	return "context_switch";
}

static const struct dma_fence_ops ve2_ctx_switch_fence_ops = {
	.get_driver_name = ve2_ctx_switch_fence_get_driver_name,
	.get_timeline_name = ve2_ctx_switch_fence_get_timeline_name,
};

/**
 * ve2_create_context_switch_fence - Create a fence that signals when context switch is allowed
 * @mgmtctx: Management context
 *
 * Called from run_job() CASE 3 when partition is busy.
 * Fence will be signaled from IRQ when partition becomes idle.
 *
 * Returns: DMA fence that will be signaled on context switch completion
 */
struct dma_fence *ve2_create_context_switch_fence(struct amdxdna_mgmtctx *mgmtctx)
{
	struct amdxdna_dev *xdna = mgmtctx->xdna;
	struct dma_fence *fence;
	unsigned long flags;

	fence = kzalloc(sizeof(*fence), GFP_KERNEL);
	if (!fence) {
		XDNA_ERR(xdna, "[CTX_SWITCH_FENCE] Failed to allocate fence");
		return ERR_PTR(-ENOMEM);
	}

	spin_lock_irqsave(&mgmtctx->ctx_switch_lock, flags);

	/* Release previous fence if it exists and is signaled */
	if (mgmtctx->ctx_switch_fence && dma_fence_is_signaled(mgmtctx->ctx_switch_fence)) {
		dma_fence_put(mgmtctx->ctx_switch_fence);
		mgmtctx->ctx_switch_fence = NULL;
	}

	/* Initialize fence */
	dma_fence_init(fence, &ve2_ctx_switch_fence_ops, &mgmtctx->ctx_switch_lock,
		       dma_fence_context_alloc(1), ++mgmtctx->ctx_switch_seqno);

	/* Store fence so IRQ can signal it */
	mgmtctx->ctx_switch_fence = dma_fence_get(fence);

	spin_unlock_irqrestore(&mgmtctx->ctx_switch_lock, flags);

	XDNA_INFO(xdna, "[CTX_SWITCH_FENCE] Created fence=%p seqno=%llu for partition start_col=%u",
		  fence, mgmtctx->ctx_switch_seqno, mgmtctx->start_col);

	return fence;
}

/**
 * ve2_signal_context_switch_fence - Signal context switch fence
 * @mgmtctx: Management context
 *
 * Called from IRQ handler when firmware ACKs context switch request.
 * This happens when:
 * 1. ve2_request_context_switch() was called (sets is_context_req=1)
 * 2. Firmware completes active context and ACKs (ve2_check_context_req sets is_idle_due_to_context=1)
 * 3. Partition becomes idle (is_partition_idle=1)
 *
 * Signals the fence that jobs waiting in CASE 3 are blocked on.
 */
void ve2_signal_context_switch_fence(struct amdxdna_mgmtctx *mgmtctx)
{
	struct amdxdna_dev *xdna = mgmtctx->xdna;
	struct dma_fence *fence;
	unsigned long flags;

	spin_lock_irqsave(&mgmtctx->ctx_switch_lock, flags);

	fence = mgmtctx->ctx_switch_fence;
	if (!fence) {
		spin_unlock_irqrestore(&mgmtctx->ctx_switch_lock, flags);
		return;
	}

	if (dma_fence_is_signaled(fence)) {
		XDNA_DBG(xdna, "[CTX_SWITCH_FENCE] Fence already signaled: fence=%p seqno=%llu",
			 fence, fence->seqno);
		spin_unlock_irqrestore(&mgmtctx->ctx_switch_lock, flags);
		return;
	}

	XDNA_INFO(xdna, "[CTX_SWITCH_FENCE] Signaling fence=%p seqno=%llu for partition start_col=%u",
		  fence, fence->seqno, mgmtctx->start_col);

	/* Signal the fence - this will wake DRM scheduler to retry waiting job */
	dma_fence_signal(fence);

	/* Clear the reference */
	dma_fence_put(mgmtctx->ctx_switch_fence);
	mgmtctx->ctx_switch_fence = NULL;

	spin_unlock_irqrestore(&mgmtctx->ctx_switch_lock, flags);
}

/*
 * ===========================================================================
 * DRM Scheduler Callbacks
 * ===========================================================================
 */

/**
 * ve2_sched_run_job - Execute a job on the hardware
 * @sched_job: DRM scheduler job to execute
 *
 * DRM Scheduler Integration - Correct Model
 *
 * KEY INSIGHT:
 * - s_fence->finished: Signals when hwctx gets SCHEDULED (handshake done)
 * - job->fence: Signals when job COMPLETES on hardware (signaled in cmd_wait)
 *
 * FLOW:
 * - CASE 1 (same hwctx): Just notify FW, signal s_fence immediately
 * - CASE 2 (can switch): Do handshake, signal s_fence immediately
 * - CASE 3 (partition busy): Return s_fence WITHOUT signaling
 *   → DRM scheduler keeps job queued and waits
 *   → IRQ calls drm_sched_run_queue() to wake scheduler
 *   → Scheduler retries run_job() when partition becomes idle
 */
static struct dma_fence *ve2_sched_run_job(struct drm_sched_job *sched_job)
{
	struct amdxdna_sched_job *job = drm_job_to_xdna_job(sched_job);
	struct amdxdna_ctx *hwctx = job->ctx;
	struct amdxdna_dev *xdna = hwctx->client->xdna;
	struct amdxdna_mgmtctx *mgmtctx = &xdna->dev_handle->ve2_mgmtctx[hwctx->start_col];
	u32 cert_idle_status;
	bool fw_is_idle;
	int ret;

	/* Get scheduler's fence - this is what scheduler waits on */
	mutex_lock(&mgmtctx->ctx_lock);

	XDNA_INFO(xdna, "[RUN_JOB] ENTER: seq=%llu hwctx=%p active_ctx=%p",
		  job->seq, hwctx, mgmtctx->active_ctx);
	XDNA_INFO(xdna, "[DRM_SCHED_PICK] DRM scheduler picked job: seq=%llu hwctx=%p entity=%p job=%p (compare with SEQ_ASSIGN/PUSH order)",
		  job->seq, hwctx, &hwctx->priv->entity, job);

	/* Debug: Show scheduler and entity state */
	XDNA_INFO(xdna, "[RUN_JOB] Scheduler: sched=%p timeout=%ld",
		  &mgmtctx->sched, mgmtctx->sched.timeout);
	XDNA_INFO(xdna, "[RUN_JOB] Entity: entity=%p priority=%u",
		  &hwctx->priv->entity, hwctx->priv->entity.priority);

	/* Check for MISC interrupt */
	ve2_check_misc_interrupt(mgmtctx);
	if (mgmtctx->active_ctx && mgmtctx->active_ctx->priv &&
	    mgmtctx->active_ctx->priv->misc_intrpt_flag) {
		XDNA_ERR(xdna, "MISC interrupt from firmware");
	}

	/* Check context switch ACK */
	ve2_check_context_req(mgmtctx);

	/* Get firmware idle status */
	cert_idle_status = get_cert_idle_status(mgmtctx);
	fw_is_idle = (cert_idle_status & CERT_IS_IDLE) != 0;

	XDNA_INFO(xdna, "[RUN_JOB] FLAGS: is_partition_idle=%u is_idle_due_to_context=%u cert_idle=0x%x fw_idle=%d",
		  mgmtctx->is_partition_idle, mgmtctx->is_idle_due_to_context, cert_idle_status, fw_is_idle);

	/*
	 * THREE CASES:
	 * 1. Same hwctx already active
	 * 2. Can switch to this hwctx (idle/no active/ACK)
	 * 3. Partition busy - defer handshake
	 */

	if (mgmtctx->active_ctx == hwctx) {
		/* CASE 1: Same hwctx - just notify more work */
		XDNA_INFO(xdna, "[RUN_JOB] CASE 1: Same hwctx=%p, notifying FW", hwctx);

		ret = notify_fw_cmd_ready(hwctx);
		if (ret < 0)
			XDNA_ERR(xdna, "[RUN_JOB] CASE 1: notify failed: ret=%d", ret);

		/* Don't signal s_fence manually - will be signaled by drm_sched_job_done() in IRQ */
		XDNA_INFO(xdna, "[RUN_JOB] CASE 1: Command submitted, s_fence will signal on completion");
	}
	else if (!mgmtctx->active_ctx || mgmtctx->is_partition_idle ||
		 mgmtctx->is_idle_due_to_context || fw_is_idle) {
		/* CASE 2: Can switch now */
		XDNA_INFO(xdna, "[RUN_JOB] CASE 2: Switching to hwctx=%p (from active_ctx=%p)",
			  hwctx, mgmtctx->active_ctx);

		/* Debug: Show which condition triggered CASE 2 */
		XDNA_INFO(xdna, "[RUN_JOB] CASE 2: Conditions: !active_ctx=%d is_partition_idle=%d is_idle_due_to_context=%d fw_is_idle=%d",
			  !mgmtctx->active_ctx, mgmtctx->is_partition_idle,
			  mgmtctx->is_idle_due_to_context, fw_is_idle);

                if (mgmtctx->is_partition_idle)
        		mgmtctx->is_partition_idle = 0;

                if (mgmtctx->is_idle_due_to_context)
                        mgmtctx->is_idle_due_to_context = 0;

                XDNA_INFO(xdna, "[RUN_JOB] CASE 2: Performing HANDSHAKE for context switch (was: active_ctx=%p idle_due_to_context=%d)",
                                mgmtctx->active_ctx, mgmtctx->is_idle_due_to_context);

                ve2_mgmt_handshake_init(xdna, hwctx);

                XDNA_INFO(xdna, "[RUN_JOB] CASE 2: Handshake complete, updating active_ctx %p -> %p",
                                mgmtctx->active_ctx, hwctx);
                mgmtctx->active_ctx = hwctx;

		XDNA_INFO(xdna, "[RUN_JOB] CASE 2: Calling notify_fw_cmd_ready for active_ctx %p hwctx=%p", mgmtctx->active_ctx, hwctx);
		ret = notify_fw_cmd_ready(hwctx);
		if (ret < 0)
			XDNA_ERR(xdna, "[RUN_JOB] CASE 2: notify failed: ret=%d", ret);
		else
			XDNA_INFO(xdna, "[RUN_JOB] CASE 2: notify_fw_cmd_ready succeeded");

                /* Debug: Show active ctx queue state */
		if (mgmtctx->active_ctx->priv && mgmtctx->active_ctx->priv->hwctx_hsa_queue.hsa_queue_p) {
			struct ve2_hsa_queue *active_queue = &mgmtctx->active_ctx->priv->hwctx_hsa_queue;
			u64 active_read = active_queue->hsa_queue_p->hq_header.read_index;
			u64 active_write = active_queue->hsa_queue_p->hq_header.write_index;
			XDNA_INFO(xdna, "[RUN_JOB] CASE 3: Active_ctx %p queue: read=%llu write=%llu (pending=%llu)",
				  mgmtctx->active_ctx, active_read, active_write, active_write - active_read);
		}


		/* Don't signal s_fence manually - will be signaled by drm_sched_job_done() in IRQ */
		XDNA_INFO(xdna, "[RUN_JOB] CASE 2: Command submitted, active_ctx now=%p", mgmtctx->active_ctx);
	}
	else {
		/* CASE 3: Partition busy - need to request context switch */
		XDNA_INFO(xdna, "[RUN_JOB] CASE 3: Partition busy, requesting context switch (blocked by active_ctx=%p, is_idle_due_to_context=%u)",
			  mgmtctx->active_ctx, mgmtctx->is_idle_due_to_context);

		/* Debug: Show active ctx queue state */
		if (mgmtctx->active_ctx->priv && mgmtctx->active_ctx->priv->hwctx_hsa_queue.hsa_queue_p) {
			struct ve2_hsa_queue *active_queue = &mgmtctx->active_ctx->priv->hwctx_hsa_queue;
			u64 active_read = active_queue->hsa_queue_p->hq_header.read_index;
			u64 active_write = active_queue->hsa_queue_p->hq_header.write_index;
			XDNA_INFO(xdna, "[RUN_JOB] CASE 3: Active_ctx queue: read=%llu write=%llu (pending=%llu)",
				  active_read, active_write, active_write - active_read);
		}

		/*
		 * CRITICAL: Request context switch from firmware.
		 * Without this, the partition will NEVER become idle for the new hwctx.
		 * The firmware will continue running active_ctx's jobs forever.
		 */
		ve2_request_context_switch(xdna, mgmtctx);

		/*
		 * NEW APPROACH: Return a context switch fence instead of NULL.
		 *
		 * This fence will be signaled from IRQ when partition becomes idle.
		 * DRM scheduler will wait on this fence, and when it signals,
		 * will automatically retry run_job() for this job.
		 *
		 * Benefits over returning NULL:
		 * 1. Job has a fence DRM scheduler can wait on (proper dependency tracking)
		 * 2. No risk of job being dropped if entity destroyed before retry
		 * 3. Fence can be signaled with error if context destroyed prematurely
		 */
		struct dma_fence *ctx_switch_fence = ve2_create_context_switch_fence(mgmtctx);
		if (IS_ERR(ctx_switch_fence)) {
			XDNA_ERR(xdna, "[RUN_JOB] CASE 3: Failed to create context switch fence");
			mutex_unlock(&mgmtctx->ctx_lock);
			return NULL;  /* Fallback to NULL */
		}

		XDNA_INFO(xdna, "[RUN_JOB] CASE 3: Context switch requested, returning fence=%p seqno=%llu",
			  ctx_switch_fence, ctx_switch_fence->seqno);

		mutex_unlock(&mgmtctx->ctx_lock);

		/*
		 * Return context switch fence.
		 * DRM scheduler will wait on this fence.
		 * When IRQ signals it (partition idle), scheduler retries this job.
		 */
		return ctx_switch_fence;
	}

	XDNA_INFO(xdna, "[RUN_JOB] EXIT: seq=%llu hwctx=%p job->fence=%p",
		  job->seq, hwctx, job->fence);
	mutex_unlock(&mgmtctx->ctx_lock);

	/*
	 * Return job->fence (hardware completion fence).
	 * DRM scheduler will wait on this fence.
	 * When we signal job->fence in IRQ, scheduler knows job is done
	 * and will automatically signal s_fence->finished and call free_job().
	 *
	 * NOTE: Don't call dma_fence_get() here. The scheduler "inherits" the
	 * reference from our job struct. We already took a reference in cmd_submit.
	 */
	return job->fence;
}

/**
 * ve2_sched_free_job - Free job resources
 * @sched_job: DRM scheduler job to free
 *
 * Called by DRM scheduler after job completion or cancellation.
 * IMPORTANT: Signal job->fence if completed but not yet signaled.
 * This ensures fences signal even if cmd_wait() is not called.
 */
static void ve2_sched_free_job(struct drm_sched_job *sched_job)
{
	struct amdxdna_sched_job *job = drm_job_to_xdna_job(sched_job);
	struct amdxdna_ctx *hwctx = job->ctx;
	struct amdxdna_dev *xdna = hwctx->client->xdna;

	XDNA_INFO(xdna, "[FREE_JOB] seq=%llu hwctx=%p fence_signaled=%d",
		  job->seq, hwctx, job->fence ? dma_fence_is_signaled(job->fence) : -1);

	/*
	 * CRITICAL: If fence not signaled, signal it with error.
	 * This happens when:
	 * 1. Context destroyed before job executed (entity flushed)
	 * 2. Job returned context_switch_fence but never got to retry
	 *
	 * Ensures userspace doesn't hang waiting on unsignaled fence.
	 */
	if (job->fence && !dma_fence_is_signaled(job->fence)) {
		XDNA_ERR(xdna, "[FREE_JOB] Job dropped before execution, signaling fence with error: seq=%llu",
			 job->seq);
		dma_fence_set_error(job->fence, -ECANCELED);
		dma_fence_signal(job->fence);
	}

	/*
	 * Cleanup scheduler state.
	 */
	drm_sched_job_cleanup(sched_job);
	ve2_job_put(job);
}

/**
 * ve2_sched_timedout_job - Handle job timeout
 */
static enum drm_gpu_sched_stat ve2_sched_timedout_job(struct drm_sched_job *sched_job)
{
	struct amdxdna_sched_job *job = drm_job_to_xdna_job(sched_job);
	struct amdxdna_ctx *hwctx = job->ctx;
	struct amdxdna_dev *xdna = hwctx->client->xdna;
	struct amdxdna_mgmtctx *mgmtctx;

	mgmtctx = &xdna->dev_handle->ve2_mgmtctx[hwctx->start_col];

	XDNA_ERR(xdna, "[TIMEOUT] DRM scheduler job timeout: seq=%llu hwctx=%p", job->seq, hwctx);

	if (hwctx->priv && hwctx->priv->hwctx_hsa_queue.hsa_queue_p) {
		struct ve2_hsa_queue *queue = &hwctx->priv->hwctx_hsa_queue;
		u64 read_idx = queue->hsa_queue_p->hq_header.read_index;
		u64 write_idx = queue->hsa_queue_p->hq_header.write_index;
		u64 reserved_wr = queue->reserved_write_index;

		XDNA_ERR(xdna, "[TIMEOUT] HSA Queue: read_idx=%llu write_idx=%llu reserved_wr=%llu",
			 read_idx, write_idx, reserved_wr);
	}

	ve2_dump_debug_state(xdna, mgmtctx);

	if (hwctx->priv)
		hwctx->priv->misc_intrpt_flag = true;

	return DRM_GPU_SCHED_STAT_ENODEV;
}

static const struct drm_sched_backend_ops ve2_sched_ops = {
	.run_job = ve2_sched_run_job,
	.free_job = ve2_sched_free_job,
	.timedout_job = ve2_sched_timedout_job,
};

/*
 * ===========================================================================
 * DRM Scheduler Management
 * ===========================================================================
 */

/**
 * ve2_drm_init_scheduler - Initialize DRM scheduler for a partition
 */
int ve2_drm_init_scheduler(struct amdxdna_mgmtctx *mgmtctx)
{
	struct amdxdna_dev *xdna = mgmtctx->xdna;
	struct drm_gpu_scheduler *sched = &mgmtctx->sched;
	unsigned long timeout_ms = 2000;
	int ret;

	XDNA_INFO(xdna, "*** NEW_DRIVER_V18: DRM Scheduler - Set cmd BO state via ve2_process_hqc_completion ***");
	XDNA_INFO(xdna, "DEBUG: Calling drm_sched_init for partition start_col=%u sched=%p",
		  mgmtctx->start_col, sched);

	/* Initialize context switch fence mechanism */
	spin_lock_init(&mgmtctx->ctx_switch_lock);
	mgmtctx->ctx_switch_fence = NULL;
	mgmtctx->ctx_switch_seqno = 0;

	ret = drm_sched_init(sched, &ve2_sched_ops,
			     NULL,					/* NULL = create own workqueue */
			     DRM_SCHED_PRIORITY_COUNT,			/* num_rqs (priority count) */
			     1,						/* hw_jobs_limit: 1 for temporal sharing */
			     0,						/* hang_limit (0 = disabled) */
			     msecs_to_jiffies(timeout_ms),		/* timeout */
			     NULL,					/* timeout_wq */
			     NULL,					/* atomic_timeout_wq */
			     "ve2_mgmt",				/* name */
			     mgmtctx->xdna->ddev.dev);			/* dev */
	if (ret) {
		XDNA_ERR(xdna, "Failed to initialize DRM scheduler: ret=%d", ret);
		return ret;
	}

	XDNA_INFO(xdna, "DRM scheduler initialized for partition start_col=%u sched=%p ready=%d",
		  mgmtctx->start_col, sched, sched->ready);
	return 0;
}

/**
 * ve2_drm_fini_scheduler - Cleanup DRM scheduler for a partition
 */
void ve2_drm_fini_scheduler(struct amdxdna_mgmtctx *mgmtctx)
{
	struct amdxdna_dev *xdna = mgmtctx->xdna;
	unsigned long flags;

	XDNA_INFO(xdna, "Destroying DRM scheduler for partition start_col=%u", mgmtctx->start_col);

	/* Cleanup context switch fence */
	spin_lock_irqsave(&mgmtctx->ctx_switch_lock, flags);
	if (mgmtctx->ctx_switch_fence) {
		/* Signal with error if still pending */
		if (!dma_fence_is_signaled(mgmtctx->ctx_switch_fence)) {
			dma_fence_set_error(mgmtctx->ctx_switch_fence, -ECANCELED);
			dma_fence_signal(mgmtctx->ctx_switch_fence);
		}
		dma_fence_put(mgmtctx->ctx_switch_fence);
		mgmtctx->ctx_switch_fence = NULL;
	}
	spin_unlock_irqrestore(&mgmtctx->ctx_switch_lock, flags);

	drm_sched_fini(&mgmtctx->sched);
	synchronize_rcu();
}

/*
 * ===========================================================================
 * Hardware Context DRM Scheduler Integration
 * ===========================================================================
 */

int ve2_drm_hwctx_init(struct amdxdna_ctx *hwctx)
{
	struct amdxdna_dev *xdna = hwctx->client->xdna;
	struct amdxdna_ctx_priv *priv = hwctx->priv;
	struct amdxdna_mgmtctx *mgmtctx = &xdna->dev_handle->ve2_mgmtctx[hwctx->start_col];
	int ret;

	priv->sched = &mgmtctx->sched;

	/*
	 * Initialize last_fence_signaled to current queue read_index.
	 * This ensures we only signal fences for jobs submitted after this hwctx
	 * was created, not for jobs that completed before.
	 */
	priv->last_fence_signaled = 0;
	XDNA_INFO(xdna, "[DRM_INIT] Initialized last_fence_signaled=%llu from queue read_index",
		  priv->last_fence_signaled);

	mutex_init(&priv->drm_submit_lock);

	ret = drm_sched_entity_init(&priv->entity,
				    DRM_SCHED_PRIORITY_NORMAL,
				    &priv->sched, 1,
				    NULL);
	if (ret) {
		XDNA_ERR(xdna, "Failed to initialize DRM scheduler entity: ret=%d", ret);
		priv->sched = NULL;
		return ret;
	}

	XDNA_INFO(xdna, "[ENTITY_INIT] Created entity=%p for hwctx=%p on scheduler=%p (start_col=%u)",
		  &priv->entity, hwctx, &mgmtctx->sched, mgmtctx->start_col);
	XDNA_INFO(xdna, "[ENTITY_INIT] Entity now registered with DRM scheduler, can receive jobs");
	return 0;
}

void ve2_drm_hwctx_fini(struct amdxdna_ctx *hwctx)
{
	struct amdxdna_ctx_priv *nhwctx = hwctx->priv;

	if (nhwctx->sched)
		drm_sched_entity_destroy(&hwctx->priv->entity);
}

/*
 * ===========================================================================
 * Job Completion Handling
 * ===========================================================================
 */

/**
 * ve2_drm_signal_fences - Signal fences for completed jobs
 * @hwctx: Hardware context
 * @read_index: Current read index from hardware
 *
 * Called from IRQ handler when jobs complete.
 * Calls drm_sched_job_done() for completed jobs to signal s_fence.
 * Also signals job->fence (completion fence) for XRT to wait on.
 */
void ve2_drm_signal_fences(struct amdxdna_ctx *hwctx, u64 read_index)
{
	struct amdxdna_ctx_priv *priv = hwctx->priv;
	struct amdxdna_dev *xdna = hwctx->client->xdna;
	struct amdxdna_sched_job *job;
	u64 seq;

	if (!priv || !xdna) {
		pr_err("[IRQ_FENCE] NULL priv=%p or xdna=%p for hwctx=%p\n", priv, xdna, hwctx);
		return;
	}

	XDNA_INFO(xdna, "[IRQ_FENCE] ENTER: hwctx=%p read_index=%llu last_fence_signaled=%llu",
		  hwctx, read_index, priv->last_fence_signaled);

	mutex_lock(&priv->privctx_lock);

	XDNA_INFO(xdna, "[IRQ_FENCE] After lock: signaling from seq=%llu to seq=%llu",
		  priv->last_fence_signaled, read_index);

	/*
	 * Signal fences for all completed jobs from last_fence_signaled to read_index.
	 *
	 * For cmd_chains: Multiple slots may be used but only the LAST slot has a job.
	 * Example: cmd_chain uses slots 0,1 → seq=1 assigned to slot 1, slot 0 has no job.
	 * When read_index advances from 0 to 2, we iterate seq 0,1 but only seq=1 has a job.
	 *
	 * Solution: Continue through NULL entries (they're intermediate chain slots),
	 * but always update last_fence_signaled to avoid re-checking them.
	 */
	for (seq = priv->last_fence_signaled; seq < read_index; seq++) {
		u32 idx = get_job_idx(seq);
		job = priv->pending[idx];

		XDNA_INFO(xdna, "[PENDING_CHECK] Checking pending[%u] for seq=%llu: job=%p",
			  idx, seq, job);

		if (!job) {
			/*
			 * No job at this sequence - likely an intermediate slot in a cmd_chain.
			 * Continue to next sequence, but update last_fence_signaled.
			 */
			XDNA_INFO(xdna, "[IRQ] No job in pending[%u] for seq=%llu (likely cmd_chain intermediate slot)",
				  idx, seq);
			priv->last_fence_signaled = seq;
			continue;
		}

		XDNA_INFO(xdna, "[IRQ] Completing job seq=%llu hwctx=%p job=%p", seq, hwctx, job);

		/*
		 * CRITICAL: Process HQC completion to set command BO state.
		 * XRT reads this state to determine job completion status.
		 * Must be called BEFORE signaling fence!
		 */
		ve2_process_hqc_completion(xdna, hwctx, job, seq);

		/*
		 * Signal job->fence (hardware completion fence).
		 * DRM scheduler is waiting on this fence (returned from run_job).
		 * When it signals, the scheduler automatically:
		 * 1. Signals s_fence->finished
		 * 2. Calls free_job() callback
		 */
		if (job->fence && !dma_fence_is_signaled(job->fence)) {
			dma_fence_signal(job->fence);
		}

		/*
		 * Clear pending array IMMEDIATELY after signaling fence.
		 * Update last_fence_signaled to seq+1 to track progress.
		 */
		priv->pending[idx] = NULL;
		priv->last_fence_signaled = seq;
		XDNA_INFO(xdna, "[IRQ] Signaled fence for seq=%llu, updated last_fence_signaled=%llu",
			  seq, priv->last_fence_signaled);
	}

	/* Check if this hwctx has more pending jobs */
	{
		struct ve2_hsa_queue *queue = &priv->hwctx_hsa_queue;
		u64 read_idx = queue->hsa_queue_p->hq_header.read_index;
		u64 write_idx = queue->hsa_queue_p->hq_header.write_index;
		u64 pending = write_idx - read_idx;

		XDNA_INFO(xdna, "[IRQ_FENCE] Queue state after completion: hwctx=%p read=%llu write=%llu pending=%llu",
			  hwctx, read_idx, write_idx, pending);

		if (pending == 0) {
			XDNA_INFO(xdna, "[IRQ_FENCE] *** hwctx=%p has NO MORE pending jobs (queue empty) ***", hwctx);
		} else {
			XDNA_INFO(xdna, "[IRQ_FENCE] hwctx=%p still has %llu pending jobs in queue", hwctx, pending);
		}
	}

	mutex_unlock(&priv->privctx_lock);

	/* Wake up all waiters - for cmd_wait if it's being used */
	wake_up_interruptible_all(&priv->waitq);
}

/**
 * ve2_drm_kick_scheduler - Wake DRM scheduler to retry waiting jobs
 * @mgmtctx: Management context
 *
 * Called from IRQ when partition becomes idle.
 * Tells DRM scheduler to re-evaluate runnable jobs.
 */
void ve2_drm_kick_scheduler(struct amdxdna_mgmtctx *mgmtctx)
{
	struct amdxdna_dev *xdna = mgmtctx->xdna;

	XDNA_INFO(xdna, "[KICK] Waking DRM scheduler for partition start_col=%u", mgmtctx->start_col);

	/*
	 * drm_sched_wqueue_start() wakes the scheduler to retry waiting jobs.
	 * Jobs that returned NULL in run_job() will be retried.
	 */
	drm_sched_wqueue_start(&mgmtctx->sched);
}

/*
 * ===========================================================================
 * Job Submission
 * ===========================================================================
 */

/**
 * ve2_drm_cmd_submit - Submit command using DRM scheduler
 */
int ve2_drm_cmd_submit(struct amdxdna_sched_job *job, u64 seq)
{
	struct amdxdna_ctx *hwctx = job->ctx;
	struct amdxdna_dev *xdna = hwctx->client->xdna;
	struct amdxdna_ctx_priv *priv = hwctx->priv;
	int ret;

	XDNA_INFO(xdna, "[CMD_SUBMIT] ENTER: hwctx=%p seq=%llu", hwctx, seq);

	/* Print HSA queue state */
	if (priv && priv->hwctx_hsa_queue.hsa_queue_p) {
		struct ve2_hsa_queue *queue = &priv->hwctx_hsa_queue;
		u64 read_idx = queue->hsa_queue_p->hq_header.read_index;
		u64 write_idx = queue->hsa_queue_p->hq_header.write_index;
		u64 reserved_wr = queue->reserved_write_index;
		XDNA_INFO(xdna, "[CMD_SUBMIT] HSA Queue: read_idx=%llu write_idx=%llu reserved_wr=%llu",
			  read_idx, write_idx, reserved_wr);
	}

	/*
	 * NOTE: Mutex is already held by ve2_cmd_submit() caller to protect
	 * the entire submission path from slot reservation through DRM push.
	 */

	/* DRM scheduler - initialize and push job */
	ret = drm_sched_job_init(&job->base, &hwctx->priv->entity, 1, NULL);
	if (ret) {
		XDNA_ERR(xdna, "drm_sched_job_init failed: ret=%d", ret);
		return ret;
	}

	XDNA_INFO(xdna, "[DRM_SCHED_PUSH] Before arm: hwctx=%p seq=%llu entity=%p job=%p",
		  hwctx, seq, &hwctx->priv->entity, job);

	/* Arm job - this creates the scheduler fence (s_fence) */
	drm_sched_job_arm(&job->base);

	XDNA_INFO(xdna, "[DRM_SCHED_PUSH] Before push: hwctx=%p seq=%llu s_fence=%p job->fence=%p",
		  hwctx, seq, job->base.s_fence, job->fence);

	/* Push to DRM scheduler */
	drm_sched_entity_push_job(&job->base);

	XDNA_INFO(xdna, "[CMD_SUBMIT] Job pushed to entity queue: hwctx=%p seq=%llu entity=%p",
		  hwctx, seq, &hwctx->priv->entity);
	XDNA_INFO(xdna, "[CMD_SUBMIT] Scheduler: sched=%p timeout=%ld",
		  priv->sched, priv->sched->timeout);
	XDNA_INFO(xdna, "[CMD_SUBMIT] EXIT: DRM job pushed seq=%llu (s_fence for scheduling, job->fence for completion)",
		  seq);
	return 0;
}

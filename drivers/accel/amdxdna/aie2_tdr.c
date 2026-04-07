// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2026, Advanced Micro Devices, Inc.
 */

/*
 * AIE2 TDR (Timeout Detection and Recovery for legacy kernels)
 *
 * This file provides TDR detection logic for older linux kernels.
 * A standalone TDR timer is used for AIE2 devices.
 *
 * Standalone TDR timer for older kernels:
 *    The DRM scheduler timeout is set to MAX_SCHEDULE_TIMEOUT (effectively
 *    infinite). A delayed_work fires every tdr_timeout_ms to call
 *    aie2_legacy_tdr_detect(). On stall, aie2_tdr_recover_all()
 *    iterates all stuck contexts, dumps health, and performs stop/restart.
 *
 * Detection uses a two-phase approach to avoid false positives: each call
 * compares the current TDR status against the previous progress snapshot.
 * A stall is confirmed only when no signal (from job completion or submission)
 * has occurred across two consecutive intervals while jobs remain pending.
 */

#ifndef HAVE_6_17_drm_gpu_sched_stat_no_hang
#include "aie2_pci.h"
#include "amdxdna_pci_drv.h"
#include "amdxdna_ctx.h"
#include <linux/jiffies.h>

#define TDR_TIMEOUT_JIFF msecs_to_jiffies(tdr_timeout_ms)

static int aie2_legacy_tdr_hwctx_pending(struct amdxdna_hwctx *hwctx, void *arg)
{
	u64 submit_cnt = atomic64_read(&hwctx->job_submit_cnt);

	if (submit_cnt > hwctx->priv->completed)
		return 1;

	return 0;
}

static bool aie2_legacy_tdr_detect(struct amdxdna_dev *xdna)
{
	struct amdxdna_dev_hdl *ndev = xdna->dev_handle;
	struct amdxdna_client *client;
	enum aie2_tdr_status tdr;
	int pending = 0;

	/* Check if there are any pending jobs */
	amdxdna_for_each_client(xdna, client) {
		pending = amdxdna_hwctx_walk(client, NULL, aie2_legacy_tdr_hwctx_pending);
		if (pending)
			break;
	}

	tdr = READ_ONCE(ndev->tdr.status);
	if (pending && tdr == AIE2_TDR_WAIT && ndev->tdr.progress == tdr) {
		XDNA_ERR(xdna, "TDR timeout detected");
		return true;
	}

	if (tdr != AIE2_TDR_WAIT)
		WRITE_ONCE(ndev->tdr.status, AIE2_TDR_WAIT);
	else if (!pending)
		/*
		 * this is to avoid false positives. In submission, the counter is increased after
		 * the job is submitted to the drm scheduler but tdr signal is in job run time.
		 */
		tdr = AIE2_TDR_SIGNALED;

	ndev->tdr.progress = tdr;

	return false;
}

static void aie2_tdr_dump_health_report(struct amdxdna_dev *xdna,
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

static int aie2_tdr_stop_hwctx(struct amdxdna_hwctx *hwctx, void *arg)
{
	struct amdxdna_dev *xdna = hwctx->client->xdna;
	struct app_health_report *report = NULL;
	struct drm_gpu_scheduler *sched;
	struct drm_sched_job *s_job;
	int ret;

	report = kzalloc_obj(*report);
	if (report) {
		ret = aie2_query_app_health(xdna->dev_handle, hwctx->fw_ctx_id, report);
		if (ret) {
			kfree(report);
			report = NULL;
		} else if (tdr_dump_only) {
			aie2_tdr_dump_health_report(xdna, report);
			kfree(report);
		}
	}

	if (tdr_dump_only)
		return 0;

	sched = &hwctx->priv->sched;
	drm_sched_stop(sched, NULL);
	/*
	 * On older kernels (before 6.17), drm_sched_entity
	 * exposes the pending_list directly for each scheduler.
	 * It is safe to access sched->pending_list here as the
	 * list remains available and visible outside the DRM core.
	 * Newer kernels may encapsulate or change this, but for
	 * legacy compatibility, this direct access is intentional.
	 */
	s_job = list_first_entry_or_null(&sched->pending_list, struct drm_sched_job, list);
	if (s_job && report) {
		struct amdxdna_sched_job *job;

		job = drm_job_to_xdna_job(s_job);
		job->job_timeout = true;
		job->aie2_job_health = report;
		report = NULL;
	}

	kfree(report);

	aie2_destroy_context(xdna->dev_handle, hwctx);
#ifdef HAVE_6_13_drm_sched_start_errno
	drm_sched_start(sched, 0);
#elif defined(HAVE_6_10_drm_sched_start_full_recovery)
	drm_sched_start(sched, true);
#else
	drm_sched_start(sched);
#endif

	return 0;
}

static void aie2_tdr_recover_all(struct amdxdna_dev *xdna)
{
	struct amdxdna_client *client;

	amdxdna_for_each_client(xdna, client) {
		amdxdna_hwctx_walk(client, NULL, aie2_tdr_stop_hwctx);
		aie2_hwctx_resume(client);
	}
}

static void aie2_tdr_work_func(struct work_struct *work)
{
	struct aie2_tdr *tdr = container_of(work, struct aie2_tdr, work.work);
	struct amdxdna_dev_hdl *ndev = container_of(tdr, struct amdxdna_dev_hdl, tdr);
	struct amdxdna_dev *xdna = ndev->aie.xdna;

	guard(mutex)(&xdna->dev_lock);

	if (aie2_legacy_tdr_detect(xdna)) {
		XDNA_WARN(xdna, "Device isn't making progress");
		aie2_tdr_recover_all(xdna);
	}

	schedule_delayed_work(&tdr->work, TDR_TIMEOUT_JIFF);
}

void aie2_tdr_start(struct amdxdna_dev *xdna)
{
	struct aie2_tdr *tdr = &xdna->dev_handle->tdr;

	if (tdr_timeout_ms <= 0) {
		XDNA_DBG(xdna, "TDR timeout disabled, watchdog not started");
		return;
	}

	tdr->progress = AIE2_TDR_SIGNALED;
	INIT_DELAYED_WORK(&tdr->work, aie2_tdr_work_func);
	schedule_delayed_work(&tdr->work, TDR_TIMEOUT_JIFF);
	XDNA_DBG(xdna, "TDR timer started, interval %d ms", tdr_timeout_ms);
}

/*
 * aie2_tdr_stop - Stop the TDR timer.
 *
 * Called from aie2_fini() during device removal with dev_lock held.
 * Must temporarily drop dev_lock before cancel_delayed_work_sync()
 * because the TDR work function also acquires dev_lock.
 */
void aie2_tdr_stop(struct amdxdna_dev *xdna)
{
	struct aie2_tdr *tdr = &xdna->dev_handle->tdr;

	if (tdr_timeout_ms <= 0)
		return;

	drm_WARN_ON(&xdna->ddev, !mutex_is_locked(&xdna->dev_lock));

	mutex_unlock(&xdna->dev_lock);
	cancel_delayed_work_sync(&tdr->work);
	mutex_lock(&xdna->dev_lock);

	XDNA_DBG(xdna, "TDR timer stopped");
}

#endif /* HAVE_6_17_drm_gpu_sched_stat_no_hang */

// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2026, Advanced Micro Devices, Inc.
 */

/*
 * AIE2 TDR (Timeout Detection and Recovery)
 *
 * A standalone TDR timer is used for AIE2 devices. A delayed_work fires
 * every tdr_timeout_ms and performs two tasks:
 *
 * 1. Dead firmware detection: aie2_tdr_dead_fw_detect() checks for a device-
 *    wide stall. On stall, aie2_tdr_dead_fw_recover_all() iterates all stuck
 *    contexts, dumps health, and performs stop/restart. Detection uses a
 *    two-phase approach: a stall is confirmed only when no signal (from job
 *    completion or submission) has occurred across two consecutive intervals
 *    while jobs remain pending.
 *
 * 2. Starvation detection: aie2_tdr_starvation_detect_and_recover() checks
 *    each non-realtime context for lack of progress while jobs are outstanding.
 *    A starved context is temporarily boosted to realtime priority via
 *    aie2_set_context_priority() and restored when progress resumes.
 */

#include "aie2_pci.h"
#include "amdxdna_coredump.h"
#include "amdxdna_drv.h"
#include "amdxdna_ctx.h"
#include <linux/jiffies.h>

#define TDR_TIMEOUT_JIFF msecs_to_jiffies(tdr_timeout_ms)

static int aie2_tdr_hwctx_pending(struct amdxdna_hwctx *hwctx, void *arg)
{
	if (atomic64_read(&hwctx->job_submit_cnt) > atomic64_read(&hwctx->job_free_cnt))
		return 1;

	return 0;
}

static bool aie2_tdr_dead_fw_detect(struct amdxdna_dev *xdna)
{
	struct amdxdna_dev_hdl *ndev = xdna->dev_handle;
	struct amdxdna_client *client;
	enum aie2_tdr_status tdr;
	int pending = 0;

	/* Check if there are any pending jobs */
	amdxdna_for_each_client(xdna, client) {
		pending = amdxdna_hwctx_walk(client, NULL, NULL, aie2_tdr_hwctx_pending);
		if (pending)
			break;
	}

	tdr = READ_ONCE(ndev->tdr_status);
	if (pending && tdr == AIE2_TDR_WAIT && ndev->tdr.progress == tdr) {
		XDNA_ERR(xdna, "TDR timeout detected");
		return true;
	}

	if (tdr != AIE2_TDR_WAIT)
		WRITE_ONCE(ndev->tdr_status, AIE2_TDR_WAIT);
	else if (!pending)
		/*
		 * Avoid false positives: job_submit_cnt is incremented before
		 * aie2_tdr_signal() fires in aie2_job_run(). If no jobs are
		 * pending, treat as signaled so the next interval starts fresh.
		 */
		tdr = AIE2_TDR_SIGNALED;

	ndev->tdr.progress = tdr;

	return false;
}

static int aie2_tdr_stop_hwctx(struct amdxdna_hwctx *hwctx, void *arg)
{
	struct amdxdna_dev *xdna = hwctx->client->xdna;
	struct amdxdna_dev_hdl *ndev = xdna->dev_handle;
	struct app_health_report *report = NULL;
	bool *fw_dead = arg;
	int ret;

	report = kzalloc_obj(*report);
	if (report) {
		ret = aie2_query_app_health(ndev, hwctx->fw_ctx_id, report);
		if (ret) {
			kfree(report);
			report = NULL;
		}
	}

	if (xdna->auto_coredump) {
		kvfree(hwctx->coredump);
		hwctx->coredump = amdxdna_get_hwctx_coredump(hwctx);
		if (IS_ERR(hwctx->coredump)) {
			XDNA_ERR(xdna, "Failed to get core dump on hwctx timing out: %ld",
				 PTR_ERR(hwctx->coredump));
			hwctx->coredump = NULL;
		}
	}

	kfree(hwctx->priv->cached_health);
	/*
	 * dev_lock is held here but is not what protects this assignment against
	 * response handlers — those do not acquire dev_lock. The ordering is what
	 * makes this safe: cached_health is set before aie2_destroy_context()
	 * stops the mailbox channel and drains pending callbacks. Response handlers
	 * only check cached_health when data == NULL, which only happens during
	 * that drain, so cached_health is always fully set by then.
	 */
	hwctx->priv->cached_health = report;

	ret = aie2_hwctx_stop(hwctx);
	if (ret == -ETIME || ret == -ENODEV)
		*fw_dead = true;

	return 0;
}

static int aie2_tdr_resume_hwctx(struct amdxdna_hwctx *hwctx, void *arg)
{
	struct amdxdna_dev *xdna = arg;
	int ret;

	ret = aie2_hwctx_restart(xdna, hwctx);
	if (ret)
		XDNA_ERR(xdna, "%s restart failed, ret %d", hwctx->name, ret);

	/* Always return 0 so the walk visits every context. */
	return 0;
}

static int aie2_hwctx_starvation_detect_and_recover(struct amdxdna_hwctx *hwctx, void *arg)
{
	struct amdxdna_dev *xdna = hwctx->client->xdna;
	u64 submit_cnt, free_cnt;

	/* Realtime contexts cannot be preempted; no starvation possible. */
	if (hwctx->qos.priority == AMDXDNA_QOS_REALTIME_PRIORITY)
		return 0;

	submit_cnt = atomic64_read(&hwctx->job_submit_cnt);
	free_cnt = atomic64_read(&hwctx->job_free_cnt);

	/*
	 * Best-effort starvation detection: no completions since the last
	 * interval (free_cnt unchanged) AND jobs were already outstanding at
	 * the last snapshot (last_submit_cnt > last_free_cnt). This avoids
	 * false positives when a burst of new submissions arrives just before
	 * the interval fires. Boosting a hung job to realtime is harmless —
	 * it does not prevent TDR from recovering it.
	 */
	if (free_cnt == hwctx->priv->starvation_last_free_cnt &&
	    hwctx->priv->starvation_last_submit_cnt > hwctx->priv->starvation_last_free_cnt) {
		if (!hwctx->priv->starvation_priority_boosted) {
			/* Best-effort: mark boosted regardless of return value.
			 * A failed boost is harmless — TDR will recover a hung ctx.
			 */
			aie2_set_context_priority(hwctx, AMDXDNA_QOS_REALTIME_PRIORITY);
			XDNA_WARN_RATELIMITED(xdna, "PID %d fw ctx %d starved, boosted priority",
					      hwctx->client->pid, hwctx->fw_ctx_id);
			hwctx->priv->starvation_priority_boosted = true;
		}
	} else {
		if (hwctx->priv->starvation_priority_boosted) {
			aie2_set_context_priority(hwctx, hwctx->qos.priority);
			XDNA_INFO_RATELIMITED(xdna,
					      "PID %d fw ctx %d not starved, restoring priority",
					      hwctx->client->pid, hwctx->fw_ctx_id);
			hwctx->priv->starvation_priority_boosted = false;
		}
		hwctx->priv->starvation_last_submit_cnt = submit_cnt;
		hwctx->priv->starvation_last_free_cnt = free_cnt;
	}

	return 0;
}

static void aie2_tdr_starvation_detect_and_recover(struct amdxdna_dev *xdna)
{
	struct amdxdna_client *client;

	amdxdna_for_each_client(xdna, client)
		amdxdna_hwctx_walk(client, NULL, NULL, aie2_hwctx_starvation_detect_and_recover);
}

static void aie2_tdr_dead_fw_recover_all(struct amdxdna_dev *xdna)
{
	struct amdxdna_client *client;
	bool fw_dead = false;

	amdxdna_for_each_client(xdna, client)
		amdxdna_hwctx_walk(client, &fw_dead, NULL, aie2_tdr_stop_hwctx);

	if (fw_dead) {
		/*
		 * Firmware did not respond — attempt a best-effort power-cycle.
		 * Context resume is always handled by the loop below regardless
		 * of whether the reset succeeds, so paused jobs are unblocked
		 * and can fail gracefully rather than stalling forever.
		 */
		XDNA_WARN(xdna, "Firmware unresponsive, power-cycling NPU");
		aie2_hw_reset(xdna);
	}

	amdxdna_for_each_client(xdna, client)
		amdxdna_hwctx_walk(client, xdna, NULL, aie2_tdr_resume_hwctx);
}

static void aie2_tdr_work_func(struct work_struct *work)
{
	struct aie2_tdr *tdr = container_of(work, struct aie2_tdr, work.work);
	struct amdxdna_dev_hdl *ndev = container_of(tdr, struct amdxdna_dev_hdl, tdr);
	struct amdxdna_dev *xdna = ndev->aie.xdna;

	guard(mutex)(&xdna->dev_lock);

	if (aie2_tdr_dead_fw_detect(xdna)) {
		XDNA_WARN(xdna, "Device isn't making progress");
		aie2_tdr_dead_fw_recover_all(xdna);
	}

	aie2_tdr_starvation_detect_and_recover(xdna);

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

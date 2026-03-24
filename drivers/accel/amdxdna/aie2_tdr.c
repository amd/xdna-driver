// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2026, Advanced Micro Devices, Inc.
 */

/*
 * AIE2 TDR (Timeout Detection and Recovery)
 *
 * This file provides TDR detection logic, module parameters, and (on older
 * kernels) a standalone TDR timer for AIE2 devices in the AMD XDNA driver.
 *
 * Two mechanisms are used depending on kernel capabilities:
 *
 * 1. DRM scheduler timeout with NO_HANG (kernel >= 6.17):
 *    The DRM scheduler fires a timeout every tdr_timeout_ms. The timedout_job
 *    callback (in aie2_ctx.c) calls aie2_tdr_detect() and returns NO_HANG if
 *    the device is still making progress, avoiding unnecessary recovery.
 *
 * 2. Standalone TDR timer (older kernels):
 *    The DRM scheduler timeout is set to MAX_SCHEDULE_TIMEOUT (effectively
 *    infinite). A delayed_work fires every tdr_timeout_ms to call
 *    aie2_tdr_detect(). On stall, aie2_tdr_recover_all() (in aie2_ctx.c)
 *    iterates all stuck contexts, dumps health, and performs stop/restart.
 *
 * Detection uses a two-phase approach to avoid false positives: each call
 * compares the current TDR status against the previous progress snapshot.
 * A stall is confirmed only when no signal (from job completion or submission)
 * has occurred across two consecutive intervals while jobs remain pending.
 */

#include "aie2_pci.h"
#include "amdxdna_pci_drv.h"
#include "amdxdna_ctx.h"
#include <linux/jiffies.h>

#define TDR_TIMEOUT_MS 2000
int tdr_timeout_ms = TDR_TIMEOUT_MS;
module_param(tdr_timeout_ms, int, 0400);
MODULE_PARM_DESC(tdr_timeout_ms, "TDR (Timeout Detection and Recovery) timeout in milliseconds (0 or negative = disable)");
#define TDR_TIMEOUT_JIFF msecs_to_jiffies(tdr_timeout_ms)

bool tdr_dump_only;
module_param(tdr_dump_only, bool, 0600);
MODULE_PARM_DESC(tdr_dump_only, "Only dump health info on timeout, skip recovery (default: false)");

bool aie2_tdr_detect(struct amdxdna_dev *xdna)
{
	struct amdxdna_dev_hdl *ndev = xdna->dev_handle;
	struct amdxdna_client *client;
	struct amdxdna_hwctx *hwctx;
	enum aie2_tdr_status tdr;
	unsigned long hwctx_id;
	bool pending = false;

	drm_WARN_ON(&xdna->ddev, !mutex_is_locked(&xdna->dev_lock));

	/* TDR has been checked less than required TDR timeout period */
	if (!time_after(jiffies, ndev->tdr.last_jiffies + TDR_TIMEOUT_JIFF))
		return false;

	/* Check if there are any pending jobs */
	amdxdna_for_each_client(xdna, client) {
		amdxdna_for_each_hwctx(client, hwctx_id, hwctx) {
			u64 submit_cnt = atomic64_read(&hwctx->job_submit_cnt);

			if (submit_cnt > hwctx->priv->completed) {
				pending = true;
				goto done_scan;
			}
		}
	}
done_scan:

	ndev->tdr.last_jiffies = jiffies;
	tdr = READ_ONCE(ndev->tdr.status);
	if (pending && tdr == AIE2_TDR_WAIT && ndev->tdr.progress == tdr) {
		XDNA_ERR(xdna, "TDR timeout detected");
		return true;
	}

	if (tdr != AIE2_TDR_WAIT)
		WRITE_ONCE(ndev->tdr.status, AIE2_TDR_WAIT);

	ndev->tdr.progress = tdr;

	return false;
}

#ifndef HAVE_6_17_drm_gpu_sched_stat_no_hang
static void aie2_tdr_work_func(struct work_struct *work)
{
	struct aie2_tdr *tdr = container_of(work, struct aie2_tdr, work.work);
	struct amdxdna_dev_hdl *ndev = container_of(tdr, struct amdxdna_dev_hdl, tdr);
	struct amdxdna_dev *xdna = ndev->xdna;

	guard(mutex)(&xdna->dev_lock);

	if (aie2_tdr_detect(xdna)) {
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
#endif

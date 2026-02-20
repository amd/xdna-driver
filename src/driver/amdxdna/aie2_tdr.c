// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2024-2025, Advanced Micro Devices, Inc.
 */

#include <linux/container_of.h>

#include "amdxdna_drm.h"
#include "aie2_pci.h"
#include "aie2_tdr.h"

uint timeout_in_sec = 2;
module_param(timeout_in_sec, uint, 0644);
MODULE_PARM_DESC(timeout_in_sec, "Seconds to timeout and recovery, default 2; 0 - No TDR");

bool tdr_dump_ctx;
module_param(tdr_dump_ctx, bool, 0644);
MODULE_PARM_DESC(tdr_dump_ctx, "Instead of resetting, just dump the ctx info for debugging");

#define TDR_TIMEOUT_JIFF msecs_to_jiffies(timeout_in_sec * 1000)
#define to_tdr(w) \
	((struct aie2_tdr *)container_of(w, struct aie2_tdr, work))
#define tdr_to_xdna(t) \
	(((struct amdxdna_dev_hdl *)container_of(t, struct amdxdna_dev_hdl, tdr))->xdna)

/* This function returns recover is needed or not */
static bool aie2_tdr_detect(struct aie2_tdr *tdr)
{
	struct amdxdna_dev *xdna = tdr_to_xdna(tdr);
	struct aie2_ctx_rq *rq = &xdna->dev_handle->ctx_rq;

	if (aie2_rq_handle_idle_ctx(rq))
		return false;

	return aie2_rq_is_all_context_stuck(rq);
}

/*
 * Progressive recovery escalation.
 *
 * Each consecutive TDR failure escalates to a harder reset:
 *   counter == 1: Soft recovery (context stop/restart)
 *   counter == 2: Firmware reset (suspend/resume firmware)
 *   counter == 3: PCIe FLR (full hardware reset)
 *   counter >= 4: Device declared unrecoverable
 *
 * Success at any level resets the counter to 0. The counter is also
 * reset when the device resumes making progress on its own.
 *
 * Uses manual mutex_lock/unlock instead of guard(mutex) because the
 * FLR path needs to release dev_lock around the PCI reset.
 */
static void aie2_tdr_recover(struct aie2_tdr *tdr, bool dump_only)
{
	struct amdxdna_dev *xdna = tdr_to_xdna(tdr);
	struct amdxdna_dev_hdl *ndev = xdna->dev_handle;
	struct aie2_ctx_rq *rq = &ndev->ctx_rq;
	int ret;

	mutex_lock(&xdna->dev_lock);
	aie2_rq_dump_all(rq);
	if (dump_only) {
		mutex_unlock(&xdna->dev_lock);
		return;
	}

	aie2_rq_stop_all(rq);

	switch (tdr->counter) {
	case 1:
		/* Level 0: Soft recovery -- just restart contexts */
		break;
	case 2:
		/* Level 1: Firmware reset via suspend/resume */
		XDNA_WARN(xdna, "Soft recovery failed, escalating to firmware reset");
		mutex_lock(&ndev->aie2_lock);
		ret = aie2_suspend_fw(ndev);
		if (!ret)
			ret = aie2_resume_fw(ndev);
		mutex_unlock(&ndev->aie2_lock);
		if (ret) {
			XDNA_ERR(xdna, "Firmware reset failed, ret %d", ret);
			goto restart;
		}
		XDNA_INFO(xdna, "Firmware reset successful");
		tdr->counter = 0;
		break;
	case 3:
		/* Level 2: PCIe Function Level Reset */
		XDNA_WARN(xdna, "Firmware reset failed, escalating to FLR");
		/*
		 * Release dev_lock before FLR. aie2_flr() manages its own
		 * locking internally. The runqueue is already stopped and
		 * dev_status will be set to INIT by the teardown, so no
		 * new work can start during this window.
		 */
		mutex_unlock(&xdna->dev_lock);
		ret = aie2_flr(xdna);
		mutex_lock(&xdna->dev_lock);
		if (ret) {
			/*
			 * FLR tears down firmware before the PCI reset.
			 * If the reset itself fails, the device is left
			 * without firmware -- restarting contexts would
			 * crash. Treat as unrecoverable.
			 */
			XDNA_ERR(xdna, "FLR failed (ret %d), device is unrecoverable", ret);
			goto unrecoverable;
		}
		XDNA_INFO(xdna, "FLR successful");
		tdr->counter = 0;
		break;
	default:
unrecoverable:
		/* All recovery exhausted -- device is unrecoverable */
		XDNA_ERR(xdna, "All recovery methods exhausted, device is unrecoverable");
		XDNA_ERR(xdna, "Device requires reboot to restore NPU functionality");
		/*
		 * Stop the timer to prevent further TDR firings.
		 * timer_delete_sync() waits for any concurrent timer
		 * callback to finish, preventing a re-arm race where
		 * the callback's mod_timer() runs after our delete.
		 * Safe from work context (not timer context).
		 */
		timer_delete_sync(&tdr->timer);
		tdr->started = 0;
		mutex_unlock(&xdna->dev_lock);
		return;
	}

restart:
	aie2_rq_restart_all(rq);
	mutex_unlock(&xdna->dev_lock);
}

static void aie2_tdr_work(struct work_struct *work)
{
	struct aie2_tdr *tdr = to_tdr(work);

	if (aie2_tdr_detect(tdr)) {
		XDNA_WARN(tdr_to_xdna(tdr),
			  "Device isn't making progress... Count %d",
			  ++tdr->counter);
		aie2_tdr_recover(tdr, tdr_dump_ctx);
	} else if (tdr->counter) {
		/* Device recovered, reset escalation level */
		tdr->counter = 0;
	}
}

static void aie2_tdr_timer(struct timer_list *t)
{
#if defined from_timer
	struct aie2_tdr *tdr = from_timer(tdr, t, timer);
#elif defined timer_container_of
	struct aie2_tdr *tdr = timer_container_of(tdr, t, timer);
#endif

	queue_work(system_long_wq, &tdr->work);

	mod_timer(t, jiffies + TDR_TIMEOUT_JIFF);
}

void aie2_tdr_start(struct amdxdna_dev *xdna)
{
	struct aie2_tdr *tdr = &xdna->dev_handle->tdr;

	if (!timeout_in_sec) {
		XDNA_DBG(xdna, "timeout_in_sec is zero, watchdog NOT started");
		return;
	}

	timer_setup(&tdr->timer, aie2_tdr_timer, 0);
	INIT_WORK(&tdr->work, aie2_tdr_work);

	tdr->timer.expires = jiffies + TDR_TIMEOUT_JIFF;
	add_timer(&tdr->timer);
	tdr->started = 1;
	XDNA_DBG(xdna, "TDR started, checking activities in every %d secs", timeout_in_sec);
}

void aie2_tdr_stop(struct amdxdna_dev *xdna)
{
	struct aie2_tdr *tdr = &xdna->dev_handle->tdr;

	if (!tdr->started)
		return;

	timer_delete_sync(&tdr->timer);
	cancel_work_sync(&tdr->work);
	XDNA_DBG(xdna, "TDR stopped");
}

// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2026, Advanced Micro Devices, Inc.
 */

#include <linux/jiffies.h>
#include <linux/module.h>

#include "amdxdna_drv.h"
#include "ve2_aux.h"
#include "ve2_hwctx.h"
#include "ve2_mgmt.h"

static uint tdr_timeout_ms = 2000;
module_param(tdr_timeout_ms, uint, 0400);
MODULE_PARM_DESC(tdr_timeout_ms,
		 "TDR (Timeout Detection and Recovery) timeout in milliseconds (0 = disable)");

static unsigned long ve2_tdr_delay(void)
{
	return msecs_to_jiffies(tdr_timeout_ms);
}

static bool ve2_tdr_expired(struct amdxdna_hwctx *hwctx)
{
	struct amdxdna_ctx_priv *vp = ve2_hw_priv(hwctx);

	if (!vp)
		return false;

	if (READ_ONCE(vp->tdr_reset_pending) || READ_ONCE(vp->misc_intrpt_flag))
		return true;

	/*
	 * A debug-queue session stops CERT at a breakpoint and leaves the host
	 * queue outstanding while the test inspects tiles. That pause is the
	 * debug session: debug_queue waits 20 seconds before its first access.
	 * Recovering it tears down the breakpoint and the following debug-queue
	 * read times out.
	 */
	if (enable_debug_queue && vp->dbg_queue.dbg_queue_p) {
		ve2_hwctx_tdr_signal(hwctx);
		return false;
	}

	if (!ve2_hwctx_tdr_pending(hwctx))
		return false;

	return time_after_eq(jiffies,
			     READ_ONCE(vp->tdr_last_progress) + ve2_tdr_delay());
}

static void ve2_tdr_work_func(struct work_struct *work)
{
	struct ve2_tdr *tdr = container_of(to_delayed_work(work), struct ve2_tdr, work);
	struct amdxdna_dev_hdl *hdl = container_of(tdr, struct amdxdna_dev_hdl, tdr);
	struct amdxdna_dev *xdna = hdl->xdna;
	unsigned long flags;
	u32 col;

	guard(mutex)(&xdna->dev_lock);

	for (col = 0; col < hdl->aie_dev_info.cols; col++) {
		struct amdxdna_mgmtctx *mgmtctx = &hdl->ve2_mgmtctx[col];
		struct amdxdna_hwctx *hwctx;

		mutex_lock(&mgmtctx->ctx_lock);
		hwctx = mgmtctx->active_ctx;
		if (!hwctx || !ve2_tdr_expired(hwctx)) {
			mutex_unlock(&mgmtctx->ctx_lock);
			continue;
		}

		XDNA_ERR(xdna, "TDR timeout detected on hwctx %u, partition col %u",
			 hwctx->id, mgmtctx->start_col);
		mutex_unlock(&mgmtctx->ctx_lock);

		if (ve2_mgmt_recover_hwctx(hwctx))
			XDNA_ERR(xdna, "TDR recovery failed for hwctx %u", hwctx->id);
	}

	spin_lock_irqsave(&tdr->lock, flags);
	if (tdr->started)
		schedule_delayed_work(&tdr->work, ve2_tdr_delay());
	spin_unlock_irqrestore(&tdr->lock, flags);
}

void ve2_tdr_start(struct amdxdna_dev *xdna)
{
	struct ve2_tdr *tdr = &ve2_dev_hdl(xdna)->tdr;

	spin_lock_init(&tdr->lock);
	if (!tdr_timeout_ms) {
		XDNA_DBG(xdna, "TDR timeout disabled, watchdog not started");
		return;
	}

	INIT_DELAYED_WORK(&tdr->work, ve2_tdr_work_func);
	tdr->started = true;
	schedule_delayed_work(&tdr->work, ve2_tdr_delay());
	XDNA_DBG(xdna, "TDR timer started, interval %u ms", tdr_timeout_ms);
}

void ve2_tdr_stop(struct amdxdna_dev *xdna)
{
	struct ve2_tdr *tdr = &ve2_dev_hdl(xdna)->tdr;
	unsigned long flags;

	spin_lock_irqsave(&tdr->lock, flags);
	if (!tdr->started) {
		spin_unlock_irqrestore(&tdr->lock, flags);
		return;
	}
	tdr->started = false;
	spin_unlock_irqrestore(&tdr->lock, flags);

	drm_WARN_ON(&xdna->ddev, !mutex_is_locked(&xdna->dev_lock));

	mutex_unlock(&xdna->dev_lock);
	cancel_delayed_work_sync(&tdr->work);
	mutex_lock(&xdna->dev_lock);

	XDNA_DBG(xdna, "TDR timer stopped");
}

void ve2_tdr_queue(struct amdxdna_dev *xdna)
{
	struct ve2_tdr *tdr = &ve2_dev_hdl(xdna)->tdr;
	unsigned long flags;

	spin_lock_irqsave(&tdr->lock, flags);
	if (tdr->started)
		mod_delayed_work(system_wq, &tdr->work, 0);
	spin_unlock_irqrestore(&tdr->lock, flags);
}

bool ve2_tdr_enabled(struct amdxdna_dev *xdna)
{
	struct ve2_tdr *tdr = &ve2_dev_hdl(xdna)->tdr;
	unsigned long flags;
	bool enabled;

	spin_lock_irqsave(&tdr->lock, flags);
	enabled = tdr->started;
	spin_unlock_irqrestore(&tdr->lock, flags);

	return enabled;
}

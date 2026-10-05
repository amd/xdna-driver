// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2026, Advanced Micro Devices, Inc.
 *
 * VE2 timeout recovery is event driven. CERT or the host wait path reports
 * that a command timed out, or an AIE/MISC fault marks the active context.
 * That path queues this work; there is no periodic inactivity watchdog.
 */

#include "amdxdna_drv.h"
#include "ve2_aux.h"
#include "ve2_hwctx.h"
#include "ve2_mgmt.h"

static void ve2_tdr_work_func(struct work_struct *work)
{
	struct ve2_tdr *tdr = container_of(work, struct ve2_tdr, work);
	struct amdxdna_dev_hdl *hdl = container_of(tdr, struct amdxdna_dev_hdl, tdr);
	struct amdxdna_dev *xdna = hdl->xdna;
	u32 col;

	guard(mutex)(&xdna->dev_lock);

	for (col = 0; col < hdl->aie_dev_info.cols; col++) {
		struct amdxdna_mgmtctx *mgmtctx = &hdl->ve2_mgmtctx[col];
		struct amdxdna_ctx_priv *vp;
		struct amdxdna_hwctx *hwctx;

		mutex_lock(&mgmtctx->ctx_lock);
		hwctx = mgmtctx->active_ctx;
		vp = hwctx ? ve2_hw_priv(hwctx) : NULL;
		if (!vp || !READ_ONCE(vp->tdr_reset_pending)) {
			mutex_unlock(&mgmtctx->ctx_lock);
			continue;
		}

		XDNA_ERR(xdna, "TDR recovery queued for hwctx %u, partition col %u",
			 hwctx->id, mgmtctx->start_col);
		mutex_unlock(&mgmtctx->ctx_lock);

		if (ve2_mgmt_recover_hwctx(hwctx))
			XDNA_ERR(xdna, "TDR recovery failed for hwctx %u", hwctx->id);
	}
}

void ve2_tdr_start(struct amdxdna_dev *xdna)
{
	struct ve2_tdr *tdr = &ve2_dev_hdl(xdna)->tdr;

	spin_lock_init(&tdr->lock);
	INIT_WORK(&tdr->work, ve2_tdr_work_func);
	tdr->started = true;
	XDNA_DBG(xdna, "TDR recovery enabled");
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
	cancel_work_sync(&tdr->work);
	mutex_lock(&xdna->dev_lock);

	XDNA_DBG(xdna, "TDR recovery stopped");
}

void ve2_tdr_queue(struct amdxdna_dev *xdna)
{
	struct ve2_tdr *tdr = &ve2_dev_hdl(xdna)->tdr;
	unsigned long flags;

	spin_lock_irqsave(&tdr->lock, flags);
	if (tdr->started)
		queue_work(system_wq, &tdr->work);
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

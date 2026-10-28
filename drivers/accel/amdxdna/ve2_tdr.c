// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2026, Advanced Micro Devices, Inc.
 *
 * VE2 timeout recovery is event driven. CERT or the host wait path reports
 * that a command timed out, or an AIE/MISC fault marks the active context.
 * That path queues this work; there is no periodic inactivity watchdog.
 */

#include <linux/jiffies.h>
#include <linux/list.h>
#include <linux/workqueue.h>

#include "amdxdna_drv.h"
#include "ve2_aux.h"
#include "ve2_hwctx.h"
#include "ve2_mgmt.h"

/* First attempt plus two retries, then the context is marked unusable. */
#define VE2_TDR_MAX_ATTEMPTS	3
#define VE2_TDR_RETRY_MS	200

static void ve2_tdr_work_func(struct work_struct *work)
{
	struct ve2_tdr *tdr = container_of(work, struct ve2_tdr, work.work);
	struct amdxdna_dev_hdl *hdl = container_of(tdr, struct amdxdna_dev_hdl, tdr);
	struct amdxdna_dev *xdna = hdl->xdna;
	bool retry = false;
	u32 col;

	guard(mutex)(&xdna->dev_lock);

	/*
	 * Walk every context on the partition, not only active_ctx. CERT
	 * publishes TIMEOUT through the completion worker, and the
	 * high-priority scheduler can switch the partition before that worker
	 * or this one runs. The faulting context then sits inactive with
	 * tdr_reset_pending set.
	 */
	for (col = 0; col < hdl->aie_dev_info.cols; col++) {
		struct amdxdna_mgmtctx *mgmtctx = &hdl->ve2_mgmtctx[col];
		struct amdxdna_ctx_priv *vp, *tmp;

		mutex_lock(&mgmtctx->ctx_lock);
		list_for_each_entry_safe(vp, tmp, &mgmtctx->ctx_list, partition_link) {
			struct amdxdna_hwctx *hwctx;
			int ret;

			if (!READ_ONCE(vp->tdr_reset_pending) || !vp->hwctx)
				continue;

			hwctx = vp->hwctx;
			XDNA_ERR(xdna, "TDR recovery queued for hwctx %u, partition col %u",
				 hwctx->id, mgmtctx->start_col);
			mutex_unlock(&mgmtctx->ctx_lock);

			ret = ve2_mgmt_recover_hwctx(hwctx);
			/*
			 * A non-zero return with the flag cleared means teardown
			 * halted CERT and the jobs were released. The flag stays
			 * set only when re-init and teardown both failed; nothing
			 * else will interrupt, so retry and then give up.
			 */
			if (ret && READ_ONCE(vp->tdr_reset_pending)) {
				vp->tdr_attempts++;
				if (vp->tdr_attempts < VE2_TDR_MAX_ATTEMPTS) {
					XDNA_ERR(xdna,
						 "TDR recovery failed for hwctx %u (%d), retry %u/%u",
						 hwctx->id, ret, vp->tdr_attempts,
						 VE2_TDR_MAX_ATTEMPTS);
					retry = true;
				} else {
					XDNA_ERR(xdna,
						 "TDR recovery failed for hwctx %u (%d), retries exhausted",
						 hwctx->id, ret);
					ve2_mgmt_tdr_abandon(hwctx);
				}
			} else if (ret) {
				XDNA_ERR(xdna,
					 "TDR re-init failed for hwctx %u (%d); CERT was halted",
					 hwctx->id, ret);
			}

			mutex_lock(&mgmtctx->ctx_lock);
		}
		mutex_unlock(&mgmtctx->ctx_lock);
	}

	if (retry) {
		unsigned long flags;

		spin_lock_irqsave(&tdr->lock, flags);
		if (tdr->started)
			queue_delayed_work(system_wq, &tdr->work,
					   msecs_to_jiffies(VE2_TDR_RETRY_MS));
		spin_unlock_irqrestore(&tdr->lock, flags);
	}
}

void ve2_tdr_start(struct amdxdna_dev *xdna)
{
	struct ve2_tdr *tdr = &ve2_dev_hdl(xdna)->tdr;

	spin_lock_init(&tdr->lock);
	INIT_DELAYED_WORK(&tdr->work, ve2_tdr_work_func);
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
	cancel_delayed_work_sync(&tdr->work);
	mutex_lock(&xdna->dev_lock);

	XDNA_DBG(xdna, "TDR recovery stopped");
}

void ve2_tdr_queue(struct amdxdna_dev *xdna)
{
	struct ve2_tdr *tdr = &ve2_dev_hdl(xdna)->tdr;
	unsigned long flags;

	spin_lock_irqsave(&tdr->lock, flags);
	if (tdr->started)
		queue_delayed_work(system_wq, &tdr->work, 0);
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

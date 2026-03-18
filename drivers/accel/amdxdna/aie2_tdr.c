// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2026, Advanced Micro Devices, Inc.
 */

/*
 * AIE2 TDR (Timeout Detection and Recovery)
 *
 * This file provides the TDR detection logic and module parameters for AIE2
 * devices in the AMD XDNA driver.
 *
 * The DRM scheduler fires a timeout when a submitted job doesn't complete
 * within tdr_timeout_ms. The scheduler's timedout_job callback (in aie2_ctx.c)
 * calls aie2_tdr_detect() to determine whether the device is truly stuck.
 *
 * Detection uses a two-phase approach to avoid false positives: each call
 * compares the current TDR status against the previous progress snapshot.
 * A stall is confirmed only when no signal (from job completion or submission)
 * has occurred across two consecutive intervals while jobs remain pending.
 *
 * Upon detecting a stall, the timedout_job callback queries firmware health,
 * then stops and restarts the affected hardware context.
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

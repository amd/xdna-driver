// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2024-2025, Advanced Micro Devices, Inc.
 */

#include "amdxdna_drm.h"
#include "amdxdna_tdr.h"

uint timeout_in_sec = 2;
module_param(timeout_in_sec, uint, 0644);
MODULE_PARM_DESC(timeout_in_sec, "Seconds to timeout and recovery, default 2; 0 - No TDR");

bool tdr_dump_ctx;
module_param(tdr_dump_ctx, bool, 0644);
MODULE_PARM_DESC(tdr_dump_ctx, "Instead of resetting, just dump the ctx info for debugging");

#define TDR_TIMEOUT_JIFF msecs_to_jiffies(timeout_in_sec * 1000)

static void amdxdna_tdr_work(struct work_struct *work)
{
	struct amdxdna_tdr *tdr = to_tdr(work);
	struct amdxdna_dev *xdna;

	xdna = tdr_to_xdna_dev(tdr);
	if (xdna->dev_info->ops->detect(xdna)) {
		XDNA_WARN(xdna, "Device isn't making progress... Count %d", ++tdr->tdr_counter);
		xdna->dev_info->ops->recover(xdna, tdr_dump_ctx);
	}
}

static void amdxdna_tdr_timer(struct timer_list *t)
{
#if defined from_timer
	struct amdxdna_tdr *tdr = from_timer(tdr, t, timer);
#elif defined timer_container_of
	struct amdxdna_tdr *tdr = timer_container_of(tdr, t, timer);
#endif

	queue_work(system_long_wq, &tdr->tdr_work);

	mod_timer(t, jiffies + TDR_TIMEOUT_JIFF);
}

void amdxdna_tdr_start(struct amdxdna_tdr *tdr)
{
	struct amdxdna_dev *xdna = tdr_to_xdna_dev(tdr);

	if (!xdna->dev_info->ops->recover) {
		XDNA_DBG(xdna, "Not support recovery, watchdog NOT started");
		return;
	}

	if (!timeout_in_sec) {
		XDNA_DBG(xdna, "timeout_in_sec is zero, watchdog NOT started");
		return;
	}

	timer_setup(&tdr->timer, amdxdna_tdr_timer, 0);
	INIT_WORK(&tdr->tdr_work, amdxdna_tdr_work);

	tdr->timer.expires = jiffies + TDR_TIMEOUT_JIFF;
	add_timer(&tdr->timer);
	tdr->started = 1;
	XDNA_DBG(xdna, "Check activities in every %d secs", timeout_in_sec);
}

void amdxdna_tdr_stop(struct amdxdna_tdr *tdr)
{
	struct amdxdna_dev *xdna = tdr_to_xdna_dev(tdr);

	if (!tdr->started)
		return;

	timer_delete_sync(&tdr->timer);
	cancel_work_sync(&tdr->tdr_work);
	XDNA_DBG(xdna, "Timer stopped");
}

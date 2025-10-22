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
#define to_tdr(work) \
	((struct aie2_tdr *)container_of(work, struct aie2_tdr, work))
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

static void aie2_tdr_recover(struct aie2_tdr *tdr, bool dump_only)
{
	struct amdxdna_dev *xdna = tdr_to_xdna(tdr);
	struct aie2_ctx_rq *rq = &xdna->dev_handle->ctx_rq;

	guard(mutex)(&xdna->dev_lock);
	aie2_rq_dump_all(rq);
	if (dump_only)
		return;
	aie2_rq_stop_all(rq);
	aie2_rq_restart_all(rq);
}

static void aie2_tdr_work(struct work_struct *work)
{
	struct aie2_tdr *tdr = to_tdr(work);

	if (aie2_tdr_detect(tdr)) {
		XDNA_WARN(tdr_to_xdna(tdr),
			  "Device isn't making progress... Count %d", ++tdr->counter);
		aie2_tdr_recover(tdr, tdr_dump_ctx);
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

// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2026, Advanced Micro Devices, Inc.
 *
 * VE2 DRM hardware context: XRS, host queue, AIE partition/context.
 */

#include <linux/atomic.h>
#include <linux/errno.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/timer.h>

#include "drm/amdxdna_accel.h"

#include "amdxdna_ctx.h"
#include "amdxdna_drv.h"
#include "ve2_aie.h"
#include "ve2_aux.h"
#include "ve2_hq.h"
#include "ve2_hwctx.h"
#include "ve2_trace.h"
#include "amdxdna_ve2_solver.h"

int ve2_trace;
module_param(ve2_trace, int, 0644);
MODULE_PARM_DESC(ve2_trace,
		 "VE2 trace to dmesg: 0=off, 1=ioctl boundaries, 2=verbose (default 0)");

static void ve2_hwctx_link_init(struct amdxdna_hwctx *hwctx, u32 start_col, u32 num_cols)
{
	struct ve2_hwctx_link *link;

	link = kzalloc(sizeof(*link), GFP_KERNEL);
	if (!link)
		return;

	link->col_config = kcalloc(num_cols, sizeof(*link->col_config), GFP_KERNEL);
	if (!link->col_config) {
		kfree(link);
		return;
	}

	hwctx->start_col = start_col;
	hwctx->num_col = num_cols;
	hwctx->aux_ctx_priv = link;
}

static void ve2_hwctx_link_fini(struct amdxdna_hwctx *hwctx)
{
	struct ve2_hwctx_link *link = hwctx->aux_ctx_priv;

	if (!link)
		return;

	kfree(link->col_config);
	kfree(link);
	hwctx->aux_ctx_priv = NULL;
}

static void ve2_aie_teardown_hwctx(struct amdxdna_dev *xdna, struct amdxdna_hwctx *hwctx)
{
	struct ve2_hwctx_link *link = hwctx->aux_ctx_priv;

	if (!link || !link->aie_ctx)
		return;

	ve2_aie_hwctx_destroy(xdna, link->aie_ctx, link->partition_id);
	link->aie_ctx = NULL;
	link->partition_id = 0;
}

static void ve2_release_xrs(struct amdxdna_dev *xdna, struct amdxdna_hwctx *hwctx)
{
	struct solver_state *xrs = xdna->xrs_hdl;
	struct xrs_action_load la = { };

	if (!xrs)
		return;

	mutex_lock(&xrs->xrs_lock);
	ve2_xrs_release_resource(xrs, (u64)(uintptr_t)hwctx, &la);
	mutex_unlock(&xrs->xrs_lock);
}

int enable_polling;
module_param(enable_polling, int, 0644);
MODULE_PARM_DESC(enable_polling,
		 "Enable host-queue polling timer (wake waitq periodically). Default: interrupt mode.");

#define CTX_TIMER	msecs_to_jiffies(1)

static void ve2_hwctx_poll_timer(struct timer_list *t)
{
	struct ve2_hwctx_priv *vp = from_timer(vp, t, event_timer);
	static atomic_t poll_ticks;

	if (ve2_trace >= 2 && !(atomic_inc_return(&poll_ticks) % 5000)) {
		struct amdxdna_hwctx *hwctx = NULL;
		struct amdxdna_client *client;

		/* Best-effort: vp is embedded in hwctx priv; log tick only */
		(void)hwctx;
		(void)client;
		pr_info("VE2: poll_timer tick (enable_polling=1)\n");
	}

	wake_up_interruptible_all(&vp->waitq);
	mod_timer(&vp->event_timer, jiffies + CTX_TIMER);
}

static int ve2_xrs_align_cols = 4;
module_param(ve2_xrs_align_cols, int, 0644);
MODULE_PARM_DESC(ve2_xrs_align_cols, "VE2 XRS start-column stride (default 4)");

int ve2_hwctx_config_opcode_timeout(struct amdxdna_hwctx *hwctx, u32 op_timeout)
{
	struct ve2_hwctx_link *link = hwctx->aux_ctx_priv;
	u32 col;

	if (!link || !link->col_config)
		return -EINVAL;

	for (col = 0; col < hwctx->num_col; col++)
		link->col_config[col].opcode_timeout_config = op_timeout;

	return 0;
}

void ve2_hwctx_fill_hs_config(struct amdxdna_hwctx *hwctx, struct handshake *hs, u32 col_idx)
{
	struct ve2_hwctx_link *link = hwctx->aux_ctx_priv;

	if (!link || !link->col_config || col_idx >= hwctx->num_col)
		return;

	hs->opcode_timeout_config = link->col_config[col_idx].opcode_timeout_config;
}

/**
 * ve2_hwctx_setup - column list, XRS, host queue, AIE partition/context.
 */
int ve2_hwctx_setup(struct amdxdna_hwctx *hwctx)
{
	struct amdxdna_client *client = hwctx->client;
	struct amdxdna_dev *xdna = client->xdna;
	struct amdxdna_dev_hdl *hdl;
	struct amdxdna_hwctx_priv *priv;
	struct ve2_hwctx_priv *vp;
	struct ve2_hwctx_link *link;
	int ret;

	VE2_TRACE(xdna, "hwctx_setup ENTER pid=%d num_tiles=%u user_start_col=%u",
		  client->pid, hwctx->num_tiles, hwctx->qos.user_start_col);

	hdl = ve2_dev_hdl(xdna);
	if (!hdl)
		return -ENODEV;

	priv = kzalloc(sizeof(*priv), GFP_KERNEL);
	if (!priv)
		return -ENOMEM;

	vp = kzalloc(sizeof(*vp), GFP_KERNEL);
	if (!vp) {
		kfree(priv);
		return -ENOMEM;
	}
	priv->hw_priv = vp;
	hwctx->priv = priv;

	mutex_init(&vp->privctx_lock);
	init_waitqueue_head(&vp->waitq);
	init_waitqueue_head(&priv->job_free_wq);

	/*
	 * VE2: num_tiles is the number of AIE columns (not a 2D tile count).
	 * Column placement comes from XRS (ve2_xrs_request), not
	 * amdxdna_hwctx_col_list() which is for PCI AIE2/AIE4.
	 */
	if (!hwctx->num_tiles) {
		XDNA_ERR(xdna, "num_tiles is zero");
		ret = -EINVAL;
		goto free_vp;
	}

	VE2_TRACE(xdna, "hwctx_setup: xrs_request...");
	ret = ve2_xrs_request(xdna, hwctx);
	if (ret) {
		XDNA_ERR(xdna, "XRS resource request failed, ret %d", ret);
		goto free_vp;
	}
	VE2_TRACE(xdna, "hwctx_setup: xrs ok start_col=%u num_col=%u",
		  hwctx->start_col, hwctx->num_col);

	ve2_hwctx_link_init(hwctx, hwctx->start_col, hwctx->num_col);
	if (!hwctx->aux_ctx_priv) {
		ret = -ENOMEM;
		goto release_xrs;
	}

	ve2_auto_select_mem_bitmap(xdna, hwctx);
	link = hwctx->aux_ctx_priv;
	if (ve2_hw_priv(hwctx))
		ve2_hw_priv(hwctx)->mem_bitmap = link->mem_bitmap;

	VE2_TRACE(xdna, "hwctx_setup: hq_alloc...");
	ret = ve2_hq_alloc(hwctx);
	if (ret) {
		XDNA_ERR(xdna, "Host queue alloc failed, ret %d", ret);
		goto cleanup_link;
	}
	VE2_TRACE(xdna, "hwctx_setup: hq ok");

	VE2_TRACE(xdna, "hwctx_setup: aie_hwctx_create...");
	ret = ve2_aie_hwctx_create(xdna, hwctx, &link->partition_id, &link->aie_ctx);
	if (ret)
		goto free_hq;
	VE2_TRACE(xdna, "hwctx_setup: aie ok partition_id=0x%x", link->partition_id);

	VE2_TRACE(xdna, "hwctx_setup: syncobj_create...");
	ret = amdxdna_ctx_syncobj_create(hwctx);
	if (ret) {
		XDNA_ERR(xdna, "Create syncobj failed, ret %d", ret);
		goto cleanup_aie;
	}

	if (!hwctx->max_opc)
		hwctx->max_opc = HWCTX_MAX_CMDS;

	if (enable_polling) {
		timer_setup(&vp->event_timer, ve2_hwctx_poll_timer, 0);
		mod_timer(&vp->event_timer, jiffies + CTX_TIMER);
		XDNA_DBG(xdna, "hwctx %p: polling mode enabled", hwctx);
	} else {
		XDNA_DBG(xdna, "hwctx %p: interrupt mode", hwctx);
	}

	VE2_TRACE(xdna, "hwctx_setup DONE hwctx=%p start_col=%u pid=%d polling=%d",
		  hwctx, hwctx->start_col, client->pid, enable_polling);

	return 0;

cleanup_aie:
	ve2_aie_teardown_hwctx(xdna, hwctx);
free_hq:
	ve2_hq_free(hwctx);
cleanup_link:
	ve2_hwctx_link_fini(hwctx);
release_xrs:
	ve2_release_xrs(xdna, hwctx);
free_vp:
	mutex_destroy(&vp->privctx_lock);
	kfree(vp);
	kfree(priv);
	hwctx->priv = NULL;
	return ret;
}

/**
 * ve2_hwctx_teardown - Release resources from ve2_hwctx_setup(); caller holds @xdna->dev_lock.
 */
void ve2_hwctx_teardown(struct amdxdna_hwctx *hwctx)
{
	struct amdxdna_dev *xdna = hwctx->client->xdna;
	struct amdxdna_hwctx_priv *priv = hwctx->priv;
	struct ve2_hwctx_priv *vp;

	VE2_TRACE(xdna, "hwctx_teardown ENTER pid=%d hwctx=%p start_col=%u",
		  hwctx->client->pid, hwctx, hwctx->start_col);

	ve2_aie_teardown_hwctx(xdna, hwctx);
	ve2_hq_free(hwctx);
	ve2_hwctx_link_fini(hwctx);
	ve2_release_xrs(xdna, hwctx);

	kfree(hwctx->col_list);
	hwctx->col_list = NULL;

	if (priv) {
		amdxdna_ctx_syncobj_destroy(hwctx);
		vp = priv->hw_priv;
		if (vp) {
			if (enable_polling)
				del_timer_sync(&vp->event_timer);
			mutex_destroy(&vp->privctx_lock);
		}
		kfree(vp);
		kfree(priv);
		hwctx->priv = NULL;
	}
}

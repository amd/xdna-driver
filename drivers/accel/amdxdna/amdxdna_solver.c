// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2022-2026, Advanced Micro Devices, Inc.
 */

#include "drm/amdxdna_accel.h"
#include <drm/drm_device.h>
#include <drm/drm_managed.h>
#include <drm/drm_print.h>
#include <linux/bitmap.h>
#include <linux/mutex.h>
#include <linux/slab.h>

#include "amdxdna_ctx.h"
#include "amdxdna_pci_drv.h"
#include "amdxdna_solver.h"

static u32 calculate_gops(struct aie_qos *rqos)
{
	u32 service_rate = 0;

	if (rqos->latency)
		service_rate = (1000 / rqos->latency);

	if (rqos->fps > service_rate)
		return rqos->fps * rqos->gops;

	return service_rate * rqos->gops;
}

/*
 * qos_meet() - Check the QOS request can be met.
 */
static int qos_meet(struct solver_state *xrs, struct aie_qos *rqos, u32 cgops)
{
	u32 request_gops = calculate_gops(rqos) * xrs->cfg.sys_eff_factor;

	if (request_gops <= cgops)
		return 0;

	return -EINVAL;
}

/*
 * sanity_check() - Do a basic sanity check on allocation request.
 */
static int sanity_check(struct solver_state *xrs, struct alloc_requests *req)
{
	struct cdo_parts *cdop = &req->cdo;
	struct aie_qos *rqos = &req->rqos;
	u32 cu_clk_freq;

	if (cdop->ncols > xrs->cfg.total_col)
		return -EINVAL;

	if (!xrs->cfg.clk_list.num_levels)
		return 0;

	/*
	 * We can find at least one CDOs groups that meet the
	 * GOPs requirement.
	 */
	cu_clk_freq = xrs->cfg.clk_list.cu_clk_list[xrs->cfg.clk_list.num_levels - 1];

	if (qos_meet(xrs, rqos, cdop->qos_cap.opc * cu_clk_freq / 1000))
		return -EINVAL;

	return 0;
}

static bool is_valid_qos_dpm_params(struct aie_qos *rqos)
{
	/*
	 * gops is retrieved from the xmodel, so it's always set
	 * fps and latency are the configurable params from the application
	 */
	if (rqos->gops > 0 && (rqos->fps > 0 || rqos->latency > 0))
		return true;

	return false;
}

u32 xrs_get_gops(struct aie_qos *rqos)
{
	if (!is_valid_qos_dpm_params(rqos))
		return 0;

	return calculate_gops(rqos) * DEFAULT_SYS_EFF_FACTOR;
}

static int set_dpm_level(struct solver_state *xrs, struct alloc_requests *req, u32 *dpm_level)
{
	struct solver_rgroup *rgp = &xrs->rgp;
	struct cdo_parts *cdop = &req->cdo;
	struct aie_qos *rqos = &req->rqos;
	u32 freq, max_dpm_level, level;
	struct solver_node *node;

	max_dpm_level = xrs->cfg.clk_list.num_levels - 1;
	/* If no QoS parameters are passed, set it to the max DPM level */
	if (!is_valid_qos_dpm_params(rqos)) {
		level = max_dpm_level;
		goto set_dpm;
	}

	/* Find one CDO group that meet the GOPs requirement. */
	for (level = 0; level < max_dpm_level; level++) {
		freq = xrs->cfg.clk_list.cu_clk_list[level];
		if (!qos_meet(xrs, rqos, cdop->qos_cap.opc * freq / 1000))
			break;
	}

	/* set the dpm level which fits all the sessions */
	list_for_each_entry(node, &rgp->node_list, list) {
		if (node->dpm_level > level)
			level = node->dpm_level;
	}

set_dpm:
	*dpm_level = level;
	return xrs->cfg.actions->set_dft_dpm_level(xrs->cfg.ddev, level);
}

static struct solver_node *rg_search_node(struct solver_rgroup *rgp, u64 rid)
{
	struct solver_node *node;

	list_for_each_entry(node, &rgp->node_list, list) {
		if (node->rid == rid)
			return node;
	}

	return NULL;
}

static void remove_partition_node(struct solver_rgroup *rgp,
				  struct partition_node *pt_node,
				  struct xrs_action_load *action)
{
	pt_node->nshared--;
	if (pt_node->nshared > 0) {
		if (action)
			action->release_aie_part = false;
		return;
	}

	list_del(&pt_node->list);
	rgp->npartition_node--;

	bitmap_clear(rgp->resbit, pt_node->start_col, pt_node->ncols);
	kfree(pt_node);

	if (action)
		action->release_aie_part = true;
}

static void remove_solver_node(struct solver_rgroup *rgp,
			       struct solver_node *node,
			       struct xrs_action_load *action)
{
	list_del(&node->list);
	rgp->nnode--;

	if (node->pt_node)
		remove_partition_node(rgp, node->pt_node, action);

	kfree(node);
}

static int get_free_partition(struct solver_state *xrs,
			      struct solver_node *snode,
			      struct alloc_requests *req)
{
	u32 user_col = req->rqos.user_start_col;
	u32 total_col = xrs->cfg.total_col;
	struct partition_node *pt_node;
	u32 ncols = req->cdo.ncols;
	u32 col, i;

	if (user_col != USER_START_COL_NOT_REQUESTED) {
		/* User pinned a specific start column — validate and use it directly. */
		col = user_col;
		if (find_next_bit(xrs->rgp.resbit, total_col, col) < col + ncols)
			return -ENODEV;
	} else {
		for (i = 0; i < snode->cols_len; i++) {
			col = snode->start_cols[i];
			if (find_next_bit(xrs->rgp.resbit, total_col, col) >= col + ncols)
				break;
		}
		if (i == snode->cols_len)
			return -ENODEV;
	}

	pt_node = kzalloc_obj(*pt_node);
	if (!pt_node)
		return -ENOMEM;

	pt_node->nshared = 1;
	pt_node->start_col = col;
	pt_node->ncols = ncols;
	pt_node->exclusive = req->rqos.exclusive;

	list_add_tail(&pt_node->list, &xrs->rgp.pt_node_list);
	xrs->rgp.npartition_node++;
	bitmap_set(xrs->rgp.resbit, pt_node->start_col, pt_node->ncols);

	snode->pt_node = pt_node;

	return 0;
}

static int allocate_partition(struct solver_state *xrs,
			      struct solver_node *snode,
			      struct alloc_requests *req)
{
	struct partition_node *pt_node, *rpt_node = NULL;
	int idx, ret;

	ret = get_free_partition(xrs, snode, req);
	if (!ret)
		return ret;

	/* Exclusive requests must get a free partition; never share. */
	if (req->rqos.exclusive)
		return -ENODEV;

	/* try to get a share-able partition */
	list_for_each_entry(pt_node, &xrs->rgp.pt_node_list, list) {
		if (pt_node->exclusive)
			continue;

		if (rpt_node && pt_node->nshared >= rpt_node->nshared)
			continue;

		for (idx = 0; idx < snode->cols_len; idx++) {
			if (snode->start_cols[idx] != pt_node->start_col)
				continue;

			if (req->cdo.ncols != pt_node->ncols)
				continue;

			rpt_node = pt_node;
			break;
		}
	}

	if (!rpt_node)
		return -ENODEV;

	rpt_node->nshared++;
	snode->pt_node = rpt_node;

	return 0;
}

static struct solver_node *create_solver_node(struct solver_state *xrs,
					      struct alloc_requests *req)
{
	struct cdo_parts *cdop = &req->cdo;
	struct solver_node *node;
	int ret;

	node = kzalloc_flex(*node, start_cols, cdop->cols_len);
	if (!node)
		return ERR_PTR(-ENOMEM);

	node->rid = req->rid;
	node->cols_len = cdop->cols_len;
	memcpy(node->start_cols, cdop->start_cols, cdop->cols_len * sizeof(u32));

	ret = allocate_partition(xrs, node, req);
	if (ret)
		goto free_node;

	list_add_tail(&node->list, &xrs->rgp.node_list);
	xrs->rgp.nnode++;
	return node;

free_node:
	kfree(node);
	return ERR_PTR(ret);
}

static void fill_load_action(struct solver_node *snode,
			     struct xrs_action_load *action)
{
	if (!action)
		return;

	action->rid = snode->rid;
	action->part.start_col = snode->pt_node->start_col;
	action->part.ncols = snode->pt_node->ncols;
	action->create_aie_part = (snode->pt_node->nshared == 1);
}

int xrs_allocate_resource(void *hdl, struct alloc_requests *req, void *cb_arg,
			  struct xrs_action_load *action)
{
	struct solver_state *xrs = hdl;
	struct solver_node *snode;
	u32 dpm_level;
	int ret;

	if (!xrs || !req)
		return -EINVAL;

	ret = sanity_check(xrs, req);
	if (ret) {
		drm_err(xrs->cfg.ddev, "invalid request");
		return ret;
	}

	if (rg_search_node(&xrs->rgp, req->rid)) {
		drm_err(xrs->cfg.ddev, "rid %lld is in-use", req->rid);
		return -EEXIST;
	}

	/* Real-time priority requires an exclusive partition. */
	if (req->rqos.priority == AMDXDNA_QOS_REALTIME_PRIORITY)
		req->rqos.exclusive = true;

	snode = create_solver_node(xrs, req);
	if (IS_ERR(snode))
		return PTR_ERR(snode);

	/* Both paths report the chosen columns through @action. */
	fill_load_action(snode, action);

	/* PCI (NPU) only: run the backend load callback and pick a DPM level. */
	if (xrs->cfg.actions) {
		ret = xrs->cfg.actions->load(cb_arg, action);
		if (ret)
			goto free_node;

		ret = set_dpm_level(xrs, req, &dpm_level);
		if (ret)
			goto free_node;

		snode->dpm_level = dpm_level;
		snode->cb_arg = cb_arg;
	}

	drm_dbg(xrs->cfg.ddev, "start col %d ncols %d\n",
		snode->pt_node->start_col, snode->pt_node->ncols);

	return 0;

free_node:
	remove_solver_node(&xrs->rgp, snode, NULL);

	return ret;
}

int xrs_release_resource(void *hdl, u64 rid, struct xrs_action_load *action)
{
	struct solver_state *xrs = hdl;
	struct solver_node *node;

	if (!xrs)
		return -EINVAL;

	node = rg_search_node(&xrs->rgp, rid);
	if (!node) {
		drm_err(xrs->cfg.ddev, "rid %lld not found", rid);
		return -ENODEV;
	}

	/* PCI: invoke backend unload (mailbox destroy_context, DPM, etc.). */
	if (xrs->cfg.actions)
		xrs->cfg.actions->unload(node->cb_arg);

	remove_solver_node(&xrs->rgp, node, action);
	return 0;
}

void *xrsm_init(struct init_config *cfg)
{
	struct solver_rgroup *rgp;
	struct solver_state *xrs;
	size_t bitmap_size;

	bitmap_size = BITS_TO_LONGS(cfg->total_col) * sizeof(unsigned long);
	xrs = drmm_kzalloc(cfg->ddev, sizeof(*xrs) + bitmap_size, GFP_KERNEL);
	if (!xrs)
		return NULL;

	memcpy(&xrs->cfg, cfg, sizeof(*cfg));

	rgp = &xrs->rgp;
	rgp->resbit = (unsigned long *)(xrs + 1);
	INIT_LIST_HEAD(&rgp->node_list);
	INIT_LIST_HEAD(&rgp->pt_node_list);
	mutex_init(&xrs->xrs_lock);

	return xrs;
}

int amdxdna_alloc_resource(struct amdxdna_hwctx *hwctx, bool *create_aie_part)
{
	struct amdxdna_dev *xdna = hwctx->client->xdna;
	struct xrs_action_load load_act = { };
	struct alloc_requests *xrs_req;
	int ret;

	xrs_req = kzalloc_obj(*xrs_req);
	if (!xrs_req)
		return -ENOMEM;

	xrs_req->cdo.start_cols = hwctx->col_list;
	xrs_req->cdo.cols_len = hwctx->col_list_len;
	xrs_req->cdo.ncols = hwctx->num_col;
	xrs_req->cdo.qos_cap.opc = hwctx->max_opc;

	xrs_req->rqos.gops = hwctx->qos.gops;
	xrs_req->rqos.fps = hwctx->qos.fps;
	xrs_req->rqos.dma_bw = hwctx->qos.dma_bandwidth;
	xrs_req->rqos.latency = hwctx->qos.latency;
	xrs_req->rqos.exec_time = hwctx->qos.frame_exec_time;
	xrs_req->rqos.priority = hwctx->qos.priority;
	xrs_req->rqos.exclusive = (hwctx->qos.priority == AMDXDNA_QOS_REALTIME_PRIORITY);
	xrs_req->rqos.user_start_col = hwctx->qos.user_start_col;

	xrs_req->rid = (uintptr_t)hwctx;

	ret = xrs_allocate_resource(xdna->xrs_hdl, xrs_req, hwctx, &load_act);
	if (ret)
		drm_err(&xdna->ddev, "Allocate AIE resource failed, ret %d", ret);

	hwctx->start_col = load_act.part.start_col;
	hwctx->num_col = load_act.part.ncols;

	/*
	 * Report whether this allocation created a fresh AIE partition (first
	 * sharer) or attached to one already in use (subsequent sharer). VE2
	 * uses this to decide whether to request the partition / register IRQ.
	 */
	if (!ret && create_aie_part)
		*create_aie_part = load_act.create_aie_part;

	kfree(xrs_req);
	return ret;
}

void amdxdna_release_resource(struct amdxdna_hwctx *hwctx, bool *release_aie_part)
{
	struct amdxdna_dev *xdna = hwctx->client->xdna;
	struct xrs_action_load release_act = { };
	int ret;

	ret = xrs_release_resource(xdna->xrs_hdl, (uintptr_t)hwctx, &release_act);
	if (ret)
		drm_err(&xdna->ddev, "Release AIE resource failed, ret %d", ret);

	/*
	 * Report whether this was the last sharer (the AIE partition can now be
	 * torn down) or whether other contexts still reference the partition.
	 */
	if (!ret && release_aie_part)
		*release_aie_part = release_act.release_aie_part;
}

// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2025-2026, Advanced Micro Devices, Inc.
 *
 * VE2 resource solver implementation — see amdxdna_ve2_solver.h.
 */

#include <drm/drm_device.h>
#include <drm/drm_managed.h>
#include <drm/drm_print.h>
#include <linux/bitops.h>
#include <linux/bitmap.h>

#include "drm/amdxdna_accel.h"

#include "amdxdna_ctx.h"
#include "amdxdna_drv.h"
#include "amdxdna_ve2_solver.h"

static int sanity_check(struct solver_state *xrs, struct alloc_requests *req)
{
	struct cdo_parts *cdop = &req->cdo;

	if (cdop->ncols > xrs->cfg.total_col)
		return -EINVAL;

	return 0;
}

int ve2_xrs_get_total_cols(struct solver_state *xrs)
{
	if (!xrs || !xrs->cfg.total_col)
		return -EINVAL;

	return xrs->cfg.total_col;
}

struct solver_node *ve2_rg_search_node(struct solver_rgroup *rgp, u64 rid)
{
	struct solver_node *node;

	list_for_each_entry(node, &rgp->node_list, list) {
		if (node->rid == rid)
			return node;
	}

	return NULL;
}

static void remove_partition_node(struct solver_rgroup *rgp, struct partition_node *pt_node,
				  struct xrs_action_load *action)
{
	pt_node->nshared--;
	if (pt_node->nshared > 0) {
		action->release_aie_part = false;
		return;
	}

	list_del(&pt_node->list);

	rgp->npartition_node--;
	bitmap_clear(rgp->resbit, pt_node->start_col, pt_node->ncols);

	kfree(pt_node);
	action->release_aie_part = true;
}

static void remove_solver_node(struct solver_rgroup *rgp, struct solver_node *node,
			       struct xrs_action_load *action)
{
	list_del(&node->list);
	rgp->nnode--;

	if (node->pt_node)
		remove_partition_node(rgp, node->pt_node, action);

	kfree(node);
}

static inline struct partition_node *create_partition_node(u32 start_col, u32 ncols, bool exclusive)
{
	struct partition_node *pt_node = kzalloc(sizeof(*pt_node), GFP_KERNEL);

	if (!pt_node)
		return NULL;

	pt_node->start_col = start_col;
	pt_node->ncols = ncols;
	pt_node->exclusive = exclusive;
	pt_node->nshared = 1;

	return pt_node;
}

static inline bool is_partition_free(struct solver_state *xrs, u32 col, u32 ncols)
{
	for (u32 i = col; i < col + ncols; i++) {
		if (test_bit(i, xrs->rgp.resbit))
			return false;
	}

	return true;
}

static inline bool is_valid_start_col(struct solver_node *snode, u32 col)
{
	for (u32 i = 0; i < snode->cols_len; i++) {
		if (snode->start_cols[i] == col)
			return true;
	}

	return false;
}

static int allocate_partition_exclusive(struct solver_state *xrs,
					struct solver_node *snode,
					struct alloc_requests *req)
{
	struct partition_node *pt_node;
	u32 ncols = req->cdo.ncols;
	u32 col;
	u32 i;

	drm_dbg(xrs->cfg.ddev, "Allocating new exclusive partition\n");

	if (req->rqos.user_start_col == USER_START_COL_NOT_REQUESTED) {
		for (i = 0; i < snode->cols_len; i++) {
			col = snode->start_cols[i];
			if (is_partition_free(xrs, col, ncols)) {
				drm_dbg(xrs->cfg.ddev,
					"Found free exclusive partition at col=%u\n", col);
				break;
			}
		}
		if (i == snode->cols_len) {
			drm_err(xrs->cfg.ddev, "No free exclusive partition found\n");
			return -ENODEV;
		}
	} else {
		col = req->rqos.user_start_col;

		if (!is_valid_start_col(snode, col)) {
			drm_err(xrs->cfg.ddev,
				"Requested start col %u is not a valid start column for this partition\n",
				col);
			return -EINVAL;
		}

		if (!is_partition_free(xrs, col, ncols)) {
			drm_err(xrs->cfg.ddev,
				"Requested exclusive partition start col %u is not free\n", col);
			return -ENODEV;
		}
		drm_dbg(xrs->cfg.ddev,
			"Requested exclusive partition from user request at col=%u\n", col);
	}

	pt_node = create_partition_node(col, ncols, req->rqos.exclusive);
	if (!pt_node)
		return -ENOMEM;

	list_add_tail(&pt_node->list, &xrs->rgp.pt_node_list);
	xrs->rgp.npartition_node++;
	bitmap_set(xrs->rgp.resbit, pt_node->start_col, pt_node->ncols);

	snode->pt_node = pt_node;
	drm_dbg(xrs->cfg.ddev, "Allocated new exclusive partition at col=%u\n",
		pt_node->start_col);

	return 0;
}

static inline struct partition_node *find_least_used_partition(struct solver_state *xrs,
							       struct solver_node *snode,
							       u32 ncols)
{
	struct partition_node *pt_node;
	struct partition_node *least_used = NULL;
	int idx;
	u32 candidate_col;

	for (idx = 0; idx < snode->cols_len; idx++) {
		candidate_col = snode->start_cols[idx];
		list_for_each_entry(pt_node, &xrs->rgp.pt_node_list, list) {
			if (!pt_node->exclusive &&
			    pt_node->start_col == candidate_col &&
			    pt_node->ncols == ncols) {
				if (!least_used || pt_node->nshared < least_used->nshared)
					least_used = pt_node;
			}
		}
	}

	return least_used;
}

static inline bool is_exclusive_partition(struct solver_state *xrs, u32 col, u32 ncols)
{
	struct partition_node *pt_node;
	u32 req_end = col + ncols;

	list_for_each_entry(pt_node, &xrs->rgp.pt_node_list, list) {
		if (pt_node->exclusive) {
			u32 pt_end = pt_node->start_col + pt_node->ncols;

			if (col < pt_end && req_end > pt_node->start_col)
				return true;
		}
	}

	return false;
}

static int allocate_partition_shared(struct solver_state *xrs,
				     struct solver_node *snode,
				     struct alloc_requests *req)
{
	struct partition_node *pt_node, *least_used = NULL;
	u32 ncols = req->cdo.ncols;
	bool is_free = false;
	u32 candidate_col;
	int idx;

	drm_dbg(xrs->cfg.ddev, "rid=%llu ncols=%u cols_len=%u\n",
		snode->rid, ncols, snode->cols_len);

	if (req->rqos.user_start_col == USER_START_COL_NOT_REQUESTED) {
		drm_dbg(xrs->cfg.ddev, "Searching for free shared partition\n");
		for (idx = 0; idx < snode->cols_len; idx++) {
			candidate_col = snode->start_cols[idx];

			if (is_exclusive_partition(xrs, candidate_col, ncols))
				continue;

			if (is_partition_free(xrs, candidate_col, ncols)) {
				is_free = true;
				drm_dbg(xrs->cfg.ddev,
					"Found free shared partition at col=%u\n", candidate_col);
				break;
			}
		}
	} else {
		candidate_col = req->rqos.user_start_col;

		if (!is_valid_start_col(snode, candidate_col)) {
			drm_err(xrs->cfg.ddev,
				"Requested start col %u is not a valid start column for this partition\n",
				candidate_col);
			return -EINVAL;
		}

		if (is_exclusive_partition(xrs, candidate_col, ncols)) {
			drm_err(xrs->cfg.ddev,
				"Can't allocate shared partition col : %u. Exclusive already\n",
				candidate_col);
			return -ENODEV;
		}

		drm_dbg(xrs->cfg.ddev,
			"Requested shared partition from user request at col=%u\n", candidate_col);
		is_free = is_partition_free(xrs, candidate_col, ncols);
	}

	if (is_free) {
		drm_dbg(xrs->cfg.ddev, "Allocating new shared partition at UNUSED col=%u\n",
			candidate_col);
		pt_node = create_partition_node(candidate_col, ncols, false);
		if (!pt_node)
			return -ENOMEM;

		list_add_tail(&pt_node->list, &xrs->rgp.pt_node_list);
		xrs->rgp.npartition_node++;
		snode->pt_node = pt_node;
		bitmap_set(xrs->rgp.resbit, pt_node->start_col, pt_node->ncols);
		return 0;
	}

	if (req->rqos.user_start_col == USER_START_COL_NOT_REQUESTED) {
		least_used = find_least_used_partition(xrs, snode, ncols);
	} else {
		candidate_col = req->rqos.user_start_col;
		list_for_each_entry(pt_node, &xrs->rgp.pt_node_list, list) {
			if (!pt_node->exclusive &&
			    pt_node->start_col == candidate_col &&
			    pt_node->ncols == ncols) {
				least_used = pt_node;
				break;
			}
		}
	}

	if (!least_used) {
		drm_err(xrs->cfg.ddev, "No available shared partition for col=%u ncols=%u\n",
			candidate_col, ncols);
		return -ENODEV;
	}

	least_used->nshared++;
	snode->pt_node = least_used;
	drm_dbg(xrs->cfg.ddev, "Reused shared partition at col=%u (nshared now %u)\n",
		least_used->start_col, least_used->nshared);

	return 0;
}

static struct solver_node *create_solver_node(struct solver_state *xrs, struct alloc_requests *req)
{
	struct cdo_parts *cdop = &req->cdo;
	struct solver_node *node;
	int ret;

	node = kzalloc(struct_size(node, start_cols, cdop->cols_len), GFP_KERNEL);
	if (!node)
		return ERR_PTR(-ENOMEM);

	node->rid = req->rid;
	node->cols_len = cdop->cols_len;
	memcpy(node->start_cols, cdop->start_cols, cdop->cols_len * sizeof(u32));

	if (req->rqos.exclusive)
		ret = allocate_partition_exclusive(xrs, node, req);
	else
		ret = allocate_partition_shared(xrs, node, req);

	if (ret)
		goto free_node;

	list_add_tail(&node->list, &xrs->rgp.node_list);
	xrs->rgp.nnode++;

	return node;

free_node:
	kfree(node);
	return ERR_PTR(ret);
}

static void fill_load_action(struct solver_state *xrs, struct solver_node *snode,
			     struct xrs_action_load *action)
{
	action->rid = snode->rid;
	action->part.start_col = snode->pt_node->start_col;
	action->part.ncols = snode->pt_node->ncols;
	if (snode->pt_node->nshared == 1)
		action->create_aie_part = true;
	else
		action->create_aie_part = false;
}

int ve2_xrs_release_resource(void *hdl, u64 rid, struct xrs_action_load *action)
{
	struct solver_state *xrs = hdl;
	struct solver_node *node;

	node = ve2_rg_search_node(&xrs->rgp, rid);
	if (!node) {
		drm_err(xrs->cfg.ddev, "node not exist for rid=0x%llx\n", rid);
		return -ENODEV;
	}

	remove_solver_node(&xrs->rgp, node, action);

	return 0;
}

int ve2_xrs_allocate_resource(void *hdl, struct alloc_requests *req,
			      struct xrs_action_load *load_act)
{
	struct solver_state *xrs = (struct solver_state *)hdl;
	struct solver_node *snode;
	int ret;

	ret = sanity_check(xrs, req);
	if (ret) {
		drm_err(xrs->cfg.ddev, "invalid request: ncols=%u > total_col=%u\n",
			req->cdo.ncols, xrs->cfg.total_col);
		return ret;
	}

	if (ve2_rg_search_node(&xrs->rgp, req->rid)) {
		drm_err(xrs->cfg.ddev, "rid 0x%llx is in-use\n", req->rid);
		return -EEXIST;
	}

	if (req->rqos.priority == AMDXDNA_QOS_REALTIME_PRIORITY)
		req->rqos.exclusive = true;
	else
		req->rqos.exclusive = false;

	snode = create_solver_node(xrs, req);
	if (IS_ERR(snode)) {
		drm_err(xrs->cfg.ddev, "Failed to create solver node, err=%ld\n", PTR_ERR(snode));
		return PTR_ERR(snode);
	}

	fill_load_action(xrs, snode, load_act);
	drm_dbg(xrs->cfg.ddev, "Resource allocated: start_col=%u, ncols=%u, exclusive=%s, create_part=%d\n",
		snode->pt_node->start_col, snode->pt_node->ncols,
		req->rqos.exclusive ? "true" : "false", load_act->create_aie_part);

	return 0;
}

void *ve2_xrsm_init(struct init_config *cfg)
{
	struct solver_rgroup *rgp;
	struct solver_state *xrs;
	size_t bitmap_size;

	bitmap_size = BITS_TO_LONGS(cfg->total_col) * sizeof(unsigned long);
	xrs = drmm_kzalloc(cfg->ddev, sizeof(*xrs) + bitmap_size, GFP_KERNEL);
	if (!xrs) {
		drm_err(cfg->ddev, "Failed to allocate resource solver state\n");
		return NULL;
	}

	memcpy(&xrs->cfg, cfg, sizeof(*cfg));

	rgp = &xrs->rgp;
	rgp->resbit = (unsigned long *)(xrs + 1);
	INIT_LIST_HEAD(&rgp->node_list);
	INIT_LIST_HEAD(&rgp->pt_node_list);
	mutex_init(&xrs->xrs_lock);

	return xrs;
}

static int ve2_xrs_col_list(struct amdxdna_dev *xdna, struct alloc_requests *xrs_req,
			    u32 num_col)
{
	struct solver_state *xrs = xdna->xrs_hdl;
	int total_col;
	int entries;
	int i;

	if (!xrs || !num_col)
		return -EINVAL;

	total_col = ve2_xrs_get_total_cols(xrs);
	if (total_col < 0 || num_col > (u32)total_col)
		return -EINVAL;

	entries = total_col - (int)num_col + 1;
	if (!entries)
		return -EINVAL;

	xrs_req->cdo.start_cols = kmalloc_array(entries, sizeof(*xrs_req->cdo.start_cols),
						GFP_KERNEL);
	if (!xrs_req->cdo.start_cols)
		return -ENOMEM;

	xrs_req->cdo.cols_len = entries;
	for (i = 0; i < entries; i++)
		xrs_req->cdo.start_cols[i] = i;

	return 0;
}

int ve2_xrs_request(struct amdxdna_dev *xdna, struct amdxdna_hwctx *hwctx)
{
	struct solver_state *xrs = xdna->xrs_hdl;
	struct xrs_action_load load_act = { };
	struct alloc_requests *xrs_req;
	int ret;

	if (!xrs)
		return -EINVAL;

	xrs_req = kzalloc(sizeof(*xrs_req), GFP_KERNEL);
	if (!xrs_req)
		return -ENOMEM;

	xrs_req->cdo.ncols = hwctx->num_tiles ? hwctx->num_tiles : 1;
	xrs_req->rqos.priority = hwctx->qos.priority;

	/* Pass user_start_col through to XRS column picker. */
	xrs_req->rqos.user_start_col = hwctx->qos.user_start_col;

	if (xrs_req->rqos.user_start_col != USER_START_COL_NOT_REQUESTED) {
		u32 total_col = ve2_xrs_get_total_cols(xrs);

		if (xrs_req->rqos.user_start_col % VE2_MIN_COL_SUPPORT) {
			ret = -EINVAL;
			goto out_free;
		}
		if (total_col > 0 &&
		    xrs_req->rqos.user_start_col + xrs_req->cdo.ncols > total_col) {
			ret = -ERANGE;
			goto out_free;
		}
	}

	xrs_req->rid = (uintptr_t)hwctx;

	ret = ve2_xrs_col_list(xdna, xrs_req, xrs_req->cdo.ncols);
	if (ret)
		goto out_free;

	mutex_lock(&xrs->xrs_lock);
	ret = ve2_xrs_allocate_resource(xrs, xrs_req, &load_act);
	mutex_unlock(&xrs->xrs_lock);
	if (ret)
		goto out_free_cols;

	hwctx->start_col = load_act.part.start_col;
	hwctx->num_col = load_act.part.ncols;

out_free_cols:
	kfree(xrs_req->cdo.start_cols);
out_free:
	kfree(xrs_req);
	return ret;
}

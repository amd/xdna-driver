// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2025, Advanced Micro Devices, Inc.
 */

#include <drm/drm_device.h>
#include <drm/drm_managed.h>
#include <drm/drm_print.h>
#include <linux/bitops.h>
#include <linux/bitmap.h>

#include "ve2_res_solver.h"

/*
 * sanity_check() - Do a basic sanity check on allocation request.
 */
static int sanity_check(struct solver_state *xrs, struct alloc_requests *req)
{
	struct cdo_parts *cdop = &req->cdo;

	if (cdop->ncols > xrs->cfg.total_col)
		return -EINVAL;

	return 0;
}

int xrs_get_total_cols(struct solver_state *xrs)
{
	if (!xrs && !xrs->cfg.total_col)
		return -EINVAL;

	return xrs->cfg.total_col;
}

struct solver_node *rg_search_node(struct solver_rgroup *rgp, u64 rid)
{
	struct solver_node *node;

	list_for_each_entry(node, &rgp->node_list, list) {
		if (node->rid == rid)
			return node;
	}

	return NULL;
}

static void remove_partition_node(struct solver_rgroup *rgp, struct partition_node *pt_node)
{
	pt_node->nshared--;
	if (pt_node->nshared > 0)
		return;

	list_del(&pt_node->list);
	rgp->npartition_node--;

	bitmap_clear(rgp->resbit, pt_node->start_col, pt_node->ncols);
	kfree(pt_node);
}

static void remove_solver_node(struct solver_rgroup *rgp, struct solver_node *node)
{
	list_del(&node->list);
	rgp->nnode--;

	if (node->pt_node)
		remove_partition_node(rgp, node->pt_node);

	kfree(node);
}

static int get_free_partition(struct solver_state *xrs, struct solver_node *snode,
			      struct alloc_requests *req)
{
	struct partition_node *pt_node;
	u32 ncols = req->cdo.ncols;
	u32 col, i;

	for (i = 0; i < snode->cols_len; i++) {
		col = snode->start_cols[i];
		if (find_next_bit(xrs->rgp.resbit, XRS_MAX_COL, col) >= col + ncols)
			break;
	}

	if (i == snode->cols_len)
		return -ENODEV;

	pt_node = kzalloc(sizeof(*pt_node), GFP_KERNEL);
	if (!pt_node)
		return -ENOMEM;

	pt_node->nshared = 1;
	pt_node->start_col = col;
	pt_node->ncols = ncols;

	/*
	 * Always set exclusive to false for now.
	 */
	pt_node->exclusive = true;

	list_add_tail(&pt_node->list, &xrs->rgp.pt_node_list);
	xrs->rgp.npartition_node++;
	bitmap_set(xrs->rgp.resbit, pt_node->start_col, pt_node->ncols);

	snode->pt_node = pt_node;

	return 0;
}

static int allocate_partition(struct solver_state *xrs, struct solver_node *snode,
			      struct alloc_requests *req)
{
	struct partition_node *pt_node, *rpt_node = NULL;
	int idx, ret;

	ret = get_free_partition(xrs, snode, req);
	if (!ret)
		return ret;

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

static void fill_load_action(struct solver_state *xrs, struct solver_node *snode,
			     struct xrs_action_load *action)
{
	action->rid = snode->rid;
	action->part.start_col = snode->pt_node->start_col;
	action->part.ncols = snode->pt_node->ncols;
}

/*
 * xrs_release_resource() - Release resources for a given request id
 *
 * @hdl:        Resource solver handle obtained from xrs_init()
 * @rid:        Request id for which resources need to be released
 *
 * Return:      0 when successful.
 *              Or standard error number when failing
 *
 * Note:
 *      Ensure that all resources associated with the request id are properly released.
 */
int xrs_release_resource(void *hdl, u64 rid)
{
	struct solver_state *xrs = hdl;
	struct solver_node *node;

	mutex_lock(&xrs->xrs_lock);
	node = rg_search_node(&xrs->rgp, rid);
	if (!node) {
		drm_err(xrs->cfg.ddev, "node not exist");
		mutex_unlock(&xrs->xrs_lock);
		return -ENODEV;
	}
	remove_solver_node(&xrs->rgp, node);
	mutex_unlock(&xrs->xrs_lock);

	return 0;
}

/*
 * xrs_allocate_resource() - Request to allocate resources for a given context
 *                           and a partition metadata. (See struct part_meta)
 *
 * @hdl:	Resource solver handle obtained from xrs_init()
 * @req:	Input to the Resource solver including request id
 *		and partition metadata.
 * @load_act:	The possible action
 *
 * Return:	0 when successful.
 *		Or standard error number when failing
 *
 * Note:
 *      There is no lock mechanism inside resource solver. So it is
 *      the caller's responsibility to lock down XCLBINs and grab
 *      necessary lock.
 */
int xrs_allocate_resource(void *hdl, struct alloc_requests *req, struct xrs_action_load *load_act)
{
	struct solver_state *xrs = (struct solver_state *)hdl;
	struct solver_node *snode;
	int ret;

	ret = sanity_check(xrs, req);
	if (ret) {
		drm_err(xrs->cfg.ddev, "invalid request");
		return ret;
	}

	if (rg_search_node(&xrs->rgp, req->rid)) {
		drm_err(xrs->cfg.ddev, "rid %lld is in-use", req->rid);
		return -EEXIST;
	}

	snode = create_solver_node(xrs, req);
	if (IS_ERR(snode))
		return PTR_ERR(snode);

	fill_load_action(xrs, snode, load_act);
	drm_dbg(xrs->cfg.ddev, "start col %d ncols %d\n", snode->pt_node->start_col,
		snode->pt_node->ncols);

	return 0;
}

/*
 * xrsm_init() - Register resource solver. Resource solver client needs
 *              to call this function to register itself.
 *
 * @cfg:	The system metrics for resource solver to use
 *
 * Return:	A resource solver handle
 *
 * Note: We should only create one handle per AIE array to be managed.
 */
void *xrsm_init(struct init_config *cfg)
{
	struct solver_rgroup *rgp;
	struct solver_state *xrs;

	xrs = drmm_kzalloc(cfg->ddev, sizeof(*xrs), GFP_KERNEL);
	if (!xrs)
		return NULL;

	memcpy(&xrs->cfg, cfg, sizeof(*cfg));

	rgp = &xrs->rgp;
	INIT_LIST_HEAD(&rgp->node_list);
	INIT_LIST_HEAD(&rgp->pt_node_list);
	mutex_init(&xrs->xrs_lock);

	return xrs;
}

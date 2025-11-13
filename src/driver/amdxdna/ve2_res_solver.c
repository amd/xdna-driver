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

/**
 * create_partition_node - Allocate and initialize a partition node
 * @start_col: Starting column index for the partition
 * @ncols: Number of columns in the partition
 * @exclusive: Whether this partition is exclusive or shared
 *
 * Returns: Pointer to newly allocated partition_node or NULL on failure.
 */
static inline struct partition_node *create_partition_node(u32 start_col, u32 ncols, bool exclusive)
{
	struct partition_node *pt_node = kzalloc(sizeof(*pt_node), GFP_KERNEL);

	if (!pt_node)
		return NULL;

	pt_node->start_col = start_col;
	pt_node->ncols = ncols;
	pt_node->exclusive = exclusive;
	pt_node->nshared = 1; /* Initialize shared count */

	return pt_node;
}

/**
 * is_partition_in_use - Check if a partition with given start_col and ncols exists
 * @xrs: Solver state
 * @col: Starting column
 * @ncols: Number of columns
 *
 * Returns: true if partition exists, false otherwise.
 */
 static inline bool is_partition_in_use(struct solver_state *xrs, u32 col, u32 ncols)
 {
	 struct partition_node *pt_node;
 
	 list_for_each_entry(pt_node, &xrs->rgp.pt_node_list, list) {
		 if (pt_node->start_col == col && pt_node->ncols == ncols)
			 return true;
	 }
 
	 return false;
 }
 
/**
 * allocate_partition_exclusive - Find and allocate a free partition for exclusive use
 * @xrs: Solver state containing resource group info
 * @snode: Solver node requesting partition
 * @req: Allocation request details
 *
 * Scans available columns in snode->start_cols and checks bitmap for free space.
 * Allocates a new partition node if space is available.
 *
 * Returns: 0 on success, -ENODEV if no free partition, -ENOMEM if allocation fails.
 */
static int allocate_partition_exclusive(struct solver_state *xrs,
					struct solver_node *snode,
					struct alloc_requests *req)
{
	struct partition_node *pt_node;
	u32 ncols = req->cdo.ncols;
	u32 col, i;

	drm_dbg(xrs->cfg.ddev, "Allocating new exclusive partition\n");

	if (req->rqos.start_col_req == USER_START_COL_NOT_REQUESTED) {
		for (i = 0; i < snode->cols_len; i++) {
			col = snode->start_cols[i];
			if (!is_partition_in_use(xrs, col, ncols)) {
				drm_dbg(xrs->cfg.ddev, "Found free exclusive partition at col=%u\n", col);
				break;
			}
		}
		if (i == snode->cols_len) {
			drm_err(xrs->cfg.ddev, "No free exclusive partition found\n");
			return -ENODEV; /* No free partition found */
		}
	} else {
		col = req->rqos.start_col_req;
		if (is_partition_in_use(xrs, col, ncols)) {
			drm_err(xrs->cfg.ddev, "Requested exclusive partition start col %u is in use\n", col);
			return -ENODEV; /* No free partition found */
		}
		drm_dbg(xrs->cfg.ddev, "Requested exclusive partition from user request at col=%u\n", col);
	}

	/* Allocate and initialize partition node */
	pt_node = create_partition_node(col, ncols, req->rqos.exclusive);
	if (!pt_node)
		return -ENOMEM;

	/* Add to resource group list and update bitmap */
	list_add_tail(&pt_node->list, &xrs->rgp.pt_node_list);
	xrs->rgp.npartition_node++;
	bitmap_set(xrs->rgp.resbit, pt_node->start_col, pt_node->ncols);

	snode->pt_node = pt_node;
	drm_dbg(xrs->cfg.ddev, "Allocated new exclusive partition at col=%u\n",
		pt_node->start_col);
	return 0;
}

/**
 * find_least_used_partition - Find least shared partition for given col and ncols
 * @xrs: Solver state
 * @col: Starting column
 * @ncols: Number of columns
 *
 * Skips exclusive partitions and returns the one with minimum nshared count.
 *
 * Returns: Pointer to least-used partition or NULL if none found.
 */
static inline struct partition_node *find_least_used_partition(struct solver_state *xrs,
							       u32 col, u32 ncols)
{
	struct partition_node *pt_node, *least_used = NULL;

	list_for_each_entry(pt_node, &xrs->rgp.pt_node_list, list) {
		if (pt_node->exclusive)
			continue;

		if (pt_node->start_col == col && pt_node->ncols == ncols) {
			if (!least_used || pt_node->nshared < least_used->nshared)
				least_used = pt_node;
		}
	}

	return least_used;
}

/**
 * is_exclusive_partition - Check if a partition at 'col' and 'ncols' is exclusive
 * @xrs: Solver state pointer
 * @col: Starting column for the partition to check
 * @ncols: Number of columns in the partition
 *
 * Returns: true if a matching exclusive partition exists, false otherwise.
 */
static inline bool is_exclusive_partition(struct solver_state *xrs, u32 col, u32 ncols)
{
	struct partition_node *pt_node;

	list_for_each_entry(pt_node, &xrs->rgp.pt_node_list, list) {
		if (pt_node->exclusive &&
		    pt_node->start_col == col &&
		    pt_node->ncols == ncols)
			return true;
	}

	return false;
}

/**
 * allocate_partition_shared - Allocate or reuse a shared partition
 * @xrs: Solver state
 * @snode: Solver node requesting partition
 * @req: Allocation request details
 *
 * Returns: 0 on success, -ENOMEM if allocation fails, -ENODEV if no partition available.
 */
static int allocate_partition_shared(struct solver_state *xrs,
				     struct solver_node *snode,
				     struct alloc_requests *req)
{
	struct partition_node *pt_node, *least_used = NULL;
	u32 ncols = req->cdo.ncols;
	bool in_use = false;
	u32 candidate_col;
	int idx;

	drm_dbg(xrs->cfg.ddev, "rid=%llu ncols=%u cols_len=%u\n",
		snode->rid, ncols, snode->cols_len);

	/* STEP 1: Check if requested or any column is free */
	if (req->rqos.start_col_req == USER_START_COL_NOT_REQUESTED) {
		drm_dbg(xrs->cfg.ddev, "Searching for free shared partition\n");
		for (idx = 0; idx < snode->cols_len; idx++) {	
			candidate_col = snode->start_cols[idx];
			if (is_exclusive_partition(xrs, candidate_col, ncols))
				continue;
			
			in_use = is_partition_in_use(xrs, candidate_col, ncols);
			if (!in_use) {
				drm_dbg(xrs->cfg.ddev, "Found free shared partition at col=%u\n", candidate_col);
				break;
			}
		}
	} else {
		candidate_col = req->rqos.start_col_req;
		drm_dbg(xrs->cfg.ddev, "Requested shared partition from user request at col=%u\n", candidate_col);
		in_use = is_partition_in_use(xrs, candidate_col, ncols);
	}

	/* STEP 2: Allocate new partition if unused */
	if (!in_use) {
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

	/* STEP 3: Reuse least-used partition */
	if (req->rqos.start_col_req == USER_START_COL_NOT_REQUESTED) {
		for (idx = 0; idx < snode->cols_len; idx++) {
			candidate_col = snode->start_cols[idx];
			least_used = find_least_used_partition(xrs, candidate_col, ncols);
			if (least_used)
				break;
		}
		
		candidate_col = req->rqos.start_col_req;
		list_for_each_entry(pt_node, &xrs->rgp.pt_node_list, list) {
			if (pt_node->exclusive)
				continue;
			
			if (pt_node->start_col == candidate_col && pt_node->ncols == ncols) {
				least_used = pt_node;
				break;
			}
		}
		if (!least_used) {
			drm_err(xrs->cfg.ddev, "No least-used shared partition found at col=%u\n", candidate_col);
			return -ENODEV;
		}
	}

	if (least_used) {
		least_used->nshared++;
		snode->pt_node = least_used;
		drm_dbg(xrs->cfg.ddev, "Reused shared partition at col=%u (nshared now %u)\n",
			 least_used->start_col, least_used->nshared);
		return 0;
	}

	drm_info(xrs->cfg.ddev, "No available shared partition\n");

	return -ENODEV;
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
int xrs_release_resource(void *hdl, u64 rid, struct xrs_action_load *action)
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

	remove_solver_node(&xrs->rgp, node, action);
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

	if (req->rqos.priority == AMDXDNA_QOS_REALTIME_PRIORITY)
		req->rqos.exclusive = true;
	else
		req->rqos.exclusive = false;

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

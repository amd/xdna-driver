// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2020-2022 Xilinx, Inc. All rights reserved.
 * Copyright (C) 2022-2024, Advanced Micro Devices, Inc.
 */

#include <linux/slab.h>
#include "solver.h"

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
 *
 * @xrs:	Softstate of xrs
 * @rqos:	Requested QoS
 * @cgops:	giga ops Capability
 *
 * Return:	0 when successful or standard error number when failing
 *		Failing scenarios
 *			1. can't meet qos requirement
 */
static int qos_meet(struct solver_state *xrs, struct aie_qos *rqos, u32 cgops)
{
	u32 request_gops = calculate_gops(rqos) * xrs->cfg.sys_eff_factor;

	if (request_gops <= cgops)
		return 0;

	return -EINVAL;
}

/*
 * sanity_check() - Do a basic sanity check on allocation requests.
 *
 * @pmp:	Input partition metadata (for Fat-XCLBIN)
 * @rqos:	Requested QoS
 * @xrs:	Soft state of xrs
 *
 * Return:	0 when successful or standard error number when failing
 *		Failing scenarios
 *			1. Invalid rqos
 *			2. GOPs in requested QoS exceed all CDO groups
 *			   GOPs capabilities.
 */
static int sanity_check(struct part_meta *pmp, struct aie_qos *rqos, struct solver_state *xrs)
{
	struct cdo_parts *cdop = pmp->cdo;
	u32 cu_clk_freq;

	if (!rqos)
		return -EINVAL;

	/*
	 * We can find at least one CDOs groups that meet the
	 * GOPs requirement.
	 */
	cu_clk_freq = xrs->cfg.clk_list.cu_clk_list[xrs->cfg.clk_list.num_levels - 1];

	if (qos_meet(xrs, rqos, cdop->qos_cap->opc * cu_clk_freq / 1000))
		return -EINVAL;

	return 0;
}

static struct solver_node *rg_search_node(struct solver_rgroup *rgp, u32 rid)
{
	struct solver_node *node;

	list_for_each_entry(node, &rgp->node_list, list) {
		if (node->rid == rid)
			return node;
	}

	return NULL;
}

static void remove_partition_node(struct solver_rgroup *rgp,
				  struct partition_node *pt_node)
{
	pt_node->nshared--;
	if (pt_node->nshared > 0)
		return;

	list_del(&pt_node->list);
	rgp->npartition_node--;
	rgp->allocated -= pt_node->ncol;

	bitmap_clear(rgp->resbit, pt_node->start_col, pt_node->ncol);
	kfree(pt_node);
}

static void remove_solver_node(struct solver_rgroup *rgp,
			       struct solver_node *node)
{
	list_del(&node->list);
	rgp->nnode--;

	if (node->pt_node)
		remove_partition_node(rgp, node->pt_node);

	kfree(node->oly);
	kfree(node);
}

static struct solver_node *allocate_solver_node(struct solver_state *xrs,
						struct alloc_requests *req)
{
	struct cdo_parts *cdop = req->pmp->cdo;
	struct solver_node *node;

	node = kzalloc(sizeof(*node), GFP_KERNEL);
	if (!node)
		return NULL;

	node->oly = kcalloc(cdop->nparts, sizeof(u32), GFP_KERNEL);
	if (!node->oly)
		goto free_node;

	uuid_copy(&node->xclbin_uuid, req->pmp->xclbin_uuid);
	uuid_copy(&node->cdo_uuid, cdop->cdo_uuid);
	node->rid = req->rid;
	node->noly = cdop->nparts;
	node->ncol = cdop->ncols;
	memcpy(node->oly, cdop->start_col_list, cdop->nparts * sizeof(u32));

	memcpy(&node->qos_cap, cdop->qos_cap, sizeof(struct aie_qos_cap));
	memcpy(&node->rqos, req->rqos, sizeof(struct aie_qos));

	list_add_tail(&node->list, &xrs->rgp.node_list);
	xrs->rgp.nnode++;
	return node;

free_node:
	kfree(node);
	return NULL;
}

static int get_free_partition(struct solver_state *xrs, u32 *overlays,
			      u32 num_overlay, u32 oly_start_idx, u32 ncol,
			      u32 *part)
{
	u32 start_col, j;

	for (j = oly_start_idx; j < num_overlay; j++) {
		start_col = overlays[j];

		if (find_next_bit(xrs->rgp.resbit, XRS_MAX_COL, start_col) >=
		    start_col + ncol) {
			*part = j;
			return 0;
		}
	}

	return -ENODEV;
}

static void fill_partition_node(struct partition_node *pt_node,
				u32 start_col, u32 ncol, struct aie_qos *rqos)
{
	pt_node->nshared = 1;
	pt_node->start_col = start_col;
	pt_node->ncol = ncol;

	/*
	 * Before fully support latency in QoS, if a request
	 * specifies a non-zero latency value, it will not share
	 * the partition with other requests.
	 */
	if (rqos->latency)
		pt_node->exclusive = true;

	memcpy(&pt_node->pqos, rqos, sizeof(struct aie_qos));
}

static void add_partition_node(struct solver_rgroup *rgp,
			       struct partition_node *pt_node)
{
	list_add_tail(&pt_node->list, &rgp->pt_node_list);

	rgp->npartition_node++;
	rgp->allocated += pt_node->ncol;
	bitmap_set(rgp->resbit, pt_node->start_col, pt_node->ncol);
}

static int allocate_partition(struct solver_state *xrs, struct part_meta *pmp,
			      struct aie_qos *rqos, struct solver_node *snode)
{
	struct partition_node *pt_node, *rpt_node = NULL;
	struct cdo_parts *cdop = pmp->cdo;
	int j, ret;

	ret = get_free_partition(xrs, cdop->start_col_list, cdop->nparts, 0,
				 cdop->ncols, &snode->part);
	if (!ret) {
		/* got free partition */
		pt_node = kzalloc(sizeof(*pt_node), GFP_KERNEL);
		if (!pt_node)
			return -ENOMEM;

		fill_partition_node(pt_node, snode->oly[snode->part],
				    snode->ncol, &snode->rqos);
		add_partition_node(&xrs->rgp, pt_node);
		snode->pt_node = pt_node;

		return 0;
	}

	if (xrs->cfg.mode != XRS_MODE_TEMPORAL_BEST) {
		dev_err(xrs->cfg.dev, "no available partition");
		return -ENODEV;
	}

	/* try to get a share-able partition */
	list_for_each_entry(pt_node, &xrs->rgp.pt_node_list, list) {
		if (pt_node->exclusive)
			continue;

		if (rpt_node && pt_node->nshared >= rpt_node->nshared)
			continue;

		for (j = 0; j < cdop->nparts; j++) {
			if (cdop->start_col_list[j] == pt_node->start_col &&
			    cdop->ncols == pt_node->ncol) {
				rpt_node = pt_node;
				snode->part = j;
				break;
			}
		}
	}

	if (!rpt_node)
		return -ENODEV;

	rpt_node->nshared++;
	snode->pt_node = rpt_node;

	return 0;
}

static void fill_load_action(struct solver_state *xrs,
			     struct solver_node *snode,
			     struct xrs_action_load *action)
{
	action->rid = snode->rid;
	action->xclbin_uuid = &snode->xclbin_uuid;
	action->cdo_uuid = &snode->cdo_uuid;
	action->part.start_col = snode->pt_node->start_col;
	action->part.ncol = snode->pt_node->ncol;
}

int xrs_allocate_resource(void *hdl, struct alloc_requests *req, void *cb_arg)
{
	struct part_meta *pmp = req->pmp;
	struct xrs_action_load load_act;
	struct solver_node *snode;
	struct solver_state *xrs;
	int ret;

	xrs = (struct solver_state *)hdl;

	ret = sanity_check(pmp, req->rqos, xrs);
	if (ret) {
		dev_err(xrs->cfg.dev, "invalid QoS request");
		return ret;
	}

	if (rg_search_node(&xrs->rgp, req->rid)) {
		dev_err(xrs->cfg.dev, "rid %d is in-use", req->rid);
		return -EEXIST;
	}

	if (xrs->cfg.total_col - xrs->rgp.allocated < pmp->cdo->ncols)
		return -EBUSY;

	snode = allocate_solver_node(xrs, req);
	if (!snode)
		return -ENOMEM;

	ret = allocate_partition(xrs, pmp, req->rqos, snode);
	if (ret)
		goto free_node;

	fill_load_action(xrs, snode, &load_act);
	ret = xrs->cfg.actions->load(cb_arg, &load_act);
	if (ret)
		goto free_node;

	snode->cb_arg = cb_arg;

	dev_dbg(xrs->cfg.dev, "allocated part %d, start col %d\n",
		snode->part, snode->pt_node->start_col);

	return 0;

free_node:
	remove_solver_node(&xrs->rgp, snode);

	return ret;
}

int xrs_release_resource(void *hdl, u32 rid)
{
	struct solver_state *xrs = hdl;
	struct solver_node *node;

	node = rg_search_node(&xrs->rgp, rid);
	if (!node) {
		dev_err(xrs->cfg.dev, "node not exist");
		return -ENODEV;
	}

	xrs->cfg.actions->unload(node->cb_arg);
	remove_solver_node(&xrs->rgp, node);

	return 0;
}

void *xrs_init(struct init_config *cfg)
{
	struct solver_rgroup *rgp;
	struct solver_state *xrs;

	xrs = devm_kzalloc(cfg->dev, sizeof(*xrs), GFP_KERNEL);
	if (!xrs)
		return NULL;

	memcpy(&xrs->cfg, cfg, sizeof(struct init_config));

	rgp = &xrs->rgp;
	INIT_LIST_HEAD(&rgp->node_list);
	INIT_LIST_HEAD(&rgp->pt_node_list);

	return xrs;
}

// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2024, Advanced Micro Devices, Inc.
 */

#include "amdxdna_drv.h"
#include "npu_common.h"
#include "npu_solver.h"

void npu_default_xrs_cfg(struct amdxdna_dev *xdna, struct init_config *xrs_cfg)
{
	xrs_cfg->clk_list.num_levels = 3;
	xrs_cfg->clk_list.cu_clk_list[0] = 0;
	xrs_cfg->clk_list.cu_clk_list[1] = 800;
	xrs_cfg->clk_list.cu_clk_list[2] = 1000;
	xrs_cfg->sys_eff_factor = 1;
	xrs_cfg->mode = XRS_MODE_TEMPORAL_BEST;
	xrs_cfg->dev = xdna->ddev.dev;
}

int npu_alloc_resource(struct amdxdna_hwctx *hwctx)
{
	struct amdxdna_xclbin *xclbin = hwctx->xclbin;
	struct amdxdna_dev *xdna = hwctx->client->xdna;
	struct aie_qos_cap cqos = { 0 };
	struct alloc_requests xrs_req;
	struct amdxdna_partition *part;
	struct cdo_parts *cdo;
	struct part_meta pmp;
	struct aie_qos qos;
	int ret, i;

	cdo = kzalloc(sizeof(*cdo), GFP_KERNEL);
	if (!cdo)
		return -ENOMEM;

	part = &xclbin->partition;
	cdo->cdo_uuid = &part->pdis[0].uuid;
	cdo->ncols = part->ncols;
	cdo->nparts = part->nparts;
	cdo->qos_cap = &cqos;
	cdo->qos_cap->opc = part->ops;

	cdo->start_col_list = kcalloc(cdo->nparts, sizeof(u32), GFP_KERNEL);
	if (!cdo->start_col_list) {
		ret = -ENOMEM;
		goto out;
	}

	qos.gops = hwctx->qos.gops;
	qos.fps = hwctx->qos.fps;
	qos.dma_bw = hwctx->qos.dma_bandwidth;
	qos.latency = hwctx->qos.latency;
	qos.exec_time = hwctx->qos.frame_exec_time;
	qos.priority = hwctx->qos.priority;

	for (i = 0; i < cdo->nparts; i++)
		cdo->start_col_list[i] = part->start_cols[i];

	pmp.xclbin_uuid = &xclbin->uuid;
	pmp.cdo = cdo;

	xrs_req.rid = (uintptr_t)hwctx;
	xrs_req.rqos = &qos;

	xrs_req.pmp = &pmp;

	ret = xrs_allocate_resource(xdna->xrs_hdl, &xrs_req, hwctx);
	if (ret)
		XDNA_ERR(xdna, "Allocate AIE resource failed, ret %d", ret);

	kfree(cdo->start_col_list);
out:
	kfree(cdo);
	return ret;
}

void npu_release_resource(struct amdxdna_hwctx *hwctx)
{
	struct amdxdna_dev *xdna = hwctx->client->xdna;
	int ret;

	ret = xrs_release_resource(xdna->xrs_hdl, (uintptr_t)hwctx);
	if (ret)
		XDNA_ERR(xdna, "Release AIE resource failed, ret %d", ret);
}

// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2024, Advanced Micro Devices, Inc.
 */

#include "amdxdna_drv.h"
#include "npu_common.h"
#include "npu_solver.h"

int npu_msg_cb(void *handle, const u32 *data, size_t size)
{
	struct npu_notify *cb_arg = handle;

	if (unlikely(!data))
		goto out;

	if (unlikely(cb_arg->size != size)) {
		cb_arg->error = -EINVAL;
		goto out;
	}

	print_hex_dump_debug("resp data: ", DUMP_PREFIX_OFFSET,
			     16, 4, data, cb_arg->size, true);
	memcpy(cb_arg->data, data, cb_arg->size);
out:
	complete(&cb_arg->comp);
	return cb_arg->error;
}

int npu_send_msg_wait(struct amdxdna_dev *xdna,
		      struct mailbox_channel *chann,
		      struct xdna_mailbox_msg *msg)
{
	struct npu_notify *hdl = msg->handle;
	int ret;

	ret = xdna_mailbox_send_msg(chann, msg, TX_TIMEOUT);
	if (ret) {
		XDNA_ERR(xdna, "Send message failed, ret %d", ret);
		return ret;
	}

	ret = wait_for_completion_timeout(&hdl->comp,
					  msecs_to_jiffies(RX_TIMEOUT));
	if (!ret) {
		XDNA_ERR(xdna, "Wait for completion timeout");
		return -ETIME;
	}

	return hdl->error;
}

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
	struct amdxdna_dev *xdna = hwctx->client->xdna;
	struct alloc_requests *xrs_req;
	int ret;

	xrs_req = kzalloc(sizeof(*xrs_req), GFP_KERNEL);
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

	xrs_req->rid = (uintptr_t)hwctx;

	ret = xrs_allocate_resource(xdna->xrs_hdl, xrs_req, hwctx);
	if (ret)
		XDNA_ERR(xdna, "Allocate AIE resource failed, ret %d", ret);

	kfree(xrs_req);
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

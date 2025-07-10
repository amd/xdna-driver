// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2025, Advanced Micro Devices, Inc.
 */
#include <linux/device.h>

#include "amdxdna_ctx.h"
#include "ve2_of.h"
#include "ve2_mgmt.h"
#include "ve2_res_solver.h"

static int cert_setup_partition(struct device *aie_part, u32 col, u32 lead_col, u32 partition_size,
				u64 hsa_addr)
{
	u32 lead_col_addr = VE2_ADDR(lead_col, 0, 0);
	struct aie_location loc = { 0 };
	struct handshake cert_comm = { 0 };
	u32 rel_col = col - lead_col;
	int ret;

	cert_comm.partition_base_address = lead_col_addr;
	cert_comm.aie_info.partition_size = partition_size;
	cert_comm.hsa_addr_high =  upper_32_bits(hsa_addr);
	cert_comm.hsa_addr_low =  lower_32_bits(hsa_addr);
	cert_comm.dbg.hsa_addr_high = 0xFFFFFFFF;
	cert_comm.dbg.hsa_addr_low = 0xFFFFFFFF;
	cert_comm.mpaie_alive = ALIVE_MAGIC;

	/* write to cert handshake shared memory */
	ret = aie_partition_write_privileged_mem(aie_part, CERT_HANDSHAKE_OFF(rel_col),
						 sizeof(cert_comm), (void *)&cert_comm);
	if (ret < 0)
		return ret;

	loc.col = rel_col;
	/* wake up cert */
	return aie_partition_uc_wakeup(aie_part, &loc);
}

static int ve2_xrs_col_list(struct amdxdna_dev *xdna, struct alloc_requests *xrs_req, int total_col,
			    u32 num_col)
{
	int start, end, first, last;
	u32 entries;
	int i;

	/*
	 * In range [start, end], find out columns that is multiple of num_col.
	 *      'first' is the first column,
	 *      'last' is the last column,
	 *      'entries' is the total number of columns.
	 */
	start = 0;
	end =  total_col - num_col;

	first = start + (num_col - start % num_col) % num_col;
	last = end - end % num_col;
	if (last >= first)
		entries = (last - first) / num_col + 1;

	if (unlikely(!entries)) {
		XDNA_ERR(xdna, "Start %d end %d num_col %d", start, end, num_col);
		return -EINVAL;
	}

	xrs_req->cdo.start_cols = kmalloc_array(entries, sizeof(*xrs_req->cdo.start_cols),
						GFP_KERNEL);
	if (!xrs_req->cdo.start_cols)
		return -ENOMEM;

	xrs_req->cdo.cols_len = entries;
	xrs_req->cdo.start_cols[0] = first;
	for (i = 1; i < entries; i++)
		xrs_req->cdo.start_cols[i] = xrs_req->cdo.start_cols[i - 1] + num_col;

	XDNA_DBG(xdna, "start %d end %d first %d last %d, entries %d", start, end, first, last,
		 entries);

	return 0;
}

static int ve2_xrs_request(struct amdxdna_dev *xdna, struct amdxdna_ctx *hwctx)
{
	struct solver_state *xrs = xdna->dev_handle->xrs_hdl;
	struct xrs_action_load load_act;
	struct alloc_requests *xrs_req;
	int total_col;
	int ret;

	mutex_lock(&xrs->xrs_lock);
	xrs_req = kzalloc(sizeof(*xrs_req), GFP_KERNEL);
	if (!xrs_req) {
		mutex_unlock(&xrs->xrs_lock);
		return -ENOMEM;
	}

	xrs_req->cdo.ncols = hwctx->num_tiles;

	XDNA_DBG(xdna, "User requested num_col %d", xrs_req->cdo.ncols);

	total_col = xrs_get_total_cols(xdna->dev_handle->xrs_hdl);
	if (total_col < 0) {
		ret = -EINVAL;
		goto free_xrs_req;
	}

	ret = ve2_xrs_col_list(xdna, xrs_req, total_col, xrs_req->cdo.ncols);
	if (ret) {
		XDNA_ERR(xdna, "Allocate XRS col resource failed, ret %d", ret);
		goto free_xrs_req;
	}

	xrs_req->rid = (uintptr_t)hwctx;
	ret = xrs_allocate_resource(xrs, xrs_req, &load_act);
	if (ret) {
		XDNA_ERR(xdna, "Allocate XRS resource failed, ret %d", ret);
		goto free_start_cols;
	}

	hwctx->start_col = load_act.part.start_col;
	hwctx->num_col = load_act.part.ncols;

free_start_cols:
	kfree(xrs_req->cdo.start_cols);
free_xrs_req:
	kfree(xrs_req);
	mutex_unlock(&xrs->xrs_lock);
	return ret;
}

static void ve2_event_completion_cb(u32 partition_id, void *cb_arg)
{
	struct amdxdna_ctx *hwctx = (struct amdxdna_ctx *)cb_arg;

	wake_up_interruptible_all(&hwctx->priv->waitq);
}

int ve2_mgmt_create_partition(struct amdxdna_dev *xdna, struct amdxdna_ctx *hwctx)
{
	struct amdxdna_ctx_priv *priv = hwctx->priv;
	struct aie_partition_init_args args = { 0 };
	struct aie_partition_req request = { 0 };
	struct device *aie_part;
	u32 start_col;
	u32 num_col;
	int ret;

	ret = ve2_xrs_request(xdna, hwctx);
	if (ret) {
		XDNA_ERR(xdna, "Allocate XRS resource failed, ret %d", ret);
		return -EINVAL;
	}

	start_col = hwctx->start_col;
	num_col = hwctx->num_col;

	request.user_event1_complete = ve2_event_completion_cb;
	request.user_event1_priv = hwctx;
	request.partition_id = aie_calc_part_id(start_col, num_col);
	XDNA_DBG(xdna, "Requesting partition for start_col %d, num_col %d with partition_id %d\n",
		 start_col, num_col, request.partition_id);
	aie_part = aie_partition_request(&request);
	if (IS_ERR(aie_part)) {
		ret = -ENODEV;
		XDNA_ERR(xdna, "aie parition request failed, error %d", ret);
		goto xrs_rel_res;
	}
	priv->aie_part = aie_part;

	args.locs = NULL;
	args.num_tiles = 0;
	args.init_opts = AIE_PART_INIT_OPT_DEFAULT ^ AIE_PART_INIT_OPT_UC_ENB_MEM_PRIV;
	ret = aie_partition_initialize(aie_part, &args);
	if (ret < 0) {
		XDNA_ERR(xdna, "aie partition init failed: %d", ret);
		aie_partition_release(aie_part);
		goto xrs_rel_res;
	}

	for (u32 col = start_col; col < start_col + num_col; col++) {
		u64 hsa_addr = 0xFFFFFFFFFFFFFFFF;

		//Only lead cert(the first column) should be set with HSA Queue addr
		if (col == start_col)
			hsa_addr = priv->hwctx_hsa_queue.hsa_queue_mem.dma_addr;

		ret = cert_setup_partition(aie_part, col, start_col, num_col, hsa_addr);
		if (ret < 0) {
			XDNA_ERR(xdna, "cert_setup_partition() err %d for col %d", ret, start_col);
			goto aie_part_rel;
		}
	}

	priv->start_col = start_col;
	priv->num_col = num_col;

	return 0;
aie_part_rel:
	aie_partition_release(aie_part);
xrs_rel_res:
	xrs_release_resource(xdna->dev_handle->xrs_hdl, (uintptr_t)hwctx);
	return ret;
}

static int cert_clear_partition(struct amdxdna_dev *xdna, struct device *aie_part, u32 col)
{
	struct handshake cert_comm = { 0 };

	return aie_partition_write_privileged_mem(aie_part, CERT_HANDSHAKE_OFF(col),
						  sizeof(cert_comm), (void *)&cert_comm);
}

int ve2_mgmt_destroy_partition(struct amdxdna_ctx *hwctx)
{
	struct amdxdna_dev *xdna = hwctx->client->xdna;
	struct amdxdna_ctx_priv *priv = hwctx->priv;
	int ret;

	if (!priv->aie_part) {
		XDNA_ERR(xdna, "Parition does not have aie device handle");
		return -ENODEV;
	}

	for (u32 col = 0; col < priv->num_col; col++) {
		ret = cert_clear_partition(xdna, priv->aie_part, col);
		if (ret < 0)
			XDNA_ERR(xdna, "cert_clear_partition() err %d for col %d", ret, col);
	}

	aie_partition_teardown(priv->aie_part);
	aie_partition_release(priv->aie_part);

	return xrs_release_resource(xdna->dev_handle->xrs_hdl, (uintptr_t)hwctx);
}

struct amdxdna_ctx *ve2_get_hwctx(struct amdxdna_dev *xdna, u32 col)
{
	struct amdxdna_client *client;
	struct amdxdna_ctx *hwctx;
	unsigned long hwctx_id;
	u32 start, end;
	int idx;

	drm_WARN_ON(&xdna->ddev, !mutex_is_locked(&xdna->dev_lock));

	list_for_each_entry(client, &xdna->client_list, node) {
		idx = srcu_read_lock(&client->ctx_srcu);
		amdxdna_for_each_ctx(client, hwctx_id, hwctx) {
			start = hwctx->start_col;
			end = start + hwctx->num_col;
			if (col >= start && col < end) {
				XDNA_DBG(xdna, "hwctx found with id %d & pid %d\n", hwctx->id,
					 hwctx->client->pid);
				srcu_read_unlock(&client->ctx_srcu, idx);
				return hwctx;
			}
		}
		srcu_read_unlock(&client->ctx_srcu, idx);
	}

	XDNA_ERR(xdna, "hwctx not found for requested col: %d\n", col);

	return NULL;
}

int notify_fw_cmd_ready(struct amdxdna_ctx *hwctx)
{
	struct amdxdna_dev *xdna = hwctx->client->xdna;
	u32 value = VE2_USER_EVENT_ID;
	struct aie_location loc = {0};
	int ret;

	loc.col = hwctx->start_col;

	/* aie_partition_write() returns below possible values:
	 *  success case: number of bytes write, so, return value >= 0
	 *  failure case: negative value, so, return value < 0
	 */
	ret = aie_partition_write(hwctx->priv->aie_part, loc, VE2_EVENT_GENERATE_REG, sizeof(u32),
				  (void *)&(value), 0);
	if (ret < 0)
		XDNA_DBG(xdna, "AIE write on event_generate register throw error %d for col %u\n",
			 ret, loc.col);

	return ret;
}

// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2025, Advanced Micro Devices, Inc.
 */

#include <linux/device.h>
#include <linux/firmware.h>
#include <linux/xlnx-ai-engine.h>

#include "ve2_of.h"
#include "ve2_mgmt.h"

static int ve2_load_fw(struct amdxdna_dev_hdl *xdna_hdl)
{
	struct amdxdna_dev *xdna = xdna_hdl->xdna;
	struct aie_partition_init_args args;
	struct aie_partition_req request;
	const struct firmware *fw;
	struct device *xaie_dev;
	size_t buf_len;
	char *buf;
	int ret;

	XDNA_DBG(xdna, "Loading firmware: %s", xdna_hdl->priv->fw_path);

	ret = request_firmware(&fw, xdna_hdl->priv->fw_path, xdna->ddev.dev);
	if (ret) {
		XDNA_ERR(xdna, "request fw %s failed %d", xdna_hdl->priv->fw_path, ret);
		return -ENODEV;
	}

	XDNA_DBG(xdna, "Firmware loaded: size=%zu bytes", fw->size);

	buf = kmalloc(fw->size, GFP_KERNEL);
	if (!buf) {
		release_firmware(fw);
		return -ENOMEM;
	}
	memcpy(buf, fw->data, fw->size);
	buf_len = fw->size;
	release_firmware(fw);

	/* request all cols */
	xaie_dev = aie_partition_request(&request);
	if (IS_ERR(xaie_dev)) {
		ret = PTR_ERR(xaie_dev);
		XDNA_ERR(xdna, "aie partition request failed: %d", ret);
		goto out;
	}
	XDNA_DBG(xdna, "aie partition request succeeded: 0x%x", request.partition_id);

	args.locs = NULL;
	args.num_tiles = 0;
	args.handshake_cols = 0;
	args.handshake = NULL;
	args.init_opts = (AIE_PART_INIT_OPT_DEFAULT | AIE_PART_INIT_OPT_DIS_TLAST_ERROR)
	& ~AIE_PART_INIT_OPT_UC_ENB_MEM_PRIV;
	ret = ve2_partition_initialize(xaie_dev, &args);
	if (ret) {
		XDNA_ERR(xdna, "aie partition init failed: %d", ret);
		goto release;
	}

	ret = aie_load_cert_broadcast(xaie_dev, buf);
	if (ret) {
		XDNA_ERR(xdna, "aie load cert broadcast failed %d", ret);
		goto teardown;
	}
	XDNA_INFO(xdna, "aie load cert broadcast complete");

	ret = ve2_store_firmware_version(&xdna_hdl->fw_version, xaie_dev);
	if (ret < 0) {
		XDNA_ERR(xdna, "cert status read failed with err %d", ret);
		goto teardown;
	}
	XDNA_INFO(xdna, "CERT major: %d\n", xdna_hdl->fw_version.major);
	XDNA_INFO(xdna, "CERT minor: %d\n", xdna_hdl->fw_version.minor);
	XDNA_INFO(xdna, "CERT git hash: %s\n", xdna_hdl->fw_version.git_hash);
	XDNA_INFO(xdna, "CERT git hash date: %s\n", xdna_hdl->fw_version.date);

teardown:
	aie_partition_teardown(xaie_dev);
release:
	aie_partition_release(xaie_dev);
out:
	kfree(buf);
	return ret;
}

static int ve2_init(struct amdxdna_dev *xdna)
{
	struct device *dev = xdna->ddev.dev;
	struct ve2_firmware_status *fw_slots;
	struct init_config xrs_cfg = { 0 };
	struct amdxdna_dev_hdl *xdna_hdl;
	int ret;
	u32 col;

	xdna_hdl = devm_kzalloc(dev, sizeof(*xdna_hdl), GFP_KERNEL);
	if (!xdna_hdl)
		return -ENOMEM;

	xdna_hdl->xdna = xdna;
	xdna_hdl->priv = xdna->dev_info->dev_priv;
	xdna->dev_handle = xdna_hdl;

	if (ve2_hwctx_limit)
		xdna_hdl->hwctx_limit = ve2_hwctx_limit;
	else
		xdna_hdl->hwctx_limit = xdna_hdl->priv->hwctx_limit;

	XDNA_INFO(xdna, "Maximum limit %d hardware context(s)", xdna_hdl->hwctx_limit);

	ret = aie_get_device_info(&xdna_hdl->aie_dev_info);
	if (ret) {
		if (ret == -ENODEV) {
			XDNA_INFO(xdna, "AIE device not ready yet, deferring probe");
			return -EPROBE_DEFER;
		}
		XDNA_ERR(xdna, "Failed to get AIE device info, ret %d", ret);
		return ret;
	}
	XDNA_INFO(xdna, "AIE device: %d columns, %d rows",
		  xdna_hdl->aie_dev_info.cols, xdna_hdl->aie_dev_info.rows);

	xrs_cfg.ddev = &xdna->ddev;

	/* Support module parameters to override column count if valid */
	if (max_col > 0 && start_col >= 0 &&
	    (max_col + start_col) <= xdna_hdl->aie_dev_info.cols) {
		xrs_cfg.total_col = max_col;
		XDNA_INFO(xdna, "Using module parameter: max_col=%d, start_col=%d",
			  max_col, start_col);
	} else {
		xrs_cfg.total_col = xdna_hdl->aie_dev_info.cols;
	}

	xdna->dev_handle->xrs_hdl = xrsm_init(&xrs_cfg);
	if (!xdna->dev_handle->xrs_hdl) {
		XDNA_ERR(xdna, "Initialization of Resource resolver failed");
		return -EINVAL;
	}

	/* Load firmware */
	ret = ve2_load_fw(xdna_hdl);
	if (ret) {
		XDNA_ERR(xdna, "aie load %s failed with err %d", xdna_hdl->priv->fw_path, ret);
		return ret;
	}
	XDNA_DBG(xdna, "aie fw load %s completed", xdna_hdl->priv->fw_path);

	/* Allocate arrays based on actual column count from device */
	xdna_hdl->fw_slots = devm_kcalloc(dev, xdna_hdl->aie_dev_info.cols,
					  sizeof(*xdna_hdl->fw_slots), GFP_KERNEL);
	if (!xdna_hdl->fw_slots) {
		XDNA_ERR(xdna, "No memory for fw_slots array");
		return -ENOMEM;
	}

	xdna_hdl->ve2_mgmtctx = devm_kcalloc(dev, xdna_hdl->aie_dev_info.cols,
					     sizeof(*xdna_hdl->ve2_mgmtctx), GFP_KERNEL);
	if (!xdna_hdl->ve2_mgmtctx) {
		XDNA_ERR(xdna, "No memory for ve2_mgmtctx array");
		return -ENOMEM;
	}

	for (col = 0; col < xdna_hdl->aie_dev_info.cols; col++) {
		fw_slots = devm_kzalloc(dev, sizeof(*fw_slots), GFP_KERNEL);
		if (!fw_slots) {
			XDNA_ERR(xdna, "No memory for fw status");
			return -ENOMEM;
		}
		xdna->dev_handle->fw_slots[col] = fw_slots;
	}

	/* Default CMA only - no memory-region from DT */
	return 0;
}

static void ve2_fini(struct amdxdna_dev *xdna)
{
	/* All resources are managed by devm_/drmm_ */
	XDNA_DBG(xdna, "VE2 device cleanup function");
}

const struct amdxdna_dev_ops ve2_ops = {
	.init		= ve2_init,
	.fini		= ve2_fini,
	.ctx_init	= ve2_hwctx_init,
	.ctx_fini	= ve2_hwctx_fini,
	.ctx_config     = ve2_hwctx_config,
	.cmd_submit	= ve2_cmd_submit,
	.cmd_wait	= ve2_cmd_wait,
	.get_aie_info	= ve2_get_aie_info,
	.set_aie_state	= ve2_set_aie_state,
	.get_aie_array	= ve2_get_array,
};

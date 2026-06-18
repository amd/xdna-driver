// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2026, Advanced Micro Devices, Inc.
 *
 */

#include <linux/device.h>
#include <linux/errno.h>
#include <linux/firmware.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/xlnx-ai-engine.h>

#include "amdxdna_aux_drv.h"
#include "amdxdna_ctx.h"
#include "amdxdna_solver.h"
#include "ve2_aux.h"
#include "ve2_debug.h"
#include "ve2_hwctx.h"
#include "ve2_mgmt.h"

MODULE_FIRMWARE("amdnpu/release_cert_ve2.elf");

static int ve2_store_firmware_version(struct ve2_firmware_version *c_version,
				      struct device *xaie_dev)
{
	struct ve2_firmware_version *version;
	int ret;

	version = kzalloc(sizeof(*version), GFP_KERNEL);
	if (!version)
		return -ENOMEM;

	ret = ve2_partition_read(xaie_dev, 0, 0,
				 VE2_PROG_DATA_MEMORY_OFF + VE2_CERT_VERSION_OFF,
				 VE2_CERT_VERSION_SIZE, version);
	if (ret < 0) {
		kfree(version);
		return ret;
	}

	c_version->major = version->major;
	c_version->minor = version->minor;
	strscpy(c_version->git_hash, version->git_hash, VE2_FW_HASH_STRING_LENGTH);
	strscpy(c_version->date, version->date, VE2_FW_DATE_STRING_LENGTH);
	c_version->hotfix = version->hotfix;
	c_version->build = version->build;
	kfree(version);

	return 0;
}

static int ve2_load_fw(struct amdxdna_dev_hdl *xdna_hdl)
{
	struct amdxdna_dev *xdna = xdna_hdl->xdna;
	struct aie_partition_init_args args;
	struct aie_partition_req request = { };
	const struct firmware *fw;
	struct device *xaie_dev;
	char *buf;
	int ret;

	if (!xdna_hdl->priv || !xdna_hdl->priv->fw_path)
		return -EINVAL;

	XDNA_DBG(xdna, "Loading firmware: %s", xdna_hdl->priv->fw_path);

	ret = request_firmware(&fw, xdna_hdl->priv->fw_path, xdna->ddev.dev);
	if (ret) {
		XDNA_ERR(xdna, "request fw %s failed %d", xdna_hdl->priv->fw_path, ret);
		return -ENODEV;
	}

	buf = kmalloc(fw->size, GFP_KERNEL);
	if (!buf) {
		release_firmware(fw);
		return -ENOMEM;
	}
	memcpy(buf, fw->data, fw->size);
	release_firmware(fw);

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
	args.init_opts = (AIE_PART_INIT_OPT_DEFAULT | AIE_PART_INIT_OPT_DIS_TLAST_ERROR) &
			 ~AIE_PART_INIT_OPT_UC_ENB_MEM_PRIV;
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
	XDNA_INFO(xdna, "CERT major: %d", xdna_hdl->fw_version.major);
	XDNA_INFO(xdna, "CERT minor: %d", xdna_hdl->fw_version.minor);

teardown:
	aie_partition_teardown(xaie_dev);
release:
	aie_partition_release(xaie_dev);
out:
	kfree(buf);
	return ret;
}

void ve2_auto_select_mem_bitmap(struct amdxdna_dev *xdna, struct amdxdna_hwctx *hwctx)
{
	struct amdxdna_ctx_priv *vp = ve2_hw_priv(hwctx);

	/*
	 * XRT passes a memory-bank bitmap in CREATE_BO flags (low 8 bits).
	 * Without DT memory-region / aie-mem-topology, use bank 0 only.
	 */
	if (vp)
		vp->mem_bitmap = 0x1;
	(void)xdna;
}

int ve2_probe(struct amdxdna_dev *xdna, struct amdxdna_dev_hdl *hdl)
{
	struct init_config xrs_cfg = { };
	int ret;

	ret = aie_get_device_info(&hdl->aie_dev_info);
	if (ret) {
		if (ret == -ENODEV) {
			XDNA_INFO(xdna, "AIE device not ready yet, deferring probe");
			return -EPROBE_DEFER;
		}
		XDNA_ERR(xdna, "aie_get_device_info failed %d", ret);
		return ret;
	}

	XDNA_INFO(xdna, "AIE device: %u columns, %u rows",
		  hdl->aie_dev_info.cols, hdl->aie_dev_info.rows);

	xrs_cfg.ddev = &xdna->ddev;
	xrs_cfg.total_col = hdl->aie_dev_info.cols;
	xdna->xrs_hdl = xrsm_init(&xrs_cfg);
	if (!xdna->xrs_hdl) {
		XDNA_WARN(xdna, "Initialization of Resource resolver failed");
		return -EINVAL;
	}

	ret = ve2_load_fw(hdl);
	if (ret) {
		XDNA_ERR(xdna, "aie load %s failed with err %d", hdl->priv->fw_path, ret);
		return ret;
	}
	if (hdl->priv && hdl->priv->fw_path)
		XDNA_INFO(xdna, "aie fw load %s completed", hdl->priv->fw_path);
	else
		XDNA_INFO(xdna, "aie fw load completed");

	return 0;
}

static const struct amdxdna_dev_priv ve2_aux_priv = {
	.fw_path		= "amdnpu/release_cert_ve2.elf",
};

const struct amdxdna_dev_info dev_ve2_info = {
	.device_type	= AMDXDNA_DEV_TYPE_KMQ,
	.first_col	= 0,
	.dev_priv	= &ve2_aux_priv,
	.ops		= &ve2_ops,
};

static int ve2_aux_init(struct amdxdna_dev *xdna)
{
	struct device *dev = xdna->ddev.dev;
	struct amdxdna_dev_hdl *xdna_hdl;
	const struct amdxdna_dev_priv *priv;
	int ret;

	priv = xdna->dev_info->dev_priv;
	if (!priv)
		return -EINVAL;

	XDNA_DBG(xdna, "Initializing VE2 device");

	xdna_hdl = devm_kzalloc(dev, sizeof(*xdna_hdl), GFP_KERNEL);
	if (!xdna_hdl)
		return -ENOMEM;

	xdna_hdl->xdna = xdna;
	xdna_hdl->priv = priv;
	xdna->dev_handle = xdna_hdl;

	ret = ve2_probe(xdna, xdna_hdl);
	if (ret)
		return ret;

	XDNA_INFO(xdna, "VE2 device ready (host-queue=%s)",
		  enable_polling ? "polling" : "interrupt");

	return 0;
}

static void ve2_aux_fini(struct amdxdna_dev *xdna)
{
	struct amdxdna_dev_hdl *hdl = ve2_dev_hdl(xdna);

	if (!hdl)
		return;

	XDNA_DBG(xdna, "VE2 device cleanup");
}

const struct amdxdna_dev_ops ve2_ops = {
	.init			= ve2_aux_init,
	.fini			= ve2_aux_fini,
	.hwctx_init		= ve2_hwctx_init,
	.hwctx_fini		= ve2_hwctx_fini,
	.hwctx_config		= ve2_hwctx_config,
	.cmd_submit		= ve2_cmd_submit,
	.cmd_wait		= ve2_cmd_wait,
	.get_array		= ve2_debug_get_array,
	.set_aie_state		= ve2_set_aie_state,
};

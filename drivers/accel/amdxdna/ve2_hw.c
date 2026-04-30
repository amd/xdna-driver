// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2026, Advanced Micro Devices, Inc.
 *
 * VE2 Layer 2: device firmware (cert path, AIE partition, version read), HAL
 * slots, and `ve2_hw_ops` (ctx + command path).  Downstream ve2_fw.c and
 * ve2_mgmt.c port into this file.
 */

#include <linux/errno.h>
#include <linux/firmware.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/xlnx-ai-engine.h>

#include "amdxdna_drv.h"
#include "ve2_aux.h"
#include "ve2_hw.h"

/* Declared for modinfo / packaging; path must match `ve2_aux_priv.fw_path`. */
MODULE_FIRMWARE("amdnpu/release_cert_ve2.elf");

static int ve2_partition_read_fw(struct device *aie_dev, u32 col, u32 row,
				 u32 offset, size_t size, void *buf)
{
	struct aie_location loc = { .col = col, .row = row };

	return aie_partition_read(aie_dev, loc, offset, size, buf);
}

static int ve2_store_firmware_version(struct ve2_firmware_version *c_version,
				      struct device *xaie_dev)
{
	struct ve2_firmware_version *version;
	int ret;

	version = kzalloc(sizeof(*version), GFP_KERNEL);
	if (!version)
		return -ENOMEM;

	ret = ve2_partition_read_fw(xaie_dev, 0, 0,
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

static int ve2_partition_init_fw(struct device *dev, struct aie_partition_init_args *args)
{
	return aie_partition_initialize(dev, args);
}

int ve2_hw_load_cert_firmware(struct amdxdna_dev_hdl *xdna_hdl)
{
	struct amdxdna_dev *xdna = xdna_hdl->xdna;
	struct aie_partition_init_args args;
	struct aie_partition_req request;
	const struct firmware *fw;
	struct device *xaie_dev;
	char *buf;
	int ret;

	if (!xdna_hdl->ve2_priv || !xdna_hdl->ve2_priv->fw_path)
		return -EINVAL;

	XDNA_DBG(xdna, "Loading firmware: %s", xdna_hdl->ve2_priv->fw_path);

	ret = request_firmware(&fw, xdna_hdl->ve2_priv->fw_path, xdna->ddev.dev);
	if (ret) {
		XDNA_ERR(xdna, "request fw %s failed %d", xdna_hdl->ve2_priv->fw_path, ret);
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
	ret = ve2_partition_init_fw(xaie_dev, &args);
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

int ve2_hw_init_fw_status_slots(struct amdxdna_dev *xdna, struct amdxdna_dev_hdl *hdl)
{
	struct device *dev = xdna->ddev.dev;
	struct ve2_firmware_status *sl;
	u32 col;

	if (!hdl->aie_dev_info.cols)
		return 0;

	hdl->fw_slots = devm_kcalloc(dev, hdl->aie_dev_info.cols, sizeof(*hdl->fw_slots),
				     GFP_KERNEL);
	if (!hdl->fw_slots) {
		XDNA_ERR(xdna, "No memory for fw_slots array");
		return -ENOMEM;
	}

	for (col = 0; col < hdl->aie_dev_info.cols; col++) {
		sl = devm_kzalloc(dev, sizeof(*sl), GFP_KERNEL);
		if (!sl) {
			XDNA_ERR(xdna, "No memory for fw status");
			return -ENOMEM;
		}
		hdl->fw_slots[col] = sl;
	}

	return 0;
}

static int ve2_l2_ctx_init(struct amdxdna_hwctx *hwctx, u32 start_col, u32 num_cols)
{
	(void)hwctx;
	(void)start_col;
	(void)num_cols;
	return 0;
}

static void ve2_l2_ctx_fini(struct amdxdna_hwctx *hwctx)
{
	(void)hwctx;
}

static int ve2_l2_cmd_submit(struct amdxdna_hwctx *hwctx, struct amdxdna_sched_job *job,
			     u64 *seq)
{
	(void)hwctx;
	(void)job;
	(void)seq;
	return -EOPNOTSUPP;
}

static int ve2_l2_cmd_wait(struct amdxdna_hwctx *hwctx, u64 seq, u32 timeout_ms)
{
	(void)hwctx;
	(void)seq;
	(void)timeout_ms;
	return -EOPNOTSUPP;
}

static const struct ve2_hw_ops ve2_hw_ops_table = {
	.ctx_init	= ve2_l2_ctx_init,
	.ctx_fini	= ve2_l2_ctx_fini,
	.cmd_submit	= ve2_l2_cmd_submit,
	.cmd_wait	= ve2_l2_cmd_wait,
};

const struct ve2_hw_ops *ve2_hw_get_ops(void)
{
	return &ve2_hw_ops_table;
}

// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2026, Advanced Micro Devices, Inc.
 */

#include <linux/firmware.h>
#include <linux/string.h>

#include "amdxdna_aux_drv.h"
#include "amdxdna_ctx.h"
#include "ve2_aux.h"

/*
 * Declares firmware for modinfo/packaging.
 * Loaded at runtime via request_firmware() in ve2_load_fw().
 */
MODULE_FIRMWARE("amdnpu/release_cert_ve2.elf");

const struct amdxdna_dev_priv ve2_aux_priv = {
	.fw_path	= "amdnpu/release_cert_ve2.elf",
};

const struct amdxdna_dev_info dev_ve2_info = {
	.device_type	= AMDXDNA_DEV_TYPE_KMQ,
	.dev_priv	= &ve2_aux_priv,
	.ops		= &ve2_ops,
};

static int ve2_partition_read_wrap(struct device *aie_dev, u32 col, u32 row,
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

	ret = ve2_partition_read_wrap(xaie_dev, 0, 0,
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

static int ve2_partition_initialize_wrap(struct device *dev, struct aie_partition_init_args *args)
{
	return aie_partition_initialize(dev, args);
}

static int ve2_load_fw(struct amdxdna_dev_hdl *xdna_hdl)
{
	struct amdxdna_dev *xdna = xdna_hdl->xdna;
	struct aie_partition_init_args args;
	struct aie_partition_req request;
	const struct firmware *fw;
	struct device *xaie_dev;
	char *buf;
	int ret;

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
	ret = ve2_partition_initialize_wrap(xaie_dev, &args);
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

static int ve2_init(struct amdxdna_dev *xdna)
{
	struct ve2_firmware_status *fw_slots;
	struct device *dev = xdna->ddev.dev;
	struct amdxdna_dev_hdl *xdna_hdl;
	int ret;
	u32 col;

	XDNA_DBG(xdna, "Initializing VE2 device");

	xdna_hdl = devm_kzalloc(dev, sizeof(*xdna_hdl), GFP_KERNEL);
	if (!xdna_hdl)
		return -ENOMEM;

	xdna_hdl->xdna = xdna;
	xdna_hdl->ve2_priv = &ve2_aux_priv;
	xdna->dev_handle = xdna_hdl;

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

	ret = ve2_load_fw(xdna_hdl);
	if (ret) {
		XDNA_ERR(xdna, "aie load %s failed with err %d", xdna_hdl->ve2_priv->fw_path, ret);
		return ret;
	}
	XDNA_DBG(xdna, "aie fw load %s completed", xdna_hdl->ve2_priv->fw_path);

	xdna_hdl->fw_slots = devm_kcalloc(dev, xdna_hdl->aie_dev_info.cols,
					  sizeof(*xdna_hdl->fw_slots), GFP_KERNEL);
	if (!xdna_hdl->fw_slots) {
		XDNA_ERR(xdna, "No memory for fw_slots array");
		return -ENOMEM;
	}

	for (col = 0; col < xdna_hdl->aie_dev_info.cols; col++) {
		fw_slots = devm_kzalloc(dev, sizeof(*fw_slots), GFP_KERNEL);
		if (!fw_slots) {
			XDNA_ERR(xdna, "No memory for fw status");
			return -ENOMEM;
		}
		xdna_hdl->fw_slots[col] = fw_slots;
	}

	return 0;
}

static void ve2_fini(struct amdxdna_dev *xdna)
{
	struct amdxdna_dev_hdl *hdl = ve2_dev_hdl(xdna);

	if (!hdl)
		return;

	XDNA_DBG(xdna, "VE2 device cleanup");
}

static int ve2_get_aie_info(struct amdxdna_client *client, struct amdxdna_drm_get_info *args)
{
	return -EOPNOTSUPP;
}

static int ve2_set_aie_state(struct amdxdna_client *client, struct amdxdna_drm_set_state *args)
{
	return -EOPNOTSUPP;
}

static int ve2_hwctx_init(struct amdxdna_hwctx *hwctx)
{
	return -EOPNOTSUPP;
}

static void ve2_hwctx_fini(struct amdxdna_hwctx *hwctx)
{
}

static int ve2_hwctx_config(struct amdxdna_hwctx *hwctx, u32 type, u64 value, void *buf, u32 size)
{
	return -EOPNOTSUPP;
}

static int ve2_hwctx_sync_debug_bo(struct amdxdna_hwctx *hwctx, u32 debug_bo_hdl)
{
	return -EOPNOTSUPP;
}

static void ve2_hmm_invalidate(struct amdxdna_gem_obj *abo, unsigned long cur_seq)
{
}

static int ve2_cmd_submit(struct amdxdna_hwctx *hwctx, struct amdxdna_sched_job *job, u64 *seq)
{
	return -EOPNOTSUPP;
}

static int ve2_cmd_wait(struct amdxdna_hwctx *hwctx, u64 seq, u32 timeout_ms)
{
	/*
	 * VE2 cmd_wait will be implemented in a later patch when the DRM
	 * scheduler and hardware context submit path are functional.
	 */
	return -EOPNOTSUPP;
}

static int ve2_get_array(struct amdxdna_client *client, struct amdxdna_drm_get_array *args)
{
	return -EOPNOTSUPP;
}

const struct amdxdna_dev_ops ve2_ops = {
	.init			= ve2_init,
	.fini			= ve2_fini,
	.get_aie_info		= ve2_get_aie_info,
	.set_aie_state		= ve2_set_aie_state,
	.hwctx_init		= ve2_hwctx_init,
	.hwctx_fini		= ve2_hwctx_fini,
	.hwctx_config		= ve2_hwctx_config,
	.hwctx_sync_debug_bo	= ve2_hwctx_sync_debug_bo,
	.hmm_invalidate		= ve2_hmm_invalidate,
	.cmd_submit		= ve2_cmd_submit,
	.cmd_wait		= ve2_cmd_wait,
	.get_array		= ve2_get_array,
};

// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2025, Advanced Micro Devices, Inc.
 */

#include <linux/device.h>
#include <linux/firmware.h>
#include <linux/xlnx-ai-engine.h>

#include "ve2_of.h"

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
	buf_len = fw->size;
	release_firmware(fw);

	/* request all cols */
	xaie_dev = aie_partition_request(&request);
        if (IS_ERR(xaie_dev)) {
		XDNA_ERR(xdna, "aie partition request failed");
		ret = -ENODEV;
		goto out;
	}
	XDNA_DBG(xdna, "aie partiton request succeeded: 0x%x", request.partition_id);

	args.locs = NULL;
	args.num_tiles = 0;
	args.init_opts = AIE_PART_INIT_OPT_DEFAULT;
	ret = aie_partition_initialize(xaie_dev, &args);
	if (ret) {
		XDNA_ERR(xdna, "aie partition init failed: %d", ret);
		goto release;
	}

	ret = aie_load_cert(xaie_dev, buf);

	aie_partition_teardown(xaie_dev);

release:
	aie_partition_release(xaie_dev);
out:
	kfree(buf);
	return ret;
}

static int ve2_init(struct amdxdna_dev *xdna)
{
	struct platform_device *pdev = to_platform_device(xdna->ddev.dev);
	struct amdxdna_dev_hdl *xdna_hdl;
	int ret;

	xdna_hdl = devm_kzalloc(&pdev->dev, sizeof(*xdna_hdl), GFP_KERNEL);
	if (!xdna_hdl)
		return -ENOMEM;

	xdna_hdl->xdna = xdna;
	xdna_hdl->priv = xdna->dev_info->dev_priv;

	xdna->dev_handle = xdna_hdl;

	ret = ve2_load_fw(xdna_hdl);
	if (ret) {
		XDNA_ERR(xdna, "aie load %s failed with err %d", xdna_hdl->priv->fw_path, ret);
		return ret;
	}
	
	XDNA_DBG(xdna, "aie load %s completed", xdna_hdl->priv->fw_path);
	return 0;
}

static void ve2_fini(struct amdxdna_dev *xdna)
{
}

const struct amdxdna_dev_ops ve2_ops = {
	.init		= ve2_init,
	.fini		= ve2_fini,
};

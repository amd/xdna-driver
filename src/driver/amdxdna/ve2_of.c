// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2025, Advanced Micro Devices, Inc.
 */

#include <linux/xlnx-ai-engine.h>
#include <linux/firmware.h>

#include "ve2_of.h"

static int ve2_load_cert(struct amdxdna_dev_hdl *ndev)
{
	struct amdxdna_dev *xdna = ndev->xdna;
	struct aie_partition_init_args args;
	struct aie_partition_req request;
	const struct firmware *fw;
	struct device *xaie_dev;
	char *buf;
	size_t buf_len;
	int ret;

	ret = request_firmware(&fw, ndev->priv->fw_path, xdna->ddev.dev);
	if (ret) {
		XDNA_ERR(xdna, "request fw %s failed %d", ndev->priv->fw_path, ret);
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
	if (ret) {
		XDNA_ERR(xdna, "aie load cert failed %d", ret);
		goto teardown;
	}
	XDNA_INFO(xdna, "aie load cert complete");

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
	struct platform_device *pdev = to_platform_device(xdna->ddev.dev);
	struct amdxdna_dev_hdl *xdna_hdl;

	xdna_hdl = devm_kzalloc(&pdev->dev, sizeof(*xdna_hdl), GFP_KERNEL);
	if (!xdna_hdl)
		return -ENOMEM;

	xdna_hdl->xdna = xdna;

	xdna->dev_handle = xdna_hdl;

	ve2_load_cert(xdna_hdl);

	return 0;
}

static void ve2_fini(struct amdxdna_dev *xdna)
{
}

const struct amdxdna_dev_ops ve2_ops = {
	.init		= ve2_init,
	.fini		= ve2_fini,
};

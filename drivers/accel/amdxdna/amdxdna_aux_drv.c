// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2022-2026, Advanced Micro Devices, Inc.
 */

#include <drm/drm_drv.h>
#include <drm/drm_managed.h>
#include <linux/auxiliary_bus.h>
#include <linux/dma-mapping.h>
#include <linux/module.h>

#include "amdxdna_drv.h"
#include "amdxdna_aux_drv.h"
#include "ve2_aux.h"

const struct amdxdna_dev_priv ve2_dev_priv = {
	.fw_path	= "amdnpu/release_cert_ve2.elf",
	.hwctx_limit	= 255,
	.ctx_limit	= 255,
};

const struct amdxdna_dev_info dev_ve2_info = {
	.device_type	= AMDXDNA_DEV_TYPE_KMQ,
	.dev_priv	= &ve2_dev_priv,
	.ops		= &ve2_ops,
};

static const struct auxiliary_device_id amdxdna_ve2_aux_id_table[] = {
	{ .name = "xilinx_aie.amdxdna" },
	{}
};

MODULE_DEVICE_TABLE(auxiliary, amdxdna_ve2_aux_id_table);

static int amdxdna_ve2_aux_probe(struct auxiliary_device *auxdev,
				 const struct auxiliary_device_id *id)
{
	struct device *dev = &auxdev->dev;
	struct amdxdna_dev *xdna;
	int ret;

	xdna = devm_drm_dev_alloc(dev, &amdxdna_drm_drv, typeof(*xdna), ddev);
	if (IS_ERR(xdna))
		return PTR_ERR(xdna);

	xdna->dev_info = &dev_ve2_info;
	if (!xdna->dev_info)
		return -ENODEV;

	auxiliary_set_drvdata(auxdev, xdna);

	ret = amdxdna_dev_init(xdna);
	if (ret)
		return ret;

	if (!dev->dma_mask) {
		dev->coherent_dma_mask = DMA_BIT_MASK(64);
		dev->dma_mask = &dev->coherent_dma_mask;
	}
	ret = dma_set_mask_and_coherent(dev, DMA_BIT_MASK(64));
	if (ret) {
		ret = dma_set_mask_and_coherent(dev, DMA_BIT_MASK(32));
		if (ret) {
			XDNA_ERR(xdna, "DMA mask set failed (64 and 32 bit), ret %d", ret);
			goto failed_dev_cleanup;
		}
		XDNA_WARN(xdna, "DMA configuration downgraded to 32bit Mask\n");
	}

	return 0;

failed_dev_cleanup:
	amdxdna_dev_cleanup(xdna);
	return ret;
}

static void amdxdna_ve2_aux_remove(struct auxiliary_device *auxdev)
{
	struct amdxdna_dev *xdna = auxiliary_get_drvdata(auxdev);

	amdxdna_dev_cleanup(xdna);
}

static struct auxiliary_driver amdxdna_ve2_aux_driver = {
	.name		= "amdxdna",
	.probe		= amdxdna_ve2_aux_probe,
	.remove		= amdxdna_ve2_aux_remove,
	.id_table	= amdxdna_ve2_aux_id_table,
};

module_auxiliary_driver(amdxdna_ve2_aux_driver);

MODULE_LICENSE(AMDXDNA_MODULE_LICENSE);
MODULE_AUTHOR(AMDXDNA_MODULE_AUTHOR);
MODULE_VERSION(AMDXDNA_MODULE_VERSION);
MODULE_DESCRIPTION(AMDXDNA_MODULE_DESCRIPTION);

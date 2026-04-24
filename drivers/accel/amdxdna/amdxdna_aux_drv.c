// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2026, Advanced Micro Devices, Inc.
 *
 * Auxiliary-bus attachment for AMD XDNA devices. A matching auxiliary
 * client name selects struct amdxdna_dev_info via the matched entry's
 * .driver_data; see amdxdna_aux_id_table below.
 */

#include <drm/drm_drv.h>
#include <drm/drm_managed.h>
#include <linux/auxiliary_bus.h>
#include <linux/dma-mapping.h>
#include <linux/module.h>

#include "amdxdna_drv.h"
#include "amdxdna_aux_drv.h"
#include "ve2_aux.h"

/*
 * amdxdna_aux_id_table: each struct auxiliary_device_id row binds an
 * auxiliary-bus device name to const struct amdxdna_dev_info (via
 * .driver_data). Add an entry (and matching dev_info/ops) when supporting
 * new auxiliary-attached hardware.
 */
static const struct auxiliary_device_id amdxdna_aux_id_table[] = {
	{
		.name = "xilinx_aie.amdxdna",
		.driver_data = (kernel_ulong_t)&dev_ve2_info,
	},
	{}
};

MODULE_DEVICE_TABLE(auxiliary, amdxdna_aux_id_table);

static int amdxdna_aux_probe(struct auxiliary_device *auxdev,
			     const struct auxiliary_device_id *id)
{
	struct device *dev = &auxdev->dev;
	struct amdxdna_dev *xdna;
	int ret;

	xdna = devm_drm_dev_alloc(dev, &amdxdna_drm_drv, typeof(*xdna), ddev);
	if (IS_ERR(xdna))
		return PTR_ERR(xdna);

	xdna->dev_info = (const struct amdxdna_dev_info *)id->driver_data;
	if (!xdna->dev_info || !xdna->dev_info->ops) {
		XDNA_WARN(xdna, "No matching aux device found");
		return -EINVAL;
	}

	auxiliary_set_drvdata(auxdev, xdna);

	if (!dev->dma_mask) {
		dev->coherent_dma_mask = DMA_BIT_MASK(64);
		dev->dma_mask = &dev->coherent_dma_mask;
	}
	ret = dma_set_mask_and_coherent(dev, DMA_BIT_MASK(64));
	if (ret) {
		ret = dma_set_mask_and_coherent(dev, DMA_BIT_MASK(32));
		if (ret) {
			XDNA_ERR(xdna, "DMA mask set failed (64 and 32 bit), ret %d", ret);
			return ret;
		}
		XDNA_WARN(xdna, "DMA configuration downgraded to 32bit mask");
	}

	ret = amdxdna_dev_init(xdna);
	if (ret) {
		XDNA_ERR(xdna, "amdxdna dev init failed with ret %d", ret);
		return ret;
	}

	return 0;
}

static void amdxdna_aux_remove(struct auxiliary_device *auxdev)
{
	struct amdxdna_dev *xdna = auxiliary_get_drvdata(auxdev);

	amdxdna_dev_cleanup(xdna);
}

static struct auxiliary_driver amdxdna_aux_driver = {
	.name		= KBUILD_MODNAME,
	.probe		= amdxdna_aux_probe,
	.remove		= amdxdna_aux_remove,
	.id_table	= amdxdna_aux_id_table,
};

module_auxiliary_driver(amdxdna_aux_driver);

MODULE_LICENSE(AMDXDNA_MODULE_LICENSE);
MODULE_AUTHOR(AMDXDNA_MODULE_AUTHOR);
MODULE_VERSION(AMDXDNA_MODULE_VERSION);
MODULE_DESCRIPTION(AMDXDNA_MODULE_DESCRIPTION);

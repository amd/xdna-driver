// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2025, Advanced Micro Devices, Inc.
 */

#include <linux/module.h>
#include <linux/dma-mapping.h>
#include <linux/auxiliary_bus.h>
#include <drm/drm_managed.h>

#include "amdxdna_devel.h"
#include "amdxdna_aux_drv.h"

static int amdxdna_aux_probe(struct auxiliary_device *auxdev,
			     const struct auxiliary_device_id *id)
{
	struct device *dev = &auxdev->dev;
	struct amdxdna_dev *xdna;
	int ret;

	xdna = devm_drm_dev_alloc(dev, &amdxdna_drm_drv, typeof(*xdna), ddev);
	if (IS_ERR(xdna))
		return PTR_ERR(xdna);
	xdna->dev_info = &dev_ve2_info;
	if (!xdna->dev_info->ops->init || !xdna->dev_info->ops->fini)
		return -EOPNOTSUPP;

	drmm_mutex_init(&xdna->ddev, &xdna->dev_lock);
	INIT_LIST_HEAD(&xdna->client_list);
	auxiliary_set_drvdata(auxdev, xdna);

	mutex_lock(&xdna->dev_lock);
	ret = xdna->dev_info->ops->init(xdna);
	mutex_unlock(&xdna->dev_lock);
	if (ret) {
		/* init never leaves CMA set on error; fini would be a no-op */
		XDNA_ERR(xdna, "Hardware init failed, ret %d", ret);
		return ret;
	}

	xdna->vbnv = xdna->dev_info->default_vbnv;

	ret = drm_dev_register(&xdna->ddev, 0);
	if (ret) {
		XDNA_ERR(xdna, "DRM register failed, ret %d", ret);
		goto err_fini;
	}

	if (!xdna->dev_handle) {
		XDNA_ERR(xdna, "amdxdna device handle is null");
		ret = -EINVAL;
		goto out;
	}

	/*
	 * Auxiliary devices do not get dma_mask/coherent_dma_mask set by the
	 * bus. dma_set_mask_and_coherent() returns -EIO when dev->dma_mask is
	 * NULL, so initialize it first to use the API.
	 */
	if (!dev->dma_mask) {
		dev->coherent_dma_mask = DMA_BIT_MASK(64);
		dev->dma_mask = &dev->coherent_dma_mask;
	}
	ret = dma_set_mask_and_coherent(dev, DMA_BIT_MASK(64));
	if (ret) {
		ret = dma_set_mask_and_coherent(dev, DMA_BIT_MASK(32));
		if (ret) {
			XDNA_ERR(xdna, "DMA mask set failed (64 and 32 bit), ret %d", ret);
			goto out;
		}
		XDNA_WARN(xdna, "DMA configuration downgraded to 32bit Mask\n");
	}

	if (xdna->dev_info->ops->debugfs)
		xdna->dev_info->ops->debugfs(xdna);

	iommu_mode = AMDXDNA_IOMMU_NO_PASID;

	XDNA_DBG(xdna, "auxdev %s probed", dev_name(dev));
	return 0;
out:
	drm_dev_unregister(&xdna->ddev);
err_fini:
	mutex_lock(&xdna->dev_lock);
	xdna->dev_info->ops->fini(xdna);
	mutex_unlock(&xdna->dev_lock);
	/* Do not drm_dev_put: xdna was allocated with devm_drm_dev_alloc;
	 * devres will call the release (and drm_dev_put) when the device is unbound.
	 */
	return ret;
}

static void amdxdna_aux_remove(struct auxiliary_device *auxdev)
{
	struct amdxdna_dev *xdna = auxiliary_get_drvdata(auxdev);

	drm_dev_unplug(&xdna->ddev);
	mutex_lock(&xdna->dev_lock);
	xdna->dev_info->ops->fini(xdna);
	mutex_unlock(&xdna->dev_lock);
}

static const struct auxiliary_device_id amdxdna_aux_id_table[] = {
	{ .name = "xilinx_aie.amdxdna" },
	{ }
};
MODULE_DEVICE_TABLE(auxiliary, amdxdna_aux_id_table);

static struct auxiliary_driver amdxdna_aux_driver = {
	.probe		= amdxdna_aux_probe,
	.remove		= amdxdna_aux_remove,
	.id_table	= amdxdna_aux_id_table,
};

module_auxiliary_driver(amdxdna_aux_driver);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("XRT Team <runtimeca39d@amd.com>");
MODULE_VERSION(MODULE_VER_STR);
MODULE_DESCRIPTION("amdxdna auxiliary driver (AIE aux device)");

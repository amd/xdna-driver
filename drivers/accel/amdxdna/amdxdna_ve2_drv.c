// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2026, Advanced Micro Devices, Inc.
 *
 * VE2 attachment. The part is enumerated by the Xilinx AIE driver as the
 * auxiliary device xilinx_aie.amdxdna. It is not an OF amdxdna node and it
 * does not have the npu12 management/doorbell rings or IPI mailbox.
 *
 * This file owns module init for the VE2 build. The PCI and platform drivers
 * are not linked into that build.
 */

#include "drm/amdxdna_accel.h"
#include <drm/drm_accel.h>
#include <drm/drm_drv.h>
#include <drm/drm_managed.h>
#include <linux/auxiliary_bus.h>
#include <linux/dma-mapping.h>
#include <linux/sched/mm.h>

#include "amdxdna_cbuf.h"
#include "amdxdna_ctx.h"
#include "amdxdna_debugfs.h"
#include "amdxdna_dpt.h"
#include "amdxdna_drv.h"
#include "amdxdna_pm.h"
#include "amdxdna_ve2_drv.h"

static void amdxdna_ve2_drm_release(struct drm_device *drm, void *res)
{
	struct amdxdna_dev *xdna = res;

	amdxdna_carveout_fini(xdna);
	amdxdna_dpt_chan_fini(xdna);
	ida_destroy(&xdna->hwctx_ida);
}

static int amdxdna_ve2_probe(struct auxiliary_device *auxdev,
			     const struct auxiliary_device_id *id)
{
	struct device *dev = &auxdev->dev;
	const struct amdxdna_dev_info *dev_info;
	struct amdxdna_dev *xdna;
	struct drm_device *ddev;
	int ret;

	dev_info = (const struct amdxdna_dev_info *)id->driver_data;
	if (!dev_info || !dev_info->ops)
		return -EINVAL;

	xdna = devm_drm_dev_alloc(dev, &amdxdna_drm_drv, typeof(*xdna), ddev);
	if (IS_ERR(xdna))
		return PTR_ERR(xdna);
	ddev = &xdna->ddev;
	xdna->dev_info = dev_info;
	auxiliary_set_drvdata(auxdev, xdna);

	ret = drmm_mutex_init(ddev, &xdna->client_lock);
	if (ret)
		return ret;

	ret = drmm_mutex_init(ddev, &xdna->dev_lock);
	if (ret)
		return ret;

	init_rwsem(&xdna->notifier_lock);
	INIT_LIST_HEAD(&xdna->client_list);
	ida_init(&xdna->hwctx_ida);

	ret = amdxdna_dpt_chan_init(xdna);
	if (ret)
		return ret;

	ret = drmm_add_action(ddev, amdxdna_ve2_drm_release, xdna);
	if (ret) {
		amdxdna_dpt_chan_fini(xdna);
		return ret;
	}

	if (IS_ENABLED(CONFIG_LOCKDEP)) {
		fs_reclaim_acquire(GFP_KERNEL);
		might_lock(&xdna->notifier_lock);
		fs_reclaim_release(GFP_KERNEL);
	}

	xdna->notifier_wq = drmm_alloc_ordered_workqueue(ddev, "notifier_wq", WQ_MEM_RECLAIM);
	if (IS_ERR(xdna->notifier_wq))
		return PTR_ERR(xdna->notifier_wq);

	if (!dev->dma_mask) {
		dev->coherent_dma_mask = DMA_BIT_MASK(64);
		dev->dma_mask = &dev->coherent_dma_mask;
	}
	ret = dma_set_mask_and_coherent(dev, DMA_BIT_MASK(64));
	if (ret) {
		ret = dma_set_mask_and_coherent(dev, DMA_BIT_MASK(32));
		if (ret) {
			XDNA_ERR(xdna, "DMA mask set failed, ret %d", ret);
			return ret;
		}
	}

	mutex_lock(&xdna->dev_lock);
	ret = xdna->dev_info->ops->init(xdna);
	mutex_unlock(&xdna->dev_lock);
	if (ret) {
		XDNA_ERR(xdna, "Hardware init failed, ret %d", ret);
		return ret;
	}

	ret = amdxdna_sysfs_init(xdna);
	if (ret) {
		XDNA_ERR(xdna, "Create amdxdna attrs failed: %d", ret);
		goto failed_dev_fini;
	}

	ret = drm_dev_register(ddev, 0);
	if (ret) {
		XDNA_ERR(xdna, "DRM register failed, ret %d", ret);
		goto failed_sysfs_fini;
	}

	amdxdna_debugfs_init(xdna);
	XDNA_INFO(xdna, "VE2 device probed");
	return 0;

failed_sysfs_fini:
	amdxdna_sysfs_fini(xdna);
failed_dev_fini:
	mutex_lock(&xdna->dev_lock);
	xdna->dev_info->ops->fini(xdna);
	mutex_unlock(&xdna->dev_lock);
	return ret;
}

static void amdxdna_ve2_remove(struct auxiliary_device *auxdev)
{
	struct amdxdna_dev *xdna = auxiliary_get_drvdata(auxdev);
	struct amdxdna_client *client;

	drm_dev_unplug(&xdna->ddev);
	amdxdna_sysfs_fini(xdna);

	mutex_lock(&xdna->client_lock);
	mutex_lock(&xdna->dev_lock);
	list_for_each_entry(client, &xdna->client_list, node) {
		amdxdna_hwctx_remove_all(client);
		amdxdna_sva_fini(client);
	}

	xdna->dev_info->ops->fini(xdna);
	mutex_unlock(&xdna->dev_lock);
	mutex_unlock(&xdna->client_lock);
}

static const struct dev_pm_ops amdxdna_ve2_pm_ops = {
	SYSTEM_SLEEP_PM_OPS(amdxdna_pm_suspend, amdxdna_pm_resume)
	RUNTIME_PM_OPS(amdxdna_pm_runtime_suspend, amdxdna_pm_runtime_resume, NULL)
};

static const struct auxiliary_device_id amdxdna_ve2_id_table[] = {
	{
		.name = "xilinx_aie.amdxdna",
		.driver_data = (kernel_ulong_t)&dev_ve2_info,
	},
	{ }
};
MODULE_DEVICE_TABLE(auxiliary, amdxdna_ve2_id_table);

static struct auxiliary_driver amdxdna_ve2_driver = {
	/*
	 * Registration prints and publishes "<module>.<name>". "ve2" makes
	 * that amdxdna.ve2. The id table still matches xilinx_aie.amdxdna.
	 */
	.name		= "ve2",
	.probe		= amdxdna_ve2_probe,
	.remove		= amdxdna_ve2_remove,
	.id_table	= amdxdna_ve2_id_table,
	.driver		= {
		.pm	= &amdxdna_ve2_pm_ops,
	},
};
module_auxiliary_driver(amdxdna_ve2_driver);

MODULE_FIRMWARE("amdnpu/release_cert_ve2.elf");
#ifdef MODULE_VER_STR
MODULE_VERSION(MODULE_VER_STR);
#endif
MODULE_LICENSE("GPL");
MODULE_AUTHOR("XRT Team <runtimeca39d@amd.com>");
MODULE_DESCRIPTION("amdxdna VE2 driver");

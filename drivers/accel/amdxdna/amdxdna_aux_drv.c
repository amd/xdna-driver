// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2026, Advanced Micro Devices, Inc.
 *
 * Auxiliary-bus attachment for AMD XDNA devices (VE2/Versal SoC). A matching
 * auxiliary client name selects struct amdxdna_dev_info via the matched
 * entry's .driver_data; see amdxdna_aux_id_table below. The bus-agnostic DRM
 * core lives in amdxdna_drv.c.
 */

#include "drm/amdxdna_accel.h"
#include <drm/drm_drv.h>
#include <drm/drm_managed.h>
#include <linux/auxiliary_bus.h>
#include <linux/dma-mapping.h>
#include <linux/module.h>
#include <linux/sched/mm.h>
#include <linux/workqueue.h>

#include "amdxdna_aux_drv.h"
#include "amdxdna_cbuf.h"
#include "amdxdna_ctx.h"
#include "amdxdna_debugfs.h"
#include "amdxdna_pci_drv.h"

static void amdxdna_aux_release(struct drm_device *drm, void *res)
{
	struct amdxdna_dev *xdna = res;

	amdxdna_carveout_fini(xdna);
	cleanup_srcu_struct(&xdna->dpt_srcu);
}

/**
 * amdxdna_dev_init - bus-agnostic amdxdna device init and registration
 * @xdna: Pointer to amdxdna device
 *
 * Initializes common device structures (locks, client list, dpt srcu,
 * notifier workqueue), hardware via ops->init, sysfs, and registers the DRM
 * device. Note: unlike the PCI path, the auxiliary/SoC path does not set up an
 * IOMMU domain here; the common open path falls back to SVA or carveout.
 *
 * Return: 0 on success, negative error code on failure
 */
int amdxdna_dev_init(struct amdxdna_dev *xdna)
{
	struct drm_device *ddev = &xdna->ddev;
	int ret;

	ret = drmm_mutex_init(ddev, &xdna->client_lock);
	if (ret)
		return ret;

	drmm_mutex_init(ddev, &xdna->dev_lock);
	init_rwsem(&xdna->notifier_lock);
	INIT_LIST_HEAD(&xdna->client_list);

	ret = init_srcu_struct(&xdna->dpt_srcu);
	if (ret)
		return ret;

	ret = drmm_add_action(ddev, amdxdna_aux_release, xdna);
	if (ret) {
		cleanup_srcu_struct(&xdna->dpt_srcu);
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
	return 0;

failed_sysfs_fini:
	amdxdna_sysfs_fini(xdna);
failed_dev_fini:
	mutex_lock(&xdna->dev_lock);
	xdna->dev_info->ops->fini(xdna);
	mutex_unlock(&xdna->dev_lock);
	return ret;
}

/**
 * amdxdna_dev_cleanup - bus-agnostic amdxdna device cleanup
 * @xdna: Pointer to amdxdna device
 */
void amdxdna_dev_cleanup(struct amdxdna_dev *xdna)
{
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

MODULE_LICENSE("GPL");
MODULE_AUTHOR("XRT Team <runtimeca39d@amd.com>");
MODULE_VERSION("0.1");
MODULE_DESCRIPTION("amdxdna driver");

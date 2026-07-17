// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2022-2026, Advanced Micro Devices, Inc.
 *
 * PCI-bus attachment for AMD XDNA devices. The bus-agnostic DRM driver,
 * file operations, client open/close and shared ioctls live in amdxdna_drv.c.
 */

#include "drm/amdxdna_accel.h"
#include <drm/drm_accel.h>
#include <drm/drm_drv.h>
#include <drm/drm_gem.h>
#include <drm/drm_gem_shmem_helper.h>
#include <drm/drm_ioctl.h>
#include <drm/drm_managed.h>
#include <drm/gpu_scheduler.h>
#include <linux/delay.h>
#include <linux/iommu.h>
#include <linux/pci.h>

#include "aie.h"
#include "amdxdna_cbuf.h"
#include "amdxdna_ctx.h"
#include "amdxdna_debugfs.h"
#include "amdxdna_gem.h"
#include "amdxdna_pci_drv.h"
#include "amdxdna_pm.h"
#include "amdxdna_sensors.h"

MODULE_FIRMWARE("amdnpu/1502_00/npu.dev.sbin");
MODULE_FIRMWARE("amdnpu/17f0_10/npu.dev.sbin");
MODULE_FIRMWARE("amdnpu/17f0_11/npu.dev.sbin");
MODULE_FIRMWARE("amdnpu/17f0_20/npu.dev.sbin");
MODULE_FIRMWARE("amdnpu/1502_00/npu.sbin");
MODULE_FIRMWARE("amdnpu/17f0_10/npu.sbin");
MODULE_FIRMWARE("amdnpu/17f0_11/npu.sbin");
MODULE_FIRMWARE("amdnpu/17f0_20/npu.sbin");
MODULE_FIRMWARE("amdnpu/1502_00/npu_7.sbin");
MODULE_FIRMWARE("amdnpu/17f0_10/npu_7.sbin");
MODULE_FIRMWARE("amdnpu/17f0_11/npu_7.sbin");
MODULE_FIRMWARE("amdnpu/17f1_10/npu.dev.sbin");
MODULE_FIRMWARE("amdnpu/17f1_10/cert.dev.sbin");
MODULE_FIRMWARE("amdnpu/17f1_13/npu.dev.sbin");
MODULE_FIRMWARE("amdnpu/17f1_13/cert.dev.sbin");
MODULE_FIRMWARE("amdnpu/17f1_15/npu.dev.sbin");
MODULE_FIRMWARE("amdnpu/17f1_15/cert.dev.sbin");
MODULE_FIRMWARE("amdnpu/17f2_10/npu.dev.sbin");
MODULE_FIRMWARE("amdnpu/17f2_10/cert.dev.sbin");
MODULE_FIRMWARE("amdnpu/17f2_13/npu.dev.sbin");
MODULE_FIRMWARE("amdnpu/17f2_13/cert.dev.sbin");
MODULE_FIRMWARE("amdnpu/17f2_15/npu.dev.sbin");
MODULE_FIRMWARE("amdnpu/17f2_15/cert.dev.sbin");
MODULE_FIRMWARE("amdnpu/1b0a_00/npu.dev.sbin");
MODULE_FIRMWARE("amdnpu/1b0a_00/cert.dev.sbin");
MODULE_FIRMWARE("amdnpu/1b0b_00/npu.dev.sbin");
MODULE_FIRMWARE("amdnpu/1b0b_00/cert.dev.sbin");

/*
 * Bind the driver base on (vendor_id, device_id) pair and later use the
 * (device_id, rev_id) pair as a key to select the devices. The devices with
 * same device_id have very similar interface to host driver.
 */
static const struct pci_device_id pci_ids[] = {
	{ PCI_DEVICE(PCI_VENDOR_ID_AMD, 0x1502) },
	{ PCI_DEVICE(PCI_VENDOR_ID_AMD, 0x17f0) },
	{ PCI_DEVICE(PCI_VENDOR_ID_AMD, 0x17f1) },
	{ PCI_DEVICE(PCI_VENDOR_ID_AMD, 0x17f2) },
	{ PCI_DEVICE(PCI_VENDOR_ID_AMD, 0x17f3) },
	{ PCI_DEVICE(PCI_VENDOR_ID_AMD, 0x1b0a) },
	{ PCI_DEVICE(PCI_VENDOR_ID_AMD, 0x1b0b) },
	{ PCI_DEVICE(PCI_VENDOR_ID_AMD, 0x1b0c) },
	{0}
};

MODULE_DEVICE_TABLE(pci, pci_ids);

static const struct amdxdna_device_id amdxdna_ids[] = {
	{ 0x1502, 0x0,  &dev_npu1_info },
	{ 0x17f0, 0x10, &dev_npu4_info },
	{ 0x17f0, 0x11, &dev_npu5_info },
	{ 0x17f0, 0x20, &dev_npu6_info },
	{ 0x17f1, 0x10, &dev_npu3_classic_info },
	{ 0x17f2, 0x10, &dev_npu3_pf_info },
	{ 0x17f3, 0x10, &dev_npu3_vf_info },
	{ 0x1b0a, 0x00, &dev_npu3_classic_info },
	{ 0x1b0b, 0x00, &dev_npu3_pf_info },
	{ 0x1b0c, 0x00, &dev_npu3_vf_info },
	{ 0x17f1, 0x13, &dev_npu9_classic_info },
	{ 0x17f2, 0x13, &dev_npu9_pf_info },
	{ 0x17f3, 0x13, &dev_npu9_vf_info },
	{ 0x17f1, 0x15, &dev_npu11_classic_info },
	{ 0x17f2, 0x15, &dev_npu11_pf_info },
	{ 0x17f3, 0x15, &dev_npu11_vf_info },
	{0}
};

static const struct amdxdna_dev_info *
amdxdna_get_dev_info(struct pci_dev *pdev)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(amdxdna_ids); i++) {
		if (pdev->device == amdxdna_ids[i].device &&
		    pdev->revision == amdxdna_ids[i].revision)
			return amdxdna_ids[i].dev_info;
	}
	return NULL;
}

static void amdxdna_xdna_drm_release(struct drm_device *drm, void *res)
{
	struct amdxdna_dev *xdna = res;

	amdxdna_carveout_fini(xdna);
	cleanup_srcu_struct(&xdna->dpt_srcu);
}

static int amdxdna_probe(struct pci_dev *pdev, const struct pci_device_id *id)
{
	struct device *dev = &pdev->dev;
	struct amdxdna_dev *xdna;
	struct drm_device *ddev;
	int ret;

	xdna = devm_drm_dev_alloc(dev, &amdxdna_drm_drv, typeof(*xdna), ddev);
	if (IS_ERR(xdna))
		return PTR_ERR(xdna);
	ddev = &xdna->ddev;

	xdna->dev_info = amdxdna_get_dev_info(pdev);
	if (!xdna->dev_info)
		return -ENODEV;

	ret = drmm_mutex_init(ddev, &xdna->client_lock);
	if (ret)
		return ret;

	drmm_mutex_init(ddev, &xdna->dev_lock);
	init_rwsem(&xdna->notifier_lock);
	INIT_LIST_HEAD(&xdna->client_list);
	pci_set_drvdata(pdev, xdna);

	ret = init_srcu_struct(&xdna->dpt_srcu);
	if (ret)
		return ret;

	ret = drmm_add_action(ddev, amdxdna_xdna_drm_release, xdna);
	if (ret) {
		cleanup_srcu_struct(&xdna->dpt_srcu);
		return ret;
	}

	if (IS_ENABLED(CONFIG_LOCKDEP)) {
		fs_reclaim_acquire(GFP_KERNEL);
		might_lock(&xdna->notifier_lock);
		fs_reclaim_release(GFP_KERNEL);
	}

	ret = amdxdna_iommu_init(xdna);
	if (ret)
		return ret;

	xdna->notifier_wq = drmm_alloc_ordered_workqueue(ddev, "notifier_wq", WQ_MEM_RECLAIM);
	if (IS_ERR(xdna->notifier_wq)) {
		ret = PTR_ERR(xdna->notifier_wq);
		goto iommu_fini;
	}

	mutex_lock(&xdna->dev_lock);
	ret = xdna->dev_info->ops->init(xdna);
	mutex_unlock(&xdna->dev_lock);
	if (ret) {
		XDNA_ERR(xdna, "Hardware init failed, ret %d", ret);
		goto iommu_fini;
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
	amdxdna_hwmon_init(xdna);
	return 0;

failed_sysfs_fini:
	amdxdna_sysfs_fini(xdna);
failed_dev_fini:
	mutex_lock(&xdna->dev_lock);
	xdna->dev_info->ops->fini(xdna);
	mutex_unlock(&xdna->dev_lock);
iommu_fini:
	amdxdna_iommu_fini(xdna);
	return ret;
}

static void amdxdna_remove(struct pci_dev *pdev)
{
	struct amdxdna_dev *xdna = pci_get_drvdata(pdev);
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

	amdxdna_iommu_fini(xdna);
}

static const struct dev_pm_ops amdxdna_pm_ops = {
	SYSTEM_SLEEP_PM_OPS(amdxdna_pm_suspend, amdxdna_pm_resume)
	RUNTIME_PM_OPS(amdxdna_pm_suspend, amdxdna_pm_resume, NULL)
};

static int amdxdna_sriov_configure(struct pci_dev *pdev, int num_vfs)
{
	struct amdxdna_dev *xdna = pci_get_drvdata(pdev);

	guard(mutex)(&xdna->dev_lock);
	if (xdna->dev_info->ops->sriov_configure)
		return xdna->dev_info->ops->sriov_configure(xdna, num_vfs);

	return -ENOENT;
}

static struct pci_driver amdxdna_pci_driver = {
	.name = KBUILD_MODNAME,
	.id_table = pci_ids,
	.probe = amdxdna_probe,
	.remove = amdxdna_remove,
	.driver.pm = &amdxdna_pm_ops,
	.sriov_configure = amdxdna_sriov_configure,
};

module_pci_driver(amdxdna_pci_driver);

MODULE_LICENSE("GPL");
MODULE_IMPORT_NS("AMD_PMF");
MODULE_AUTHOR("XRT Team <runtimeca39d@amd.com>");
MODULE_VERSION("0.1");
MODULE_DESCRIPTION("amdxdna driver");

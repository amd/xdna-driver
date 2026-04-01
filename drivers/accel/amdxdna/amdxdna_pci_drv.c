// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2022-2026, Advanced Micro Devices, Inc.
 */

#include "drm/amdxdna_accel.h"
#include <drm/drm_accel.h>
#include <drm/drm_drv.h>
#include <drm/drm_gem.h>
#include <drm/drm_gem_shmem_helper.h>
#include <drm/drm_ioctl.h>
#include <drm/drm_managed.h>
#include <drm/gpu_scheduler.h>
#include <linux/iommu.h>
#include <linux/pci.h>

#include "amdxdna_ctx.h"
#include "amdxdna_drv.h"
#include "amdxdna_gem.h"
#include "amdxdna_pci_drv.h"
#include "amdxdna_pm.h"

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

/*
 * Bind the driver base on (vendor_id, device_id) pair and later use the
 * (device_id, rev_id) pair as a key to select the devices. The devices with
 * same device_id have very similar interface to host driver.
 */
static const struct pci_device_id pci_ids[] = {
	{ PCI_DEVICE(PCI_VENDOR_ID_AMD, 0x1502) },
	{ PCI_DEVICE(PCI_VENDOR_ID_AMD, 0x17f0) },
	{ PCI_DEVICE(PCI_VENDOR_ID_AMD, 0x17f2) },
	{ PCI_DEVICE(PCI_VENDOR_ID_AMD, 0x1B0B) },
	{0}
};

MODULE_DEVICE_TABLE(pci, pci_ids);

static const struct amdxdna_device_id amdxdna_ids[] = {
	{ 0x1502, 0x0,  &dev_npu1_info },
	{ 0x17f0, 0x10, &dev_npu4_info },
	{ 0x17f0, 0x11, &dev_npu5_info },
	{ 0x17f0, 0x20, &dev_npu6_info },
	{ 0x17f2, 0x10, &dev_npu3_pf_info },
	{ 0x1B0B, 0x10, &dev_npu3_pf_info },
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

static int amdxdna_probe(struct pci_dev *pdev, const struct pci_device_id *id)
{
	struct device *dev = &pdev->dev;
	struct amdxdna_dev *xdna;
	int ret;

	xdna = devm_drm_dev_alloc(dev, &amdxdna_drm_drv, typeof(*xdna), ddev);
	if (IS_ERR(xdna))
		return PTR_ERR(xdna);

	xdna->dev_info = amdxdna_get_dev_info(pdev);
	if (!xdna->dev_info)
		return -ENODEV;

	pci_set_drvdata(pdev, xdna);

	ret = amdxdna_iommu_init(xdna);
	if (ret)
		return ret;

	init_rwsem(&xdna->notifier_lock);

	if (IS_ENABLED(CONFIG_LOCKDEP)) {
		fs_reclaim_acquire(GFP_KERNEL);
		might_lock(&xdna->notifier_lock);
		fs_reclaim_release(GFP_KERNEL);
	}

	xdna->notifier_wq = alloc_ordered_workqueue("notifier_wq", WQ_MEM_RECLAIM);
	if (!xdna->notifier_wq) {
		ret = -ENOMEM;
		goto failed_iommu_fini;
	}

	ret = amdxdna_dev_init(xdna);
	if (ret)
		goto failed_destroy_wq;

	return 0;

failed_destroy_wq:
	destroy_workqueue(xdna->notifier_wq);
failed_iommu_fini:
	amdxdna_iommu_fini(xdna);
	return ret;
}

static void amdxdna_remove(struct pci_dev *pdev)
{
	struct amdxdna_dev *xdna = pci_get_drvdata(pdev);

	amdxdna_dev_cleanup(xdna);
	destroy_workqueue(xdna->notifier_wq);
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

MODULE_LICENSE(AMDXDNA_MODULE_LICENSE);
MODULE_IMPORT_NS("AMD_PMF");
MODULE_AUTHOR(AMDXDNA_MODULE_AUTHOR);
MODULE_VERSION(AMDXDNA_MODULE_VERSION);
MODULE_DESCRIPTION(AMDXDNA_MODULE_DESCRIPTION);

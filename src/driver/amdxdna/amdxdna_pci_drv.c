// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2022-2025, Advanced Micro Devices, Inc.
 */

#include <linux/module.h>
#include <linux/version.h>
#if KERNEL_VERSION(6, 10, 0) > LINUX_VERSION_CODE
#include <drm/drm_managed.h>
#endif

#include "amdxdna_pci_drv.h"
#include "amdxdna_sysfs.h"
#include "amdxdna_pm.h"
#ifdef AMDXDNA_DEVEL
#include "amdxdna_devel.h"
#include "amdxdna_carvedout_buf.h"
#endif

/*
 *  There are platforms which share the same PCI device ID
 *  but have different PCI revision IDs. So, let the PCI class
 *  determine the probe and later use the (device_id, rev_id)
 *  pair as a key to select the devices.
 */
static const struct pci_device_id pci_ids[] = {
#ifdef AMDXDNA_NPU3_LEGACY
	{ PCI_DEVICE(PCI_VENDOR_ID_AMD, 0x1569) },
	{ PCI_DEVICE(PCI_VENDOR_ID_ATI, 0x1640) },
#endif
#ifdef AMDXDNA_NPU3
	{ PCI_DEVICE(PCI_VENDOR_ID_AMD, 0x17f1) },
	{ PCI_DEVICE(PCI_VENDOR_ID_AMD, 0x17f3) },
#endif
	{ PCI_DEVICE(PCI_VENDOR_ID_AMD, PCI_ANY_ID),
		.class = PCI_CLASS_SP_OTHER << 8,  /* Signal Processing */
		.class_mask = 0xFFFF00,
	},
	{0}
};

MODULE_DEVICE_TABLE(pci, pci_ids);

static const struct amdxdna_device_id amdxdna_ids[] = {
	{ 0x1502, 0x0,  &dev_npu1_info },
	{ 0x17f0, 0x0,  &dev_npu2_info },
#ifdef AMDXDNA_NPU3_LEGACY
	{ 0x1569, 0x0,  &dev_npu3_info },
	{ 0x1640, 0x0,  &dev_npu3_info },
#endif
#ifdef AMDXDNA_NPU3
	{ 0x17f1, 0x10,  &dev_npu3_info },
	{ 0x17f3, 0x10,  &dev_npu3_info },
#endif
	{ 0x17f0, 0x10, &dev_npu4_info },
	{ 0x17f0, 0x11, &dev_npu5_info },
	{ 0x17f0, 0x20, &dev_npu6_info },
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

#if KERNEL_VERSION(6, 10, 0) > LINUX_VERSION_CODE
	drmm_mutex_init(&xdna->ddev, &xdna->dev_lock);
#else
	devm_mutex_init(dev, &xdna->dev_lock);
#endif
	init_rwsem(&xdna->notifier_lock);
	INIT_LIST_HEAD(&xdna->client_list);
	pci_set_drvdata(pdev, xdna);

	if (IS_ENABLED(CONFIG_LOCKDEP)) {
		fs_reclaim_acquire(GFP_KERNEL);
		might_lock(&xdna->notifier_lock);
		fs_reclaim_release(GFP_KERNEL);
	}

	if (!xdna->dev_info->ops->init || !xdna->dev_info->ops->fini)
		return -EOPNOTSUPP;

	xdna->notifier_wq = alloc_ordered_workqueue("notifier_wq", WQ_MEM_RECLAIM);
	if (!xdna->notifier_wq)
		return -ENOMEM;

	ret = xdna->dev_info->ops->init(xdna);
	if (ret) {
		XDNA_ERR(xdna, "Hardware init failed, ret %d", ret);
		goto destroy_notifier_wq;
	}

	ret = amdxdna_sysfs_init(xdna);
	if (ret) {
		XDNA_ERR(xdna, "Create amdxdna attrs failed: %d", ret);
		goto failed_dev_fini;
	}

	amdxdna_tdr_start(&xdna->tdr);

	ret = drm_dev_register(&xdna->ddev, 0);
	if (ret) {
		XDNA_ERR(xdna, "DRM register failed, ret %d", ret);
		goto failed_tdr_fini;
	}

	/* Debug fs needs to go after register DRM dev */
	if (xdna->dev_info->ops->debugfs)
		xdna->dev_info->ops->debugfs(xdna);

#ifdef AMDXDNA_DEVEL
	ida_init(&xdna->pdi_ida);
#endif
	amdxdna_pm_init(dev);
	return 0;

failed_tdr_fini:
	amdxdna_tdr_stop(&xdna->tdr);
	amdxdna_sysfs_fini(xdna);
failed_dev_fini:
	xdna->dev_info->ops->fini(xdna);
destroy_notifier_wq:
	destroy_workqueue(xdna->notifier_wq);
	return ret;
}

static void amdxdna_remove(struct pci_dev *pdev)
{
	struct amdxdna_dev *xdna = pci_get_drvdata(pdev);
	struct device *dev = &pdev->dev;
	struct amdxdna_client *client;

	destroy_workqueue(xdna->notifier_wq);
	amdxdna_tdr_stop(&xdna->tdr);
	amdxdna_sysfs_fini(xdna);

	amdxdna_pm_fini(dev);

#ifdef AMDXDNA_DEVEL
	amdxdna_gem_dump_mm(xdna);
#endif
	drm_dev_unplug(&xdna->ddev);

	mutex_lock(&xdna->dev_lock);
	client = list_first_entry_or_null(&xdna->client_list,
					  struct amdxdna_client, node);
	while (client) {
		list_del_init(&client->node);
		mutex_unlock(&xdna->dev_lock);

		amdxdna_ctx_remove_all(client);

		mutex_lock(&xdna->dev_lock);
		client = list_first_entry_or_null(&xdna->client_list,
						  struct amdxdna_client, node);
	}
	mutex_unlock(&xdna->dev_lock);

	xdna->dev_info->ops->fini(xdna);
#ifdef AMDXDNA_DEVEL
	ida_destroy(&xdna->pdi_ida);
#endif
}

static struct pci_driver amdxdna_pci_driver = {
	.name = KBUILD_MODNAME,
	.id_table = pci_ids,
	.probe = amdxdna_probe,
	.remove = amdxdna_remove,
	.driver.pm = &amdxdna_pm_ops,
};

static int __init amdxdna_mod_init(void)
{
	amdxdna_carvedout_init();
	return pci_register_driver(&amdxdna_pci_driver);
}

static void __exit amdxdna_mod_exit(void)
{
	pci_unregister_driver(&amdxdna_pci_driver);
	amdxdna_carvedout_fini();
}

module_init(amdxdna_mod_init);
module_exit(amdxdna_mod_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("XRT Team <runtimeca39d@amd.com>");
MODULE_VERSION("0.1");
MODULE_DESCRIPTION("amdxdna driver");

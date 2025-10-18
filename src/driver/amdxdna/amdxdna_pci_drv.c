// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2022-2025, Advanced Micro Devices, Inc.
 */

#include <linux/module.h>
#include <linux/version.h>
#include <drm/drm_managed.h>

#include "amdxdna_dpt.h"
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
	{ PCI_DEVICE(PCI_VENDOR_ID_AMD, 0x1B0A) },
	{ PCI_DEVICE(PCI_VENDOR_ID_AMD, 0x1B0C) },
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
	{ 0x17f1, 0x00,  &dev_npu3_info },
	{ 0x17f3, 0x00,  &dev_npu3_info },
	{ 0x1B0A, 0x00,  &dev_npu3_info },
	{ 0x1B0C, 0x00,  &dev_npu3_info },
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

	drmm_mutex_init(&xdna->ddev, &xdna->dev_lock);
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

	ret = amdxdna_fw_log_init(xdna);
	if (ret)
		XDNA_WARN(xdna, "Failed to enable firmware logging: %d", ret);

	/* Debug fs needs to go after register DRM dev */
	if (xdna->dev_info->ops->debugfs)
		xdna->dev_info->ops->debugfs(xdna);

#ifdef AMDXDNA_DEVEL
	ida_init(&xdna->pdi_ida);
#endif
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
	struct amdxdna_client *client;

	amdxdna_fw_log_fini(xdna);
	destroy_workqueue(xdna->notifier_wq);
	amdxdna_tdr_stop(&xdna->tdr);
	amdxdna_sysfs_fini(xdna);

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

static pci_ers_result_t amdxdna_error_detected(struct pci_dev *pdev,
					       pci_channel_state_t state)
{
	/* Return PCI_ERS_RESULT_CAN_RECOVER to indicate the driver thinks recovery is possible.
	 * Return PCI_ERS_RESULT_NEED_RESET to force a reset.
	 * Return PCI_ERS_RESULT_DISCONNECT to say the device is lost.
	 */

	return PCI_ERS_RESULT_NEED_RESET;
}

static void amdxdna_reset_prepare(struct pci_dev *pdev)
{
	struct amdxdna_dev *xdna = pci_get_drvdata(pdev);

	if (!xdna->dev_info->ops->reset_prepare)
		XDNA_ERR(xdna, "Reset prepare not supported on this device");
	else
		xdna->dev_info->ops->reset_prepare(xdna);
}

static void amdxdna_reset_done(struct pci_dev *pdev)
{
	struct amdxdna_dev *xdna = pci_get_drvdata(pdev);
	int ret;

	if (!xdna->dev_info->ops->reset_done) {
		XDNA_ERR(xdna, "Reset done not supported on this device");
	} else {
		ret = xdna->dev_info->ops->reset_done(xdna);
		if (ret)
			XDNA_ERR(xdna, "Reset done could not resume device, ret %d", ret);
	}
}

static const struct pci_error_handlers amdxdna_err_handler = {
	.error_detected = amdxdna_error_detected,
	.reset_prepare = amdxdna_reset_prepare,
	.reset_done = amdxdna_reset_done,
};

static struct pci_driver amdxdna_pci_driver = {
	.name = KBUILD_MODNAME,
	.id_table = pci_ids,
	.probe = amdxdna_probe,
	.remove = amdxdna_remove,
	.driver.pm = &amdxdna_pm_ops,
	.err_handler = &amdxdna_err_handler,
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

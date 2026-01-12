// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2022-2026, Advanced Micro Devices, Inc.
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

static int amdxdna_sriov_configure(struct pci_dev *pdev, int num_vfs);
/* common util inline functions */
static inline int is_pf_dev(const struct pci_dev *pdev)
{
	return (pdev->device == 0x17F2 || pdev->device == 0x1B0B);
}

/*
 *  There are platforms which share the same PCI device ID
 *  but have different PCI revision IDs. So, let the PCI class
 *  determine the probe and later use the (device_id, rev_id)
 *  pair as a key to select the devices.
 */
static const struct pci_device_id pci_ids[] = {
	{ PCI_DEVICE(PCI_VENDOR_ID_AMD, PCI_ANY_ID),
		.class = PCI_CLASS_SP_OTHER << 8,  /* Signal Processing */
		.class_mask = 0xFFFF00,
	},
	{0}
};

MODULE_DEVICE_TABLE(pci, pci_ids);

static const struct amdxdna_device_id amdxdna_ids[] = {
	{ 0x1502, 0x0,  &dev_npu1_info },
	{ 0x17f1, 0x10,  &dev_npu3_info },
	{ 0x17f2, 0x10,  &dev_npu3_pf_info },
	{ 0x17f3, 0x10,  &dev_npu3_info },
	{ 0x17f1, 0x11,  &dev_npu7_info },
	{ 0x17f2, 0x11,  &dev_npu7_pf_info },
	{ 0x17f3, 0x11,  &dev_npu7_info },
	{ 0x17f1, 0x12,  &dev_npu8_info },
	{ 0x17f2, 0x12,  &dev_npu8_pf_info },
	{ 0x17f3, 0x12,  &dev_npu8_info },
	{ 0x17f1, 0x13,  &dev_npu9_info },
	{ 0x17f2, 0x13,  &dev_npu9_pf_info },
	{ 0x17f3, 0x13,  &dev_npu9_info },
	{ 0x17f1, 0x14,  &dev_npu10_info },
	{ 0x17f2, 0x14,  &dev_npu10_pf_info },
	{ 0x17f3, 0x14,  &dev_npu10_info },
	{ 0x1B0A, 0x00,  &dev_npu3_info },
	{ 0x1B0B, 0x00,  &dev_npu3_pf_info },
	{ 0x1B0C, 0x00,  &dev_npu3_info },
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

static const char *amdxdna_lookup_vbnv(const struct amdxdna_rev_vbnv *tbl, u32 rev)
{
	int i;

	if (!tbl)
		return NULL;

	for (i = 0; tbl[i].vbnv; i++) {
		if (tbl[i].revision == rev)
			return tbl[i].vbnv;
	}
	return NULL;
}

static void amdxdna_vbnv_init(struct amdxdna_dev *xdna)
{
	const struct amdxdna_dev_info *info = xdna->dev_info;
	u32 rev;

	xdna->vbnv = info->default_vbnv;

	if (!info->ops->get_dev_revision)
		return;

	if (info->ops->get_dev_revision(xdna, &rev))
		return;

	xdna->vbnv = amdxdna_lookup_vbnv(info->rev_vbnv_tbl, rev);
	if (!xdna->vbnv)
		xdna->vbnv = info->default_vbnv;
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

	ret = amdxdna_iommu_init(xdna);
	if (ret)
		return ret;

	xdna->notifier_wq = alloc_ordered_workqueue("notifier_wq", WQ_MEM_RECLAIM);
	if (!xdna->notifier_wq) {
		ret = -ENOMEM;
		goto iommu_fini;
	}

	ret = xdna->dev_info->ops->init(xdna);
	if (ret) {
		XDNA_ERR(xdna, "Hardware init failed, ret %d", ret);
		goto destroy_notifier_wq;
	}

	amdxdna_vbnv_init(xdna);

	ret = amdxdna_sysfs_init(xdna);
	if (ret) {
		XDNA_ERR(xdna, "Create amdxdna attrs failed: %d", ret);
		goto failed_dev_fini;
	}

	if (xdna->dev_info->ops->tdr_start)
		xdna->dev_info->ops->tdr_start(xdna);

	ret = drm_dev_register(&xdna->ddev, 0);
	if (ret) {
		XDNA_ERR(xdna, "DRM register failed, ret %d", ret);
		goto failed_tdr_fini;
	}

	ret = amdxdna_dpt_init(xdna);
	if (ret)
		XDNA_WARN(xdna, "Failed to enable firmware debug/profile/trace: %d", ret);

	/* Debug fs needs to go after register DRM dev */
	if (xdna->dev_info->ops->debugfs)
		xdna->dev_info->ops->debugfs(xdna);

	/*
	 * Enable runtime PM only after all probe-time firmware communication
	 * is complete. Functions like vbnv_init() and dpt_init() query the
	 * firmware and must run while the device is guaranteed active.
	 * Moving rpm_init() here avoids a race where autosuspend could trigger
	 * before probe finishes.
	 */
	is_pf_dev(pdev) ? amdxdna_rpm_fini(xdna) : amdxdna_rpm_init(xdna);

#ifdef AMDXDNA_DEVEL
	ida_init(&xdna->pdi_ida);
#endif
	return 0;

failed_tdr_fini:
	if (xdna->dev_info->ops->tdr_stop)
		xdna->dev_info->ops->tdr_stop(xdna);
	amdxdna_sysfs_fini(xdna);
failed_dev_fini:
	xdna->dev_info->ops->fini(xdna);
destroy_notifier_wq:
	destroy_workqueue(xdna->notifier_wq);
iommu_fini:
	amdxdna_iommu_fini(xdna);
	return ret;
}

static void amdxdna_remove(struct pci_dev *pdev)
{
	struct amdxdna_dev *xdna = pci_get_drvdata(pdev);
	struct amdxdna_client *client;

	if (is_pf_dev(pdev))
		amdxdna_sriov_configure(pdev, 0);

	amdxdna_dpt_fini(xdna);
	destroy_workqueue(xdna->notifier_wq);
	if (xdna->dev_info->ops->tdr_stop)
		xdna->dev_info->ops->tdr_stop(xdna);
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

	/*
	 * Disable runtime PM before tearing down. This must be done before
	 * fini() since rpm_init() was moved to probe after init().
	 */
	amdxdna_rpm_fini(xdna);
	xdna->dev_info->ops->fini(xdna);
	amdxdna_iommu_fini(xdna);
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

static int amdxdna_sriov_configure(struct pci_dev *pdev, int num_vfs)
{
	struct amdxdna_dev *xdna = pci_get_drvdata(pdev);

	if (xdna->dev_info->ops->sriov_configure)
		return xdna->dev_info->ops->sriov_configure(xdna, num_vfs);

	return -EOPNOTSUPP;
}

static struct pci_driver amdxdna_pci_driver = {
	.name = KBUILD_MODNAME,
	.id_table = pci_ids,
	.probe = amdxdna_probe,
	.remove = amdxdna_remove,
	.driver.pm = &amdxdna_pm_ops,
	.err_handler = &amdxdna_err_handler,
	.sriov_configure = amdxdna_sriov_configure,
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

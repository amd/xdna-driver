// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2026, Advanced Micro Devices, Inc.
 *
 * Platform driver for AMDXDNA on non-PCI systems (e.g. Versal AIE).
 *
 * The device tree describes the AIE device with memory-region phandles for
 * CMA banks and either an RPMsg or shared-memory+IPI transport.  The
 * compatible string selects which transport to use:
 *
 *   "amd,versal-aie"      — RPMsg over VirtIO (remoteproc)
 *   "amd,amdxdna-npu3"    — Shared memory + ZynqMP IPI
 *
 * Device tree example (RPMsg):
 *
 *   reserved-memory {
 *       xdna_bank1: buffer@40000000 {
 *           compatible = "shared-dma-pool";
 *           reg = <0x0 0x40000000 0x0 0x40000000>;
 *           reusable;
 *       };
 *   };
 *
 *   amdxdna {
 *       compatible = "amd,versal-aie";
 *       memory-region = <&xdna_bank1>;
 *   };
 */

#include <drm/drm_accel.h>
#include <drm/drm_drv.h>
#include <drm/drm_managed.h>
#include <linux/iommu.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/of_platform.h>
#include <linux/platform_device.h>
#include <linux/pm_runtime.h>

#include "drm_local/amdxdna_accel.h"
#include "aie4_pci.h"
#include "amdxdna_pci_drv.h"
#include "npu3_family.h"
#include "amdxdna_pm.h"
#include "amdxdna_sysfs.h"
#include "amdxdna_cma_buf.h"
#ifdef AMDXDNA_DEVEL
#include "amdxdna_devel.h"
#endif

#ifdef CONFIG_AMDXDNA_RPMSG
#include "amdxdna_rpmsg.h"
#endif

#ifdef CONFIG_AMDXDNA_SHMEM
#include "amdxdna_shmem.h"
#endif

enum amdxdna_plat_transport {
	XDNA_TRANSPORT_RPMSG,
	XDNA_TRANSPORT_SHMEM,
};

struct amdxdna_plat_data {
	const struct amdxdna_dev_info	*dev_info;
	enum amdxdna_plat_transport	transport;
};

static int amdxdna_plat_transport_init(struct amdxdna_dev *xdna,
				       struct platform_device *pdev,
				       const struct amdxdna_plat_data *pdata)
{
	switch (pdata->transport) {
#ifdef CONFIG_AMDXDNA_RPMSG
	case XDNA_TRANSPORT_RPMSG:
		return amdxdna_rpmsg_init(xdna, pdev->dev.of_node);
#endif
#ifdef CONFIG_AMDXDNA_SHMEM
	case XDNA_TRANSPORT_SHMEM:
		return amdxdna_shmem_init(xdna, pdev);
#endif
	default:
		return -EINVAL;
	}
}

static void amdxdna_plat_transport_fini(struct amdxdna_dev *xdna,
					const struct amdxdna_plat_data *pdata)
{
	switch (pdata->transport) {
#ifdef CONFIG_AMDXDNA_RPMSG
	case XDNA_TRANSPORT_RPMSG:
		amdxdna_rpmsg_fini(xdna);
		break;
#endif
#ifdef CONFIG_AMDXDNA_SHMEM
	case XDNA_TRANSPORT_SHMEM:
		amdxdna_shmem_fini(xdna);
		break;
#endif
	default:
		break;
	}
}

static int amdxdna_plat_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	const struct amdxdna_plat_data *pdata;
	struct amdxdna_dev_hdl *ndev;
	struct amdxdna_dev *xdna;
	int ret;

	pdata = of_device_get_match_data(dev);
	if (!pdata)
		return -ENODEV;

	xdna = devm_drm_dev_alloc(dev, &amdxdna_drm_drv,
				  typeof(*xdna), ddev);
	if (IS_ERR(xdna))
		return PTR_ERR(xdna);

	xdna->dev_info = pdata->dev_info;
	xdna->vbnv = pdata->dev_info->default_vbnv;

	drmm_mutex_init(&xdna->ddev, &xdna->dev_lock);
	init_rwsem(&xdna->notifier_lock);
	INIT_LIST_HEAD(&xdna->client_list);

	if (IS_ENABLED(CONFIG_LOCKDEP)) {
		fs_reclaim_acquire(GFP_KERNEL);
		might_lock(&xdna->notifier_lock);
		fs_reclaim_release(GFP_KERNEL);
	}

	ndev = drmm_kzalloc(&xdna->ddev, sizeof(*ndev), GFP_KERNEL);
	if (!ndev)
		return -ENOMEM;

	ndev->priv = xdna->dev_info->dev_priv;
	ndev->xdna = xdna;
	xa_init(&ndev->cert_comp_xa);
	mutex_init(&ndev->aie4_lock);

	xdna->dev_handle = ndev;
	ndev->pw_mode = POWER_MODE_DEFAULT;
	platform_set_drvdata(pdev, xdna);

#ifdef AMDXDNA_DEVEL
	if (!iommu_get_domain_for_dev(dev)) {
		iommu_mode = AMDXDNA_IOMMU_NO_PASID;
		dev_dbg(dev, "No IOMMU detected, disabling PASID\n");
	}
#endif

	ret = aie4_xrs_solver_init(xdna);
	if (ret)
		return ret;

	/* Init CMA banks from memory-region phandles on this node */
	ret = amdxdna_cma_region_init(xdna, dev->of_node);
	if (ret) {
		dev_err(dev, "CMA region init failed: %d\n", ret);
		return ret;
	}

	ret = amdxdna_plat_transport_init(xdna, pdev, pdata);
	if (ret == -EPROBE_DEFER) {
		dev_dbg(dev, "Transport not ready, deferring probe\n");
		goto cma_fini;
	}
	if (ret) {
		dev_err(dev, "Transport init failed: %d\n", ret);
		goto cma_fini;
	}

	xdna->notifier_wq = alloc_ordered_workqueue("notifier_wq",
						     WQ_MEM_RECLAIM);
	if (!xdna->notifier_wq) {
		ret = -ENOMEM;
		goto transport_fini;
	}

	ret = amdxdna_sysfs_init(xdna);
	if (ret)
		goto destroy_wq;

	ret = drm_dev_register(&xdna->ddev, 0);
	if (ret)
		goto sysfs_fini;

	pm_runtime_enable(dev);
	pm_runtime_get_noresume(dev);
	amdxdna_rpm_init(xdna);

	XDNA_INFO(xdna, "Platform driver probed");
	return 0;

sysfs_fini:
	amdxdna_sysfs_fini(xdna);
destroy_wq:
	destroy_workqueue(xdna->notifier_wq);
transport_fini:
	amdxdna_plat_transport_fini(xdna, pdata);
cma_fini:
	amdxdna_cma_region_fini(xdna);
	return ret;
}

static void amdxdna_plat_remove(struct platform_device *pdev)
{
	struct amdxdna_dev *xdna = platform_get_drvdata(pdev);
	const struct amdxdna_plat_data *pdata;

	pdata = of_device_get_match_data(&pdev->dev);

	amdxdna_rpm_fini(xdna);
	pm_runtime_disable(&pdev->dev);
	drm_dev_unplug(&xdna->ddev);
	amdxdna_sysfs_fini(xdna);
	destroy_workqueue(xdna->notifier_wq);
	amdxdna_plat_transport_fini(xdna, pdata);
	amdxdna_cma_region_fini(xdna);
}

#ifdef CONFIG_AMDXDNA_RPMSG
static const struct amdxdna_plat_data plat_rpmsg_npu3 = {
	.dev_info	= &dev_npu3_info,
	.transport	= XDNA_TRANSPORT_RPMSG,
};
#endif

#ifdef CONFIG_AMDXDNA_SHMEM
static const struct amdxdna_plat_data plat_shmem_npu3 = {
	.dev_info	= &dev_npu3_info,
	.transport	= XDNA_TRANSPORT_SHMEM,
};
#endif

static const struct of_device_id amdxdna_plat_of_match[] = {
#ifdef CONFIG_AMDXDNA_RPMSG
	{ .compatible = "amd,versal-aie", .data = &plat_rpmsg_npu3 },
#endif
#ifdef CONFIG_AMDXDNA_SHMEM
	{ .compatible = "amd,amdxdna-npu3", .data = &plat_shmem_npu3 },
#endif
	{ },
};
MODULE_DEVICE_TABLE(of, amdxdna_plat_of_match);

static struct platform_driver amdxdna_plat_driver = {
	.probe	= amdxdna_plat_probe,
	.remove	= amdxdna_plat_remove,
	.driver	= {
		.name		= AMDXDNA_DRIVER_NAME,
		.of_match_table	= amdxdna_plat_of_match,
		.pm		= &amdxdna_pm_ops,
	},
};

module_platform_driver(amdxdna_plat_driver);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("XRT Team <runtimeca39d@amd.com>");
MODULE_VERSION(MODULE_VER_STR);
MODULE_DESCRIPTION("amdxdna platform driver");

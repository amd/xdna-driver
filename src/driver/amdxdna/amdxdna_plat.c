// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2026, Advanced Micro Devices, Inc.
 *
 * Platform driver for AMDXDNA on non-PCI systems (e.g. Versal AIE).
 *
 * The device tree describes the AIE device with named CMA regions and
 * either an RPMsg or shared-memory+IPI transport.  Memory regions are
 * identified by name in memory-region-names rather than by phandle
 * position; two roles are recognized:
 *
 *   "rpu-cma"     - Bound to the platform device itself.  Backs
 *                   dma_alloc_noncoherent() on the device and is used
 *                   for kernel-side firmware-visible mgmt buffers (async
 *                   event ring, FW DRAM log, FW event-trace ring,
 *                   mpnpufw work buffer).  Must live in a window the
 *                   remote firmware can address (e.g. < 4 GB on a
 *                   32-bit RPU).  The driver pins this device to a
 *                   32-bit DMA mask.
 *
 *   "app-bank<N>" - 0-indexed AIE-visible CMA banks.  Bound to child
 *                   devices with a 64-bit DMA mask and selected by
 *                   userspace via the low 8 bits of the BO flags
 *                   field.  User-mode BO ioctls default to bank 0.
 *
 * The compatible string selects which transport to use at runtime:
 *
 *   "amd,versal-aie-rpmsg" — RPMsg over VirtIO (remoteproc)
 *   "amd,versal-aie"       — Shared memory + ZynqMP IPI
 *
 * Device tree example (RPMsg):
 *
 *   reserved-memory {
 *       rpu_cma: rpu-cma@70000000 {
 *           compatible = "shared-dma-pool";
 *           reg = <0x0 0x70000000 0x0 0x04000000>;     // 64 MB, < 4 GB
 *           reusable;
 *       };
 *
 *       aie_cma0: aie-cma@8_00000000 {
 *           compatible = "shared-dma-pool";
 *           size = <0x1 0x00000000>;                   // 4 GB, > 4 GB
 *           alignment = <0x0 0x00100000>;
 *           reusable;
 *       };
 *   };
 *
 *   amdxdna {
 *       compatible = "amd,versal-aie-rpmsg";
 *       amd,remoteproc = <&r5f_0>;
 *       memory-region       = <&rpu_cma>, <&aie_cma0>;
 *       memory-region-names = "rpu-cma", "app-bank0";
 *   };
 */

#include <drm/drm_accel.h>
#include <drm/drm_drv.h>
#include <drm/drm_managed.h>
#include <linux/dma-mapping.h>
#include <linux/iommu.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/of_platform.h>
#include <linux/platform_device.h>
#include <linux/pm_runtime.h>
#include <linux/remoteproc.h>

#include "drm_local/amdxdna_accel.h"
#include "aie4_pci.h"
#include "amdxdna_pci_drv.h"
#include "npu3_family.h"
#include "amdxdna_pm.h"
#include "amdxdna_dpt.h"
#include "amdxdna_plat.h"
#include "amdxdna_sysfs.h"
#include "amdxdna_cma_buf.h"
#ifdef AMDXDNA_DEVEL
#include "amdxdna_devel.h"
#endif

#include "amdxdna_rpmsg.h"
#include "amdxdna_shmem.h"

struct amdxdna_plat_data {
	const struct amdxdna_dev_info	*dev_info;
	enum amdxdna_plat_transport	transport;
};

static bool amdxdna_plat_transport_is_shmem(enum amdxdna_plat_transport transport)
{
	return transport == AMDXDNA_TRANSPORT_SHMEM;
}

static int amdxdna_plat_transport_init(struct amdxdna_dev *xdna,
				       struct platform_device *pdev,
				       const struct amdxdna_plat_data *pdata)
{
	switch (pdata->transport) {
	case AMDXDNA_TRANSPORT_RPMSG:
		return amdxdna_rpmsg_init(xdna);
	case AMDXDNA_TRANSPORT_SHMEM:
		return amdxdna_shmem_init(xdna, pdev);
	default:
		return -EINVAL;
	}
}

static void amdxdna_plat_transport_fini(struct amdxdna_dev *xdna,
					const struct amdxdna_plat_data *pdata)
{
	switch (pdata->transport) {
	case AMDXDNA_TRANSPORT_RPMSG:
		amdxdna_rpmsg_fini(xdna);
		break;
	case AMDXDNA_TRANSPORT_SHMEM:
		amdxdna_shmem_fini(xdna);
		break;
	default:
		break;
	}
}

static const struct of_device_id amdxdna_plat_of_match[];

struct amdxdna_dev *amdxdna_plat_find_by_rproc(struct rproc *rp)
{
	struct amdxdna_dev *xdna = NULL;
	struct platform_device *pdev;
	struct device_node *np;
	struct rproc *cand;
	phandle ph;
	bool match;

	if (!rp)
		return NULL;

	for_each_matching_node(np, amdxdna_plat_of_match) {
		if (of_property_read_u32(np, "amd,remoteproc", &ph))
			continue;

		cand = rproc_get_by_phandle(ph);
		if (!cand)
			continue;
		/*
		 * Snapshot the match decision before dropping the rproc ref;
		 * after rproc_put() the underlying object may be freed and
		 * pointer-comparing the same address could spuriously alias
		 * a newly-allocated rproc.
		 */
		match = (cand == rp);
		rproc_put(cand);
		if (!match)
			continue;

		pdev = of_find_device_by_node(np);
		if (!pdev)
			continue;

		/*
		 * Only return platform devices whose plat_probe() has reached
		 * platform_set_drvdata(). This lets callers running from
		 * either a nested probe (e.g. the RPMsg endpoint probe fired
		 * by register_rpmsg_driver()) or an asynchronous bus event
		 * (RPMsg channel announcement after plat_probe completes)
		 * find the xdna without poking driver-core internals.
		 */
		xdna = platform_get_drvdata(pdev);
		put_device(&pdev->dev);
		if (xdna) {
			of_node_put(np);
			return xdna;
		}
	}

	return NULL;
}

/**
 * amdxdna_plat_register_device - Run the firmware-dependent setup for an
 *                                already-probed amdxdna platform device.
 *
 * Called from the transport's drv_probe (e.g. amdxdna_rpmsg_drv_probe)
 * once the management channel has been wired up so that ops->init() can
 * issue firmware queries.  See amdxdna_plat.h for the contract.
 *
 * Idempotency: xdna->notifier_wq doubles as the "registered" sentinel.
 * It is the first thing allocated here and the last thing freed in
 * amdxdna_plat_unregister_device(), so a non-NULL value indicates the
 * full sequence has already run.
 */
int amdxdna_plat_register_device(struct amdxdna_dev *xdna)
{
	struct device *dev = xdna->ddev.dev;
	int ret;

	if (xdna->notifier_wq)
		return 0;

	xdna->notifier_wq = alloc_ordered_workqueue("notifier_wq",
						    WQ_MEM_RECLAIM);
	if (!xdna->notifier_wq) {
		XDNA_ERR(xdna, "alloc notifier_wq failed");
		return -ENOMEM;
	}

	/*
	 * aie4_pci_init() reuses the plat_probe() ndev and xcomm_ops installed
	 * by amdxdna_shmem_init() / amdxdna_rpmsg_init().  It must run after
	 * transport init (FW mgmt uses xcomm) and before userspace open.
	 */
	if (xdna->dev_info->ops && xdna->dev_info->ops->init) {
		ret = xdna->dev_info->ops->init(xdna);
		if (ret) {
			XDNA_ERR(xdna, "ops->init failed: %d", ret);
			goto destroy_wq;
		}
	}

	ret = amdxdna_sysfs_init(xdna);
	if (ret) {
		XDNA_ERR(xdna, "sysfs_init failed: %d", ret);
		goto fini_dev;
	}

	ret = drm_dev_register(&xdna->ddev, 0);
	if (ret) {
		XDNA_ERR(xdna, "drm_dev_register failed: %d", ret);
		goto sysfs_fini;
	}

	/*
	 * Register the per-device debugfs files (dump_fw_log,
	 * dump_fw_log_buffer, dump_fw_trace, ...) for every transport that
	 * goes through amdxdna_plat. The actual files are CONFIG_DEBUG_FS
	 * guarded inside *_debugfs.c; calling the op when CONFIG_DEBUG_FS
	 * is off resolves to a stub no-op. The historic
	 * "#ifdef CONFIG_AMDXDNA_SHMEM" wrapper around this call was wrong:
	 * debugfs is independent of the management transport, and gating
	 * it on the SHMEM bus type left RPMsg / OF builds with no
	 * /sys/kernel/debug/accel/<dev>/dump_fw_log* files at all.
	 */
	if (xdna->dev_info->ops && xdna->dev_info->ops->debugfs)
		xdna->dev_info->ops->debugfs(xdna);

	ret = amdxdna_dpt_init(xdna);
	if (ret)
		XDNA_WARN(xdna, "Failed to enable firmware debug/profile/trace: %d", ret);

	pm_runtime_enable(dev);
	pm_runtime_get_noresume(dev);
	amdxdna_rpm_init(xdna);

	XDNA_INFO(xdna, "Device registered (channel up)");
	return 0;

sysfs_fini:
	amdxdna_sysfs_fini(xdna);
fini_dev:
	amdxdna_dpt_fini(xdna);
	if (xdna->dev_info->ops && xdna->dev_info->ops->fini)
		xdna->dev_info->ops->fini(xdna);
destroy_wq:
	destroy_workqueue(xdna->notifier_wq);
	xdna->notifier_wq = NULL;
	return ret;
}

void amdxdna_plat_unregister_device(struct amdxdna_dev *xdna)
{
	struct device *dev = xdna->ddev.dev;

	if (!xdna->notifier_wq)
		return;

	/*
	 * Tear-down ordering follows the PCI variant (see amdxdna_remove):
	 *   - drm_dev_unplug() first so new userspace ioctls/opens get
	 *     -ENODEV and in-flight ones drain on a known-stopping device.
	 *   - sysfs attrs removed, then stop HW and DPT timers before
	 *     touching runtime PM (rpm_fini() would otherwise resume the
	 *     device via pm_runtime_get_noresume()).
	 *   - ops->fini() and dpt_fini() while the management channel is
	 *     still alive (plat_remove tears down shmem/rpmsg right after).
	 *   - destroy_workqueue() last; the HMM notifier path in amdxdna_gem
	 *     queues onto it, so it must outlive any DRM activity above.
	 */
	drm_dev_unplug(&xdna->ddev);
	amdxdna_sysfs_fini(xdna);

	if (xdna->dev_info->ops && xdna->dev_info->ops->suspend)
		xdna->dev_info->ops->suspend(xdna);
	amdxdna_dpt_suspend(xdna);

	amdxdna_dpt_fini(xdna);
	if (xdna->dev_info->ops && xdna->dev_info->ops->fini)
		xdna->dev_info->ops->fini(xdna);

	pm_runtime_disable(dev);
	amdxdna_rpm_fini(xdna);
	destroy_workqueue(xdna->notifier_wq);
	xdna->notifier_wq = NULL;

	XDNA_INFO(xdna, "Device unregistered (channel down)");
}

/*
 * Lightweight platform probe.
 *
 * Does only the work that is independent of the management transport
 * channel: allocates the drm/xdna/ndev objects, sets drvdata so
 * amdxdna_plat_find_by_rproc() can find us, initialises the resource
 * resolver and CMA banks, then registers the transport (which
 * synchronously fires the rpmsg endpoint driver's probe if the
 * channel is already announced).  All firmware-dependent setup —
 * ops->init(), sysfs, drm_dev_register, runtime PM — is deferred to
 * amdxdna_plat_register_device(), called from the transport's
 * drv_probe once the channel is up.  Until then, the rpmsg drv_probe
 * returns -EPROBE_DEFER if it cannot yet find a probed plat device.
 */
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

	/*
	 * cert_comp_xa must be live before transport_init(): shmem IPI and
	 * rpmsg CMD_COMPLETION walk it from IRQ/callback context as soon as
	 * the channel is up, which can be before ops->init().
	 */
	aie4_ndev_init_base(ndev, xdna);
	xdna->dev_handle = ndev;
	ndev->pw_mode = POWER_MODE_DEFAULT;
	ndev->plat_transport = pdata->transport;
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

	/*
	 * Pin the platform device to a 32-bit DMA mask before binding
	 * the "rpu-cma" reserved-memory region to it.  The mgmt buffers
	 * allocated against this device are read/written by the remote
	 * firmware (e.g. RPU on T20), which on these SoCs can only
	 * address the lower 4 GB of physical memory.  AIE-visible
	 * "app-bank<N>" regions are bound to separate child devices
	 * with their own 64-bit mask in amdxdna_cma_region_init().
	 *
	 * Note: dma_buf imports done by gem_prime_import() use this
	 * platform device as the importer (drm_dev->dev), so a 64-bit
	 * "app-bank<N>" allocation would normally fail the 32-bit mask
	 * check inside dma_buf_map_attachment().  amdxdna_cmabuf_map()
	 * works around that by mapping against cbuf->dev (the producer
	 * device the BO was allocated on) instead of attach->dev.
	 */
	ret = dma_set_mask_and_coherent(dev, DMA_BIT_MASK(32));
	if (ret) {
		dev_err(dev, "Failed to set 32-bit DMA mask: %d\n", ret);
		return ret;
	}

	/* Bind named CMA regions ("rpu-cma" + "app-bank<N>"). */
	ret = amdxdna_cma_region_init(xdna, dev->of_node);
	if (ret) {
		dev_err(dev, "CMA region init failed: %d\n", ret);
		return ret;
	}

	/*
	 * Bring up the management transport.  For RPMsg this allocates
	 * rhdl, installs xcomm_ops, and registers the rpmsg endpoint
	 * driver.  If the rpdev is already announced, the rpmsg core
	 * will dispatch drv_probe synchronously here, which calls
	 * amdxdna_plat_register_device() before this returns.  If not,
	 * drv_probe will fire later (asynchronously) when the channel
	 * is announced.
	 */
	ret = amdxdna_plat_transport_init(xdna, pdev, pdata);
	if (ret) {
		dev_err(dev, "Transport init failed: %d\n", ret);
		goto cma_fini;
	}

	/*
	 * For shmem the transport is ready immediately -- call
	 * register_device inline (RPMsg does this from its drv_probe
	 * callback once the channel is announced).
	 */
	if (amdxdna_plat_transport_is_shmem(pdata->transport)) {
		ret = amdxdna_plat_register_device(xdna);
		if (ret) {
			dev_err(dev, "Device registration failed: %d\n", ret);
			goto transport_fini;
		}
	}

	XDNA_INFO(xdna, "Platform driver probed");
	return 0;

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

	/*
	 * Tear down the firmware-dependent state first.  In the typical
	 * case drv_remove() has already done this for us when the channel
	 * went down, so this is a no-op (gated on xdna->notifier_wq).  In
	 * the unbind-while-channel-up case it runs here.
	 *
	 * Then drop the transport: amdxdna_plat_transport_fini() detaches
	 * our specific rpdev (if still bound) via device_release_driver(),
	 * which would *also* fire drv_remove() and try to unregister us —
	 * but we already did, so that path becomes the no-op.
	 */
	amdxdna_plat_unregister_device(xdna);
	amdxdna_plat_transport_fini(xdna, pdata);
	amdxdna_cma_region_fini(xdna);
}

/*
 * T20: npu3/aie4 firmware over rpmsg, but the underlying AIE silicon is
 * aie2ps ("ve2").  Use the dedicated dev_npu3_aie2ps_info so XRT sees
 * vbnv "RyzenAI-npu3-aie2ps" and dispatches to the npu3_aie2ps
 * hardware_type (ve2 ELFs / xrt_smi_ve2.a) rather than the generic PCI
 * npu3 path.
 */
static const struct amdxdna_plat_data plat_rpmsg_npu3_aie2ps = {
	.dev_info	= &dev_npu3_aie2ps_info,
	.transport	= AMDXDNA_TRANSPORT_RPMSG,
};

/*
 * Same T20 SoC as the rpmsg variant above, just a different management
 * transport (shared memory mailbox instead of rpmsg).  Underlying AIE
 * silicon is still aie2ps ("ve2"), so use dev_npu3_aie2ps_info to get
 * the "RyzenAI-npu3-aie2ps" vbnv and the npu3_aie2ps XRT dispatch.
 */
static const struct amdxdna_plat_data plat_shmem_npu3_aie2ps = {
	.dev_info	= &dev_npu3_aie2ps_info,
	.transport	= AMDXDNA_TRANSPORT_SHMEM,
};

static const struct of_device_id amdxdna_plat_of_match[] = {
	{ .compatible = "amd,versal-aie-rpmsg", .data = &plat_rpmsg_npu3_aie2ps },
	{ .compatible = "amd,versal-aie", .data = &plat_shmem_npu3_aie2ps },
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

/*
 * Custom module_init/module_exit (instead of module_platform_driver())
 * so we can also register the internal rpmsg endpoint driver, with a
 * specific ordering:
 *
 *   init :  platform_driver_register()  ──►  amdxdna_rpmsg_drv_register()
 *   exit :  amdxdna_rpmsg_drv_unregister() ──►  platform_driver_unregister()
 *
 * Why this order at init?  platform_driver_register() synchronously
 * probes any matching platform devices, so by the time the rpmsg core's
 * bus walk inside amdxdna_rpmsg_drv_register() runs, plat_probe() has
 * already executed and amdxdna_plat_find_by_rproc() can resolve the
 * owning rproc to a probed xdna on the very first try.  In the
 * unfortunate case where the channel is announced before any plat_probe
 * completed (out-of-order rproc start), drv_probe() returns
 * -EPROBE_DEFER (resetting rpdev->src so the rpmsg core's failure
 * cleanup leaves it in a fresh state) and the deferred-probe machinery
 * retries when the platform device finishes binding.
 *
 * Why this order at exit?  We want to tear down all rpmsg bindings
 * before the platform driver goes away, so each plat_remove() finds the
 * device already in the "channel down" state and runs its idempotent
 * unregister path as a no-op.  unregister_rpmsg_driver() iterates all
 * bound rpdevs and fires drv_remove() (which calls
 * amdxdna_plat_unregister_device() + tears down the channel) for each.
 * Then platform_driver_unregister() can run plat_remove() to clean up
 * the remaining platform-side state.
 */
static int __init amdxdna_plat_mod_init(void)
{
	int ret;

	ret = platform_driver_register(&amdxdna_plat_driver);
	if (ret)
		return ret;

	ret = amdxdna_rpmsg_drv_register();
	if (ret) {
		platform_driver_unregister(&amdxdna_plat_driver);
		return ret;
	}

	return 0;
}

static void __exit amdxdna_plat_mod_exit(void)
{
	amdxdna_rpmsg_drv_unregister();
	platform_driver_unregister(&amdxdna_plat_driver);
}

module_init(amdxdna_plat_mod_init);
module_exit(amdxdna_plat_mod_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("XRT Team <runtimeca39d@amd.com>");
MODULE_VERSION(MODULE_VER_STR);
MODULE_DESCRIPTION("amdxdna platform driver");

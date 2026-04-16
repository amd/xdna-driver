// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2026, Advanced Micro Devices, Inc.
 *
 * Shared-memory + ZynqMP IPI transport driver for amdxdna (AIE4).
 *
 * When CONFIG_AMDXDNA_SHMEM is enabled, this file is the main driver
 * entry point.  The module registers a platform driver that binds via
 * device tree compatible string "amd,amdxdna-shmem".
 *
 * Communication with the remote firmware uses:
 *   - Two shared memory regions (mgmt mailbox + doorbell) from
 *     reserved-memory, for the actual message data.
 *   - ZynqMP IPI mailbox channels (TX + RX) via the Linux mailbox
 *     framework for interrupt notification only — no IPI message
 *     buffers are used (bufferless IPI).
 *
 * The ZynqMP IPI mailbox controller (drivers/mailbox/zynqmp-ipi-mailbox.c)
 * handles the underlying IPI hardware (SMC/HVC calls to ATF for
 * IPI notification, ack, and IRQ management).  This driver is a
 * mailbox client that requests TX/RX channels via
 * mbox_request_channel_byname() and uses mbox_send_message() to
 * trigger an IPI to the remote, and receives rx_callback() when the
 * remote triggers an IPI to us.
 *
 * See dt-bindings/amd,amdxdna-shmem.yaml for the device tree binding.
 */

#include <drm/drm_accel.h>
#include <drm/drm_drv.h>
#include <drm/drm_managed.h>
#include <linux/io.h>
#include <linux/kernel.h>
#include <linux/mailbox_client.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/of_address.h>
#include <linux/of_reserved_mem.h>
#include <linux/platform_device.h>
#include <linux/slab.h>

#include "aie4_pci.h"
#include "aie4_message.h"
#include "amdxdna_sysfs.h"

struct amdxdna_shmem_hdl {
	struct amdxdna_dev_hdl	*ndev;
	struct platform_device	*pdev;

	/* Shared memory regions mapped from device tree reserved-memory */
	void __iomem		*mgmt_shmem;
	resource_size_t		mgmt_shmem_size;
	void __iomem		*db_shmem;
	resource_size_t		db_shmem_size;

	/* Linux mailbox client for ZynqMP IPI (notification only) */
	struct mbox_client	tx_cl;
	struct mbox_client	rx_cl;
	struct mbox_chan	*tx_chan;
	struct mbox_chan	*rx_chan;
};

/*
 * Called by the mailbox framework when the remote processor sends an
 * IPI to us (RX channel callback).  The IPI itself carries no data;
 * actual message content resides in the shared memory regions.
 */
static void amdxdna_shmem_rx_callback(struct mbox_client *cl, void *data)
{
	struct amdxdna_shmem_hdl *shdl =
		container_of(cl, struct amdxdna_shmem_hdl, rx_cl);

	/*
	 * TODO: read shared memory to determine which message completed
	 * or which doorbell was rung, then dispatch accordingly via
	 * ndev->xcomm_ops callbacks.
	 */
	dev_dbg(&shdl->pdev->dev, "IPI RX notification received\n");
}

static int amdxdna_shmem_send_msg(void *xcomm_hdl,
				  const struct xdna_mailbox_msg *msg)
{
	/*
	 * TODO: write message to mgmt shared memory region, then
	 * trigger IPI via mbox_send_message(shdl->tx_chan, ...).
	 */
	return -ENOSYS;
}

static int amdxdna_shmem_ring_doorbell(void *xcomm_hdl, u32 hw_ctx_id)
{
	/*
	 * TODO: write doorbell to doorbell shared memory region, then
	 * trigger IPI via mbox_send_message(shdl->tx_chan, ...).
	 */
	return -ENOSYS;
}

static void amdxdna_shmem_fini(void *xcomm_hdl)
{
	struct amdxdna_shmem_hdl *shdl = xcomm_hdl;

	if (shdl->tx_chan)
		mbox_free_channel(shdl->tx_chan);
	if (shdl->rx_chan)
		mbox_free_channel(shdl->rx_chan);
}

static const struct amdxdna_xcomm_ops amdxdna_shmem_xcomm_ops = {
	.send_msg	= amdxdna_shmem_send_msg,
	.ring_doorbell	= amdxdna_shmem_ring_doorbell,
	.fini		= amdxdna_shmem_fini,
};

static int amdxdna_shmem_map_regions(struct amdxdna_shmem_hdl *shdl)
{
	struct platform_device *pdev = shdl->pdev;
	struct device_node *np = pdev->dev.of_node;
	struct device_node *mem_np;
	struct resource res;
	int idx, ret;

	idx = of_property_match_string(np, "memory-region-names", "mgmt");
	if (idx < 0) {
		dev_err(&pdev->dev, "missing 'mgmt' memory-region-names\n");
		return idx;
	}

	mem_np = of_parse_phandle(np, "memory-region", idx);
	if (!mem_np)
		return -ENODEV;

	ret = of_address_to_resource(mem_np, 0, &res);
	of_node_put(mem_np);
	if (ret)
		return ret;

	shdl->mgmt_shmem_size = resource_size(&res);
	shdl->mgmt_shmem = devm_ioremap(&pdev->dev, res.start,
					 shdl->mgmt_shmem_size);
	if (!shdl->mgmt_shmem)
		return -ENOMEM;

	dev_info(&pdev->dev, "mgmt shmem: %pa size 0x%llx\n",
		 &res.start, (u64)shdl->mgmt_shmem_size);

	idx = of_property_match_string(np, "memory-region-names", "doorbell");
	if (idx < 0) {
		dev_err(&pdev->dev, "missing 'doorbell' memory-region-names\n");
		return idx;
	}

	mem_np = of_parse_phandle(np, "memory-region", idx);
	if (!mem_np)
		return -ENODEV;

	ret = of_address_to_resource(mem_np, 0, &res);
	of_node_put(mem_np);
	if (ret)
		return ret;

	shdl->db_shmem_size = resource_size(&res);
	shdl->db_shmem = devm_ioremap(&pdev->dev, res.start,
				       shdl->db_shmem_size);
	if (!shdl->db_shmem)
		return -ENOMEM;

	dev_info(&pdev->dev, "doorbell shmem: %pa size 0x%llx\n",
		 &res.start, (u64)shdl->db_shmem_size);

	return 0;
}

static int amdxdna_shmem_mbox_init(struct amdxdna_shmem_hdl *shdl)
{
	struct device *dev = &shdl->pdev->dev;

	shdl->tx_cl.dev = dev;
	shdl->tx_cl.tx_block = false;
	shdl->tx_cl.knows_txdone = false;

	shdl->rx_cl.dev = dev;
	shdl->rx_cl.rx_callback = amdxdna_shmem_rx_callback;

	shdl->tx_chan = mbox_request_channel_byname(&shdl->tx_cl, "tx");
	if (IS_ERR(shdl->tx_chan)) {
		int ret = PTR_ERR(shdl->tx_chan);

		dev_err(dev, "failed to request IPI TX channel: %d\n", ret);
		shdl->tx_chan = NULL;
		return ret;
	}

	shdl->rx_chan = mbox_request_channel_byname(&shdl->rx_cl, "rx");
	if (IS_ERR(shdl->rx_chan)) {
		int ret = PTR_ERR(shdl->rx_chan);

		dev_err(dev, "failed to request IPI RX channel: %d\n", ret);
		shdl->rx_chan = NULL;
		mbox_free_channel(shdl->tx_chan);
		shdl->tx_chan = NULL;
		return ret;
	}

	dev_info(dev, "IPI mailbox TX/RX channels acquired\n");
	return 0;
}

static const struct amdxdna_dev_info amdxdna_shmem_dev_info = {
};

static int amdxdna_shmem_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct amdxdna_shmem_hdl *shdl;
	struct amdxdna_dev_hdl *ndev;
	struct amdxdna_dev *xdna;
	int ret;

	xdna = devm_drm_dev_alloc(dev, &amdxdna_drm_drv,
				  typeof(*xdna), ddev);
	if (IS_ERR(xdna))
		return PTR_ERR(xdna);

	xdna->dev_info = &amdxdna_shmem_dev_info;

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

	shdl = drmm_kzalloc(&xdna->ddev, sizeof(*shdl), GFP_KERNEL);
	if (!shdl)
		return -ENOMEM;

	shdl->ndev = ndev;
	shdl->pdev = pdev;

	ret = amdxdna_shmem_map_regions(shdl);
	if (ret) {
		dev_err(dev, "failed to map shared memory regions: %d\n", ret);
		return ret;
	}

	ret = amdxdna_shmem_mbox_init(shdl);
	if (ret)
		return ret;

	ndev->xdna = xdna;
	ndev->xcomm_ops = &amdxdna_shmem_xcomm_ops;
	ndev->xcomm_hdl = shdl;
	xa_init(&ndev->cert_comp_xa);
	mutex_init(&ndev->aie4_lock);

	xdna->dev_handle = ndev;
	platform_set_drvdata(pdev, xdna);

	xdna->notifier_wq = alloc_ordered_workqueue("notifier_wq",
						     WQ_MEM_RECLAIM);
	if (!xdna->notifier_wq) {
		ret = -ENOMEM;
		goto mbox_fini;
	}

	ret = amdxdna_sysfs_init(xdna);
	if (ret)
		goto destroy_wq;

	ret = drm_dev_register(&xdna->ddev, 0);
	if (ret)
		goto sysfs_fini;

	dev_info(dev, "amdxdna shmem+IPI driver probed\n");
	return 0;

sysfs_fini:
	amdxdna_sysfs_fini(xdna);
destroy_wq:
	destroy_workqueue(xdna->notifier_wq);
mbox_fini:
	amdxdna_shmem_fini(shdl);
	return ret;
}

static void amdxdna_shmem_remove(struct platform_device *pdev)
{
	struct amdxdna_dev *xdna = platform_get_drvdata(pdev);
	struct amdxdna_dev_hdl *ndev = xdna->dev_handle;

	destroy_workqueue(xdna->notifier_wq);
	drm_dev_unplug(&xdna->ddev);
	amdxdna_sysfs_fini(xdna);

	if (ndev->xcomm_ops && ndev->xcomm_ops->fini)
		ndev->xcomm_ops->fini(ndev->xcomm_hdl);
}

static const struct of_device_id amdxdna_shmem_of_match[] = {
	{ .compatible = "amd,amdxdna-shmem" },
	{ },
};
MODULE_DEVICE_TABLE(of, amdxdna_shmem_of_match);

static struct platform_driver amdxdna_shmem_driver = {
	.probe	= amdxdna_shmem_probe,
	.remove	= amdxdna_shmem_remove,
	.driver	= {
		.name		= "amdxdna_shmem",
		.of_match_table	= amdxdna_shmem_of_match,
	},
};

static int __init amdxdna_shmem_init(void)
{
	return platform_driver_register(&amdxdna_shmem_driver);
}

static void __exit amdxdna_shmem_exit(void)
{
	platform_driver_unregister(&amdxdna_shmem_driver);
}

module_init(amdxdna_shmem_init);
module_exit(amdxdna_shmem_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("XRT Team <runtimeca39d@amd.com>");
MODULE_DESCRIPTION("amdxdna shared-memory + IPI transport driver for AIE4");

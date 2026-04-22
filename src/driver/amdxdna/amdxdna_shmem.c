// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2026, Advanced Micro Devices, Inc.
 *
 * Shared-memory + ZynqMP IPI transport layer for amdxdna (AIE4).
 *
 * Provides the xcomm_ops implementation that sends management messages and
 * doorbell notifications via shared memory regions with ZynqMP IPI for
 * interrupt notification.  The platform driver (amdxdna_plat.c) calls
 * amdxdna_shmem_init() to set up the transport.
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
 */

#include <drm/drm_managed.h>
#include <linux/io.h>
#include <linux/kernel.h>
#include <linux/mailbox_client.h>
#include <linux/of.h>
#include <linux/of_address.h>
#include <linux/of_reserved_mem.h>
#include <linux/platform_device.h>
#include <linux/slab.h>

#include "aie4_pci.h"
#include "amdxdna_shmem.h"

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

static void amdxdna_shmem_xcomm_fini(void *xcomm_hdl)
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
	.fini		= amdxdna_shmem_xcomm_fini,
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

/**
 * amdxdna_shmem_init - Set up shared-memory + IPI transport
 * @xdna: the amdxdna device
 * @pdev: platform device with DT properties for shmem regions and IPI mboxes
 *
 * Maps the mgmt and doorbell shared memory regions, acquires IPI mailbox
 * channels, and wires up xcomm_ops.
 *
 * Return: 0 on success, negative errno on failure
 */
int amdxdna_shmem_init(struct amdxdna_dev *xdna, struct platform_device *pdev)
{
	struct amdxdna_dev_hdl *ndev = xdna->dev_handle;
	struct amdxdna_shmem_hdl *shdl;
	int ret;

	shdl = drmm_kzalloc(&xdna->ddev, sizeof(*shdl), GFP_KERNEL);
	if (!shdl)
		return -ENOMEM;

	shdl->ndev = ndev;
	shdl->pdev = pdev;

	ret = amdxdna_shmem_map_regions(shdl);
	if (ret) {
		dev_err(&pdev->dev, "failed to map shared memory regions: %d\n", ret);
		return ret;
	}

	ret = amdxdna_shmem_mbox_init(shdl);
	if (ret)
		return ret;

	ndev->xcomm_ops = &amdxdna_shmem_xcomm_ops;
	ndev->xcomm_hdl = shdl;

	return 0;
}

void amdxdna_shmem_fini(struct amdxdna_dev *xdna)
{
	struct amdxdna_dev_hdl *ndev = xdna->dev_handle;

	if (ndev->xcomm_ops && ndev->xcomm_ops->fini)
		ndev->xcomm_ops->fini(ndev->xcomm_hdl);

	ndev->xcomm_ops = NULL;
	ndev->xcomm_hdl = NULL;
}

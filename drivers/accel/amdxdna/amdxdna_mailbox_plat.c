// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2026, Advanced Micro Devices, Inc.
 *
 * Shared-memory + ZynqMP IPI implementation of the amdxdna mailbox interface
 * (amdxdna_mailbox.h) for the platform (device-tree) build.  It is the
 * compile-time-exclusive counterpart of the PCI ringbuf+MSI-X amdxdna_mailbox.c:
 * both define struct mailbox and the same external API, and exactly one is built
 * (see Kbuild).  The handle is stored in ndev->mbox like the PCI path.
 *
 * The management command/response channel and the hw_ctx dispatch doorbell live
 * in reserved-memory shmem regions; a pair of IPI mailbox channels (tx/rx) carry
 * interrupt notifications only -- the IPI has no payload, the data is always in
 * shared memory.
 *
 * NOTE: transport scaffolding.  xdnam_mailbox_create() maps the "mgmt" and
 * "doorbell" shmem regions from device tree and acquires the IPI channels so the
 * platform build links and probes; the shmem ring produce/consume for the mgmt
 * channel ops and the doorbell is a follow-up, so those functions are stubs.
 */

#include <linux/container_of.h>
#include <linux/device.h>
#include <linux/io.h>
#include <linux/mailbox_client.h>
#include <linux/of.h>
#include <linux/of_address.h>
#include <linux/platform_device.h>
#include <linux/workqueue.h>

#include "amdxdna_mailbox.h"
#include "amdxdna_mailbox_plat.h"
#include "amdxdna_drv.h"

struct mailbox {
	struct amdxdna_dev	*xdna;
	struct platform_device	*pdev;

	/* mgmt command/response shmem region */
	void __iomem		*mgmt_base;
	resource_size_t		mgmt_size;
	/* hw_ctx dispatch doorbell shmem region */
	void __iomem		*doorbell_base;
	resource_size_t		doorbell_size;

	/* IPI notification channels (payload lives in shared memory). */
	struct mbox_client	tx_cl;
	struct mbox_client	rx_cl;
	struct mbox_chan	*tx_chan;
	struct mbox_chan	*rx_chan;
	struct work_struct	rx_work;
};

struct mailbox_channel {
	struct mailbox		*mb;
};

/*
 * Map a "memory-region" reserved-memory entry selected by its
 * memory-region-names string.  The regions are device memory, so
 * devm_ioremap_wc() is used; the mapping is torn down with the platform device.
 */
static int plat_map_region(struct amdxdna_dev *xdna, struct device *dev,
			   const char *name, void __iomem **base,
			   resource_size_t *size)
{
	struct device_node *np;
	struct resource res;
	int idx, ret;

	idx = of_property_match_string(dev->of_node, "memory-region-names", name);
	if (idx < 0) {
		XDNA_ERR(xdna, "memory-region '%s' not found: %d", name, idx);
		return idx;
	}

	np = of_parse_phandle(dev->of_node, "memory-region", idx);
	if (!np) {
		XDNA_ERR(xdna, "no memory-region phandle for '%s'", name);
		return -ENODEV;
	}

	ret = of_address_to_resource(np, 0, &res);
	of_node_put(np);
	if (ret) {
		XDNA_ERR(xdna, "bad memory-region '%s': %d", name, ret);
		return ret;
	}

	*base = devm_ioremap_wc(dev, res.start, resource_size(&res));
	if (!*base) {
		XDNA_ERR(xdna, "ioremap memory-region '%s' failed", name);
		return -ENOMEM;
	}
	*size = resource_size(&res);

	XDNA_DBG(xdna, "mapped '%s' region %pa size %pa", name, &res.start, size);
	return 0;
}

static void plat_mailbox_rx_work(struct work_struct *work)
{
	/* TODO: drain the mgmt RX shmem ring and dispatch responses to waiters. */
}

static void plat_mailbox_rx_callback(struct mbox_client *cl, void *data)
{
	struct mailbox *mb = container_of(cl, struct mailbox, rx_cl);

	schedule_work(&mb->rx_work);
}

static int plat_mailbox_ipi_init(struct mailbox *mb)
{
	struct device *dev = &mb->pdev->dev;

	mb->tx_cl.dev = dev;
	mb->tx_cl.tx_block = false;
	mb->tx_cl.knows_txdone = true;

	mb->rx_cl.dev = dev;
	mb->rx_cl.rx_callback = plat_mailbox_rx_callback;

	mb->tx_chan = mbox_request_channel_byname(&mb->tx_cl, "tx");
	if (IS_ERR(mb->tx_chan)) {
		XDNA_ERR(mb->xdna, "Failed to bind 'tx' mailbox channel, ret %ld",
			 PTR_ERR(mb->tx_chan));
		return PTR_ERR(mb->tx_chan);
	}

	mb->rx_chan = mbox_request_channel_byname(&mb->rx_cl, "rx");
	if (IS_ERR(mb->rx_chan)) {
		XDNA_ERR(mb->xdna, "Failed to bind 'rx' mailbox channel, ret %ld",
			 PTR_ERR(mb->rx_chan));
		mbox_free_channel(mb->tx_chan);
		return PTR_ERR(mb->rx_chan);
	}
	return 0;
}

/* devm teardown for the IPI channels (mb itself is devm-allocated). */
static void plat_mailbox_release(void *data)
{
	struct mailbox *mb = data;

	/*
	 * Free the channels first so the mbox framework stops delivering rx
	 * callbacks, then drain any work already scheduled by a callback.
	 */
	if (!IS_ERR_OR_NULL(mb->rx_chan))
		mbox_free_channel(mb->rx_chan);
	if (!IS_ERR_OR_NULL(mb->tx_chan))
		mbox_free_channel(mb->tx_chan);
	cancel_work_sync(&mb->rx_work);
}

/*
 * xdnam_mailbox_create - platform (shmem+IPI) implementation.  Unlike the PCI
 * variant it derives its resources from the device tree (reserved-memory + IPI
 * mboxes) rather than @res, which is unused here.  The mgmt/doorbell memory is
 * statically reserved in the device node, so the handle, its region mappings and
 * the IPI channels are all managed by the platform device, not the drm device.
 */
struct mailbox *xdnam_mailbox_create(struct drm_device *ddev,
				     const struct xdna_mailbox_res *res)
{
	struct amdxdna_dev *xdna = to_xdna_dev(ddev);
	struct platform_device *pdev = to_platform_device(ddev->dev);
	struct device *dev = &pdev->dev;
	struct mailbox *mb;
	int ret;

	mb = devm_kzalloc(dev, sizeof(*mb), GFP_KERNEL);
	if (!mb)
		return ERR_PTR(-ENOMEM);

	mb->xdna = xdna;
	mb->pdev = pdev;
	INIT_WORK(&mb->rx_work, plat_mailbox_rx_work);

	ret = plat_map_region(xdna, dev, "mgmt", &mb->mgmt_base, &mb->mgmt_size);
	if (ret)
		return ERR_PTR(ret);

	ret = plat_map_region(xdna, dev, "doorbell",
			      &mb->doorbell_base, &mb->doorbell_size);
	if (ret)
		return ERR_PTR(ret);

	/* Propagate the channel-acquisition error, notably -EPROBE_DEFER. */
	ret = plat_mailbox_ipi_init(mb);
	if (ret)
		return ERR_PTR(ret);

	ret = devm_add_action_or_reset(dev, plat_mailbox_release, mb);
	if (ret)
		return ERR_PTR(ret);

	return mb;
}

struct mailbox_channel *xdna_mailbox_alloc_channel(struct mailbox *mb)
{
	struct mailbox_channel *mb_chann;

	mb_chann = devm_kzalloc(&mb->pdev->dev, sizeof(*mb_chann), GFP_KERNEL);
	if (!mb_chann)
		return NULL;

	mb_chann->mb = mb;
	return mb_chann;
}

int xdna_mailbox_start_channel(struct mailbox_channel *mb_chann,
			       const struct xdna_mailbox_chann_res *x2i,
			       const struct xdna_mailbox_chann_res *i2x,
			       u32 xdna_mailbox_intr_reg, int mb_irq)
{
	/* TODO: mgmt shmem ring bring-up (no MSI-X regs on the platform). */
	return 0;
}

void xdna_mailbox_set_async_cb(struct mailbox_channel *mailbox_chann,
			       void *async_handle, xdna_mailbox_async_cb_t async_cb)
{
	/* TODO: route firmware-initiated (id 0) messages from the mgmt RX ring. */
}

void xdna_mailbox_free_channel(struct mailbox_channel *mailbox_chann)
{
	/* The channel is devm-managed; nothing to free here. */
}

void xdna_mailbox_stop_channel(struct mailbox_channel *mailbox_chann)
{
	/* TODO: quiesce the mgmt shmem ring. */
}

void xdna_mailbox_drain_channel(struct mailbox_channel *mailbox_chann)
{
	/* TODO: consume mgmt responses already produced into the RX ring. */
}

int xdna_mailbox_send_msg(struct mailbox_channel *mailbox_chann,
			  const struct xdna_mailbox_msg *msg, u64 tx_timeout)
{
	/* TODO: SPSC-produce into the mgmt TX shmem ring, then IPI the remote. */
	return -EOPNOTSUPP;
}

int amdxdna_mailbox_plat_ring_doorbell(struct mailbox *mb, u32 hw_ctx_id)
{
	/* TODO: SPSC-produce hw_ctx_id into the doorbell shmem ring + IPI kick. */
	return -EOPNOTSUPP;
}

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
 *     buffers are used.  Uses buffered IPI5 (APU, agent 0x07) and
 *     IPI1 (RPU, agent 0x03).
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
#include <linux/bitfield.h>
#include <linux/io.h>
#include <linux/kernel.h>
#include <linux/mailbox_client.h>
#include <linux/of.h>
#include <linux/of_address.h>
#include <linux/of_reserved_mem.h>
#include <linux/platform_device.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/workqueue.h>
#include <linux/xarray.h>

#include "aie4_pci.h"
#include "aie4_message.h"
#include "amdxdna_drm.h"
#include "amdxdna_mailbox.h"
#include "amdxdna_shmem.h"
#include "amdxdna_sysfs.h"
#include "amdxdna_trace.h"

struct shmem_inflight_msg {
	u32			id;
	void			*handle;
	int			(*notify_cb)(void *handle, void __iomem *data,
					     size_t size);
};

struct amdxdna_shmem_hdl {
	struct amdxdna_dev_hdl	*ndev;
	struct platform_device	*pdev;

	/* Shared memory regions mapped from device tree reserved-memory */
	void			*mgmt_shmem;
	resource_size_t		mgmt_shmem_size;
	void			*db_shmem;
	resource_size_t		db_shmem_size;

	/* Mgmt TX ring (host is producer) */
	struct shmem_ring_hdr	*tx_hdr;
	void			*tx_ring;

	/* Mgmt RX ring (host is consumer) */
	struct shmem_ring_hdr	*rx_hdr;
	void			*rx_ring;

	/* Doorbell ring (host is producer) */
	struct shmem_db_ring	*db_ring;

	/* Cached ring_mask -- constant after init, avoids NC read on hot path */
	u64			mgmt_ring_mask;
	u64			db_ring_mask;

	/*
	 * Cached host-owned indices -- the host is the sole writer of each,
	 * so these mirror shared memory and avoid a WC read on the hot path.
	 * db_head_cached is serialized by db_lock; rx_tail_cached is written
	 * only by rx_work (single-threaded) and read locklessly by the IPI
	 * gating (aligned u64, atomic on AArch64).
	 */
	u64			db_head_cached;
	u64			rx_tail_cached;

	/* Inflight management message tracking */
	struct xarray		msg_xa;
	spinlock_t		msg_id_lock; /* protects next_msg_id + xa_insert */
	u32			next_msg_id;

	/* Produce-path locks (protect ring write + IPI send atomically) */
	spinlock_t		tx_lock; /* protects mgmt TX ring + IPI */
	spinlock_t		db_lock; /* protects doorbell ring + IPI */

	/* Linux mailbox client for ZynqMP IPI (notification only) */
	struct mbox_client	tx_cl;
	struct mbox_client	rx_cl;
	struct mbox_chan	*tx_chan;
	struct mbox_chan	*rx_chan;

	/* Deferred mgmt RX processing (doorbell runs in IRQ context) */
	struct work_struct	rx_work;

};

/* Maximum response payload we expect from firmware (fits on kernel stack) */
#define SHMEM_MAX_RESP_SIZE	512

static void shmem_dump_mgmt_msg(struct device *dev, const char *dir,
				const struct shmem_msg_hdr *hdr,
				const void *ring_buf, const void *payload,
				int payload_size)
{
	u32 body_sz = FIELD_GET(SHMEM_MSG_BODY_SZ, hdr->sz_ver);
	u32 proto = FIELD_GET(SHMEM_MSG_PROTO_VER, hdr->sz_ver);

	dev_info(dev,
		 "shmem mgmt %s: total_size=%u id=%u opcode=0x%x body_sz=%u proto=0x%x len=%d\n",
		 dir, hdr->total_size, hdr->id,
		 hdr->opcode, body_sz, proto, payload_size);
	print_hex_dump(KERN_INFO, "shmem mgmt hdr: ", DUMP_PREFIX_OFFSET,
		       16, 4, hdr, sizeof(*hdr), false);
	if (payload_size > 0)
		print_hex_dump(KERN_INFO, "shmem mgmt payload: ",
			       DUMP_PREFIX_OFFSET, 16, 4, payload,
			       payload_size, false);
}

static void amdxdna_shmem_doorbell_notify(struct amdxdna_dev_hdl *ndev)
{
	struct amdxdna_dev *xdna = ndev->xdna;
	struct cert_comp *cert_comp;
	unsigned long idx;
	u32 n = 0;

	xa_for_each(&ndev->cert_comp_xa, idx, cert_comp) {
		wake_up_all(&cert_comp->waitq);
		n++;
	}

	XDNA_DBG(xdna, "shmem doorbell IPI RX: woke %u cert_comp waitq(s)", n);
}

static void amdxdna_shmem_rx_work(struct work_struct *work)
{
	struct amdxdna_shmem_hdl *shdl =
		container_of(work, struct amdxdna_shmem_hdl, rx_work);
	u8 buf[SHMEM_MAX_RESP_SIZE];
	struct shmem_msg_hdr msg_hdr;
	struct shmem_inflight_msg *ifm;
	int payload_size;

	/* Drain all available management responses */
	while (shdl->rx_hdr) {
		payload_size = shmem_mgmt_consume(shdl->rx_hdr, shdl->rx_ring,
						  shdl->mgmt_ring_mask,
						  &msg_hdr, buf, sizeof(buf),
						  &shdl->rx_tail_cached);
		if (payload_size < 0)
			break;

		if (mailbox_verbose)
			shmem_dump_mgmt_msg(&shdl->pdev->dev, "RX", &msg_hdr,
					    shdl->rx_ring, buf, payload_size);

		trace_shmem_mgmt_rx(msg_hdr.opcode, msg_hdr.id,
				    msg_hdr.total_size);

		ifm = xa_erase(&shdl->msg_xa, msg_hdr.id);

		if (!ifm) {
			dev_dbg(&shdl->pdev->dev,
				"unexpected response id %u opcode 0x%x\n",
				msg_hdr.id, msg_hdr.opcode);
			continue;
		}

		/* Cast for xdna_mailbox_msg callback signature compatibility */
		if (ifm->notify_cb)
			ifm->notify_cb(ifm->handle, (void __iomem *)buf,
				       payload_size);

		kfree(ifm);
	}
}

/*
 * Called by the mailbox framework when the remote processor sends an
 * IPI to us (RX channel callback).  This runs in IRQ context.
 *
 * Doorbell completion is handled directly here (fast path -- just
 * wake_up_all which is IRQ-safe).  Management response draining is
 * deferred to a workqueue since it involves xarray + kfree.
 */
static void amdxdna_shmem_rx_callback(struct mbox_client *cl, void *data)
{
	struct amdxdna_shmem_hdl *shdl =
		container_of(cl, struct amdxdna_shmem_hdl, rx_cl);
	struct amdxdna_dev *xdna = shdl->ndev->xdna;

	XDNA_DBG(xdna, "shmem IPI RX callback (doorbell/completion interrupt)");
	trace_shmem_ipi_rx(shdl->rx_hdr->head, shdl->rx_hdr->tail,
			   shdl->db_ring->head, shdl->db_ring->tail);
	amdxdna_shmem_doorbell_notify(shdl->ndev);

	/*
	 * Only drain the management ring when the RPU has actually queued a
	 * response (head != tail).  Pure doorbell-completion IPIs leave the
	 * mgmt ring empty, so scheduling rx_work for them just adds a needless
	 * workqueue wakeup on the completion fast path.  SPSC-safe: the RPU
	 * publishes head (with a write barrier) before sending the IPI.
	 * tail is host-owned, so compare against the cached copy and read
	 * only the RPU-owned head fresh from WC.
	 */
	if (shdl->rx_hdr->head != shdl->rx_tail_cached)
		schedule_work(&shdl->rx_work);

	/*
	 * ACK the IPI to re-enable the notification interrupt.
	 * The zynqmp-ipi ISR disables the IRQ via SMC STATUS_ENQUIRY
	 * with DIRQ_MASK; sending on the RX channel triggers
	 * SMC_IPI_MAILBOX_ACK with EIRQ_MASK to re-enable it.
	 */
	mbox_send_message(shdl->rx_chan, NULL);
	mbox_client_txdone(shdl->rx_chan, 0);
}

static int amdxdna_shmem_send_msg(void *xcomm_hdl,
				  struct xdna_mailbox_msg *msg)
{
	struct amdxdna_shmem_hdl *shdl = xcomm_hdl;
	struct shmem_inflight_msg *ifm;
	struct shmem_msg_hdr hdr;
	u32 id;
	int ret;

	ifm = kzalloc(sizeof(*ifm), GFP_KERNEL);
	if (!ifm)
		return -ENOMEM;

	ifm->handle = msg->handle;
	ifm->notify_cb = msg->notify_cb;

	spin_lock(&shdl->msg_id_lock);
	id = shdl->next_msg_id++;
	ifm->id = id;
	ret = xa_insert(&shdl->msg_xa, id, ifm, GFP_ATOMIC);
	spin_unlock(&shdl->msg_id_lock);

	if (ret) {
		kfree(ifm);
		return ret;
	}

	msg->id = id;

	hdr.total_size = sizeof(hdr) + msg->send_size;
	hdr.sz_ver = FIELD_PREP(SHMEM_MSG_BODY_SZ, msg->send_size) |
		     FIELD_PREP(SHMEM_MSG_PROTO_VER, SHMEM_PROTOCOL_VER);
	hdr.id = id;
	hdr.opcode = msg->opcode;

	if (mailbox_verbose)
		shmem_dump_mgmt_msg(&shdl->pdev->dev, "TX", &hdr,
				    shdl->tx_ring, msg->send_data,
				    msg->send_size);

	spin_lock(&shdl->tx_lock);
	ret = shmem_mgmt_produce(shdl->tx_hdr, shdl->tx_ring,
				 shdl->mgmt_ring_mask,
				 &hdr, msg->send_data, msg->send_size);
	if (ret)
		goto unlock_tx;

	trace_shmem_mgmt_tx(hdr.opcode, hdr.id, msg->send_size,
			    shdl->tx_hdr->head, shdl->tx_hdr->tail);

	ret = mbox_send_message(shdl->tx_chan, NULL);
	if (ret < 0)
		goto unlock_tx;
	mbox_client_txdone(shdl->tx_chan, 0);
	spin_unlock(&shdl->tx_lock);

	return 0;

unlock_tx:
	spin_unlock(&shdl->tx_lock);
	xa_erase(&shdl->msg_xa, id);
	kfree(ifm);
	return ret;
}

static int amdxdna_shmem_ring_doorbell(void *xcomm_hdl, u32 hw_ctx_id)
{
	struct amdxdna_shmem_hdl *shdl = xcomm_hdl;
	struct amdxdna_dev *xdna = shdl->ndev->xdna;
	struct shmem_db_ring *ring = shdl->db_ring;
	u64 head, tail;
	int ret;

	spin_lock(&shdl->db_lock);

	ret = shmem_db_produce(ring, shdl->db_ring_mask, hw_ctx_id,
			       &shdl->db_head_cached);
	if (ret) {
		head = ring->head;
		tail = ring->tail;
		XDNA_DBG(xdna,
			 "shmem doorbell TX db_produce failed: hw_ctx_id=%u head=%llu tail=%llu ret=%d",
			 hw_ctx_id, head, tail, ret);
		goto unlock;
	}

	trace_shmem_db_tx(hw_ctx_id, (ring->head - 1) & ring->ring_mask,
			  ring->head, ring->tail);

	ret = mbox_send_message(shdl->tx_chan, NULL);
	if (ret < 0) {
		XDNA_DBG(xdna,
			 "shmem doorbell TX IPI failed: hw_ctx_id=%u head=%llu tail=%llu ret=%d",
			 hw_ctx_id, ring->head, ring->tail, ret);
		goto unlock;
	}
	mbox_client_txdone(shdl->tx_chan, 0);
	XDNA_DBG(xdna,
		 "shmem doorbell TX: hw_ctx_id=%u slot=%llu head=%llu tail=%llu (IPI sent)",
		 hw_ctx_id, (ring->head - 1) & ring->ring_mask, ring->head, ring->tail);
	ret = 0;

unlock:
	spin_unlock(&shdl->db_lock);
	return ret;
}

/*
 * Atomically remove an inflight management message that the caller has
 * given up on.  Return values follow the @abort_msg contract in
 * &amdxdna_xcomm_ops:
 *
 *   0       : we won the race, the rx_work will not invoke the callback
 *             for this id (it will hit the !ifm branch instead).
 *   -EAGAIN : rx_work already grabbed the ifm; flush_work() has waited
 *             for the callback to return so the caller's bound state
 *             (typically an on-stack &xdna_notify) is no longer
 *             referenced and may be freed.  The completion bound to the
 *             callback has already fired.
 */
static int amdxdna_shmem_abort_msg(void *xcomm_hdl, int msg_id)
{
	struct amdxdna_shmem_hdl *shdl = xcomm_hdl;
	struct shmem_inflight_msg *ifm;

	ifm = xa_erase(&shdl->msg_xa, msg_id);
	if (!ifm) {
		/*
		 * rx_work owns the ifm.  Wait until any in-flight callback
		 * has finished referencing the caller's &xdna_notify before
		 * letting the caller unwind.
		 */
		flush_work(&shdl->rx_work);
		return -EAGAIN;
	}

	kfree(ifm);
	return 0;
}

static void amdxdna_shmem_xcomm_fini(void *xcomm_hdl)
{
	struct amdxdna_shmem_hdl *shdl = xcomm_hdl;
	struct shmem_inflight_msg *ifm;
	unsigned long idx;

	if (shdl->rx_chan)
		mbox_free_channel(shdl->rx_chan);
	if (shdl->tx_chan)
		mbox_free_channel(shdl->tx_chan);

	cancel_work_sync(&shdl->rx_work);

	xa_for_each(&shdl->msg_xa, idx, ifm) {
		xa_erase(&shdl->msg_xa, idx);
		kfree(ifm);
	}
	xa_destroy(&shdl->msg_xa);
}

static void amdxdna_shmem_rings_init(struct amdxdna_shmem_hdl *shdl)
{
	resource_size_t half = shdl->mgmt_shmem_size / 2;
	resource_size_t ring_data;

	/* Split mgmt region: first half is TX, second half is RX */
	shdl->tx_hdr = (struct shmem_ring_hdr *)shdl->mgmt_shmem;
	shdl->tx_ring = shdl->mgmt_shmem + sizeof(struct shmem_ring_hdr);

	shdl->rx_hdr = (struct shmem_ring_hdr *)(shdl->mgmt_shmem + half);
	shdl->rx_ring = shdl->mgmt_shmem + half +
			sizeof(struct shmem_ring_hdr);

	/*
	 * Ring data area is the half minus the header.  Round down to the
	 * largest power-of-2 so the mask has all lower bits set.
	 */
	ring_data = rounddown_pow_of_two(half - sizeof(struct shmem_ring_hdr));
	shdl->tx_hdr->head = 0;
	shdl->tx_hdr->tail = 0;
	shdl->tx_hdr->ring_mask = ring_data - 1;
	shdl->tx_hdr->rsvd = 0;

	shdl->rx_hdr->head = 0;
	shdl->rx_hdr->tail = 0;
	shdl->rx_hdr->ring_mask = ring_data - 1;
	shdl->rx_hdr->rsvd = 0;

	shdl->mgmt_ring_mask = ring_data - 1;
	shdl->rx_tail_cached = 0;

	/* Doorbell ring uses the entire doorbell region (slot-indexed) */
	shdl->db_ring = (struct shmem_db_ring *)shdl->db_shmem;
	ring_data = (shdl->db_shmem_size - offsetof(struct shmem_db_ring, data))
		    / sizeof(u32);
	ring_data = rounddown_pow_of_two(ring_data);
	shdl->db_ring->head = 0;
	shdl->db_ring->tail = 0;
	shdl->db_ring->ring_mask = ring_data - 1;
	shdl->db_ring->rsvd = 0;

	shdl->db_ring_mask = ring_data - 1;
	shdl->db_head_cached = 0;

	xa_init(&shdl->msg_xa);
	spin_lock_init(&shdl->msg_id_lock);
	spin_lock_init(&shdl->tx_lock);
	spin_lock_init(&shdl->db_lock);
	shdl->next_msg_id = 0;

	INIT_WORK(&shdl->rx_work, amdxdna_shmem_rx_work);
}

static const struct amdxdna_xcomm_ops amdxdna_shmem_xcomm_ops = {
	.send_msg	= amdxdna_shmem_send_msg,
	.ring_doorbell	= amdxdna_shmem_ring_doorbell,
	.abort_msg	= amdxdna_shmem_abort_msg,
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
	shdl->mgmt_shmem =
		devm_ioremap_wc(&pdev->dev, res.start, shdl->mgmt_shmem_size);
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
	shdl->db_shmem =
		devm_ioremap_wc(&pdev->dev, res.start, shdl->db_shmem_size);
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
	shdl->tx_cl.knows_txdone = true;
	shdl->tx_cl.tx_done = NULL;

	shdl->rx_cl.dev = dev;
	shdl->rx_cl.rx_callback = amdxdna_shmem_rx_callback;
	shdl->rx_cl.knows_txdone = true;
	shdl->rx_cl.tx_done = NULL;

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

	/*
	 * Transport must be up before dev_info->ops->init(): aie4_hw_start()
	 * issues firmware traffic via ndev->xcomm_ops.  plat_probe() calls
	 * shmem_init, then amdxdna_plat_register_device() -> ops->init().
	 */
	if (ndev->xcomm_ops) {
		dev_err(&pdev->dev, "management transport already initialized\n");
		return -EBUSY;
	}

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

	amdxdna_shmem_rings_init(shdl);

	ndev->xcomm_ops = &amdxdna_shmem_xcomm_ops;
	ndev->xcomm_hdl = shdl;

	dev_info(&pdev->dev, "amdxdna shmem+IPI driver probed\n");
	return 0;
}

void amdxdna_shmem_fini(struct amdxdna_dev *xdna)
{
	struct amdxdna_dev_hdl *ndev = xdna->dev_handle;

	/*
	 * HW teardown (cert_timer, FW suspend, etc.) is done in
	 * amdxdna_plat_unregister_device() via ops->fini/suspend while
	 * xcomm_ops is still valid.  We only release shmem/IPI here.
	 */
	if (ndev->xcomm_ops != &amdxdna_shmem_xcomm_ops)
		return;

	ndev->xcomm_ops->fini(ndev->xcomm_hdl);
	ndev->xcomm_ops = NULL;
	ndev->xcomm_hdl = NULL;
}

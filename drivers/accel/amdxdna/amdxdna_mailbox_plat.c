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
 * The mgmt region is split in half into a TX and an RX SPSC ring; the doorbell
 * region is a single host-producer ring of hw_ctx ids.  The ring layout and the
 * produce/consume helpers are the on-wire ABI shared with the RPU firmware and
 * live in amdxdna_shmem.h.
 */

#include <linux/container_of.h>
#include <linux/device.h>
#include <linux/io.h>
#include <linux/log2.h>
#include <linux/mailbox_client.h>
#include <linux/mutex.h>
#include <linux/of.h>
#include <linux/of_address.h>
#include <linux/platform_device.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/wait.h>
#include <linux/workqueue.h>
#include <linux/xarray.h>

#include "aie4.h"
#include "amdxdna_mailbox.h"
#include "amdxdna_mailbox_plat.h"
#include "amdxdna_shmem.h"
#include "amdxdna_drv.h"

/*
 * Staging buffer for one mgmt response, sized for the kernel stack rather than
 * for the wire: the protocol allows SHMEM_MSG_BODY_SZ, the largest response any
 * opcode returns is 80.  Keep this above that largest response -- a payload
 * that overflows it is refused as -EOVERFLOW and fails the channel, reported as
 * a bad response from the RPU rather than as the local limit it is.
 */
#define SHMEM_MAX_RESP_SIZE		512

/* Max time to wait for the RPU to drain a full doorbell ring. */
#define SHMEM_DB_RING_FULL_TIMEOUT_MS	1000

/* An inflight management command, awaiting its response by message id. */
struct shmem_inflight_msg {
	void			*handle;
	int			(*notify_cb)(void *handle, void __iomem *data,
					     size_t size);
};

struct mailbox {
	struct amdxdna_dev	*xdna;
	struct platform_device	*pdev;

	/* mgmt command/response shmem region */
	void __iomem		*mgmt_base;
	resource_size_t		mgmt_size;
	/* hw_ctx dispatch doorbell shmem region */
	void __iomem		*doorbell_base;
	resource_size_t		doorbell_size;

	/* Mgmt TX ring (host produces), first half of the mgmt region */
	struct shmem_ring_hdr	*tx_hdr;
	void			*tx_ring;
	/* Mgmt RX ring (host consumes), second half of the mgmt region */
	struct shmem_ring_hdr	*rx_hdr;
	void			*rx_ring;
	/* Doorbell ring (host produces), the whole doorbell region */
	struct shmem_db_ring	*db_ring;

	/* Cached masks -- constant after init, avoids a WC read on hot paths */
	u64			mgmt_ring_mask;
	u64			db_ring_mask;

	/*
	 * Cached host-owned indices.  The host is the sole writer of each, so
	 * these mirror shared memory and avoid a WC read on the hot path.
	 * db_head_cached is serialised by db_lock; rx_tail_cached by rx_lock,
	 * and read locklessly by the IPI gating (aligned u64, atomic on
	 * AArch64).
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
	/*
	 * The mgmt and doorbell paths raise the same TX IPI under their own
	 * ring lock, so the send and its manual ack need a lock of their own.
	 */
	spinlock_t		ipi_lock;

	/* Serialises the RX consumer between rx_work and drain_channel */
	struct mutex		rx_lock;

	/* IPI notification channels (payload lives in shared memory). */
	struct mbox_client	tx_cl;
	struct mbox_client	rx_cl;
	struct mbox_chan	*tx_chan;
	struct mbox_chan	*rx_chan;
	struct work_struct	rx_work;

	/*
	 * Cert completions registered through aie4_request_notification(),
	 * keyed by msix_idx.  There is no per-cert interrupt to own on this
	 * transport, so this registry is what makes an unregister safe against
	 * the IPI fan-out: both take the xarray lock, so once
	 * aie4_free_notification() returns, no wakeup can still be referencing
	 * the entry it removed.
	 */
	struct xarray		notify_xa;

	/*
	 * Set before stop_channel() drains rx_work.  The RX channel stays live
	 * until the platform device is released, so without this a late IPI
	 * would queue the work again right after cancel_work_sync() drained it,
	 * or walk cert-completion state the caller has already destroyed.
	 */
	bool			rx_stopped;

	/*
	 * Set when the RX ring yields something that is not a valid message.
	 * An unexpected receive error means the link can no longer be trusted,
	 * so the drain stops where it is and further sends are refused until
	 * the channel is restarted.
	 */
	bool			bad_state;

	/*
	 * Woken on every RX IPI (completion interrupt).  Doorbell producers
	 * wait here for the RPU to drain the doorbell ring when it is full.
	 */
	wait_queue_head_t	db_waitq;

	/*
	 * The single management channel, or NULL when stopped.  Only one mgmt
	 * channel exists on this transport and mgmt sends are serialised under
	 * xdna->dev_lock, so this needs no further locking beyond being cleared
	 * after cancel_work_sync() in stop_channel().
	 */
	struct mailbox_channel	*mgmt_chann;
};

struct mailbox_channel {
	struct mailbox		*mb;

	/* Firmware-initiated (id 0) message sink, installed by aie4_mailbox_init() */
	void			*async_handle;
	xdna_mailbox_async_cb_t	async_cb;
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

/*
 * Carve the two mgmt rings and the doorbell ring out of the mapped regions and
 * publish their masks.  The host owns the layout: it zeroes both index pairs and
 * writes ring_mask, which the RPU reads back when it attaches.
 *
 * Zeroing the indices rather than adopting what is already in the region is what
 * makes a driver reload safe.  The regions are reserved memory that survives
 * rmmod/insmod and an RPU restart, so stale indices would desynchronise the two
 * sides.  The RPU resets the same six indices for the same reason; both starting
 * from 0 is the agreed handshake.  It caches neither index -- head and tail are
 * re-read from the region on every operation -- so it just sees an empty ring.
 *
 * The regions are devm_ioremap_wc() mappings, which amdxdna_shmem.h accesses as
 * plain memory rather than through the IO accessors (see the rationale there),
 * hence the __force casts here.
 */
static void plat_rings_init(struct mailbox *mb)
{
	void *mgmt = (void __force *)mb->mgmt_base;
	resource_size_t half = mb->mgmt_size / 2;
	u64 slots;

	/* Split mgmt region: first half is TX, second half is RX */
	mb->tx_hdr = mgmt;
	mb->tx_ring = mgmt + sizeof(struct shmem_ring_hdr);

	mb->rx_hdr = mgmt + half;
	mb->rx_ring = mgmt + half + sizeof(struct shmem_ring_hdr);

	/*
	 * Ring data area is the half minus the header.  Round down to the
	 * largest power-of-2 so the mask has all lower bits set.
	 */
	slots = rounddown_pow_of_two(half - sizeof(struct shmem_ring_hdr));

	mb->tx_hdr->head = 0;
	mb->tx_hdr->tail = 0;
	mb->tx_hdr->ring_mask = slots - 1;
	mb->tx_hdr->rsvd = 0;

	mb->rx_hdr->head = 0;
	mb->rx_hdr->tail = 0;
	mb->rx_hdr->ring_mask = slots - 1;
	mb->rx_hdr->rsvd = 0;

	mb->mgmt_ring_mask = slots - 1;
	mb->rx_tail_cached = 0;

	/* Doorbell ring uses the entire doorbell region (slot-indexed) */
	mb->db_ring = (void __force *)mb->doorbell_base;
	slots = (mb->doorbell_size - offsetof(struct shmem_db_ring, data)) /
		sizeof(u32);
	slots = rounddown_pow_of_two(slots);

	mb->db_ring->head = 0;
	mb->db_ring->tail = 0;
	mb->db_ring->ring_mask = slots - 1;
	mb->db_ring->rsvd = 0;

	mb->db_ring_mask = slots - 1;
	mb->db_head_cached = 0;

	XDNA_DBG(mb->xdna, "shmem rings: mgmt mask 0x%llx, doorbell mask 0x%llx",
		 mb->mgmt_ring_mask, mb->db_ring_mask);
}

/*
 * Drain every response the RPU has produced into the mgmt RX ring.
 *
 * Runs from the RX workqueue and, on the command timeout path, directly from
 * xdna_mailbox_drain_channel() in the sender's context; rx_lock keeps the single
 * consumer invariant that shmem_mgmt_consume() relies on.
 */
static void plat_mailbox_drain(struct mailbox *mb)
{
	struct shmem_inflight_msg *ifm;
	struct mailbox_channel *chann;
	struct shmem_msg_hdr msg_hdr;
	u8 buf[SHMEM_MAX_RESP_SIZE];
	int payload_size;

	mutex_lock(&mb->rx_lock);

	/*
	 * stop_channel() clears mgmt_chann under this lock before dropping the
	 * inflight table, so NULL here means teardown.  The IPI can still queue
	 * rx_work after cancel_work_sync() returned, having sampled rx_stopped
	 * just before the store landed; that late drain must not run, as the
	 * senders it would complete have already unwound.
	 */
	chann = mb->mgmt_chann;
	if (!chann) {
		mutex_unlock(&mb->rx_lock);
		return;
	}

	while (mb->rx_hdr) {
		payload_size = shmem_mgmt_consume(mb->rx_hdr, mb->rx_ring,
						  mb->mgmt_ring_mask, &msg_hdr,
						  buf, sizeof(buf),
						  &mb->rx_tail_cached);
		if (payload_size < 0) {
			if (payload_size == -EAGAIN)
				break;

			/*
			 * Anything else means the ring no longer holds what the
			 * protocol says it should.  Stop here and fail the
			 * channel rather than guessing where the next record
			 * begins; inflight senders then fail out on timeout.
			 */
			XDNA_ERR(mb->xdna,
				 "Bad mgmt response (%d), id %u opcode 0x%x total %u; channel marked bad",
				 payload_size, msg_hdr.id, msg_hdr.opcode,
				 msg_hdr.total_size);
			WRITE_ONCE(mb->bad_state, true);
			break;
		}

		/*
		 * Id 0 marks an RPU-initiated message (async error/event
		 * note) rather than a response to one of our commands, so it is
		 * routed to the async sink instead of the inflight table.
		 */
		if (!msg_hdr.id) {
			if (chann->async_cb)
				chann->async_cb(chann->async_handle,
						msg_hdr.opcode,
						(void __iomem *)buf,
						payload_size);
			else
				XDNA_WARN(mb->xdna,
					  "Async mgmt message opcode 0x%x with no handler",
					  msg_hdr.opcode);
			continue;
		}

		ifm = xa_erase(&mb->msg_xa, msg_hdr.id);
		if (!ifm) {
			XDNA_DBG(mb->xdna,
				 "Unexpected mgmt response id %u opcode 0x%x",
				 msg_hdr.id, msg_hdr.opcode);
			continue;
		}

		/*
		 * buf is a normal kernel buffer; the __iomem cast only satisfies
		 * the shared callback signature, which is typed for transports
		 * whose responses are read straight out of a device mapping.
		 */
		if (ifm->notify_cb)
			ifm->notify_cb(ifm->handle, (void __iomem *)buf,
				       payload_size);

		kfree(ifm);
	}

	mutex_unlock(&mb->rx_lock);
}

static void plat_mailbox_rx_work(struct work_struct *work)
{
	struct mailbox *mb = container_of(work, struct mailbox, rx_work);

	plat_mailbox_drain(mb);
}

/*
 * Wake every registered cert completion waiter.  The platform has no per-cert
 * MSI-X vector to demultiplex on, so a completion IPI wakes all of them and each
 * waiter re-checks its own condition.
 *
 * Holding the xarray lock across the walk is what keeps a concurrent
 * aie4_free_notification() from freeing a cert_comp while it is being woken:
 * the erase blocks until this walk finishes.
 */
static void plat_mailbox_cert_notify(struct mailbox *mb)
{
	struct cert_comp *cert_comp;
	unsigned long flags;
	unsigned long idx;

	xa_lock_irqsave(&mb->notify_xa, flags);
	xa_for_each(&mb->notify_xa, idx, cert_comp)
		wake_up_all(&cert_comp->waitq);
	xa_unlock_irqrestore(&mb->notify_xa, flags);

	/* The RPU drained the doorbell ring; wake any backpressured producer. */
	wake_up_all(&mb->db_waitq);
}

/*
 * The RPU raised an IPI.  Runs in IRQ context, so only the wakeups happen
 * here and the mgmt ring drain (xarray + kfree) is deferred to a workqueue.
 */
static void plat_mailbox_rx_callback(struct mbox_client *cl, void *data)
{
	struct mailbox *mb = container_of(cl, struct mailbox, rx_cl);
	int ret;

	/*
	 * The RX channel outlives the mgmt channel: it is released with the
	 * platform device, while stop_channel() runs before the caller destroys
	 * the cert-completion state and the work buffer.  Once stopped, nothing
	 * here may touch that state, so only the ack below still runs.
	 */
	if (!READ_ONCE(mb->rx_stopped)) {
		plat_mailbox_cert_notify(mb);

		/*
		 * Only drain when the RPU has actually queued a response.
		 * Pure doorbell-completion IPIs leave the mgmt ring empty, so
		 * scheduling rx_work for them just adds a needless wakeup on
		 * the submit fast path.  SPSC-safe: the RPU publishes head
		 * with a write barrier before raising the IPI, and tail is
		 * host-owned so the cached copy is authoritative.
		 */
		if (mb->rx_hdr) {
			if (mb->rx_hdr->head != mb->rx_tail_cached)
				schedule_work(&mb->rx_work);
		}
	}

	/*
	 * ACK the IPI to re-enable the notification interrupt: the zynqmp-ipi
	 * ISR masks it via SMC STATUS_ENQUIRY with DIRQ_MASK, and sending on the
	 * RX channel issues SMC_IPI_MAILBOX_ACK with EIRQ_MASK to unmask it.
	 *
	 * If the ack could not be sent there is no txdone to signal, and the
	 * notification interrupt stays masked -- worth a (ratelimited) shout,
	 * since the link is effectively dead from here on.
	 */
	ret = mbox_send_message(mb->rx_chan, NULL);
	if (ret < 0)
		XDNA_ERR_RATELIMITED(mb->xdna, "RX IPI ack failed, ret %d", ret);
	else
		mbox_client_txdone(mb->rx_chan, 0);
}

static int plat_mailbox_ipi_init(struct mailbox *mb)
{
	struct device *dev = &mb->pdev->dev;

	mb->tx_cl.dev = dev;
	mb->tx_cl.tx_block = false;
	mb->tx_cl.knows_txdone = true;

	mb->rx_cl.dev = dev;
	mb->rx_cl.rx_callback = plat_mailbox_rx_callback;
	/* The RX channel is only ever used to ACK, from the rx_callback itself. */
	mb->rx_cl.knows_txdone = true;

	mb->tx_chan = mbox_request_channel_byname(&mb->tx_cl, "tx");
	if (IS_ERR(mb->tx_chan)) {
		XDNA_ERR(mb->xdna, "Failed to bind 'tx' mailbox channel, ret %ld",
			 PTR_ERR(mb->tx_chan));
		return PTR_ERR(mb->tx_chan);
	}

	mb->rx_chan = mbox_request_channel_byname(&mb->rx_cl, "rx");
	if (IS_ERR(mb->rx_chan)) {
		int ret = PTR_ERR(mb->rx_chan);

		XDNA_ERR(mb->xdna, "Failed to bind 'rx' mailbox channel, ret %d",
			 ret);
		mbox_free_channel(mb->tx_chan);
		/* Clear both so a later teardown cannot free tx_chan twice. */
		mb->tx_chan = NULL;
		mb->rx_chan = NULL;
		return ret;
	}
	return 0;
}

/* devm teardown for the IPI channels (mb itself is devm-allocated). */
static void plat_mailbox_release(void *data)
{
	struct mailbox *mb = data;
	struct shmem_inflight_msg *ifm;
	unsigned long idx;

	/*
	 * Free the channels first so the mbox framework stops delivering rx
	 * callbacks, then drain any work already scheduled by a callback.
	 */
	if (!IS_ERR_OR_NULL(mb->rx_chan))
		mbox_free_channel(mb->rx_chan);
	if (!IS_ERR_OR_NULL(mb->tx_chan))
		mbox_free_channel(mb->tx_chan);
	cancel_work_sync(&mb->rx_work);

	/* Anything still inflight can no longer be answered. */
	xa_for_each(&mb->msg_xa, idx, ifm) {
		xa_erase(&mb->msg_xa, idx);
		kfree(ifm);
	}
	xa_destroy(&mb->msg_xa);
	xa_destroy(&mb->notify_xa);
	mutex_destroy(&mb->rx_lock);
}

/*
 * Raise the TX IPI to tell the RPU that a ring was written.
 *
 * The mgmt and doorbell paths share one IPI channel but serialise their rings
 * under separate locks, so the send and its manual ack are taken under
 * ipi_lock: the framework is in txdone_ack mode, and interleaved senders would
 * otherwise ack each other's request.  Always called with the caller's ring
 * lock held, which keeps the ring content published before the IPI.
 */
static int plat_ipi_kick(struct mailbox *mb)
{
	unsigned long flags;
	int ret;

	spin_lock_irqsave(&mb->ipi_lock, flags);
	ret = mbox_send_message(mb->tx_chan, NULL);
	if (ret >= 0) {
		mbox_client_txdone(mb->tx_chan, 0);
		ret = 0;
	}
	spin_unlock_irqrestore(&mb->ipi_lock, flags);

	return ret;
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
	xa_init(&mb->msg_xa);
	/* Walked from the IPI callback, so the xarray lock must be irq-safe. */
	xa_init_flags(&mb->notify_xa, XA_FLAGS_LOCK_IRQ);
	spin_lock_init(&mb->msg_id_lock);
	spin_lock_init(&mb->tx_lock);
	spin_lock_init(&mb->db_lock);
	spin_lock_init(&mb->ipi_lock);
	mutex_init(&mb->rx_lock);
	init_waitqueue_head(&mb->db_waitq);
	/* Id 0 is reserved for RPU-initiated messages. */
	mb->next_msg_id = 1;

	ret = plat_map_region(xdna, dev, "mgmt", &mb->mgmt_base, &mb->mgmt_size);
	if (ret)
		return ERR_PTR(ret);

	ret = plat_map_region(xdna, dev, "doorbell",
			      &mb->doorbell_base, &mb->doorbell_size);
	if (ret)
		return ERR_PTR(ret);

	/*
	 * Each region needs room for a whole record past its ring header, not
	 * merely one byte: a region that clears the header by less than that
	 * rounds down to a ring too small to ever carry one, which surfaces as
	 * every send failing -ENOSPC instead of as the bad device tree it is.
	 * For the mgmt halves the record is a message header; undersizing them
	 * also underflows the capacity check in xdnam_mailbox_send_msg(), which
	 * subtracts that header from the ring size in unsigned arithmetic.
	 */
	if (mb->mgmt_size / 2 < sizeof(struct shmem_ring_hdr) + sizeof(struct shmem_msg_hdr) ||
	    mb->doorbell_size < offsetof(struct shmem_db_ring, data) + sizeof(u32)) {
		XDNA_ERR(xdna, "shmem regions too small: mgmt %pa doorbell %pa",
			 &mb->mgmt_size, &mb->doorbell_size);
		return ERR_PTR(-EINVAL);
	}

	/*
	 * Publish the ring layout before the IPI channels exist, so the first
	 * interrupt the RPU can raise already finds initialised indices.
	 */
	plat_rings_init(mb);

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

/*
 * The rings are already mapped and initialised by xdnam_mailbox_create(), and
 * the platform has no per-channel ring registers or MSI-X vector to program, so
 * starting the channel only marks it as the live mgmt endpoint for the RX path.
 * All of @x2i, @i2x, @xdna_mailbox_intr_reg and @mb_irq describe ring-buffer
 * resources that do not exist on this transport and are unused here.
 */
int xdna_mailbox_start_channel(struct mailbox_channel *mb_chann,
			       const struct xdna_mailbox_chann_res *x2i,
			       const struct xdna_mailbox_chann_res *i2x,
			       u32 xdna_mailbox_intr_reg, int mb_irq)
{
	mb_chann->mb->rx_stopped = false;
	mb_chann->mb->bad_state = false;
	mb_chann->mb->mgmt_chann = mb_chann;
	return 0;
}

void xdna_mailbox_set_async_cb(struct mailbox_channel *mailbox_chann,
			       void *async_handle, xdna_mailbox_async_cb_t async_cb)
{
	struct mailbox *mb = mailbox_chann->mb;

	/* Pair with the RX consumer, which reads these under rx_lock. */
	mutex_lock(&mb->rx_lock);
	mailbox_chann->async_handle = async_handle;
	mailbox_chann->async_cb = async_cb;
	mutex_unlock(&mb->rx_lock);
}

void xdna_mailbox_free_channel(struct mailbox_channel *mailbox_chann)
{
	/* The channel is devm-managed; stop_channel() already quiesced it. */
}

/*
 * Quiesce the channel so no completion callback can run once this returns.
 *
 * This is the teardown half of the command-timeout path (aie_destroy_chann()),
 * where the sender's &xdna_notify lives on its stack and must not be touched
 * after it unwinds.  Mgmt sends are serialised under xdna->dev_lock, so at most
 * one command can be inflight; it is dropped without invoking its callback,
 * since its sender has already given up.
 *
 * Clearing mgmt_chann under rx_lock first is what upholds that guarantee: it
 * waits out a drain already in progress and turns away the late rx_work the IPI
 * can still queue after cancel_work_sync() has returned.  Only then is the
 * inflight table ours alone to drop.
 */
void xdna_mailbox_stop_channel(struct mailbox_channel *mailbox_chann)
{
	struct mailbox *mb = mailbox_chann->mb;
	struct shmem_inflight_msg *ifm;
	unsigned long idx;

	mutex_lock(&mb->rx_lock);
	mb->mgmt_chann = NULL;
	mutex_unlock(&mb->rx_lock);

	/* Block new RX work before draining what is already queued. */
	WRITE_ONCE(mb->rx_stopped, true);
	cancel_work_sync(&mb->rx_work);

	xa_for_each(&mb->msg_xa, idx, ifm) {
		XDNA_DBG(mb->xdna, "Dropping inflight mgmt message id %lu", idx);
		xa_erase(&mb->msg_xa, idx);
		kfree(ifm);
	}
}

/*
 * Consume responses the RPU has already produced.  The RPU completes some
 * commands (SUSPEND in particular) by writing the response without raising the
 * completion IPI, so the sender calls this before declaring a command lost.
 */
void xdna_mailbox_drain_channel(struct mailbox_channel *mailbox_chann)
{
	if (!mailbox_chann)
		return;

	plat_mailbox_drain(mailbox_chann->mb);
}

/*
 * Produce a command into the mgmt TX ring and raise the IPI.
 *
 * @tx_timeout is unused: the platform ring has no TX-side completion tracking,
 * and the sender already bounds the round trip with its own RX timeout in
 * xdna_send_msg_wait().
 */
int xdna_mailbox_send_msg(struct mailbox_channel *mailbox_chann,
			  const struct xdna_mailbox_msg *msg, u64 tx_timeout)
{
	struct mailbox *mb = mailbox_chann->mb;
	struct shmem_inflight_msg *ifm;
	struct shmem_msg_hdr hdr;
	unsigned long flags;
	u32 id;
	int ret;

	/*
	 * The payload has to fit the ring and also the 11-bit body-size field
	 * the RPU parses out of sz_ver.
	 */
	if (msg->send_size > mb->mgmt_ring_mask + 1 - sizeof(hdr) ||
	    msg->send_size > SHMEM_MSG_BODY_SZ) {
		XDNA_ERR(mb->xdna, "Mgmt message opcode 0x%x too large: %zu",
			 msg->opcode, msg->send_size);
		return -EINVAL;
	}

	/*
	 * Alignment keeps head, and with it every ring offset, a multiple of
	 * 4, which is what guarantees the 4-byte tombstone store has room
	 * before the ring end; a misaligned payload can leave a 1-3 byte gap
	 * and push that store past it.  The RPU also copies in u32 strides and
	 * rejects an unaligned payload without consuming the record, which
	 * would stall its side of the ring.
	 */
	if (!IS_ALIGNED(msg->send_size, sizeof(u32))) {
		XDNA_ERR(mb->xdna, "Mgmt message opcode 0x%x misaligned: %zu",
			 msg->opcode, msg->send_size);
		return -EINVAL;
	}

	if (READ_ONCE(mb->bad_state)) {
		XDNA_ERR(mb->xdna, "Channel in bad state, opcode 0x%x dropped",
			 msg->opcode);
		return -EPIPE;
	}

	ifm = kzalloc(sizeof(*ifm), GFP_KERNEL);
	if (!ifm)
		return -ENOMEM;

	ifm->handle = msg->handle;
	ifm->notify_cb = msg->notify_cb;

	/* Allocate a non-zero id: 0 is reserved for RPU-initiated messages. */
	spin_lock_irqsave(&mb->msg_id_lock, flags);
	do {
		id = mb->next_msg_id++;
		if (!id)
			id = mb->next_msg_id++;
		ret = xa_insert(&mb->msg_xa, id, ifm, GFP_ATOMIC);
	} while (ret == -EBUSY);
	spin_unlock_irqrestore(&mb->msg_id_lock, flags);

	if (ret) {
		kfree(ifm);
		return ret;
	}

	hdr.total_size = sizeof(hdr) + msg->send_size;
	hdr.sz_ver = FIELD_PREP(SHMEM_MSG_BODY_SZ, msg->send_size) |
		     FIELD_PREP(SHMEM_MSG_PROTO_VER, SHMEM_PROTOCOL_VER);
	hdr.id = id;
	hdr.opcode = msg->opcode;

	spin_lock_irqsave(&mb->tx_lock, flags);

	ret = shmem_mgmt_produce(mb->tx_hdr, mb->tx_ring, mb->mgmt_ring_mask,
				 &hdr, msg->send_data, msg->send_size);
	if (ret) {
		XDNA_ERR(mb->xdna, "Mgmt TX ring full, opcode 0x%x id %u",
			 msg->opcode, id);
		goto unlock;
	}

	ret = plat_ipi_kick(mb);
	if (ret) {
		XDNA_ERR(mb->xdna, "Mgmt TX IPI failed, opcode 0x%x id %u, ret %d",
			 msg->opcode, id, ret);
		goto unlock;
	}

unlock:
	spin_unlock_irqrestore(&mb->tx_lock, flags);

	if (ret) {
		/*
		 * Drop the inflight record either way: the caller gets the
		 * error and its &xdna_notify goes out of scope, so no response
		 * may be routed to it.
		 *
		 * On the ring-full path nothing was written.  On the
		 * IPI-failure path the message is already published and is
		 * deliberately left in the ring: head cannot be rewound,
		 * because the RPU reads it directly and completes some
		 * commands without waiting for the IPI, so it may have
		 * consumed the message already.  A failed IPI means the
		 * doorbell itself is broken, and one leaked ring slot is the
		 * lesser loss.
		 */
		if (xa_erase(&mb->msg_xa, id))
			kfree(ifm);
		return ret;
	}

	XDNA_DBG(mb->xdna, "Mgmt TX opcode 0x%x id %u size %zu",
		 msg->opcode, id, msg->send_size);
	return 0;
}

/*
 * Register a cert completion with the shared completion IPI.
 *
 * There is no per-cert interrupt to request on this transport; what the fan-out
 * needs instead is to know which completions are live, so it never has to reach
 * into aie4 state that may be going away.
 *
 * The _irq accessors are required, not stylistic: the fan-out takes this same
 * lock from hardirq context, so acquiring it here with interrupts enabled would
 * let the IPI deadlock against us on the same CPU.
 */
int amdxdna_mailbox_plat_register_notify(struct mailbox *mb, u32 msix_idx,
					 struct cert_comp *comp)
{
	return xa_err(xa_store_irq(&mb->notify_xa, msix_idx, comp, GFP_KERNEL));
}

/*
 * Drop a cert completion from the fan-out.  Called before the cert_comp is
 * freed; it takes the same lock plat_mailbox_cert_notify() holds, so it cannot
 * return while a wakeup is still in flight on the entry.
 */
void amdxdna_mailbox_plat_unregister_notify(struct mailbox *mb, u32 msix_idx)
{
	xa_erase_irq(&mb->notify_xa, msix_idx);
}

/*
 * Notify the RPU that @hw_ctx_id has work queued, by producing the id into the
 * doorbell ring and raising the IPI.
 */
int amdxdna_mailbox_plat_ring_doorbell(struct mailbox *mb, u32 hw_ctx_id)
{
	struct shmem_db_ring *ring = mb->db_ring;
	unsigned long flags;
	long wret;
	int ret;

	spin_lock_irqsave(&mb->db_lock, flags);

	/*
	 * If the ring is full, wait for the RPU to consume rather than dropping
	 * the doorbell: a dropped kick is unrecoverable here, as the RPU only
	 * re-examines a context when it sees a doorbell for it.  Every RX IPI
	 * means the RPU has run its doorbell ISR, so db_waitq is woken on the
	 * same event that makes room.  db_lock must be released while sleeping.
	 */
	while ((ret = shmem_db_produce(ring, mb->db_ring_mask, hw_ctx_id,
				       &mb->db_head_cached)) == -ENOSPC) {
		spin_unlock_irqrestore(&mb->db_lock, flags);

		XDNA_DBG(mb->xdna,
			 "Doorbell ring full for hw_ctx %u, head %llu tail %llu, waiting",
			 hw_ctx_id, ring->head, ring->tail);

		wret = wait_event_timeout(mb->db_waitq,
					  shmem_db_ring_has_space(ring, mb->db_ring_mask,
								  mb->db_head_cached),
					  msecs_to_jiffies(SHMEM_DB_RING_FULL_TIMEOUT_MS));
		if (!wret) {
			XDNA_ERR(mb->xdna,
				 "Doorbell ring full for hw_ctx %u, head %llu tail %llu, timed out",
				 hw_ctx_id, ring->head, ring->tail);
			return -ETIMEDOUT;
		}

		spin_lock_irqsave(&mb->db_lock, flags);
	}
	/*
	 * The produce above can only have returned 0: the loop consumed the
	 * single error it is able to report.
	 */
	ret = plat_ipi_kick(mb);
	if (ret)
		XDNA_ERR(mb->xdna, "Doorbell IPI failed for hw_ctx %u, ret %d",
			 hw_ctx_id, ret);

	spin_unlock_irqrestore(&mb->db_lock, flags);
	return ret;
}

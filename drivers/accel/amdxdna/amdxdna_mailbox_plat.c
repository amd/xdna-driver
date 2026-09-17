// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2026, Advanced Micro Devices, Inc.
 *
 * Shared-memory + ZynqMP IPI implementation of the amdxdna mailbox interface
 * (amdxdna_mailbox.h) for the platform (device-tree) build.  It is the
 * compile-time-exclusive counterpart of the PCI ringbuf+MSI-X
 * amdxdna_mailbox.c: both define struct mailbox and the same external API, and
 * exactly one is built (see Kbuild).
 *
 * The management command/response channel and the hw_ctx dispatch doorbell live
 * in reserved-memory regions; a pair of IPI mailbox channels carries interrupt
 * notifications only, as the data is always in shared memory.  The mgmt region
 * is split in half into a TX and an RX SPSC ring, the doorbell region is a
 * single host-producer ring of hw_ctx ids, and the ring layout and the
 * produce/consume helpers are the on-wire ABI in amdxdna_plat_ring.h.
 */

#include <linux/align.h>
#include <linux/bitfield.h>
#include <linux/container_of.h>
#include <linux/device.h>
#include <linux/io.h>
#include <linux/iopoll.h>
#include <linux/jiffies.h>
#include <linux/log2.h>
#include <linux/mailbox_client.h>
#include <linux/of.h>
#include <linux/of_address.h>
#include <linux/overflow.h>
#include <linux/platform_device.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/wait.h>
#include <linux/workqueue.h>
#include <linux/xarray.h>

#include "aie4.h"
#include "amdxdna_mailbox.h"
#include "amdxdna_mailbox_plat.h"
#include "amdxdna_plat_ring.h"
#include "amdxdna_drv.h"

/*
 * Staging buffer for one mgmt response payload.  The firmware caps a whole
 * record -- header plus payload -- at 512 bytes, so the largest payload it can
 * send is 512 - sizeof(struct plat_ring_msg_hdr).  Matching that cap here is
 * what keeps -EOVERFLOW unreachable for a conforming peer; do not shrink it
 * without the firmware's limit moving first.
 */
#define PLAT_RING_MAX_RESP_SIZE		512

/* Max time to wait for the firmware to drain a full doorbell ring. */
#define PLAT_RING_DB_FULL_TIMEOUT_MS	1000

/*
 * Bounds on the alive-sentinel wait.  The firmware is already running when the
 * driver probes, so this only absorbs the tail of remoteproc bring-up.
 */
#define PLAT_RING_FW_ALIVE_TIMEOUT_US	2000000
#define PLAT_RING_FW_ALIVE_POLL_US	20000

/* An inflight management command, awaiting its response by message id. */
struct plat_inflight_msg {
	void			*handle;
	int			(*notify_cb)(void *handle, void __iomem *data,
					     size_t size);
};

struct mailbox {
	struct amdxdna_dev	*xdna;
	struct platform_device	*pdev;

	/* mgmt command/response region */
	void __iomem		*mgmt_base;
	resource_size_t		mgmt_size;
	/* hw_ctx dispatch doorbell region */
	void __iomem		*doorbell_base;
	resource_size_t		doorbell_size;

	/* Mgmt TX ring (host produces), first half of the mgmt region */
	struct plat_ring_hdr	*tx_hdr;
	void			*tx_ring;
	/* Mgmt RX ring (host consumes), second half of the mgmt region */
	struct plat_ring_hdr	*rx_hdr;
	void			*rx_ring;
	/* Doorbell ring (host produces), the whole doorbell region */
	struct plat_ring_db	*db_ring;

	/* Cached masks -- constant after init, avoids a WC read on hot paths */
	u64			mgmt_ring_mask;
	u64			db_ring_mask;

	/*
	 * Cached host-owned indices, mirroring shared memory to avoid a WC read
	 * on the hot path.  db_head_cached and tx_head_cached are written under
	 * db_lock and tx_lock; rx_tail_cached is written only by rx_work, the
	 * single RX consumer.  The IPI gating reads rx_tail_cached and the
	 * doorbell full-wait reads db_head_cached outside all of that, hence the
	 * READ_ONCE() at both; neither decides anything alone, each only
	 * triggers a re-test in the proper context.
	 */
	u64			db_head_cached;
	u64			tx_head_cached;
	u64			rx_tail_cached;

	/* Inflight management message tracking, keyed by message id */
	struct xarray		msg_xa;

	/* Produce-path locks (protect ring write + IPI send atomically) */
	spinlock_t		tx_lock; /* protects mgmt TX ring + IPI */
	spinlock_t		db_lock; /* protects doorbell ring + IPI */

	/* IPI notification channels (payload lives in shared memory). */
	struct mbox_client	tx_cl;
	struct mbox_client	rx_cl;
	struct mbox_chan	*tx_chan;
	struct mbox_chan	*rx_chan;
	struct work_struct	rx_work;

	/*
	 * Cert completions registered through aie4_request_notification(), keyed
	 * by msix_idx.  Taken with the xarray lock by both the IPI fan-out and
	 * aie4_free_notification(), which is what makes an unregister safe
	 * against a wakeup in flight.
	 */
	struct xarray		notify_xa;

	/*
	 * Not a ring state -- the ring only has full, empty and non-empty.  It
	 * marks that the *consumer* stopped, and it is not about one response
	 * being bad: a message that fails validation leaves tail where it is,
	 * because there is no way to tell where the next one begins, so nothing
	 * further can ever be read.  Latch it to stop re-logging, and refuse
	 * later sends rather than have each one wait out its full timeout for a
	 * reply that can no longer arrive.
	 *
	 * Same condition and lifecycle as bad_state on the PCI transport, hence
	 * the same name.  That one also masks its MSI-X, which is not open to
	 * us: the RX IPI carries the doorbell and cert wakeups too.
	 */
	bool			bad_state;

	/* Woken on every RX IPI, for producers blocked on a full doorbell ring. */
	wait_queue_head_t	db_waitq;

	/*
	 * The single management channel, and the only gate this transport has:
	 * NULL before start_channel() installs it and again once stop_channel()
	 * or the devm release has cleared it.  The drain turns away on it, and
	 * so does the IPI callback, which keeps a callback racing teardown off
	 * everything but the ack.
	 *
	 * Accessed with READ_ONCE()/WRITE_ONCE(): its async fields are set
	 * before it is published, and no response can exist until a command has
	 * been sent, which is only after start_channel() has returned.
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
 * memory-region-names string.  Device memory, so devm_ioremap_wc().
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
 * Wait for the firmware to announce itself by publishing
 * PLAT_RING_FW_ALIVE_MAGIC into the RX ring's rsvd field.  The firmware
 * initialises the ring indices before it publishes the sentinel, so observing
 * it means the indices the caller adopts next are the peer's own.
 */
static int plat_wait_fw_alive(struct mailbox *mb)
{
	u64 rsvd;
	int ret;

	/* READ_ONCE: the peer writes this field while we poll it. */
	ret = read_poll_timeout(READ_ONCE, rsvd,
				(u32)rsvd == PLAT_RING_FW_ALIVE_MAGIC,
				PLAT_RING_FW_ALIVE_POLL_US,
				PLAT_RING_FW_ALIVE_TIMEOUT_US, false,
				mb->rx_hdr->rsvd);
	if (ret) {
		XDNA_ERR(mb->xdna,
			 "firmware is not up: no alive sentinel (0x%x) in the mgmt RX ring",
			 PLAT_RING_FW_ALIVE_MAGIC);
		return -ENODEV;
	}

	return 0;
}

/*
 * Carve the two mgmt rings and the doorbell ring out of the mapped regions,
 * publish the masks the host owns, and adopt the indices the rings already
 * carry.
 *
 * The regions are reserved memory that survives a driver reload, and the
 * firmware keeps producing across one, so zeroing the indices here would
 * desynchronise a live peer.  Only the RX tail is moved, to drop whatever a
 * previous session left unconsumed; TX and doorbell leftovers cannot be
 * discarded, as the host does not own their tail.
 *
 * The __force casts are because amdxdna_plat_ring.h accesses these
 * devm_ioremap_wc() mappings as plain memory; see the rationale there.
 */
static int plat_rings_init(struct mailbox *mb)
{
	void *mgmt = (void __force *)mb->mgmt_base;
	resource_size_t half = mb->mgmt_size / 2;
	u64 rx_head, tx_tail, db_tail, slots;
	int ret;

	/* Split mgmt region: first half is TX, second half is RX */
	mb->tx_hdr = mgmt;
	mb->tx_ring = mgmt + sizeof(struct plat_ring_hdr);

	mb->rx_hdr = mgmt + half;
	mb->rx_ring = mgmt + half + sizeof(struct plat_ring_hdr);

	/*
	 * Ring data area is the half minus the header.  Round down to the
	 * largest power-of-2 so the mask has all lower bits set.
	 */
	slots = rounddown_pow_of_two(half - sizeof(struct plat_ring_hdr));
	mb->mgmt_ring_mask = slots - 1;

	mb->tx_hdr->ring_mask = mb->mgmt_ring_mask;
	mb->rx_hdr->ring_mask = mb->mgmt_ring_mask;

	/* Doorbell ring uses the entire doorbell region (slot-indexed) */
	mb->db_ring = (void __force *)mb->doorbell_base;
	slots = (mb->doorbell_size - offsetof(struct plat_ring_db, data)) /
		sizeof(u32);
	slots = rounddown_pow_of_two(slots);
	mb->db_ring_mask = slots - 1;

	mb->db_ring->ring_mask = mb->db_ring_mask;

	ret = plat_wait_fw_alive(mb);
	if (ret)
		return ret;

	/* Past the sentinel the peer is live, so adopt its indices as they are. */
	mb->tx_head_cached = mb->tx_hdr->head;
	mb->db_head_cached = mb->db_ring->head;
	tx_tail = mb->tx_hdr->tail;
	db_tail = mb->db_ring->tail;
	rx_head = mb->rx_hdr->head;

	/*
	 * Alignment is the exception, because it decides whether the index can
	 * be used at all: the helpers in amdxdna_plat_ring.h preserve
	 * 4-alignment without establishing it, so this is the one place it can
	 * be.  A misaligned index cannot be repaired under a live peer, so
	 * refuse.  Doorbell indices count slots rather than bytes and are exempt.
	 */
	if (!IS_ALIGNED(mb->tx_head_cached, sizeof(u32)) ||
	    !IS_ALIGNED(rx_head, sizeof(u32))) {
		XDNA_ERR(mb->xdna,
			 "mgmt ring indices are not u32 aligned: tx head %llu, rx head %llu",
			 mb->tx_head_cached, rx_head);
		return -EPROTO;
	}

	/*
	 * Drop anything the firmware produced for a previous session: skipping
	 * the records rather than consuming them keeps a corrupt leftover from
	 * failing the channel before it has carried a single command.
	 */
	dma_mb();
	mb->rx_hdr->tail = rx_head;
	mb->rx_tail_cached = rx_head;

	/* head/tail apart on TX or doorbell is a previous session's leftovers. */
	XDNA_DBG(mb->xdna,
		 "ring indices adopted: mgmt mask 0x%llx tx %llu/%llu rx resumed at %llu, doorbell mask 0x%llx %llu/%llu",
		 mb->mgmt_ring_mask, mb->tx_head_cached, tx_tail, rx_head,
		 mb->db_ring_mask, mb->db_head_cached, db_tail);

	return 0;
}

/*
 * Drain every response the firmware has produced into the mgmt RX ring.
 *
 * rx_work is the only caller, which makes this the single consumer that
 * plat_ring_mgmt_consume() relies on: the workqueue never runs one work item
 * twice concurrently, and the timeout path reaches the drain by queueing that
 * work and waiting for it rather than by running it inline.
 */
static void plat_mailbox_drain(struct mailbox *mb)
{
	struct plat_inflight_msg *ifm;
	struct mailbox_channel *chann;
	struct plat_ring_msg_hdr msg_hdr;
	u8 buf[PLAT_RING_MAX_RESP_SIZE];
	int payload_size;

	/*
	 * NULL means the channel is not live: start_channel() has not installed
	 * it yet, or stop_channel() has cleared it.  The latter is what matters:
	 * the IPI can still queue rx_work after cancel_work_sync() returned, and
	 * that late drain must not complete senders that have already unwound.
	 */
	chann = READ_ONCE(mb->mgmt_chann);
	if (!chann)
		return;

	/*
	 * start_channel() drops the flag, but the tail is rebased one level up
	 * in plat_rings_init(), so in practice only a re-probe clears this.
	 */
	if (READ_ONCE(mb->bad_state))
		return;

	for (;;) {
		payload_size = plat_ring_mgmt_consume(mb->rx_hdr, mb->rx_ring,
						      mb->mgmt_ring_mask, &msg_hdr,
						      buf, sizeof(buf),
						      &mb->rx_tail_cached);
		if (payload_size < 0) {
			if (payload_size == -EAGAIN)
				break;

			/*
			 * -EPROTO means the record length did not validate, so
			 * there is no way to tell where the next record begins;
			 * -EOVERFLOW needs a peer that ignored the protocol's
			 * body-size limit.  Either way fail the channel rather
			 * than guess, and let inflight senders time out.
			 */
			XDNA_ERR(mb->xdna,
				 "Cannot parse mgmt record (%d), id %u opcode 0x%x total %u; channel marked bad",
				 payload_size, msg_hdr.id, msg_hdr.opcode,
				 msg_hdr.total_size);
			WRITE_ONCE(mb->bad_state, true);
			break;
		}

		/*
		 * Id 0 marks a firmware-initiated message, routed to the async
		 * sink instead of the inflight table.  buf is a normal kernel
		 * buffer; the __iomem __force cast only satisfies the shared
		 * callback signature, which is typed for transports that read
		 * responses straight out of a mapping.
		 */
		if (!msg_hdr.id) {
			if (chann->async_cb)
				chann->async_cb(chann->async_handle,
						msg_hdr.opcode,
						(void __iomem __force *)buf,
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

		/* Same __force cast as the async dispatch above, same reason. */
		if (ifm->notify_cb)
			ifm->notify_cb(ifm->handle, (void __iomem __force *)buf,
				       payload_size);

		kfree(ifm);
	}
}

static void plat_mailbox_rx_work(struct work_struct *work)
{
	struct mailbox *mb = container_of(work, struct mailbox, rx_work);

	plat_mailbox_drain(mb);
}

/*
 * Wake every registered cert completion waiter.  The platform has no per-cert
 * MSI-X vector to demultiplex on, so a completion IPI wakes all of them and
 * each waiter re-checks its own condition.  The xarray lock is held across the
 * walk so a concurrent aie4_free_notification() cannot free a cert_comp while
 * it is being woken.
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

	/* The firmware drained the doorbell ring; wake any backpressured producer. */
	wake_up_all(&mb->db_waitq);
}

/*
 * The firmware raised an IPI.  Runs in IRQ context, so only the wakeups happen
 * here and the mgmt ring drain (xarray + kfree) is deferred to a workqueue.
 */
static void plat_mailbox_rx_callback(struct mbox_client *cl, void *data)
{
	struct mailbox *mb = container_of(cl, struct mailbox, rx_cl);
	int ret;

	/*
	 * The RX channel outlives the mgmt channel, so skip the wakeups once it
	 * has gone.  Not what keeps the registry safe -- the xa lock does that
	 * -- but it keeps a callback racing teardown off the xarray and the ring
	 * mapping.  The ack always runs: it is what unmasks the interrupt.
	 */
	if (READ_ONCE(mb->mgmt_chann)) {
		plat_mailbox_cert_notify(mb);

		/*
		 * Pure doorbell-completion IPIs leave the mgmt ring empty, so
		 * only schedule the drain when there is something to drain.
		 */
		if (READ_ONCE(mb->rx_hdr->head) != READ_ONCE(mb->rx_tail_cached))
			schedule_work(&mb->rx_work);
	}

	/*
	 * ACK to re-enable the notification interrupt: the zynqmp-ipi ISR masks
	 * it via SMC STATUS_ENQUIRY with DIRQ_MASK, and sending on the RX
	 * channel issues SMC_IPI_MAILBOX_ACK with EIRQ_MASK to unmask it.  A
	 * failed ack leaves it masked, which kills the link.
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
	mb->rx_cl.tx_block = false;
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
	struct plat_inflight_msg *ifm;
	unsigned long idx;

	/*
	 * Close the gate first: teardown can be reached without stop_channel(),
	 * e.g. a probe unwind, so the channel may still be live here.
	 */
	WRITE_ONCE(mb->mgmt_chann, NULL);

	/*
	 * Free the channels first so no further rx callback is delivered, then
	 * shut the work down.  A callback already running is not waited out --
	 * the controller's shutdown masks the interrupt without synchronising
	 * it, and no client-visible API does -- so it can still reach its
	 * schedule_work() after this point.  Hence disable_work_sync() rather
	 * than cancel_work_sync(): it refuses the later queue as well as
	 * waiting out a run in progress, and devm frees mb as soon as this
	 * returns.  The gate closed above keeps such a callback off everything
	 * but the ack.
	 */
	if (!IS_ERR_OR_NULL(mb->rx_chan))
		mbox_free_channel(mb->rx_chan);
	if (!IS_ERR_OR_NULL(mb->tx_chan))
		mbox_free_channel(mb->tx_chan);
	disable_work_sync(&mb->rx_work);

	/* Anything still inflight can no longer be answered. */
	xa_for_each(&mb->msg_xa, idx, ifm) {
		xa_erase(&mb->msg_xa, idx);
		kfree(ifm);
	}
	xa_destroy(&mb->msg_xa);
	xa_destroy(&mb->notify_xa);
}

/*
 * Raise the TX IPI to tell the firmware that a ring was written.  Always called
 * with the caller's ring lock held, which keeps the ring content published
 * before the IPI.
 *
 * The mgmt and doorbell paths hold different ring locks, so both can be in here
 * at once, but neither needs a lock of its own: the message is NULL, so the
 * framework records no active request for the other to ack, and it already runs
 * the queue accounting and the send under its own per-channel lock.
 */
static int plat_ipi_kick(struct mailbox *mb)
{
	int ret;

	/*
	 * Order the ring index the caller just published against the interrupt
	 * raised below, so the firmware cannot be woken to read an index still
	 * sitting in a write buffer.  Nothing on the way supplies it: the
	 * producer barriers only reach as far as the index, and zynqmp-ipi goes
	 * straight to the SMC.  This is the same dma_wmb() a writel() doorbell
	 * would carry implicitly.
	 */
	dma_wmb();

	ret = mbox_send_message(mb->tx_chan, NULL);
	if (ret >= 0) {
		mbox_client_txdone(mb->tx_chan, 0);
		ret = 0;
	}

	return ret;
}

/*
 * xdnam_mailbox_create - platform (shared memory + IPI) implementation.  Unlike
 * the PCI variant it derives its resources from the device tree, so @res is
 * unused, and the handle, its mappings and the IPI channels are all managed by
 * the platform device rather than the drm device.
 */
struct mailbox *xdnam_mailbox_create(struct drm_device *ddev,
				     const struct xdna_mailbox_res *res)
{
	struct amdxdna_dev *xdna = to_xdna_dev(ddev);
	struct platform_device *pdev = to_platform_device(ddev->dev);
	struct device *dev = &pdev->dev;
	unsigned int mgmt_align = __alignof__(struct plat_ring_hdr);
	unsigned int db_align = __alignof__(struct plat_ring_db);
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
	spin_lock_init(&mb->tx_lock);
	spin_lock_init(&mb->db_lock);
	init_waitqueue_head(&mb->db_waitq);

	ret = plat_map_region(xdna, dev, "mgmt", &mb->mgmt_base, &mb->mgmt_size);
	if (ret)
		return ERR_PTR(ret);

	ret = plat_map_region(xdna, dev, "doorbell",
			      &mb->doorbell_base, &mb->doorbell_size);
	if (ret)
		return ERR_PTR(ret);

	/*
	 * Each region needs room for a whole record past its ring header, not
	 * merely one byte: anything less rounds down to a ring too small to
	 * carry one, and undersizing the mgmt halves also underflows the
	 * unsigned capacity check in xdna_mailbox_send_msg().
	 */
	if (mb->mgmt_size / 2 < sizeof(struct plat_ring_hdr) + sizeof(struct plat_ring_msg_hdr) ||
	    mb->doorbell_size < struct_size_t(struct plat_ring_db, data, 1)) {
		XDNA_ERR(xdna, "mailbox regions too small: mgmt %pa doorbell %pa",
			 &mb->mgmt_size, &mb->doorbell_size);
		return ERR_PTR(-EINVAL);
	}

	/*
	 * The ring headers are __aligned(64), and where they land is
	 * device-tree data.  The mgmt region is split into two equal halves, so
	 * requiring twice the header alignment across the whole region is what
	 * makes the RX header at the midpoint aligned too.
	 */
	if (!IS_ALIGNED((unsigned long)(void __force *)mb->mgmt_base, mgmt_align) ||
	    !IS_ALIGNED((unsigned long)(void __force *)mb->doorbell_base, db_align) ||
	    !IS_ALIGNED(mb->mgmt_size, 2 * mgmt_align)) {
		XDNA_ERR(xdna,
			 "mailbox regions misaligned: mgmt %pa need %u, doorbell %pa need %u",
			 &mb->mgmt_size, 2 * mgmt_align, &mb->doorbell_size, db_align);
		return ERR_PTR(-EINVAL);
	}

	/*
	 * Resolve the ring layout before the IPI channels exist, so the first
	 * interrupt the firmware can raise already finds the indices adopted.
	 */
	ret = plat_rings_init(mb);
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

/*
 * The rings are already mapped and initialised by xdnam_mailbox_create(), and
 * the platform has no per-channel ring registers or MSI-X vector to program, so
 * starting the channel only marks it as the live mgmt endpoint for the RX path.
 * @x2i, @i2x, @xdna_mailbox_intr_reg and @mb_irq all describe ring-buffer
 * resources that do not exist on this transport.
 *
 * The IPI channels are already bound by create(), so a callback and a drain can
 * be running against these fields already.  mgmt_chann is published last, after
 * bad_state and after the caller has installed the async sink; until it is
 * non-NULL both the drain and the IPI callback turn away.
 */
int xdna_mailbox_start_channel(struct mailbox_channel *mb_chann,
			       const struct xdna_mailbox_chann_res *x2i,
			       const struct xdna_mailbox_chann_res *i2x,
			       u32 xdna_mailbox_intr_reg, int mb_irq, u32 n_msg)
{
	struct mailbox *mb = mb_chann->mb;

	WRITE_ONCE(mb->bad_state, false);
	WRITE_ONCE(mb->mgmt_chann, mb_chann);

	return 0;
}

/*
 * Register the sink for firmware-initiated (id 0) messages.  Unlocked: the
 * caller runs this before xdna_mailbox_start_channel(), and the RX drain --
 * the only reader -- returns early while mgmt_chann is NULL.
 */
void xdna_mailbox_set_async_cb(struct mailbox_channel *mailbox_chann,
			       void *async_handle, xdna_mailbox_async_cb_t async_cb)
{
	mailbox_chann->async_handle = async_handle;
	mailbox_chann->async_cb = async_cb;
}

void xdna_mailbox_free_channel(struct mailbox_channel *mailbox_chann)
{
	/* The channel is devm-managed; stop_channel() already quiesced it. */
}

/*
 * Quiesce the channel so no completion callback can run once this returns.
 *
 * This is the teardown half of the command-timeout path, where the sender's
 * &xdna_notify lives on its stack and must not be touched after it unwinds.
 * Clearing mgmt_chann before the cancel is what upholds that: cancel_work_sync()
 * waits out a drain already in progress, and the NULL turns away the late
 * rx_work the IPI can still queue after it has returned.  Anything still
 * inflight is dropped without its callback, its sender having given up.
 */
void xdna_mailbox_stop_channel(struct mailbox_channel *mailbox_chann)
{
	struct mailbox *mb = mailbox_chann->mb;
	struct plat_inflight_msg *ifm;
	unsigned long idx;

	/* Close the gate, then drain whatever is already queued. */
	WRITE_ONCE(mb->mgmt_chann, NULL);
	cancel_work_sync(&mb->rx_work);

	xa_for_each(&mb->msg_xa, idx, ifm) {
		XDNA_DBG(mb->xdna, "Dropping inflight mgmt message id %lu", idx);
		xa_erase(&mb->msg_xa, idx);
		kfree(ifm);
	}
}

/*
 * Consume responses the firmware has already produced.  It completes some
 * commands (SUSPEND in particular) without raising the IPI, so the sender calls
 * this before declaring a command lost.
 *
 * Goes through rx_work rather than draining inline, so that work stays the only
 * consumer of the RX ring.  schedule_work() re-arms it even if it is already
 * running, and flush_work() waits for that run, so the caller observes the ring
 * as of at least this call.
 */
void xdna_mailbox_drain_channel(struct mailbox_channel *mailbox_chann)
{
	struct mailbox *mb;

	if (!mailbox_chann)
		return;

	mb = mailbox_chann->mb;
	schedule_work(&mb->rx_work);
	flush_work(&mb->rx_work);
}

/*
 * Produce a command into the mgmt TX ring and raise the IPI.  @tx_timeout is
 * unused: there is no TX-side completion tracking here, and the sender already
 * bounds the round trip with its own RX timeout.
 */
int xdna_mailbox_send_msg(struct mailbox_channel *mailbox_chann,
			  const struct xdna_mailbox_msg *msg, u64 tx_timeout)
{
	struct mailbox *mb = mailbox_chann->mb;
	struct plat_inflight_msg *ifm;
	struct plat_ring_msg_hdr hdr;
	unsigned long flags;
	u32 id;
	int ret;

	/* Must fit both the ring and the 11-bit body-size field in sz_ver. */
	if (msg->send_size > mb->mgmt_ring_mask + 1 - sizeof(hdr) ||
	    msg->send_size > FIELD_MAX(PLAT_RING_MSG_BODY_SZ)) {
		XDNA_ERR(mb->xdna, "Mgmt message opcode 0x%x too large: %zu",
			 msg->opcode, msg->send_size);
		return -EINVAL;
	}

	/*
	 * Alignment keeps head, and with it every ring offset, a multiple of 4,
	 * which is what guarantees the 4-byte tombstone store has room before
	 * the ring end.  The firmware also copies in u32 strides.
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

	hdr.total_size = sizeof(hdr) + msg->send_size;
	hdr.sz_ver = FIELD_PREP(PLAT_RING_MSG_BODY_SZ, msg->send_size) |
		     FIELD_PREP(PLAT_RING_MSG_PROTO_VER, PLAT_RING_PROTOCOL_VER);
	hdr.opcode = msg->opcode;

	spin_lock_irqsave(&mb->tx_lock, flags);

	/*
	 * Ids come from the TX ring position rather than a counter, because the
	 * firmware outlives the driver: a teardown that skipped SUSPEND can
	 * leave commands it answers after the next probe, and a counter
	 * restarting at 1 would hand their ids straight back out, letting a
	 * stale response complete a new command's waiter.  head is adopted at
	 * probe and only advances, so no two live messages share an id.  The
	 * shift is lossless because head stays 4-aligned; id 0 is reserved for
	 * firmware-initiated messages, hence the +1 and the fixup.
	 */
	id = (u32)((mb->tx_head_cached >> 2) + 1);
	if (!id)
		id = 1;
	hdr.id = id;

	ret = xa_insert(&mb->msg_xa, id, ifm, GFP_ATOMIC);
	if (ret) {
		spin_unlock_irqrestore(&mb->tx_lock, flags);
		XDNA_ERR(mb->xdna, "Mgmt id %u busy, opcode 0x%x, ret %d",
			 id, msg->opcode, ret);
		kfree(ifm);
		return ret;
	}

	ret = plat_ring_mgmt_produce(mb->tx_hdr, mb->tx_ring, mb->mgmt_ring_mask,
				     &hdr, msg->send_data, msg->send_size,
				     &mb->tx_head_cached);
	if (ret) {
		XDNA_ERR(mb->xdna, "Mgmt TX ring full, opcode 0x%x id %u",
			 msg->opcode, id);
		goto unlock;
	}

	ret = plat_ipi_kick(mb);
	if (ret)
		XDNA_ERR(mb->xdna, "Mgmt TX IPI failed, opcode 0x%x id %u, ret %d",
			 msg->opcode, id, ret);

unlock:
	spin_unlock_irqrestore(&mb->tx_lock, flags);

	if (ret) {
		/*
		 * On the IPI-failure path the message is already published and
		 * is left in the ring, because head cannot be rewound once the
		 * firmware may have consumed it.  Losing the race to erase it
		 * means the drain has taken the entry and may be inside the
		 * notify_cb, which writes into the caller's on-stack
		 * xdna_notify, so wait that run out before unwinding.
		 */
		if (xa_erase(&mb->msg_xa, id))
			kfree(ifm);
		else
			flush_work(&mb->rx_work);
		return ret;
	}

	XDNA_DBG(mb->xdna, "Mgmt TX opcode 0x%x id %u size %zu",
		 msg->opcode, id, msg->send_size);
	return 0;
}

/*
 * Register a cert completion with the shared completion IPI.  There is no
 * per-cert interrupt to request here; the fan-out just needs to know which
 * completions are live.
 *
 * The _irq accessors are required, not stylistic: the fan-out takes this same
 * lock from hardirq, so acquiring it with interrupts enabled would let the IPI
 * deadlock against us on the same CPU.
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
 * Notify the firmware that @hw_ctx_id has work queued, by producing the id into
 * the doorbell ring and raising the IPI.
 */
int amdxdna_mailbox_plat_ring_doorbell(struct mailbox *mb, u32 hw_ctx_id)
{
	struct plat_ring_db *ring = mb->db_ring;
	unsigned long flags;
	long wret;
	int ret;

	spin_lock_irqsave(&mb->db_lock, flags);

	/*
	 * If the ring is full, wait rather than drop: the firmware only
	 * re-examines a context when it sees a doorbell for it, so a dropped
	 * kick is unrecoverable.  db_waitq is woken by every RX IPI, which is
	 * the same event that makes room.
	 */
	while ((ret = plat_ring_db_produce(ring, mb->db_ring_mask, hw_ctx_id,
					   &mb->db_head_cached)) == -ENOSPC) {
		spin_unlock_irqrestore(&mb->db_lock, flags);

		XDNA_DBG(mb->xdna,
			 "Doorbell ring full for hw_ctx %u, head %llu tail %llu, waiting",
			 hw_ctx_id, mb->db_head_cached, ring->tail);

		wret = wait_event_timeout(mb->db_waitq,
					  plat_ring_db_has_space(ring, mb->db_ring_mask,
								 READ_ONCE(mb->db_head_cached)),
					  msecs_to_jiffies(PLAT_RING_DB_FULL_TIMEOUT_MS));
		if (!wret) {
			XDNA_ERR(mb->xdna,
				 "Doorbell ring full for hw_ctx %u, head %llu tail %llu, timed out",
				 hw_ctx_id, mb->db_head_cached, ring->tail);
			return -ETIMEDOUT;
		}

		spin_lock_irqsave(&mb->db_lock, flags);
	}
	/* The produce above can only be 0; the loop consumed its one error. */
	ret = plat_ipi_kick(mb);
	if (ret)
		XDNA_ERR(mb->xdna, "Doorbell IPI failed for hw_ctx %u, ret %d",
			 hw_ctx_id, ret);

	spin_unlock_irqrestore(&mb->db_lock, flags);
	return ret;
}

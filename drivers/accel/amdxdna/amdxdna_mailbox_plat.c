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
 * in reserved-memory regions; a pair of IPI mailbox channels (tx/rx) carry
 * interrupt notifications only -- the IPI has no payload, the data is always in
 * shared memory.
 *
 * The mgmt region is split in half into a TX and an RX SPSC ring; the doorbell
 * region is a single host-producer ring of hw_ctx ids.  The ring layout and the
 * produce/consume helpers are the on-wire ABI shared with the firmware and
 * live in amdxdna_plat_ring.h.
 */

#include <linux/align.h>
#include <linux/bitfield.h>
#include <linux/container_of.h>
#include <linux/delay.h>
#include <linux/device.h>
#include <linux/io.h>
#include <linux/jiffies.h>
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
#include "amdxdna_plat_ring.h"
#include "amdxdna_drv.h"

/*
 * Staging buffer for one mgmt response, sized for the kernel stack rather than
 * for the wire: the protocol allows PLAT_RING_MSG_BODY_SZ, the largest response
 * any opcode returns is 80.  Keep this above that largest response -- a payload
 * that overflows it is refused as -EOVERFLOW and fails the channel, reported as
 * a bad response from the firmware rather than as the local limit it is.
 */
#define PLAT_RING_MAX_RESP_SIZE		512

/* Max time to wait for the firmware to drain a full doorbell ring. */
#define PLAT_RING_DB_FULL_TIMEOUT_MS	1000

/*
 * Bounds on the alive-sentinel wait at probe.  The firmware is already running
 * by the time the driver probes, so this only absorbs the asynchronous tail of
 * remoteproc bring-up; it is not a budget for booting the firmware.
 */
#define PLAT_RING_FW_ALIVE_TIMEOUT_MS	2000
#define PLAT_RING_FW_ALIVE_POLL_MS	20

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
	 * Cached host-owned indices.  The host is the sole writer of each, so
	 * these mirror shared memory and avoid a WC read on the hot path.
	 * Once running, writes are serialised by db_lock, tx_lock and rx_lock
	 * respectively.  plat_rings_init() seeds all three unlocked, which is
	 * safe because it runs before the IPI channels are bound.
	 *
	 * Two readers take no lock -- the IPI gating reads rx_tail_cached, and
	 * the doorbell full-wait reads db_head_cached -- which is safe because
	 * they are aligned u64 (single-copy atomic on AArch64) and neither
	 * decides anything on its own: the gating only chooses whether to
	 * schedule a drain that re-reads under rx_lock, and a stale head can
	 * only understate occupancy, so the wait errs towards a spurious wakeup
	 * that re-tests under db_lock.  Both spell that out with READ_ONCE(),
	 * which is what marks a read deliberately taken outside the lock that
	 * serialises its writer.
	 */
	u64			db_head_cached;
	u64			tx_head_cached;
	u64			rx_tail_cached;

	/* Inflight management message tracking */
	struct xarray		msg_xa;
	/*
	 * Ids are derived from the TX ring position rather than counted, so
	 * there is no allocator state here and nothing to serialise beyond
	 * tx_lock, which already covers the head the id comes from.
	 */

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
	 * wait here for the firmware to drain the doorbell ring when it is full.
	 */
	wait_queue_head_t	db_waitq;

	/*
	 * The single management channel: NULL before start_channel() installs
	 * it and again once stop_channel() has cleared it.  All three sites use
	 * rx_lock -- the RX consumer to read it, both channel calls to publish
	 * it -- which is what lets teardown wait out a drain already running;
	 * see the ordering rule at stop_channel() before touching any of them.
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
 * Wait for the firmware to announce itself by publishing
 * PLAT_RING_FW_ALIVE_MAGIC into the RX ring's rsvd field; see that define for
 * what the sentinel means and why nothing else can stand in for it.
 *
 * The firmware is brought up before this driver probes, so the first read is
 * expected to succeed; the wait only covers the asynchronous tail of
 * remoteproc bring-up and is not a supported "load before firmware" mode.
 *
 * The sentinel guards the ring indices the caller adopts next, exactly as a
 * published head guards the ring behind it, so the same read-read rule applies:
 * branching on it is a control dependency, which the CPU may predict, leaving
 * the index loads observed ahead of the sentinel and pre-init values adopted.
 * The dma_rmb() below is what forbids that, and it sits here rather than at the
 * call site so it binds to the observation itself.
 */
static int plat_wait_fw_alive(struct mailbox *mb)
{
	unsigned long timeout = jiffies + msecs_to_jiffies(PLAT_RING_FW_ALIVE_TIMEOUT_MS);

	for (;;) {
		/* READ_ONCE: the peer writes this field while we spin on it. */
		if ((u32)READ_ONCE(mb->rx_hdr->rsvd) == PLAT_RING_FW_ALIVE_MAGIC) {
			dma_rmb();
			return 0;
		}

		if (time_after(jiffies, timeout))
			break;

		msleep(PLAT_RING_FW_ALIVE_POLL_MS);
	}

	XDNA_ERR(mb->xdna,
		 "firmware is not up: no alive sentinel (0x%x) in the mgmt RX ring",
		 PLAT_RING_FW_ALIVE_MAGIC);

	return -ENODEV;
}

/*
 * Carve the two mgmt rings and the doorbell ring out of the mapped regions,
 * publish the masks the host owns, and adopt the indices the rings already
 * carry.
 *
 * The regions are reserved memory that survives both rmmod/insmod and a firmware
 * restart, and the firmware boots first and keeps producing across a driver
 * reload. Zeroing the indices here would therefore desynchronise a live peer,
 * which is what makes re-probe impossible; adopting them is what makes it work.
 *   The host still publishes ring_mask on all three rings, because that field is
 * host-owned by protocol and the firmware only ever reads it back.
 *
 * Only the RX tail is moved, to drop whatever a previous session left
 * unconsumed.  Leftovers in the TX and doorbell rings cannot be discarded: the
 * host does not own their tail, and the firmware polls both without needing an
 * IPI, so a dead session's commands may still execute.  Their responses are not
 * misdelivered though: ids come from the adopted head, which only advances, so a
 * new session does not hand back the ids an old one used and the inflight lookup
 * in plat_mailbox_drain() has nothing to match.  See xdna_mailbox_send_msg()
 * for the single wrap that qualifies this.  A leftover therefore costs a ring
 * slot and a debug line, and nothing else.
 *
 * The regions are devm_ioremap_wc() mappings, which amdxdna_plat_ring.h accesses
 * as plain memory rather than through the IO accessors (see the rationale
 * there), hence the __force casts here.
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

	/*
	 * Past the sentinel the peer is live, so its indices are the protocol's
	 * truth and their values are adopted as they stand.  Second-guessing
	 * how far apart they are would be host-side scaffolding around a
	 * firmware defect: we own both ends of this protocol, so a
	 * desynchronised ring is fixed on the firmware side.
	 */
	mb->tx_head_cached = mb->tx_hdr->head;
	mb->db_head_cached = mb->db_ring->head;
	tx_tail = mb->tx_hdr->tail;
	db_tail = mb->db_ring->tail;
	rx_head = mb->rx_hdr->head;

	/*
	 * Alignment is the exception, because it is not a question of where the
	 * peer has got to but of whether the index can be used at all: the mgmt
	 * indices are byte offsets that every ring access derives from, and the
	 * helpers in amdxdna_plat_ring.h preserve 4-alignment without
	 * establishing it, so this is the one place it can be.  A misaligned
	 * index cannot be repaired without moving it out from under a live peer,
	 * so refuse.
	 *
	 * The doorbell indices are exempt: they count slots, not bytes, and
	 * head & ring_mask indexes data[] in bounds whatever its alignment.
	 */
	if (!IS_ALIGNED(mb->tx_head_cached, sizeof(u32)) ||
	    !IS_ALIGNED(rx_head, sizeof(u32))) {
		XDNA_ERR(mb->xdna,
			 "mgmt ring indices are not u32 aligned: tx head %llu, rx head %llu",
			 mb->tx_head_cached, rx_head);
		return -EPROTO;
	}

	/*
	 * Drop anything the firmware produced for a previous session.  tail is
	 * the consumer's own index, so this is ours to move; skipping the
	 * records rather than consuming them keeps a corrupt leftover from
	 * failing the channel before it has carried a single command.  dma_mb()
	 * orders the head load against the tail store, as for any consumer
	 * publish.
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
 * Runs from the RX workqueue and, on the command timeout path, directly from
 * xdna_mailbox_drain_channel() in the sender's context; rx_lock keeps the single
 * consumer invariant that plat_ring_mgmt_consume() relies on.
 */
static void plat_mailbox_drain(struct mailbox *mb)
{
	struct plat_inflight_msg *ifm;
	struct mailbox_channel *chann;
	struct plat_ring_msg_hdr msg_hdr;
	u8 buf[PLAT_RING_MAX_RESP_SIZE];
	int payload_size;

	mutex_lock(&mb->rx_lock);

	/*
	 * NULL means the channel is not live: either start_channel() has not
	 * installed it yet -- the IPI channels are bound in create(), so a
	 * callback can arrive before that -- or stop_channel() has cleared it
	 * under this lock before dropping the inflight table.  The teardown
	 * case is the one that matters: the IPI can still queue rx_work after
	 * cancel_work_sync() returned, having sampled rx_stopped just before
	 * the store landed, and that late drain must not run because the
	 * senders it would complete have already unwound.
	 */
	chann = mb->mgmt_chann;
	if (!chann) {
		mutex_unlock(&mb->rx_lock);
		return;
	}

	/*
	 * Both failure paths below stop without advancing tail, by design, so
	 * the head/tail mismatch that tripped them is permanent: every later
	 * IPI would re-enter here, re-read the same bad record and re-log it.
	 * Only a re-probe clears it.  start_channel() drops the flag, but the
	 * tail that still points at the bad record is rebased one level up, in
	 * plat_rings_init(), so restarting the channel alone would just walk
	 * back into it.
	 */
	if (READ_ONCE(mb->bad_state)) {
		mutex_unlock(&mb->rx_lock);
		return;
	}

	for (;;) {
		payload_size = plat_ring_mgmt_consume(mb->rx_hdr, mb->rx_ring,
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
		 * Id 0 marks a firmware-initiated message (async error/event
		 * note) rather than a response to one of our commands, so it is
		 * routed to the async sink instead of the inflight table.
		 *
		 * buf is a normal kernel buffer; the __iomem cast only satisfies
		 * the shared callback signature, which is typed for transports
		 * whose responses are read straight out of a device mapping.
		 * It is annotated __force for the same reason: the address
		 * space it names is one this transport never enters.
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
	 * The RX channel outlives the mgmt channel: it is released with the
	 * platform device, while stop_channel() runs before the caller destroys
	 * the cert-completion state and the work buffer.  Once stopped, nothing
	 * here may touch that state, so only the ack below still runs.
	 */
	if (!READ_ONCE(mb->rx_stopped)) {
		plat_mailbox_cert_notify(mb);

		/*
		 * Only drain when the firmware has actually queued a response.
		 * Pure doorbell-completion IPIs leave the mgmt ring empty, so
		 * scheduling rx_work for them just adds a needless wakeup on
		 * the submit fast path.  SPSC-safe: the firmware publishes head
		 * with a write barrier before raising the IPI, and tail is
		 * host-owned so the cached copy is authoritative.
		 */
		if (READ_ONCE(mb->rx_hdr->head) != READ_ONCE(mb->rx_tail_cached))
			schedule_work(&mb->rx_work);
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
	 * Teardown can be reached without stop_channel() having run -- a
	 * probe-failure unwind gets here with the rings live -- so set this
	 * here rather than relying on that path to have set it.
	 */
	WRITE_ONCE(mb->rx_stopped, true);

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
 * Raise the TX IPI to tell the firmware that a ring was written.
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

	/*
	 * Order the ring index the caller just published against the interrupt
	 * raised below, so the firmware cannot be woken to read an index still
	 * sitting in a write buffer.  The producer barriers in
	 * amdxdna_plat_ring.h only reach as far as that index; past it the kick
	 * leaves normal non-cacheable memory for a device register written by
	 * EL3, and the two are not ordered against each other by the SMC.
	 * Nothing on the way there supplies it either: the mailbox framework
	 * takes the channel lock, whose acquire says nothing about stores
	 * already issued, and zynqmp-ipi goes straight to the SMC with no
	 * barrier of its own.  This is the same dma_wmb() a writel() doorbell
	 * would carry implicitly.
	 */
	dma_wmb();

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
 * xdnam_mailbox_create - platform (shared memory + IPI) implementation.  Unlike
 * the PCI variant it derives its resources from the device tree (reserved-memory
 * + IPI mboxes) rather than @res, which is unused here.  The mgmt/doorbell
 * memory is statically reserved in the device node, so the handle, its region
 * mappings and the IPI channels are all managed by the platform device, not the
 * drm device.
 */
struct mailbox *xdnam_mailbox_create(struct drm_device *ddev,
				     const struct xdna_mailbox_res *res)
{
	struct amdxdna_dev *xdna = to_xdna_dev(ddev);
	struct platform_device *pdev = to_platform_device(ddev->dev);
	struct device *dev = &pdev->dev;
	unsigned int align = __alignof__(struct plat_ring_hdr);
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
	spin_lock_init(&mb->ipi_lock);
	mutex_init(&mb->rx_lock);
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
	 * merely one byte: a region that clears the header by less than that
	 * rounds down to a ring too small to ever carry one, which surfaces as
	 * every send failing -ENOSPC instead of as the bad device tree it is.
	 * For the mgmt halves the record is a message header; undersizing them
	 * also underflows the capacity check in xdna_mailbox_send_msg(), which
	 * subtracts that header from the ring size in unsigned arithmetic.
	 */
	if (mb->mgmt_size / 2 < sizeof(struct plat_ring_hdr) + sizeof(struct plat_ring_msg_hdr) ||
	    mb->doorbell_size < offsetof(struct plat_ring_db, data) + sizeof(u32)) {
		XDNA_ERR(xdna, "mailbox regions too small: mgmt %pa doorbell %pa",
			 &mb->mgmt_size, &mb->doorbell_size);
		return ERR_PTR(-EINVAL);
	}

	/*
	 * The ring headers are __aligned(64) so that head and tail sit on
	 * separate cache lines and each index is a single-copy-atomic u64
	 * against the firmware.  Both properties come from where the region
	 * lands, which is device-tree data: the mgmt RX header sits at half the
	 * region, so an odd size would misalign it and silently cost both.
	 */
	static_assert(__alignof__(struct plat_ring_db) == __alignof__(struct plat_ring_hdr));
	if (!IS_ALIGNED((unsigned long)(void __force *)mb->mgmt_base, align) ||
	    !IS_ALIGNED((unsigned long)(void __force *)mb->doorbell_base, align) ||
	    !IS_ALIGNED(mb->mgmt_size / 2, align)) {
		XDNA_ERR(xdna,
			 "mailbox regions need %u-byte alignment: mgmt size %pa, doorbell size %pa",
			 align, &mb->mgmt_size, &mb->doorbell_size);
		return ERR_PTR(-EINVAL);
	}

	/*
	 * Resolve the ring layout before the IPI channels exist, so the first
	 * interrupt the firmware can raise already finds the indices adopted and
	 * the RX ring rebased past any leftovers.
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
 * All of @x2i, @i2x, @xdna_mailbox_intr_reg and @mb_irq describe ring-buffer
 * resources that do not exist on this transport and are unused here.
 *
 * Unlike PCI -- where this is where the interrupt is requested -- the IPI
 * channels are already bound by create(), so a callback and a drain can be
 * running against these fields before the first store lands.  Publishing
 * therefore mirrors stop_channel(): mgmt_chann under rx_lock, which is the lock
 * the drain reads it under, and the two flags with WRITE_ONCE(), for the IPI
 * callback that reads them without taking it.
 */
int xdna_mailbox_start_channel(struct mailbox_channel *mb_chann,
			       const struct xdna_mailbox_chann_res *x2i,
			       const struct xdna_mailbox_chann_res *i2x,
			       u32 xdna_mailbox_intr_reg, int mb_irq)
{
	struct mailbox *mb = mb_chann->mb;

	mutex_lock(&mb->rx_lock);
	WRITE_ONCE(mb->rx_stopped, false);
	WRITE_ONCE(mb->bad_state, false);
	mb->mgmt_chann = mb_chann;
	mutex_unlock(&mb->rx_lock);

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
	struct plat_inflight_msg *ifm;
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
 * Consume responses the firmware has already produced.  The firmware completes
 * some commands (SUSPEND in particular) by writing the response without raising
 * the completion IPI, so the sender calls this before declaring a command lost.
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
	struct plat_inflight_msg *ifm;
	struct plat_ring_msg_hdr hdr;
	unsigned long flags;
	u32 id;
	int ret;

	/*
	 * The payload has to fit the ring and also the 11-bit body-size field
	 * the firmware parses out of sz_ver.
	 */
	if (msg->send_size > mb->mgmt_ring_mask + 1 - sizeof(hdr) ||
	    msg->send_size > FIELD_MAX(PLAT_RING_MSG_BODY_SZ)) {
		XDNA_ERR(mb->xdna, "Mgmt message opcode 0x%x too large: %zu",
			 msg->opcode, msg->send_size);
		return -EINVAL;
	}

	/*
	 * Alignment keeps head, and with it every ring offset, a multiple of 4,
	 * which is what guarantees the 4-byte tombstone store has room before
	 * the ring end; a misaligned payload can leave a 1-3 byte gap and push
	 * that store past it.  The firmware also copies in u32 strides and
	 * rejects an unaligned payload without consuming the record, which would
	 * stall its side of the ring.
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
	 * Derive the id from the ring position this message takes rather than
	 * from a counter, because the firmware outlives the driver: a teardown
	 * that skipped SUSPEND can leave commands it answers after the next
	 * probe, and a counter restarting at 1 would hand their ids straight
	 * back out, letting a stale response complete a new command's waiter.
	 *
	 * head is adopted at probe and only advances, so every id a previous
	 * session used lies below it and no two messages share one.  The only
	 * thing that rewinds head is firmware re-init, which zeroes head and
	 * tail together, so whenever the id space restarts the ring is already
	 * empty.  u32 truncation repeats an id only after 16GB of traffic, by
	 * which point the command that used it is long consumed.
	 *
	 * The shift is lossless because head stays 4-aligned.  Id 0 is reserved
	 * for firmware-initiated messages, so it has to be skipped rather than
	 * merely be unlikely: the +1 covers the head of 0 a fresh ring starts
	 * from, and the fixup covers the one head the truncation lands back on.
	 * That is the only id a wrap issues twice, and xa_insert() refuses it
	 * if the first is somehow still outstanding.
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
		 * Drop the inflight record either way: the caller gets the
		 * error and its &xdna_notify goes out of scope, so no response
		 * may be routed to it.
		 *
		 * On the ring-full path nothing was written.  On the
		 * IPI-failure path the message is already published and is
		 * deliberately left in the ring: head cannot be rewound,
		 * because the firmware reads it directly and completes some
		 * commands without waiting for the IPI, so it may have
		 * consumed the message already.  A failed IPI means the
		 * doorbell itself is broken, and one leaked ring slot is the
		 * lesser loss.
		 *
		 * That same "may have consumed it already" is why the erase
		 * needs rx_lock.  The firmware can answer a published record
		 * while this path is still in the failing kick, and the drain
		 * holds rx_lock across the notify_cb it would then run -- a
		 * callback that writes into the caller's on-stack xdna_notify.
		 * Erasing unlocked lets this return, and that stack go out of
		 * scope, while the callback is still writing to it.  Under the
		 * lock the two are exclusive: either the drain never finds the
		 * record, or it is done with it before the caller is told the
		 * send failed.
		 */
		mutex_lock(&mb->rx_lock);
		if (xa_erase(&mb->msg_xa, id))
			kfree(ifm);
		mutex_unlock(&mb->rx_lock);
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
	 * If the ring is full, wait for the firmware to consume rather than
	 * dropping the doorbell: a dropped kick is unrecoverable here, as the
	 * firmware only re-examines a context when it sees a doorbell for it.
	 * Every RX IPI means the firmware has run its doorbell ISR, so db_waitq
	 * is woken on the same event that makes room.  db_lock must be released
	 * while sleeping.
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

/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2026, Advanced Micro Devices, Inc.
 *
 * Shared-memory ring layout and SPSC helpers for the amdxdna platform
 * mailbox transport.
 *
 * These definitions are an on-wire ABI: the fw implements the peer side of
 * the same rings in its own shmem_ring.h, so a change here is a change on
 * both sides of the boundary.
 *
 * Shared memory is mapped via devm_ioremap_wc() (Normal Non-Cacheable
 * on ARM64) and accessed as plain memory: header and payload copies use
 * plain memcpy (kernel-optimized LDP/STP), not the memcpy_toio/fromio IO
 * accessors which carry Device-MMIO semantics we do not need here.
 * Single u64 index updates use plain stores with natural 8-byte
 * alignment guaranteeing atomicity on AArch64.  Barriers order data
 * against index updates across the non-coherent boundary, and which one
 * to use follows from the pair being ordered: a producer publishing its
 * index after writing data needs store-store, so dma_wmb(); a consumer
 * reading the peer's index before the ring it guards needs read-read, so
 * dma_rmb(); and ordering a load before a later store -- a consumer
 * publishing a tail it has finished reading behind, or a producer
 * overwriting space the peer's tail just released -- needs dma_mb(),
 * because dma_rmb() is specified as read-read only whatever a given
 * architecture happens to implement.  Both sides are little-endian, so
 * no byte-swap is needed.
 *
 * Host-owned indices are cached driver-side (the host is the sole
 * writer): both producers cache their head and the mgmt-RX consumer
 * caches its tail, so the hot paths never pay a WC read for an index
 * they already know.  Firmware-owned indices are always read fresh.  The
 * helpers take ring_mask as an argument for the same reason: it is
 * constant after init, so the caller passes its cached copy rather
 * than reading the field back.
 *
 * The mgmt indices are byte offsets into the ring data area and must be
 * 4-aligned.  The helpers below preserve that -- a record is a 16-byte
 * header plus a u32-multiple payload, and a wrap gap is 4-aligned too --
 * but they do not establish it, so the driver validates the indices it
 * adopts at probe.  Alignment is what keeps the 4-byte wrap tombstone
 * from straddling the end of the data area, in either direction: the
 * producer stores it and the consumer loads it before it has bounded
 * anything.  The doorbell ring is slot-indexed and needs no such rule.
 */

#ifndef _AMDXDNA_PLAT_RING_H_
#define _AMDXDNA_PLAT_RING_H_

#include <asm/barrier.h>
#include <linux/align.h>
#include <linux/bitfield.h>
#include <linux/build_bug.h>
#include <linux/compiler.h>
#include <linux/string.h>
#include <linux/types.h>

/*
 * HSA-aligned ring control header for the SPSC transport.
 *
 * head and tail are 64-bit, naturally 8-byte aligned, and placed on
 * separate 64-byte cache lines to eliminate false sharing between
 * producer and consumer cores.
 *
 * This struct is the on-wire ABI shared between the host (Linux) and the
 * firmware (Zephyr).  Both sides must use the same layout.  Sits at the start
 * of each TX/RX; followed by (ring_mask + 1) bytes of ring data.
 *
 * Field ownership across the two sides:
 *
 *   head       producer-owned.
 *   tail       consumer-owned.
 *   ring_mask  host-owned on every ring.  The host publishes it at probe
 *              and the firmware only ever reads it back.
 *   rsvd       never written by the host.  On the RX ring it carries the
 *              firmware's liveness sentinel, see PLAT_RING_FW_ALIVE_MAGIC; on
 *              the others it is reserved for the peer to define.
 */
struct plat_ring_hdr {
	u64 head;			/* offset  0: producer index           */
	u64 ring_mask;			/* offset  8: (ring_data_size - 1)     */
	u64 rsvd;			/* offset 16: reserved / FW alive magic */
	u8  _pad0[40];			/* offset 24: pad to cache line boundary */
	/* --- 64-byte cache line boundary --- */
	u64 tail;			/* offset 64: consumer index           */
	u8  _pad1[56];			/* offset 72: pad to 128-byte total    */
} __aligned(64);

static_assert(offsetof(struct plat_ring_hdr, tail) == 64);
static_assert(sizeof(struct plat_ring_hdr) == 128);

/*
 * Liveness sentinel the firmware writes into rsvd of the ring it produces into
 * -- the host's RX ring.  It is set once the firmware has initialised its npu
 * clients and re-asserted on every IPI, so reading it is how the host tells
 * "the firmware is up" from "the ring is merely empty": zeroed indices are also
 * what a correctly initialised idle ring looks like.
 *
 * The host must therefore never write rsvd.  Clearing it as a reserved
 * field is what forced the firmware to re-assert the sentinel on every IPI
 * rather than write it once at init.
 */
#define PLAT_RING_FW_ALIVE_MAGIC	0x52505546	/* "RPUF" */

/*
 * Per-message header inside the management ring data area.
 * Followed by payload of total_size - sizeof(plat_ring_msg_hdr) bytes.
 *
 * Wire format must match npu_mbox_msg_header (FW) and xdna_msg_header
 * exactly so npu_msg_process() can consume ring data directly without
 * adaptation.
 *
 * One semantic difference: total_size counts the header plus the payload, where
 * the identically-placed size field in the PCI transport's xdna_msg_header
 * counts the payload alone.
 */
#define PLAT_RING_MSG_BODY_SZ	GENMASK(10, 0)
#define PLAT_RING_MSG_PROTO_VER	GENMASK(23, 16)
#define PLAT_RING_PROTOCOL_VER	0x1

struct plat_ring_msg_hdr {
	u32 total_size;
	u32 sz_ver;
	u32 id;
	u32 opcode;
};

/*
 * Tombstone sentinel for ring wrap.  Written at the current offset when a
 * message does not fit before the ring-end boundary; consumer skips past it.
 *
 * The first u32 of every real message is total_size, which the protocol bounds
 * to a header plus PLAT_RING_MSG_BODY_SZ, so it can never collide with
 * 0xDEADFACE.
 */
#define PLAT_RING_TOMBSTONE	0xDEADFACE

/*
 * HSA-aligned doorbell ring for hw_ctx dispatch notification.
 *
 * Same cache-line-separated index layout as plat_ring_hdr.
 * The flexible data[] array (u32 hw_ctx_id slots) begins at offset 128.
 * Linux produces; firmware consumes.
 */
struct plat_ring_db {
	u64 head;			/* offset  0: producer index       */
	u64 ring_mask;			/* offset  8: (num_slots - 1)      */
	u64 rsvd;			/* offset 16: reserved             */
	u8  _pad0[40];			/* offset 24: pad to cache line    */
	/* --- 64-byte cache line boundary --- */
	u64 tail;			/* offset 64: consumer index       */
	u8  _pad1[56];			/* offset 72: pad to 128 bytes     */
	/* --- data starts at offset 128 --- */
	u32 data[];
} __aligned(64);

static_assert(offsetof(struct plat_ring_db, tail) == 64);
static_assert(offsetof(struct plat_ring_db, data) == 128);

/*
 * The host is the only producer (advances head under db_lock); the firmware
 * advances tail as it consumes doorbells.  There is room when fewer than
 * ring_mask + 1 entries are outstanding.
 *
 * Takes the cached head so this agrees with plat_ring_db_produce(): a WC
 * read-back of the host-owned index can lag and report space the producer does
 * not see.
 */
static inline bool plat_ring_db_has_space(struct plat_ring_db *ring,
					  u64 ring_mask, u64 head)
{
	return (head - ring->tail) <= ring_mask;
}

/*
 * Management ring -- produce (host writes to TX ring).
 *
 * head comes from the caller's cache, tail is read fresh (see the caching
 * rule at the top).  @payload_size is the caller's to bound: it is summed
 * into a u32 here, and xdna_mailbox_send_msg() caps it against both the ring
 * size and the body-size field before calling.
 *
 * tail is the peer's to write, and a peer that runs it past head can defeat
 * the capacity test below.  Doing so corrupts the stream, not memory: every
 * store lands at a masked offset with the ring-end case split off, so the
 * writes stay inside the data area whatever tail says.
 *
 * Returns 0 on success, -ENOSPC if the ring is full.
 */
static inline int plat_ring_mgmt_produce(struct plat_ring_hdr *hdr,
					 void *ring_base, u64 ring_mask,
					 const struct plat_ring_msg_hdr *msg_hdr,
					 const void *payload,
					 size_t payload_size,
					 u64 *head_cached)
{
	u64 size = ring_mask + 1;
	u64 head = *head_cached;
	u64 tail = hdr->tail;
	u32 total = sizeof(*msg_hdr) + payload_size;
	u64 off, gap;

	if (head - tail + total > size)
		return -ENOSPC;

	/* Order the tail load against the ring stores that reuse the space. */
	dma_mb();

	off = head & ring_mask;

	/*
	 * Not enough room before the ring end: tombstone the gap and restart
	 * from offset 0.  off is 4-aligned and below size, so at least a u32
	 * remains and the sentinel always fits before the end.
	 *
	 * Writing it before a recheck that can still fail is safe: head is not
	 * published on the -ENOSPC path, and the firmware reads only below the
	 * published head.  The next produce rewrites the same sentinel here, or
	 * overwrites it with a real header if the message fits the gap.
	 */
	if (off + total > size) {
		gap = size - off;
		*(u32 *)(ring_base + off) = PLAT_RING_TOMBSTONE;
		head += gap;

		if (head - tail + total > size)
			return -ENOSPC;
		off = head & ring_mask;
	}

	memcpy(ring_base + off, msg_hdr, sizeof(*msg_hdr));
	if (payload_size)
		memcpy(ring_base + off + sizeof(*msg_hdr),
		       payload, payload_size);

	dma_wmb();

	head += total;
	hdr->head = head;
	*head_cached = head;

	return 0;
}

/*
 * Management ring -- consume (host reads from RX ring).
 *
 * tail comes from the caller's cache, head is read fresh (see the caching
 * rule at the top).
 *
 * Returns payload size on success, -EAGAIN if the ring is empty, -EPROTO if
 * the record fails validation, and -EOVERFLOW if the payload exceeds
 * payload_max.  The caller treats anything but -EAGAIN as fatal to the link.
 */
static inline int plat_ring_mgmt_consume(struct plat_ring_hdr *hdr,
					 void *ring_base, u64 ring_mask,
					 struct plat_ring_msg_hdr *msg_hdr,
					 void *payload, size_t payload_max,
					 u64 *tail_cached)
{
	u64 size = ring_mask + 1;
	u64 head, tail;
	u64 off, avail;
	u32 payload_size;

	head = hdr->head;
	dma_rmb();
	tail = *tail_cached;

	if (head == tail)
		return -EAGAIN;

	/*
	 * head - tail is the occupancy the firmware published, and it bounds
	 * the record below.  A firmware restart under a live driver rewinds
	 * head while our cached tail stays put, which underflows that
	 * subtraction and leaves total_size bounded only by the ring end --
	 * loose enough to dispatch leftover ring bytes as a response.  Reject
	 * the desync here so the caller marks the channel bad instead.
	 */
	if (head - tail > size) {
		/* The caller logs these fields on error; they were never read. */
		memset(msg_hdr, 0, sizeof(*msg_hdr));
		return -EPROTO;
	}

	off = tail & ring_mask;

	/*
	 * Skip a wrap tombstone and re-read at offset 0.  This load precedes
	 * the bounds checks below, so it relies on tail being 4-aligned to stay
	 * inside the data area (see the alignment rule at the top).
	 *
	 * It needs no barrier of its own: the record it lands on was published
	 * by the same head loaded above, and the dma_rmb() there orders that
	 * load against every ring read below it, not merely the next one.
	 */
	if (*(u32 *)(ring_base + off) == PLAT_RING_TOMBSTONE) {
		tail += size - off;
		if (tail == head) {
			dma_mb();
			hdr->tail = tail;
			*tail_cached = tail;
			return -EAGAIN;
		}
		/*
		 * A gap the producer really wrote never reaches past head: it
		 * advances head over the gap before publishing.  One that does
		 * underflows the same occupancy the checks below rest on, so
		 * re-apply the bound now that tail has moved.
		 */
		if (head - tail > size) {
			memset(msg_hdr, 0, sizeof(*msg_hdr));
			return -EPROTO;
		}
		off = tail & ring_mask;
	}

	/*
	 * The record is firmware-supplied, so bound it before trusting it.
	 * avail is the room before the ring end: a header must fit there to be
	 * read at all, and total_size must then be at least a header, u32
	 * aligned for the strided copy the firmware does, and within both avail
	 * and what the firmware published (head - tail).
	 *
	 * tail is left alone on rejection: the caller marks the channel bad
	 * rather than resynchronising, so the ring is preserved for inspection.
	 */
	avail = size - off;
	if (avail < sizeof(*msg_hdr)) {
		/* The caller logs these fields on error; they were never read. */
		memset(msg_hdr, 0, sizeof(*msg_hdr));
		return -EPROTO;
	}

	memcpy(msg_hdr, ring_base + off, sizeof(*msg_hdr));

	if (msg_hdr->total_size < sizeof(*msg_hdr) ||
	    !IS_ALIGNED(msg_hdr->total_size, sizeof(u32)) ||
	    msg_hdr->total_size > head - tail ||
	    msg_hdr->total_size > avail)
		return -EPROTO;

	payload_size = msg_hdr->total_size - sizeof(*msg_hdr);
	if (payload_size > payload_max)
		return -EOVERFLOW;

	if (payload_size)
		memcpy(payload, ring_base + off + sizeof(*msg_hdr),
		       payload_size);

	dma_mb();

	tail += msg_hdr->total_size;
	hdr->tail = tail;
	*tail_cached = tail;

	return payload_size;
}

/*
 * Doorbell ring -- produce (host writes hw_ctx_id).
 *
 * head comes from the caller's cache, tail is read fresh (see the caching
 * rule at the top).  tail is the peer's to write and the space test is
 * unsigned, so a peer that runs it past head wraps the subtraction to a huge
 * value.  That reads as a full ring and returns -ENOSPC, which is the safe
 * direction to fail in; plat_ring_db_has_space() wraps the same way, so the
 * caller waits rather than overwriting a slot the peer still owns.
 *
 * Returns 0 on success, -ENOSPC if ring is full.
 */
static inline int plat_ring_db_produce(struct plat_ring_db *ring,
				       u64 ring_mask, u32 hw_ctx_id,
				       u64 *head_cached)
{
	u64 size = ring_mask + 1;
	u64 head = *head_cached;
	u64 tail = ring->tail;

	if (head - tail >= size)
		return -ENOSPC;

	/* Order the tail load against the slot store that reuses the space. */
	dma_mb();

	ring->data[head & ring_mask] = hw_ctx_id;

	dma_wmb();

	head++;
	ring->head = head;
	*head_cached = head;

	return 0;
}

#endif /* _AMDXDNA_PLAT_RING_H_ */

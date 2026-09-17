/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2026, Advanced Micro Devices, Inc.
 *
 * Shared-memory ring layout and SPSC helpers for the amdxdna platform mailbox
 * transport.  These definitions are an on-wire ABI: the firmware implements the
 * peer side of the same rings, so a change here is a change on both sides.
 *
 * The rings live in memory mapped with devm_ioremap_wc() (Normal Non-Cacheable
 * on arm64) and are accessed as plain memory: plain memcpy rather than the
 * memcpy_toio/fromio accessors, which carry Device-MMIO semantics we do not
 * need.  Index updates are single naturally-aligned u64 stores.  Both sides are
 * little-endian.
 *
 * Barriers order ring data against index updates across the non-coherent
 * boundary.  A producer publishing its index after writing data needs
 * dma_wmb(); a consumer reading the peer's index before the ring it guards
 * needs dma_rmb(); ordering a load before a later store -- publishing a tail
 * read behind, or overwriting space the peer's tail just released -- needs
 * dma_mb(), as dma_rmb() is specified read-read only.
 *
 * Host-owned indices are cached driver-side so the hot paths never pay a WC
 * read for an index the host itself wrote; firmware-owned indices are read
 * fresh.  ring_mask is passed in for the same reason: it is constant post-init.
 *
 * Mgmt ring indices are byte offsets into the data area and must be 4-aligned,
 * which the driver validates at probe.  That is what keeps the 4-byte wrap
 * tombstone from straddling the end of the data area.  The doorbell ring is
 * slot-indexed and needs no such rule.
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
 * Ring control header, on-wire ABI shared with the firmware.  Sits at the start
 * of each ring, followed by (ring_mask + 1) bytes of ring data.  head and tail
 * are on separate cache lines to avoid false sharing between producer and
 * consumer.
 *
 * head is producer-owned and tail consumer-owned.  ring_mask is host-owned on
 * every ring; the firmware only reads it back.  rsvd is never written by the
 * host: on the RX ring it carries the firmware's liveness sentinel, see
 * PLAT_RING_FW_ALIVE_MAGIC, and elsewhere it is the peer's to define.
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
 * Liveness sentinel the firmware writes into rsvd of the host's RX ring once it
 * has initialised its npu clients.  Zeroed indices are also what a correctly
 * initialised idle ring looks like, so this is how the host tells "firmware is
 * up" from "ring is merely empty".  The host must never write rsvd; the
 * firmware re-asserts the sentinel on every IPI.
 */
#define PLAT_RING_FW_ALIVE_MAGIC	0x52505546	/* "RPUF" */

/*
 * Per-message header inside the management ring data area, followed by
 * total_size - sizeof(plat_ring_msg_hdr) payload bytes.  The layout must match
 * the firmware's header exactly so it can consume ring data without adaptation.
 *
 * Note total_size counts header plus payload, where the identically-placed size
 * field in the PCI transport's xdna_msg_header counts the payload alone.
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
 * Written at the current offset when a message does not fit before the ring
 * end; the consumer skips past it.  The first u32 of a real message is
 * total_size, which the protocol bounds to a header plus PLAT_RING_MSG_BODY_SZ,
 * so the two cannot collide.
 */
#define PLAT_RING_TOMBSTONE	0xDEADFACE

/*
 * Doorbell ring for hw_ctx dispatch notification.  Same cache-line-separated
 * index layout as plat_ring_hdr; the u32 hw_ctx_id slots begin at offset 128.
 * Linux produces, firmware consumes.
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
 * There is room when fewer than ring_mask + 1 entries are outstanding.  Takes
 * the cached head so this agrees with plat_ring_db_produce(): a WC read-back of
 * a host-owned index can lag and report space the producer does not see.
 */
static inline bool plat_ring_db_has_space(struct plat_ring_db *ring,
					  u64 ring_mask, u64 head)
{
	return (head - ring->tail) <= ring_mask;
}

/*
 * Management ring -- produce (host writes to TX ring).
 *
 * @payload_size is the caller's to bound: it is summed into a u32 here, and
 * xdna_mailbox_send_msg() caps it against both the ring size and the body-size
 * field before calling.  A peer that runs tail past head can defeat the
 * capacity test, which corrupts the stream but not memory: every store lands at
 * a masked offset with the ring-end case split off.
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
	 * from offset 0.  off is 4-aligned and below size, so the sentinel
	 * always fits.  Writing it before a recheck that can still fail is
	 * safe: head is not published on the -ENOSPC path, and the firmware
	 * reads only below the published head.
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
 * Returns payload size on success, -EAGAIN if the ring is empty, -EPROTO if the
 * record fails validation, and -EOVERFLOW if the payload exceeds payload_max.
 * The caller treats anything but -EAGAIN as fatal to the link.
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
	 * head - tail is the occupancy the firmware published and it bounds the
	 * record below.  A firmware restart under a live driver rewinds head
	 * while our cached tail stays put, underflowing that subtraction and
	 * leaving total_size bounded only by the ring end -- loose enough to
	 * dispatch leftover ring bytes as a response.  Reject the desync.
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
	 * inside the data area.  No barrier of its own: the dma_rmb() above
	 * orders the head load against every ring read below it.
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
		 * A gap the producer really wrote never reaches past head.  One
		 * that does underflows the occupancy the checks below rest on,
		 * so re-apply the bound now that tail has moved.
		 */
		if (head - tail > size) {
			memset(msg_hdr, 0, sizeof(*msg_hdr));
			return -EPROTO;
		}
		off = tail & ring_mask;
	}

	/*
	 * The record is firmware-supplied, so bound it before trusting it.
	 * avail is the room before the ring end.  tail is left alone on
	 * rejection: the caller marks the channel bad rather than
	 * resynchronising, so the ring is preserved for inspection.
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
 * tail is the peer's to write and the space test is unsigned, so a peer that
 * runs it past head wraps the subtraction to a huge value.  That reads as a
 * full ring and returns -ENOSPC, which is the safe direction to fail in;
 * plat_ring_db_has_space() wraps the same way, so the caller waits rather than
 * overwriting a slot the peer still owns.
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

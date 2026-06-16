/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2026, Advanced Micro Devices, Inc.
 *
 * Shared-memory ring layout and SPSC helpers for the amdxdna shmem+IPI
 * transport.
 *
 * Shared memory is mapped via devm_ioremap_wc() (Normal Non-Cacheable
 * on ARM64) and accessed as plain memory: header and payload copies use
 * plain memcpy (kernel-optimized LDP/STP), not the memcpy_toio/fromio IO
 * accessors which carry Device-MMIO semantics we do not need here.
 * Single u64 index updates use plain stores with natural 8-byte
 * alignment guaranteeing atomicity on AArch64.  dma_wmb()/dma_rmb()
 * order data vs. index updates across the non-coherent boundary.  Both
 * sides are little-endian, so no byte-swap is needed.
 *
 * Host-owned indices are cached driver-side (the host is the sole
 * writer): the doorbell producer caches its head and the mgmt-RX
 * consumer caches its tail, so the hot paths never pay a WC read for an
 * index they already know.  The remote-owned index is always read fresh.
 */

#ifndef _AMDXDNA_SHMEM_H_
#define _AMDXDNA_SHMEM_H_

#include <asm/barrier.h>
#include <linux/bitfield.h>
#include <linux/build_bug.h>
#include <linux/compiler.h>
#include <linux/io.h>
#include <linux/platform_device.h>
#include <linux/string.h>
#include <linux/types.h>

struct amdxdna_dev;

int amdxdna_shmem_init(struct amdxdna_dev *xdna, struct platform_device *pdev);
void amdxdna_shmem_fini(struct amdxdna_dev *xdna);

/*
 * HSA-aligned ring control header for shmem SPSC transport.
 *
 * head and tail are 64-bit, naturally 8-byte aligned, and placed on
 * separate 64-byte cache lines to eliminate false sharing between
 * producer and consumer cores.
 *
 * This struct is the on-wire ABI shared between APU (Linux) and RPU
 * (Zephyr).  Both sides must use the same layout.  Sits at the start of
 * each TX/RX; followed by (ring_mask + 1) bytes of ring data.
 */
struct shmem_ring_hdr {
	u64 head;			/* offset  0: producer index           */
	u64 ring_mask;			/* offset  8: (ring_data_size - 1)     */
	u64 rsvd;			/* offset 16: reserved / FW alive magic */
	u8  _pad0[40];			/* offset 24: pad to cache line boundary */
	/* --- 64-byte cache line boundary --- */
	u64 tail;			/* offset 64: consumer index           */
	u8  _pad1[56];			/* offset 72: pad to 128-byte total    */
} __aligned(64);

static_assert(offsetof(struct shmem_ring_hdr, tail) == 64);
static_assert(sizeof(struct shmem_ring_hdr) == 128);

/*
 * Per-message header inside the management ring data area.
 * Followed by payload of total_size - sizeof(shmem_msg_hdr) bytes.
 *
 * Wire format must match npu_mbox_msg_header (FW) and xdna_msg_header
 * (PCI mailbox) exactly so npu_msg_process() can consume ring data
 * directly without adaptation.
 */
#define SHMEM_MSG_BODY_SZ	GENMASK(10, 0)
#define SHMEM_MSG_PROTO_VER	GENMASK(23, 16)
#define SHMEM_PROTOCOL_VER	0x1

struct shmem_msg_hdr {
	u32 total_size;
	u32 sz_ver;
	u32 id;
	u32 opcode;
};

/*
 * Tombstone sentinel for ring wrap.  Written at the current offset when a
 * message does not fit before the ring-end boundary; consumer skips past it.
 *
 * The first u32 of every real message is total_size (sizeof(shmem_msg_hdr) +
 * payload), which is at most ~100 bytes for current opcodes and can never
 * collide with 0xDEADFACE.
 */
#define SHMEM_TOMBSTONE	0xDEADFACE

/*
 * HSA-aligned doorbell ring for hw_ctx dispatch notification.
 *
 * Same cache-line-separated index layout as shmem_ring_hdr.
 * The flexible data[] array (u32 hw_ctx_id slots) begins at offset 128.
 * Linux produces; RPU firmware consumes.
 */
struct shmem_db_ring {
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

static_assert(offsetof(struct shmem_db_ring, tail) == 64);
static_assert(offsetof(struct shmem_db_ring, data) == 128);

/*
 * Management ring -- produce (host writes to TX ring).
 *
 * Caller passes the cached ring_mask (constant after init) to avoid a
 * WC read on every call.  head and tail are read fresh from shared
 * memory each time (stateless indices).
 *
 * Returns 0 on success, -ENOSPC if ring is full.
 */
static inline int shmem_mgmt_produce(struct shmem_ring_hdr *hdr,
					      void *ring_base, u64 ring_mask,
					      const struct shmem_msg_hdr *msg_hdr,
					      const void *payload,
					      size_t payload_size)
{
	u64 size = ring_mask + 1;
	u64 head = hdr->head;
	u64 tail = hdr->tail;
	u32 total = sizeof(*msg_hdr) + payload_size;
	u64 off, gap;

	if (head - tail + total > size)
		return -ENOSPC;

	off = head & ring_mask;

	if (off + total > size) {
		gap = size - off;
		*(u32 *)(ring_base + off) = SHMEM_TOMBSTONE;
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

	return 0;
}

/*
 * Management ring -- consume (host reads from RX ring).
 *
 * Caller passes the cached ring_mask (constant after init) and a pointer
 * to the cached tail.  The host owns tail (sole consumer), so it is read
 * from the cache and only ever written to shared memory -- never read
 * back from WC.  head is owned by the RPU and read fresh each call.
 *
 * Returns payload size on success, -EAGAIN if ring is empty, -EOVERFLOW
 * if the message payload exceeds payload_max.
 */
static inline int shmem_mgmt_consume(struct shmem_ring_hdr *hdr,
					      void *ring_base, u64 ring_mask,
					      struct shmem_msg_hdr *msg_hdr,
					      void *payload, size_t payload_max,
					      u64 *tail_cached)
{
	u64 size = ring_mask + 1;
	u64 head, tail;
	u64 off;
	u32 payload_size;

	dma_rmb();
	head = hdr->head;
	tail = *tail_cached;

	if (head == tail)
		return -EAGAIN;

	off = tail & ring_mask;

	if (*(u32 *)(ring_base + off) == SHMEM_TOMBSTONE) {
		tail += size - off;
		if (tail == head) {
			hdr->tail = tail;
			*tail_cached = tail;
			dma_wmb();
			return -EAGAIN;
		}
		off = tail & ring_mask;
		dma_rmb();
	}

	memcpy(msg_hdr, ring_base + off, sizeof(*msg_hdr));

	payload_size = msg_hdr->total_size - sizeof(*msg_hdr);
	if (payload_size > payload_max)
		return -EOVERFLOW;

	if (payload_size)
		memcpy(payload, ring_base + off + sizeof(*msg_hdr),
		       payload_size);

	dma_wmb();

	tail += msg_hdr->total_size;
	hdr->tail = tail;
	*tail_cached = tail;

	return payload_size;
}

/*
 * Doorbell ring -- produce (host writes hw_ctx_id).
 *
 * Caller passes the cached ring_mask (constant after init) and a pointer
 * to the cached head.  The host owns head (sole producer), so it is read
 * from the cache and only ever written to shared memory -- never read
 * back from WC.  tail is owned by the RPU and read fresh to check space.
 *
 * Returns 0 on success, -ENOSPC if ring is full.
 */
static inline int shmem_db_produce(struct shmem_db_ring *ring,
					    u64 ring_mask, u32 hw_ctx_id,
					    u64 *head_cached)
{
	u64 size = ring_mask + 1;
	u64 head = *head_cached;
	u64 tail = ring->tail;

	if (head - tail >= size)
		return -ENOSPC;

	ring->data[head & ring_mask] = hw_ctx_id;

	dma_wmb();

	head++;
	ring->head = head;
	*head_cached = head;

	return 0;
}

#endif /* _AMDXDNA_SHMEM_H_ */

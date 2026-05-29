/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2026, Advanced Micro Devices, Inc.
 *
 * Shared-memory ring layout and SPSC helpers for the amdxdna shmem+IPI
 * transport.
 *
 * Shared memory is mapped via devm_ioremap_wc() (Normal Non-Cacheable
 * on ARM64).  Bulk data copies use memcpy_toio/memcpy_fromio (the
 * kernel-sanctioned accessors for IO-mapped memory); single u64 index
 * updates use plain stores with natural 8-byte alignment guaranteeing
 * atomicity on AArch64.  dma_wmb()/dma_rmb() order data vs. index
 * updates across the non-coherent boundary.
 * Both sides are little-endian, so no byte-swap is needed.
 */

#ifndef _AMDXDNA_SHMEM_H_
#define _AMDXDNA_SHMEM_H_

#include <asm/barrier.h>
#include <linux/bitfield.h>
#include <linux/build_bug.h>
#include <linux/compiler.h>
#include <linux/io.h>
#include <linux/platform_device.h>
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
 * Stateless: head and tail are read fresh from shared memory on every
 * call.  No caller-side cached indices required.
 *
 * Returns 0 on success, -ENOSPC if ring is full.
 */
static inline int shmem_mgmt_produce(struct shmem_ring_hdr *hdr,
				     void *ring_base,
				     const struct shmem_msg_hdr *msg_hdr,
				     const void *payload, size_t payload_size)
{
	u64 mask = hdr->ring_mask;
	u64 size = mask + 1;
	u64 head = hdr->head;
	u64 tail = hdr->tail;
	u32 total = sizeof(*msg_hdr) + payload_size;
	u64 off, gap;

	if (head - tail + total > size)
		return -ENOSPC;

	off = head & mask;

	if (off + total > size) {
		gap = size - off;
		*(u32 *)(ring_base + off) = SHMEM_TOMBSTONE;
		head += gap;

		if (head - tail + total > size)
			return -ENOSPC;
		off = head & mask;
	}

	memcpy_toio(ring_base + off, msg_hdr, sizeof(*msg_hdr));
	if (payload_size)
		memcpy_toio(ring_base + off + sizeof(*msg_hdr),
			    payload, payload_size);

	dma_wmb();

	head += total;
	hdr->head = head;

	return 0;
}

/*
 * Management ring -- consume (host reads from RX ring).
 *
 * Stateless: head and tail are read fresh from shared memory on every
 * call.  No caller-side cached indices required.
 *
 * Returns payload size on success, -EAGAIN if ring is empty, -EOVERFLOW
 * if the message payload exceeds payload_max.
 */
static inline int shmem_mgmt_consume(struct shmem_ring_hdr *hdr,
				     void *ring_base,
				     struct shmem_msg_hdr *msg_hdr,
				     void *payload, size_t payload_max)
{
	u64 mask = hdr->ring_mask;
	u64 size = mask + 1;
	u64 head, tail;
	u64 off;
	u32 payload_size;

	dma_rmb();
	head = hdr->head;
	tail = hdr->tail;

	if (head == tail)
		return -EAGAIN;

	off = tail & mask;

	if (*(u32 *)(ring_base + off) == SHMEM_TOMBSTONE) {
		tail += size - off;
		if (tail == head) {
			hdr->tail = tail;
			dma_wmb();
			return -EAGAIN;
		}
		off = tail & mask;
		dma_rmb();
	}

	memcpy_fromio(msg_hdr, ring_base + off, sizeof(*msg_hdr));

	payload_size = msg_hdr->total_size - sizeof(*msg_hdr);
	if (payload_size > payload_max)
		return -EOVERFLOW;

	if (payload_size)
		memcpy_fromio(payload, ring_base + off + sizeof(*msg_hdr),
			      payload_size);

	dma_wmb();

	tail += msg_hdr->total_size;
	hdr->tail = tail;

	return payload_size;
}

/*
 * Doorbell ring -- produce (host writes hw_ctx_id).
 *
 * Stateless: head and tail are read fresh from shared memory on every
 * call.  No caller-side cached indices required.
 *
 * Returns 0 on success, -ENOSPC if ring is full.
 */
static inline int shmem_db_produce(struct shmem_db_ring *ring, u32 hw_ctx_id)
{
	u64 mask = ring->ring_mask;
	u64 size = mask + 1;
	u64 head = ring->head;
	u64 tail = ring->tail;

	if (head - tail >= size)
		return -ENOSPC;

	ring->data[head & mask] = hw_ctx_id;

	dma_wmb();

	head++;
	ring->head = head;

	return 0;
}

#endif /* _AMDXDNA_SHMEM_H_ */

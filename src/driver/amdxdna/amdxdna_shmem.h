/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2026, Advanced Micro Devices, Inc.
 *
 * Shared-memory ring layout and SPSC helpers for the amdxdna shmem+IPI
 * transport.
 *
 * Shared memory is mapped via devm_ioremap_wc() (Normal Non-Cacheable
 * on ARM64).  Bulk data copies use memcpy_toio/memcpy_fromio (the
 * kernel-sanctioned accessors for IO-mapped memory); single u32 index
 * updates use plain stores.  dma_wmb()/dma_rmb() order data vs. index
 * updates across the non-coherent boundary.
 * Both sides are little-endian, so no byte-swap is needed.
 */

#ifndef _AMDXDNA_SHMEM_H_
#define _AMDXDNA_SHMEM_H_

#include <asm/barrier.h>
#include <linux/compiler.h>
#include <linux/io.h>
#include <linux/platform_device.h>
#include <linux/types.h>

struct amdxdna_dev;

int amdxdna_shmem_init(struct amdxdna_dev *xdna, struct platform_device *pdev);
void amdxdna_shmem_fini(struct amdxdna_dev *xdna);
/*
 * Management ring header -- sits at the start of each TX/RX ring region.
 * Followed by ring_mask+1 bytes of ring data.
 */
struct shmem_ring_hdr {
	u32 head;
	u32 tail;
	u32 ring_mask;
	u32 rsvd;
};

/*
 * Per-message header inside the management ring data area.
 * Followed by payload of total_size - sizeof(shmem_msg_hdr) bytes.
 */
struct shmem_msg_hdr {
	u32 total_size;
	u32 id;
	u32 opcode;
	u32 status;
};

/*
 * Doorbell ring -- the entire doorbell memory-region is one of these.
 * Each data[] slot carries a hw_ctx_id.
 */
struct shmem_db_ring {
	u32 head;
	u32 tail;
	u32 ring_mask;
	u32 rsvd;
	u32 data[];
};

/*
 * Management ring -- produce (host writes to TX ring).
 *
 * @hdr:         ring header in shared memory
 * @ring_base:   ring data area (right after the header)
 * @local_head:  caller's cached head (updated on return)
 * @cached_tail: caller's cached copy of firmware's tail (re-read if ring full)
 * @msg_hdr:     message header values (caller fills total_size, id, opcode, status)
 * @payload:     message payload (kernel memory)
 * @payload_size: payload size in bytes
 *
 * Returns 0 on success, -ENOSPC if ring is full.
 *
 * TODO: If a message straddles the ring-end boundary, a split copy is
 * needed.  Currently messages are small relative to the ring so wrap
 * does not occur in practice.  Add aligned head advancement (with
 * matching firmware change) to eliminate wrap entirely.
 */
static inline int shmem_mgmt_produce(struct shmem_ring_hdr *hdr,
				     void *ring_base,
				     u32 *local_head, u32 *cached_tail,
				     const struct shmem_msg_hdr *msg_hdr,
				     const void *payload, size_t payload_size)
{
	u32 mask = hdr->ring_mask;
	u32 size = mask + 1;
	u32 head = *local_head;
	u32 total = sizeof(*msg_hdr) + payload_size;
	u32 off;

	if (head - *cached_tail + total > size) {
		*cached_tail = hdr->tail;
		if (head - *cached_tail + total > size)
			return -ENOSPC;
	}

	off = head & mask;

	memcpy_toio(ring_base + off, msg_hdr, sizeof(*msg_hdr));
	if (payload_size)
		memcpy_toio(ring_base + off + sizeof(*msg_hdr),
			    payload, payload_size);

	dma_wmb();

	head += total;
	hdr->head = head;
	*local_head = head;

	return 0;
}

/*
 * Management ring -- consume (host reads from RX ring).
 *
 * @hdr:          ring header in shared memory
 * @ring_base:    ring data area
 * @local_tail:   caller's cached tail (updated on return)
 * @cached_head:  caller's cached copy of firmware's head (re-read if empty)
 * @msg_hdr:      output message header
 * @payload:      output buffer for payload (kernel memory)
 * @payload_max:  maximum payload bytes to copy
 *
 * Returns payload size on success, -EAGAIN if ring is empty, -EOVERFLOW
 * if the message payload exceeds payload_max.
 *
 * TODO: Handle ring wrap (see shmem_mgmt_produce TODO).
 */
static inline int shmem_mgmt_consume(struct shmem_ring_hdr *hdr,
				     void *ring_base,
				     u32 *local_tail, u32 *cached_head,
				     struct shmem_msg_hdr *msg_hdr,
				     void *payload, size_t payload_max)
{
	u32 mask = hdr->ring_mask;
	u32 tail = *local_tail;
	u32 off, payload_size;

	if (*cached_head == tail) {
		*cached_head = hdr->head;
		if (*cached_head == tail)
			return -EAGAIN;
	}

	dma_rmb();

	off = tail & mask;

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
	*local_tail = tail;

	return payload_size;
}

/*
 * Doorbell ring -- produce (host writes hw_ctx_id).
 *
 * @ring:        doorbell ring in shared memory
 * @local_head:  caller's cached head (updated on return)
 * @cached_tail: caller's cached copy of firmware's tail
 * @hw_ctx_id:   hardware context ID to write
 *
 * Returns 0 on success, -ENOSPC if ring is full.
 */
static inline int shmem_db_produce(struct shmem_db_ring *ring,
				   u32 *local_head, u32 *cached_tail,
				   u32 hw_ctx_id)
{
	u32 mask = ring->ring_mask;
	u32 size = mask + 1;
	u32 head = *local_head;

	if (head - *cached_tail >= size) {
		*cached_tail = ring->tail;
		if (head - *cached_tail >= size)
			return -ENOSPC;
	}

	ring->data[head & mask] = hw_ctx_id;

	dma_wmb();

	head++;
	ring->head = head;
	*local_head = head;

	return 0;
}

#endif /* _AMDXDNA_SHMEM_H_ */

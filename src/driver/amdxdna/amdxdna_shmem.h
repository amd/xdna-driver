/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2026, Advanced Micro Devices, Inc.
<<<<<<< HEAD
=======
 *
 * Shared-memory ring layout and SPSC helpers for the amdxdna shmem+IPI
 * transport.
 *
 * Shared memory is mapped via devm_ioremap_wc() (write-combining, Normal
 * Non-Cacheable on ARM64) so normal loads/stores work directly.  We use
 * READ_ONCE/WRITE_ONCE to prevent compiler tearing/reordering, and
 * dma_wmb()/dma_rmb() to order data vs. index updates across the
 * non-coherent boundary.
 * Both sides are little-endian, so no byte-swap is needed.
>>>>>>> cf2da81 (amdxdna: shmem: implement shared-memory ring transport)
 */

#ifndef _AMDXDNA_SHMEM_H_
#define _AMDXDNA_SHMEM_H_

#include <linux/platform_device.h>

#include <linux/compiler.h>
#include <asm/barrier.h>
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

static inline u32 shmem_ring_used(u32 head, u32 tail, u32 mask)
{
	return (head - tail) & mask;
}

static inline u32 shmem_ring_free(u32 head, u32 tail, u32 mask)
{
	return mask - shmem_ring_used(head, tail, mask);
}

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
 */
static inline int shmem_mgmt_produce(struct shmem_ring_hdr *hdr,
				     void *ring_base,
				     u32 *local_head, u32 *cached_tail,
				     const struct shmem_msg_hdr *msg_hdr,
				     const void *payload, size_t payload_size)
{
	u32 mask = READ_ONCE(hdr->ring_mask);
	u32 head = *local_head;
	u32 total = sizeof(*msg_hdr) + payload_size;
	u32 off, i;
	const u32 *src;

	if (shmem_ring_free(head, *cached_tail, mask) < total) {
		*cached_tail = READ_ONCE(hdr->tail);
		if (shmem_ring_free(head, *cached_tail, mask) < total)
			return -ENOSPC;
	}

	off = head & mask;

	WRITE_ONCE(*(u32 *)(ring_base + off), msg_hdr->total_size);
	off = (off + sizeof(u32)) & mask;
	WRITE_ONCE(*(u32 *)(ring_base + off), msg_hdr->id);
	off = (off + sizeof(u32)) & mask;
	WRITE_ONCE(*(u32 *)(ring_base + off), msg_hdr->opcode);
	off = (off + sizeof(u32)) & mask;
	WRITE_ONCE(*(u32 *)(ring_base + off), msg_hdr->status);
	off = (off + sizeof(u32)) & mask;

	src = payload;
	for (i = 0; i < payload_size / sizeof(u32); i++) {
		WRITE_ONCE(*(u32 *)(ring_base + off), src[i]);
		off = (off + sizeof(u32)) & mask;
	}

	/* Ensure message data is visible before consumer sees new head. */
	dma_wmb();

	head += total;
	*local_head = head;
	WRITE_ONCE(hdr->head, head);

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
 */
static inline int shmem_mgmt_consume(struct shmem_ring_hdr *hdr,
				     void *ring_base,
				     u32 *local_tail, u32 *cached_head,
				     struct shmem_msg_hdr *msg_hdr,
				     void *payload, size_t payload_max)
{
	u32 mask = READ_ONCE(hdr->ring_mask);
	u32 tail = *local_tail;
	u32 off, i, payload_size;
	u32 *dst;

	if (shmem_ring_used(*cached_head, tail, mask) < sizeof(*msg_hdr)) {
		*cached_head = READ_ONCE(hdr->head);
		if (shmem_ring_used(*cached_head, tail, mask) < sizeof(*msg_hdr))
			return -EAGAIN;
	}

	/* Ensure we see data written before the head we just read. */
	dma_rmb();

	off = tail & mask;

	msg_hdr->total_size = READ_ONCE(*(u32 *)(ring_base + off));
	off = (off + sizeof(u32)) & mask;
	msg_hdr->id = READ_ONCE(*(u32 *)(ring_base + off));
	off = (off + sizeof(u32)) & mask;
	msg_hdr->opcode = READ_ONCE(*(u32 *)(ring_base + off));
	off = (off + sizeof(u32)) & mask;
	msg_hdr->status = READ_ONCE(*(u32 *)(ring_base + off));
	off = (off + sizeof(u32)) & mask;

	payload_size = msg_hdr->total_size - sizeof(*msg_hdr);
	if (payload_size > payload_max)
		return -EOVERFLOW;

	dst = payload;
	for (i = 0; i < payload_size / sizeof(u32); i++) {
		dst[i] = READ_ONCE(*(u32 *)(ring_base + off));
		off = (off + sizeof(u32)) & mask;
	}

	/* Ensure all data is read before producer sees new tail. */
	dma_wmb();

	tail += msg_hdr->total_size;
	*local_tail = tail;
	WRITE_ONCE(hdr->tail, tail);

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
	u32 mask = READ_ONCE(ring->ring_mask);
	u32 head = *local_head;

	if (shmem_ring_free(head, *cached_tail, mask) < 1) {
		*cached_tail = READ_ONCE(ring->tail);
		if (shmem_ring_free(head, *cached_tail, mask) < 1)
			return -ENOSPC;
	}

	WRITE_ONCE(ring->data[head & mask], hw_ctx_id);

	/* Ensure hw_ctx_id is visible before consumer sees new head. */
	dma_wmb();

	head++;
	*local_head = head;
	WRITE_ONCE(ring->head, head);

	return 0;
}

#endif /* _AMDXDNA_SHMEM_H_ */

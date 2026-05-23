/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2025, Advanced Micro Devices, Inc.
 */

#ifndef _VE2_HOST_QUEUE_H_
#define _VE2_HOST_QUEUE_H_

#include <linux/dma-mapping.h>
#include <linux/mutex.h>

#define HOST_QUEUE_ENTRY        32
#define HOST_INDIRECT_PKT_NUM   36

#define LAST_CMD (0)
#define NOT_LAST_CMD (1)

struct exec_buf {
	u32	dtrace_buf_host_addr_low;
	u32	dpu_control_code_host_addr_low;
	u32	dpu_control_code_host_addr_high;
	u16	args_len;
	u16	dtrace_buf_host_addr_high;
	u32	args_host_addr_low;
	u32	args_host_addr_high;
};

struct host_queue_header {
	u64	read_index;
	struct {
		u16 major;
		u16 minor;
	} version;
	u32	capacity;
	u64	write_index;
	u64	data_address;
};

struct host_indirect_packet_entry {
	u32	host_addr_low;
	u32	host_addr_high:25;
	u32	uc_index:7;
};

enum host_queue_packet_type {
	HOST_QUEUE_PACKET_TYPE_VENDOR_SPECIFIC = 0,
	HOST_QUEUE_PACKET_TYPE_INVALID = 1,
};

enum host_queue_packet_opcode {
	HOST_QUEUE_PACKET_EXEC_BUF = 1,
	HOST_QUEUE_PACKET_TEST = 2,
	HOST_QUEUE_PACKET_EXIT = 3,
};

struct common_header {
	union {
		struct {
			u16 type: 8;
			u16 barrier: 1;
			u16 acquire_fence_scope: 2;
			u16 release_fence_scope: 2;
		};
		u16	header;
	};
	u8	opcode;
	u8	chain_flag;
	u16	count;
	u8	distribute;
	u8	indirect;
};

struct xrt_packet_header {
	struct common_header	common_header;
	u64			completion_signal;
};

struct xrt_packet {
	struct xrt_packet_header	xrt_header;
	u64				xrt_payload_host_addr;
};

struct host_queue_packet {
	struct xrt_packet_header	xrt_header;
	u32				data[12];
};

struct host_queue_indirect_hdr {
	struct common_header	header;
	u32	data[HOST_INDIRECT_PKT_NUM * sizeof(struct host_indirect_packet_entry)];
};

struct host_queue_indirect_pkt {
	struct common_header		header;
	struct exec_buf			payload;
};

struct host_queue_entry {
	struct host_queue_header	hq_header;
	struct host_queue_packet	hq_entry[HOST_QUEUE_ENTRY];
};

struct hsa_queue {
	struct host_queue_header	hq_header;
	struct host_queue_packet	hq_entry[HOST_QUEUE_ENTRY];
	struct host_queue_indirect_hdr	hq_indirect_hdr[HOST_QUEUE_ENTRY];
	struct host_queue_indirect_pkt	hq_indirect_pkt[HOST_INDIRECT_PKT_NUM][HOST_QUEUE_ENTRY];
};

struct ve2_hq_complete {
	u64	*hqc_mem;
	u64	hqc_dma_addr;
};

struct ve2_mem {
	u64	user_addr;
	u64	dma_addr;
};

struct ve2_hsa_queue {
	struct hsa_queue		*hsa_queue_p;
	struct ve2_mem			hsa_queue_mem;
	struct ve2_hq_complete		hq_complete;
	struct mutex			hq_lock;/* protect host queue submit and wait */
	u64				reserved_write_index;
	struct device			*alloc_dev;
};

static inline void hsa_queue_sync_read_index_for_read(struct ve2_hsa_queue *queue)
{
	dma_addr_t read_idx_addr = queue->hsa_queue_mem.dma_addr +
		offsetof(struct hsa_queue, hq_header) +
		offsetof(struct host_queue_header, read_index);

	dma_sync_single_for_cpu(queue->alloc_dev,
				read_idx_addr,
				sizeof(queue->hsa_queue_p->hq_header.read_index),
				DMA_FROM_DEVICE);
}

static inline void hsa_queue_sync_write_index_for_write(struct ve2_hsa_queue *queue)
{
	dma_addr_t write_idx_addr = queue->hsa_queue_mem.dma_addr +
		offsetof(struct hsa_queue, hq_header) +
		offsetof(struct host_queue_header, write_index);

	dma_sync_single_for_device(queue->alloc_dev,
				   write_idx_addr,
				   sizeof(queue->hsa_queue_p->hq_header.write_index),
				   DMA_TO_DEVICE);
}

static inline void hsa_queue_sync_packet_for_write(struct ve2_hsa_queue *queue,
						   u32 slot_idx)
{
	dma_addr_t pkt_dma_addr = queue->hsa_queue_mem.dma_addr +
		offsetof(struct hsa_queue, hq_entry) +
		slot_idx * sizeof(struct host_queue_packet);

	dma_sync_single_for_device(queue->alloc_dev,
				   pkt_dma_addr,
				   sizeof(struct host_queue_packet),
				   DMA_TO_DEVICE);
}

static inline void hsa_queue_sync_indirect_hdr_for_write(struct ve2_hsa_queue *queue,
							 u32 slot_idx)
{
	dma_addr_t hdr_dma_addr = queue->hsa_queue_mem.dma_addr +
		offsetof(struct hsa_queue, hq_indirect_hdr) +
		slot_idx * sizeof(struct host_queue_indirect_hdr);

	dma_sync_single_for_device(queue->alloc_dev,
				   hdr_dma_addr,
				   sizeof(struct host_queue_indirect_hdr),
				   DMA_TO_DEVICE);
}

static inline void hsa_queue_sync_indirect_pkt_for_write(struct ve2_hsa_queue *queue,
							 u32 uc_idx, u32 slot_idx)
{
	dma_addr_t pkt_dma_addr = queue->hsa_queue_mem.dma_addr +
		offsetof(struct hsa_queue, hq_indirect_pkt) +
		(uc_idx * HOST_QUEUE_ENTRY + slot_idx) * sizeof(struct host_queue_indirect_pkt);

	dma_sync_single_for_device(queue->alloc_dev,
				   pkt_dma_addr,
				   sizeof(struct host_queue_indirect_pkt),
				   DMA_TO_DEVICE);
}

static inline void hsa_queue_sync_completion_for_read(struct ve2_hsa_queue *queue,
						      u32 slot_idx)
{
	dma_addr_t comp_dma_addr = queue->hq_complete.hqc_dma_addr +
		slot_idx * sizeof(u64);

	dma_sync_single_for_cpu(queue->alloc_dev,
				comp_dma_addr,
				sizeof(u64),
				DMA_FROM_DEVICE);
}

static inline void hsa_queue_sync_completion_for_write(struct ve2_hsa_queue *queue,
						       u32 slot_idx)
{
	dma_addr_t comp_dma_addr = queue->hq_complete.hqc_dma_addr +
		slot_idx * sizeof(u64);

	dma_sync_single_for_device(queue->alloc_dev,
				   comp_dma_addr,
				   sizeof(u64),
				   DMA_TO_DEVICE);
}

static inline void hsa_queue_pkt_set_invalid(struct host_queue_packet *pkt)
{
	pkt->xrt_header.common_header.type = HOST_QUEUE_PACKET_TYPE_INVALID;
}

static inline struct host_queue_packet *hsa_queue_get_pkt(struct hsa_queue *queue, u64 slot)
{
	return &queue->hq_entry[slot & (queue->hq_header.capacity - 1)];
}

#endif /* _VE2_HOST_QUEUE_H_ */

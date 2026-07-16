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

#define HOST_QUEUE_MAJOR_VERSION 1
#define HOST_QUEUE_MINOR_VERSION 0

#define LAST_CMD (0)
#define NOT_LAST_CMD (1)

/* Byte offset of read_index within struct hsa_queue (host queue header). */
#define HSA_QUEUE_READ_INDEX_OFFSET	0x0

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
	u64	read_index;		/* 0x00 — device updates this */
	struct {
		u16 major;
		u16 minor;
	} version;			/* 0x08 */
	u32	capacity;		/* 0x0c — must be a power of two */
	u64	padding0[6];		/* 0x10 — pad to 64-byte boundary */
	u64	write_index;		/* 0x40 — host updates this */
	u64	padding1[6];		/* 0x48 — pad to next 64-byte boundary */
	u64	data_address;		/* 0x78 — DMA address of packet ring */
} __aligned(64);

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

struct ve2_hsa_queue {
	struct hsa_queue		*hsa_queue_p;
	dma_addr_t			hsa_queue_dma_addr;
	struct ve2_hq_complete		hq_complete;
	struct mutex			hq_lock;/* protect host queue submit and wait */
	u64				reserved_write_index;
	struct device			*alloc_dev;
};

static inline void hsa_queue_sync_read_index_for_read(struct ve2_hsa_queue *queue)
{
	dma_addr_t read_idx_addr = queue->hsa_queue_dma_addr +
		offsetof(struct hsa_queue, hq_header) +
		offsetof(struct host_queue_header, read_index);

	dma_sync_single_for_cpu(queue->alloc_dev,
				read_idx_addr,
				sizeof(queue->hsa_queue_p->hq_header.read_index),
				DMA_FROM_DEVICE);
}

static inline void hsa_queue_sync_write_index_for_write(struct ve2_hsa_queue *queue)
{
	dma_addr_t write_idx_addr = queue->hsa_queue_dma_addr +
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
	dma_addr_t pkt_dma_addr = queue->hsa_queue_dma_addr +
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
	dma_addr_t hdr_dma_addr = queue->hsa_queue_dma_addr +
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
	dma_addr_t pkt_dma_addr = queue->hsa_queue_dma_addr +
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

/* CERT handshake (firmware ABI) */
#define ALIVE_MAGIC		0x404C5645
#define NUM_PDI_SAVE		2
#define HSA_QUEUE_NOT_EMPTY	1
#define CERT_IS_IDLE		4
#define COMPLETION_STATUS_DONE	1

struct handshake {
	u32 mpaie_alive;
	u32 partition_base_address;
	struct {
		u32 partition_size:7;
		u32 reserved:23;
		u32 mode:1;
		u32 uc_b:1;
	} aie_info;
	u32 hsa_addr_high;
	u32 hsa_addr_low;
	u32 ctx_switch_req;
	u32 hsa_location;
	u32 cert_idle_status;
	u32 misc_status;
	u32 log_addr_high;
	u32 log_addr_low;
	u32 log_buf_size;
	u32 host_time_high;
	u32 host_time_low;
	struct {
		u32 dtrace_addr_high;
		u32 dtrace_addr_low;
	} trace;
	union {
		struct {
			struct {
				u16 page_index:15;
				u16 cmd_chain_failure:1;
				u16 page_offset;
			} restore_page;
			struct {
				u32 id;
				u16 page_index;
				u16 page_offset:15;
				u16 core_elf_type:1;
			} pdi[NUM_PDI_SAVE];
		} contents;
		u32 raw[NUM_PDI_SAVE * 2 + 1];
	} ctx_save;
	struct {
		u32 hsa_addr_high;
		u32 hsa_addr_low;
	} dbg;
	struct {
		u32 dbg_buf_addr_high;
		u32 dbg_buf_addr_low;
		u32 size;
	} dbg_buf;
	union {
		struct {
			u16 page_index;
			u16 fired_count;
		} info;
		u32 raw;
	} trace_save;
	u32 doorbell_pending;
	u32 runlist_read_idx;
	u32 completion_status;	/* 0x74: FW sets to COMPLETION_STATUS_DONE before completion IRQ */
	u32 last_preemption_id;		/* 0x78 */
	u32 save_dbg_buf_offset;	/* 0x7c: FW-updated debug-buffer DDR write offset */
	u32 reserved1[4];		/* pad so vm starts at offset 0xa0 */
	u32 last_ddr_dm2mm_addr_high;
	u32 last_ddr_dm2mm_addr_low;
	u32 last_ddr_mm2dm_addr_high;
	u32 last_ddr_mm2dm_addr_low;
	struct {
		u32 fw_state;
		u32 abs_page_index;
		u32 ppc;
	} vm;
	struct {
		u32 ear;
		u32 esr;
		u32 pc;
	} exception;
	struct {
		u32 c_job_readiness_checked;
		u32 c_opcode;
		u32 c_job_launched;
		u32 c_job_finished;
		u32 c_hsa_pkt;
		u32 c_page;
		u32 c_doorbell;
		u32 c_uc_scrub;
		u32 c_tct_requested;
		u32 c_tct_received;
		u16 c_preemption_ucdma;
		u16 c_preemption_ucdma_sync;
		u16 c_preemption_poll;
		u16 c_preemption_mask_poll;
		u16 c_preemption_remote_barrier;
		u16 c_preemption_wait_tct;
		u16 c_block_ucdma;
		u16 c_block_ucdma_sync;
		u16 c_block_local_barrier;
		u16 c_block_remote_barrier;
		u16 c_block_wait_tct;
		u16 c_actor_hash_conflict;
	} counter;
	u32 opcode_timeout_config;
	struct {
		u32 host_addr_offset_high_bits:25;
		u32 reserved:6;
		u32 valid:1;
	} host_addr_offset_high;
	u32 host_addr_offset_low;
};

#endif /* _VE2_HOST_QUEUE_H_ */

/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2025, Advanced Micro Devices, Inc.
 */

#define HOST_QUEUE_ENTRY        32
#define HOST_INDIRECT_PKT_NUM   36

struct exec_buf {
	u16	cu_index;
	u16	reserved0;
	u32	dpu_control_code_host_addr_low;
	u32	dpu_control_code_host_addr_high;
	u16	args_len;
	u16	reserved1;
	u32	args_host_addr_low;
	u32	args_host_addr_high;
};

struct host_queue_header {
	u64	read_index;
	struct {
		u16 major;
		u16 minor;
	}
	version;
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
	struct {
		u16 type: 8;
		u16 barrier: 1;
		u16 acquire_fence_scope: 2;
		u16 release_fence_scope: 2;
	};
	u16	opcode;
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

struct host_queue_entry {
	struct host_queue_header	hq_header;
	struct host_queue_packet	hq_entry[HOST_QUEUE_ENTRY];
};

struct hsa_queue {
	struct host_queue_header	hq_header;
	struct host_queue_packet	hq_entry[HOST_QUEUE_ENTRY];
	struct host_queue_indirect_hdr	hq_indirect_hdr[HOST_QUEUE_ENTRY];
	struct host_queue_indirect_pkt	hq_indirect_pkt[HOST_QUEUE_ENTRY][HOST_INDIRECT_PKT_NUM];
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
	/* hq_lock protects hsa_queue_p->hq_header->[read | write]_index */
	struct mutex			hq_lock;
};

// Handshake packet structure format
#define ALIVE_MAGIC		0x404C5645
struct handshake {
	u32	mpaie_alive;
	u32	partition_base_address;
	struct {
		u32	partition_size:7;
		u32	reserved:23;
		u32	mode:1;
		u32	uc_b:1;
	}
	aie_info;
	u32	hsa_addr_high;
	u32	hsa_addr_low;
	u32	ctx_switch_req;
	u32	hsa_location;
	u32	cert_idle_status;
	u32	misc_status;
	u32	log_addr_high;
	u32	log_addr_low;
	u32	log_buf_size;
	u32	host_time_high;
	u32	host_time_low;
	struct {
		u32	dtrace_addr_high;
		u32	dtrace_addr_low;
	}
	trace;
	struct {
		u32	restore_page;
		u32	pdi_id;
		struct {
			u16	page_index;
			u16	page_len;
		}
		pdi_page;
	}
	ctx_save;
	struct {
		u32	hsa_addr_high;
		u32	hsa_addr_low;
	}
	dbg;
	struct {
		u32	dbg_buf_addr_high;
		u32	dbg_buf_addr_low;
		u32	size;
	}
	dbg_buf;
	struct {
		u32	c_job_readiness_checked;
		u32	c_opcode;
		u32	c_job_launched;
		u32	c_job_finished;
		u32	c_hsa_pkt;
		u32	c_page;
		u32	c_doorbell;
		u32	c_uc_scrub;
		u32	c_tct_requested;
		u32	c_tct_received;
		u16	c_preemption_ucdma;
		u16	c_preemption_ucdma_sync;
		u16	c_preemption_poll;
		u16	c_preemption_mask_poll;
		u16	c_preemption_remote_barrier;
		u16	c_preemption_wait_tct;
		u16	c_block_ucdma;
		u16	c_block_ucdma_sync;
		u16	c_block_local_barrier;
		u16	c_block_remote_barrier;
		u16	c_block_wait_tct;
		u16	c_actor_hash_conflict;
	}
	counter;
	struct {
		u32	fw_state;
		u32	abs_page_index;
		u32	ppc;
	}
	vm;
	struct {
		u32	ear;
		u32	esr;
		u32	pc;
	}
	exception;
#ifdef PDI_LOAD_TEST
	u32 test_pdi_addr_high;
	u32 test_pdi_addr_low;
#endif
};

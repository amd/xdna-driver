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
	//Queue capacity, must be a power of two.
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
	u16	opcode;
	u16	count;
	u8		distribute;
	u8		indirect;
};

struct xrt_packet_header {
	struct common_header	common_header;
	u64		completion_signal;
};

struct host_queue_packet {
	struct xrt_packet_header	xrt_header;
	u32				data[12];
};

typedef struct host_queue_header host_queue_header_t;
typedef enum host_queue_packet_type host_queue_packet_type_t;
typedef struct host_indirect_packet_entry host_indirect_packet_entry_t;
typedef struct host_queue_packet host_queue_packet_t;
typedef enum host_queue_packet_opcode host_queue_packet_opcode_t;
typedef struct xrt_packet_header xrt_packet_header_t;

struct host_queue_entry {
	struct host_queue_header	hq_header;
	struct host_queue_packet	hq_entry[HOST_QUEUE_ENTRY];
};

typedef struct host_queue_indirect_pkt {
	struct common_header		header;
	struct exec_buf			payload;
} host_queue_indirect_pkt_t;

typedef struct host_queue_indirect_hdr {
	struct common_header	header;
	u32	data[HOST_INDIRECT_PKT_NUM * sizeof(host_indirect_packet_entry_t)];
} host_queue_indirect_hdr_t;

struct hsa_queue {
	host_queue_header_t		hq_header;
	host_queue_packet_t		hq_entry[HOST_QUEUE_ENTRY];
	host_queue_indirect_hdr_t	hq_indirect_hdr[HOST_QUEUE_ENTRY];
	host_queue_indirect_pkt_t	hq_indirect_pkt[HOST_QUEUE_ENTRY][HOST_INDIRECT_PKT_NUM];
};

struct ve2_hq_complete {
	u64		*hqc_mem;
	u64		hqc_dma_addr;
};

struct ve2_mem {
	// mapped for user to access memory
	u64		user_addr;
	// addr for hardware to access, can be phy_t or dma_t
	u64		dma_addr;
};

struct ve2_hsa_queue {
	struct hsa_queue		*hsa_queue_p;
	struct ve2_mem			hsa_queue_mem;
	struct ve2_hq_complete		hq_complete;
	// protect hwctx idr
	struct mutex			hq_lock;
};

// Handshake packet structure format
#define ALIVE_MAGIC		0x404C5645
typedef struct {
	u32	mpaie_alive;			//0
	u32	partition_base_address;		//4
	struct {
		u32	partition_size:7;	//8
		u32	reserved:23;		//8
		u32	mode:1;			//8
		u32	uc_b:1;			//8
	}
	aie_info;
	u32	hsa_addr_high;			//c
	u32	hsa_addr_low;			//10
	u32	ctx_switch_req;			//14
	u32	hsa_location;			//18
	u32	cert_idle_status;		//1c
	u32	misc_status;			//20
	u32	log_addr_high;			//24
	u32	log_addr_low;			//28
	u32	log_buf_size;			//2c
	u32	host_time_high;			//30
	u32	host_time_low;			//34
	struct {
		u32	dtrace_addr_high;	//38
		u32	dtrace_addr_low;	//3c
	}
	trace;
	struct {
		u32	restore_page;		//40
		u32	pdi_id;			//44
		struct {
			u16	page_index;
			u16	page_len;
		}
		pdi_page;			//48
	}
	ctx_save;
	struct {
		u32	hsa_addr_high;		//4c
		u32	hsa_addr_low;		//50
	}
	dbg;
	struct {
		u32	dbg_buf_addr_high;	//54
		u32	dbg_buf_addr_low;	//58
		u32	size;			//5c
	}
	dbg_buf;
	volatile struct {
		// number of checks whether there are jobs ready
		u32	c_job_readiness_checked;
		// number of opcode run
		u32	c_opcode;
		u32	c_job_launched;
		u32	c_job_finished;
		// number of hsa pkt handled
		u32	c_hsa_pkt;
		// number of pages loaded
		u32	c_page;
		// number of hsa doorbell ring
		u32	c_doorbell;
		// number of uc memory(PM) scrub
		u32	c_uc_scrub;
		// number of tct requested
		u32	c_tct_requested;
		// number of tct received
		u32	c_tct_received;
		// run out of wait handle UC_DMA_WRITE_DES opcode
		u16	c_preemption_ucdma;
		// run out of wait handle UC_DMA_WRITE_DES_SYNC opcode
		u16	c_preemption_ucdma_sync;
		// POLL_32 opcode retry times
		u16	c_preemption_poll;
		// MASK_POLL_32 opcode retry times
		u16	c_preemption_mask_poll;
		// run out of physical barrier REMOTE_BARRIER opcode
		u16	c_preemption_remote_barrier;
		// actor entry overflow or run out of wait handle WAIT_TCTS opcode
		u16	c_preemption_wait_tct;
		// block UC_DMA_WRITE_DES opcode
		u16	c_block_ucdma;
		// block UC_DMA_WRITE_DES_SYNC opcode
		u16	c_block_ucdma_sync;
		// block local_barrier opcode
		u16	c_block_local_barrier;
		// block REMOTE_BARRIER opcode
		u16	c_block_remote_barrier;
		// block WAIT_TCTS opcode
		u16	c_block_wait_tct;
		// number of slow actor entry lookup
		u16	c_actor_hash_conflict;
	}
	counter;
	volatile struct {
		u32	fw_state;
		//absolute index of page where current control code are in
		u32	abs_page_index;
		// previous pc (relative addr to current page) that drives current_job_ctxt to NULL
		u32	ppc;
	}
	vm;
	volatile struct
	{
		//exception address
		u32	ear;
		//exception status
		u32	esr;
		//exception pc
		u32	pc;
	}
	exception;
#ifdef PDI_LOAD_TEST
	u32 test_pdi_addr_high;
	u32 test_pdi_addr_low;
#endif
} handshake_t;

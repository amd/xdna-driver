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

//handshake
#define ALIVE_MAGIC 0x404C5645
struct handshake {
	u32 mpaie_alive; //0
	u32 partition_base_address; //4
	struct {
		u32 partition_size:7; //8
		u32 reserved:23; //8
		u32 mode:1; //8
		u32 uc_b:1; //8
	}
	aie_info;
	u32 hsa_addr_high; //c
	u32 hsa_addr_low; //10
	u32 ctx_switch_req; //14
	u32 hsa_location; //18
	u32 cert_idle_status; //1c
	u32 misc_status; //20
	u32 log_addr_high; //24
	u32 log_addr_low; //28
	u32 log_buf_size; //2c
	u32 host_time_high; //30
	u32 host_time_low; //34
	struct {
		u32 dtrace_addr_high; //38
		u32 dtrace_addr_low; //3c
	}
	trace;
	struct {
#define NUM_PDI_SAVE 2 //we can save one ss and one elf
		u32 restore_page; //40
		struct {
			u32 id; //44 4c
			u16 page_index; //48 50
			u16 page_len;
		}
		pdi[NUM_PDI_SAVE];
	}
	ctx_save;
	struct {
		u32 hsa_addr_high; //54
		u32 hsa_addr_low; //58
	}
	dbg;
	struct {
		u32 dbg_buf_addr_high; //5c
		u32 dbg_buf_addr_low;  //60
		u32 size;   // 64
	}
	dbg_buf;
	u32 reserved1[14]; //make sure vm (below) starts at offset 0xa0
	volatile struct { /* Hardware sync required */
		u32 fw_state;
		u32 abs_page_index; //absolute index of page where current control code are in
		u32 ppc; // previous pc (relative to current page) drives current_job_context to NULL
	}
	vm;
	volatile struct { /* Hardware sync required */
		u32 ear; //exception address
		u32 esr; //exception status
		u32 pc; //exception pc
	}
	exception;
	volatile struct { /* Hardware sync required */
		u32 c_job_readiness_checked; // number of checks whether there are jobs ready
		u32 c_opcode; // number of opcode run
		u32 c_job_launched;
		u32 c_job_finished;
		u32 c_hsa_pkt; // number of hsa pkt handled
		u32 c_page; // number of pages loaded
		u32 c_doorbell; // number of hsa doorbell ring
		u32 c_uc_scrub; // number of uc memory(PM) scrub
		u32 c_tct_requested; // number of tct requested
		u32 c_tct_received; // number of tct received
		u16 c_preemption_ucdma; // run out of wait handle UC_DMA_WRITE_DES opcode
		u16 c_preemption_ucdma_sync; // run out of wait handle UC_DMA_WRITE_DES_SYNC opcode
		u16 c_preemption_poll; // POLL_32 opcode retry times
		u16 c_preemption_mask_poll; // MASK_POLL_32 opcode retry times
		u16 c_preemption_remote_barrier; // run out of physical barrier REMOTE_BARRIER
		u16 c_preemption_wait_tct;//actor entry overflow or run out of wait handle WAIT_TCTS
		u16 c_block_ucdma; // block UC_DMA_WRITE_DES opcode
		u16 c_block_ucdma_sync; // block UC_DMA_WRITE_DES_SYNC opcode
		u16 c_block_local_barrier; // block local_barrier opcode
		u16 c_block_remote_barrier; // block REMOTE_BARRIER opcode
		u16 c_block_wait_tct; // block WAIT_TCTS opcode
		u16 c_actor_hash_conflict; // number of slow actor entry lookup
	}
	counter;
#ifdef PDI_LOAD_TEST
	u32 test_pdi_addr_high;
	u32 test_pdi_addr_low;
#endif
	u32 opcode_timeout_config;
	struct {
		u32 host_addr_offset_high_bits:25;
		u32 reserved:6;
		u32 valid:1;
	} host_addr_offset_high;
	u32 host_addr_offset_low;
};

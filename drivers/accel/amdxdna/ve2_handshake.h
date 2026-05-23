/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2025-2026, Advanced Micro Devices, Inc.
 *
 * VE2 CERT handshake layout (must match firmware / ve2_host_queue.h).
 */

#ifndef _VE2_HANDSHAKE_H_
#define _VE2_HANDSHAKE_H_

#include <linux/types.h>

#define ALIVE_MAGIC		0x404C5645
#define NUM_PDI_SAVE		2
#define HSA_QUEUE_NOT_EMPTY	1
#define CERT_IS_IDLE		4

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
	u32 reserved1[7];
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

#endif /* _VE2_HANDSHAKE_H_ */

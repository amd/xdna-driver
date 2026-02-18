/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2026, Advanced Micro Devices, Inc.
 */

#ifndef _AIE4_HOST_QUEUE_H_
#define _AIE4_HOST_QUEUE_H_

/* Allow at least one runlist cmd and a few single cmds. Must be power of 2. */
#define CTX_MAX_CMDS			32
#define HSA_MAX_LEVEL1_INDIRECT_ENTRIES	6
#define QUEUE_INDEX_START		0

struct host_queue_header {
	u64 read_index;
	struct {
		u16 major;
		u16 minor;
	} version;
	u32 capacity; /* Queue capacity, must be power of two. */
	u64 write_index;
	u64 data_address; /* The xdna dev addr for payload. */
};

struct exec_buf {
	u32 dtrace_buf_host_addr_low;
	u32 dpu_control_code_host_addr_low;
	u32 dpu_control_code_host_addr_high;
	u16 args_len;
	u16 dtrace_buf_host_addr_high;
	u32 args_host_addr_low;
	u32 args_host_addr_high;
};

#define OPCODE_EXEC_BUF		1
#define CHAIN_FLG_LAST_CMD	0
#define CHAIN_FLG_NOT_LAST_CMD	1
struct common_header {
	u16 reserved; /* MBZ. */
	u8 opcode;
	u8 chain_flag;
	u16 count;
	u8 distribute;
	u8 indirect;
};

struct host_queue_packet_header {
	struct common_header common_header;
	u64 completion_signal;
};

struct host_queue_packet {
	struct host_queue_packet_header pkt_header;
	u32 data[12]; /* total 64-byte packet */
};

struct host_indirect_packet_entry {
	u32 host_addr_low;
	u32 host_addr_high_uc_index;
};

#define HIPE_HOST_ADDR_HIGH_SHIFT	0
#define HIPE_HOST_ADDR_HIGH_MASK	GENMASK(24, 0)
#define HIPE_UC_INDEX_SHIFT		25
#define HIPE_UC_INDEX_MASK		GENMASK(31, 25)

static inline void hipe_set_host_addr_high(u32 *val, u32 addr_hi)
{
	*val &= ~HIPE_HOST_ADDR_HIGH_MASK;
	*val |= (addr_hi << HIPE_HOST_ADDR_HIGH_SHIFT) & HIPE_HOST_ADDR_HIGH_MASK;
}

static inline void hipe_set_uc_index(u32 *val, u32 uc_idx)
{
	*val &= ~HIPE_UC_INDEX_MASK;
	*val |= (uc_idx << HIPE_UC_INDEX_SHIFT) & HIPE_UC_INDEX_MASK;
}

struct host_indirect_packet_data {
	struct common_header header;
	struct exec_buf payload;
};

#endif /* _AIE4_HOST_QUEUE_H_ */

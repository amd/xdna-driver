/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2022-2024, Advanced Micro Devices, Inc.
 */

#ifndef _AIE2_MSG_PRIV_H_
#define _AIE2_MSG_PRIV_H_

#include <linux/uuid.h>

enum aie2_msg_opcode {
	MSG_OP_CREATE_CONTEXT              = 0x2,
	MSG_OP_DESTROY_CONTEXT             = 0x3,
#ifdef AMDXDNA_DEVEL
	MSG_OP_GET_TELEMETRY               = 0x4,
#endif
	MSG_OP_SYNC_BO			   = 0x7,
	MSG_OP_EXECUTE_BUFFER_CF           = 0xC,
	MSG_OP_QUERY_COL_STATUS            = 0xD,
	MSG_OP_QUERY_AIE_TILE_INFO         = 0xE,
	MSG_OP_QUERY_AIE_VERSION           = 0xF,
	MSG_OP_EXEC_DPU                    = 0x10,
	MSG_OP_CONFIG_CU                   = 0x11,
	MSG_OP_CHAIN_EXEC_BUFFER_CF        = 0x12,
	MSG_OP_CHAIN_EXEC_DPU              = 0x13,
	MSG_OP_CONFIG_DEBUG_BO		   = 0x14,
	MSG_OP_EXEC_DPU_PREEMPT		   = 0x15,
#ifdef AMDXDNA_DEVEL
	MSG_OP_REGISTER_PDI                = 0x1,
	MSG_OP_UNREGISTER_PDI              = 0xA,
	MSG_OP_LEGACY_CONFIG_CU            = 0xB,
#endif
	MSG_OP_MAX_XRT_OPCODE,
	MSG_OP_SUSPEND                     = 0x101,
	MSG_OP_RESUME                      = 0x102,
	MSG_OP_ASSIGN_MGMT_PASID           = 0x103,
	MSG_OP_INVOKE_SELF_TEST            = 0x104,
	MSG_OP_MAP_HOST_BUFFER             = 0x106,
	MSG_OP_GET_FIRMWARE_VERSION        = 0x108,
	MSG_OP_SET_RUNTIME_CONFIG          = 0x10A,
	MSG_OP_GET_RUNTIME_CONFIG          = 0x10B,
	MSG_OP_REGISTER_ASYNC_EVENT_MSG    = 0x10C,
	MSG_OP_MAX_DRV_OPCODE,
	MSG_OP_GET_PROTOCOL_VERSION        = 0x301,
	MSG_OP_MAX_OPCODE
};

enum aie2_msg_status {
	AIE2_STATUS_SUCCESS				= 0x0,
	/* AIE Error codes */
	AIE2_STATUS_AIE_SATURATION_ERROR		= 0x1000001,
	AIE2_STATUS_AIE_FP_ERROR			= 0x1000002,
	AIE2_STATUS_AIE_STREAM_ERROR			= 0x1000003,
	AIE2_STATUS_AIE_ACCESS_ERROR			= 0x1000004,
	AIE2_STATUS_AIE_BUS_ERROR			= 0x1000005,
	AIE2_STATUS_AIE_INSTRUCTION_ERROR		= 0x1000006,
	AIE2_STATUS_AIE_ECC_ERROR			= 0x1000007,
	AIE2_STATUS_AIE_LOCK_ERROR			= 0x1000008,
	AIE2_STATUS_AIE_DMA_ERROR			= 0x1000009,
	AIE2_STATUS_AIE_MEM_PARITY_ERROR		= 0x100000a,
	AIE2_STATUS_AIE_PWR_CFG_ERROR			= 0x100000b,
	AIE2_STATUS_AIE_BACKTRACK_ERROR			= 0x100000c,
	AIE2_STATUS_MAX_AIE_STATUS_CODE,
	/* MGMT ERT Error codes */
	AIE2_STATUS_MGMT_ERT_SELF_TEST_FAILURE		= 0x2000001,
	AIE2_STATUS_MGMT_ERT_HASH_MISMATCH,
	AIE2_STATUS_MGMT_ERT_NOAVAIL,
	AIE2_STATUS_MGMT_ERT_INVALID_PARAM,
	AIE2_STATUS_MGMT_ERT_ENTER_SUSPEND_FAILURE,
	AIE2_STATUS_MGMT_ERT_BUSY,
	AIE2_STATUS_MGMT_ERT_APPLICATION_ACTIVE,
	MAX_MGMT_ERT_STATUS_CODE,
	/* APP ERT Error codes */
	AIE2_STATUS_APP_ERT_FIRST_ERROR			= 0x3000001,
	AIE2_STATUS_APP_INVALID_INSTR,
	AIE2_STATUS_APP_LOAD_PDI_FAIL,
	MAX_APP_ERT_STATUS_CODE,
	/* NPU RTOS Error Codes */
	AIE2_STATUS_INVALID_INPUT_BUFFER		= 0x4000001,
	AIE2_STATUS_INVALID_COMMAND,
	AIE2_STATUS_INVALID_PARAM,
#ifdef AMDXDNA_DEVEL
	AIE2_STATUS_PDI_REG_FAILED,
	AIE2_STATUS_PDI_UNREG_FAILED,
#endif
	AIE2_STATUS_INVALID_OPERATION                    = 0x4000006,
	AIE2_STATUS_ASYNC_EVENT_MSGS_FULL,
	AIE2_STATUS_DEBUG_BO_CONFIG_FAILED,
	AIE2_STATUS_MAX_RTOS_STATUS_CODE,
	MAX_AIE2_STATUS_CODE
};

struct assign_mgmt_pasid_req {
	u16	pasid;
	u16	reserved;
} __packed;

struct assign_mgmt_pasid_resp {
	enum aie2_msg_status	status;
} __packed;

struct map_host_buffer_req {
	u32		context_id;
	u64		buf_addr;
	u64		buf_size;
} __packed;

struct map_host_buffer_resp {
	enum aie2_msg_status	status;
} __packed;

#define MAX_CQ_PAIRS		2
struct cq_info {
	u32 head_addr;
	u32 tail_addr;
	u32 buf_addr;
	u32 buf_size;
};

struct cq_pair {
	struct cq_info x2i_q;
	struct cq_info i2x_q;
};

struct create_ctx_req {
	u32	aie_type;
	u8	start_col;
	u8	num_col;
	u16	reserved;
	u8	num_cq_pairs_requested;
	u8	reserved1;
	u16	pasid;
	u32	pad[2];
	u32	sec_comm_target_type;
	u32     context_priority;
} __packed;

struct create_ctx_resp {
	enum aie2_msg_status	status;
	u32			context_id;
	u16			msix_id;
	u8			num_cq_pairs_allocated;
	u8			reserved;
	struct cq_pair		cq_pair[MAX_CQ_PAIRS];
} __packed;

struct destroy_ctx_req {
	u32	context_id;
} __packed;

struct destroy_ctx_resp {
	enum aie2_msg_status	status;
} __packed;

#ifdef AMDXDNA_DEVEL
enum telemetry_type {
	TELEMETRY_TYPE_DISABLED = 0,
	TELEMETRY_TYPE_HEALTH,
	TELEMETRY_TYPE_ERROR_INFO,
	TELEMETRY_TYPE_PROFILING,
	TELEMETRY_TYPE_DEBUG,
	MAX_TELEMETRY_TYPE
};

struct get_telemetry_req {
	enum telemetry_type	type;
	u64	buf_addr;
	u32	buf_size;
} __packed;

struct get_telemetry_resp {
	u32	major;
	u32	minor;
	u32	size;
	enum aie2_msg_status	status;
} __packed;
#endif
struct execute_buffer_req {
	u32	cu_idx;
	u32	payload[19];
} __packed;

struct exec_dpu_req {
	u64	inst_buf_addr;
	u32     inst_size;
	u32     inst_prop_cnt;
	u32     cu_idx;
	u32	payload[35];
} __packed;

struct exec_dpu_preempt_req {
	u64	inst_buf_addr;
	u64	save_buf_addr;
	u64	restore_buf_addr;
	u32	inst_size;
	u32	save_size;
	u32	restore_size;
	u32	inst_prop_cnt;
	u32	cu_idx;
	u32	payload[29];
} __packed;

struct execute_buffer_resp {
	enum aie2_msg_status	status;
} __packed;

struct aie_tile_info {
	u32		size;
	u16		major;
	u16		minor;
	u16		cols;
	u16		rows;
	u16		core_rows;
	u16		mem_rows;
	u16		shim_rows;
	u16		core_row_start;
	u16		mem_row_start;
	u16		shim_row_start;
	u16		core_dma_channels;
	u16		mem_dma_channels;
	u16		shim_dma_channels;
	u16		core_locks;
	u16		mem_locks;
	u16		shim_locks;
	u16		core_events;
	u16		mem_events;
	u16		shim_events;
	u16		reserved;
};

struct aie_tile_info_req {
	u32	reserved;
} __packed;

struct aie_tile_info_resp {
	enum aie2_msg_status	status;
	struct aie_tile_info	info;
} __packed;

struct aie_version_info_req {
	u32		reserved;
} __packed;

struct aie_version_info_resp {
	enum aie2_msg_status	status;
	u16			major;
	u16			minor;
} __packed;

struct aie_column_info_req {
	u64 dump_buff_addr;
	u32 dump_buff_size;
	u32 num_cols;
	u32 aie_bitmap;
} __packed;

struct aie_column_info_resp {
	enum aie2_msg_status	status;
	u32 size;
} __packed;

struct suspend_req {
	u32		place_holder;
} __packed;

struct suspend_resp {
	enum aie2_msg_status	status;
} __packed;

struct resume_req {
	u32		place_holder;
} __packed;

struct resume_resp {
	enum aie2_msg_status	status;
} __packed;

struct check_header_hash_req {
	u64		hash_high;
	u64		hash_low;
} __packed;

struct check_header_hash_resp {
	enum aie2_msg_status	status;
} __packed;

#if defined(CONFIG_DEBUG_FS)
struct check_self_test_req {
	u32    test_mask;
} __packed;

struct check_self_test_resp {
	enum aie2_msg_status status;
} __packed;
#endif

struct query_error_req {
	u64		buf_addr;
	u32		buf_size;
	u32		next_row;
	u32		next_column;
	u32		next_module;
} __packed;

struct query_error_resp {
	enum aie2_msg_status	status;
	u32			num_err;
	u32			has_next_err;
	u32			next_row;
	u32			next_column;
	u32			next_module;
} __packed;

struct protocol_version_req {
	u32		reserved;
} __packed;

struct protocol_version_resp {
	enum aie2_msg_status	status;
	u32			major;
	u32			minor;
} __packed;

struct firmware_version_req {
	u32		reserved;
} __packed;

struct firmware_version_resp {
	enum aie2_msg_status	status;
	u32			major;
	u32			minor;
	u32			sub;
	u32			build;
} __packed;

#define MAX_NUM_CUS			32
#define AIE2_MSG_CFG_CU_PDI_ADDR	GENMASK(16, 0)
#define AIE2_MSG_CFG_CU_FUNC		GENMASK(24, 17)
struct config_cu_req {
	u32	num_cus;
	u32	cfgs[MAX_NUM_CUS];
} __packed;

struct config_cu_resp {
	enum aie2_msg_status	status;
} __packed;

struct set_runtime_cfg_req {
	u32	type;
	u64	value;
} __packed;

struct set_runtime_cfg_resp {
	enum aie2_msg_status	status;
} __packed;

struct get_runtime_cfg_req {
	u32	type;
} __packed;

struct get_runtime_cfg_resp {
	enum aie2_msg_status	status;
	u64			value;
} __packed;

enum async_event_type {
	ASYNC_EVENT_TYPE_AIE_ERROR,
	ASYNC_EVENT_TYPE_EXCEPTION,
	MAX_ASYNC_EVENT_TYPE
};

#define ASYNC_BUF_SIZE 0x2000
struct async_event_msg_req {
	u64 buf_addr;
	u32 buf_size;
} __packed;

struct async_event_msg_resp {
	enum aie2_msg_status	status;
	enum async_event_type	type;
} __packed;

#define MAX_CHAIN_CMDBUF_SIZE 0x1000
#define slot_cf_has_space(offset, payload_size) \
	(MAX_CHAIN_CMDBUF_SIZE - ((offset) + (payload_size)) > \
	 offsetof(struct cmd_chain_slot_execbuf_cf, args[0]))
struct cmd_chain_slot_execbuf_cf {
	u32 cu_idx;
	u32 arg_cnt;
	u32 args[] __counted_by(arg_cnt);
};

#define slot_dpu_has_space(offset, payload_size) \
	(MAX_CHAIN_CMDBUF_SIZE - ((offset) + (payload_size)) > \
	 offsetof(struct cmd_chain_slot_dpu, args[0]))
struct cmd_chain_slot_dpu {
	u64 inst_buf_addr;
	u32 inst_size;
	u32 inst_prop_cnt;
	u32 cu_idx;
	u32 arg_cnt;
#define MAX_DPU_ARGS_SIZE (34 * sizeof(u32))
	u32 args[] __counted_by(arg_cnt);
};

struct cmd_chain_req {
	u64 buf_addr;
	u32 buf_size;
	u32 count;
} __packed;

struct cmd_chain_resp {
	enum aie2_msg_status	status;
	u32			fail_cmd_idx;
	enum aie2_msg_status	fail_cmd_status;
} __packed;

#define AIE2_MSG_SYNC_BO_SRC_TYPE	GENMASK(3, 0)
#define AIE2_MSG_SYNC_BO_DST_TYPE	GENMASK(7, 4)
struct sync_bo_req {
	u64 src_addr;
	u64 dst_addr;
	u32 size;
#define SYNC_BO_DEV_MEM  0
#define SYNC_BO_HOST_MEM 2
	u32 type;
} __packed;

struct sync_bo_resp {
	enum aie2_msg_status	status;
} __packed;

struct config_debug_bo_req {
	u64	offset;
	u64	size;
#define UNREGISTER 0
#define REGISTER   1
	u32	config;
} __packed;

struct config_debug_bo_resp {
	enum aie2_msg_status	status;
} __packed;

#ifdef AMDXDNA_DEVEL
#define AIE2_MAX_PDI_ID	255
struct pdi_info {
	u32		registered;
	u32		pad[2];
	u64		address;
	u32		size;
	int		type;
	u8		pdi_id;
} __packed;

struct register_pdi_req {
	u32			num_infos;
	struct pdi_info		pdi_info;
	/*
	 * sizeof(pdi_info) is 29 bytes, pad 7 pdi_info
	 * total = 7 * 29 = 203 bytes
	 */
	u8			pad[203];
} __packed;

struct register_pdi_resp {
	enum aie2_msg_status	status;
	u8			reg_index;
	/* 7 + 4 * 8 = 39 bytes */
	u8			pad[39];
} __packed;

struct unregister_pdi_req {
	u32			num_pdi;
	u8			pdi_id;
	u8			pad[7];
} __packed;

struct unregister_pdi_resp {
	enum aie2_msg_status	status;
	u32			pad[8];
} __packed;

struct cu_cfg_info {
	u32 cu_idx : 16;
	u32 cu_func : 8;
	u32 cu_pdi_id : 8;
};

struct legacy_config_cu_req {
	u32			num_cus;
	struct cu_cfg_info	configs[MAX_NUM_CUS];
} __packed;

struct legacy_config_cu_resp {
	enum aie2_msg_status	status;
} __packed;
#endif /* AMDXDNA_DEVEL */
#endif /* _AIE2_MSG_PRIV_H_ */

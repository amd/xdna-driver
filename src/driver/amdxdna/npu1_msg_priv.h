/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2022-2024, Advanced Micro Devices, Inc.
 */

#ifndef _NPU1_MSG_PRIV_H_
#define _NPU1_MSG_PRIV_H_

#include <linux/uuid.h>

enum npu_msg_opcode {
	MSG_OP_CREATE_CONTEXT              = 0x2,
	MSG_OP_DESTROY_CONTEXT             = 0x3,
	MSG_OP_GET_TELEMETRY               = 0x4,
	MSG_OP_RESET_PARTITION             = 0x5,
	MSG_OP_EXECUTE_BUFFER              = 0x6,
	MSG_OP_DPU_SELF_TEST               = 0x8,
	MSG_OP_QUERY_ERROR_INFO            = 0x9,
	MSG_OP_EXECUTE_BUFFER_CF           = 0xC,
	MSG_OP_QUERY_COL_STATUS            = 0xD,
	MSG_OP_QUERY_AIE_TILE_INFO         = 0xE,
	MSG_OP_QUERY_AIE_VERSION           = 0xF,
	MSG_OP_CONFIG_CU                   = 0x11,
	MSG_OP_MAX_XRT_OPCODE,
	MSG_OP_SUSPEND                     = 0x101,
	MSG_OP_RESUME                      = 0x102,
	MSG_OP_ASSIGN_MGMT_PASID           = 0x103,
	MSG_OP_INVOKE_SELF_TEST            = 0x104,
	MSG_OP_CHECK_HEADER_HASH           = 0x105,
	MSG_OP_MAP_HOST_BUFFER             = 0x106,
	MSG_OP_GET_FIRMWARE_VERSION        = 0x108,
	MSG_OP_SET_RUNTIME_CONFIG          = 0x10A,
	MSG_OP_GET_RUNTIME_CONFIG          = 0x10B,
	MSG_OP_REGISTER_ASYNC_EVENT_MSG    = 0x10C,
	MSG_OP_MAX_DRV_OPCODE,
	MSG_OP_ASYNC_MSG_AIE_ERROR         = 0x201,
	MSG_OP_ASYNC_MSG_WATCHDOG_TIMEOUT  = 0x202,
	MSG_OP_MAX_ASYNC_OPCODE,
	MSG_OP_GET_PROTOCOL_VERSION        = 0x301,
	MSG_OP_MAX_OPCODE
};

enum npu_msg_status {
	NPU_STATUS_SUCCESS				= 0x0,
	/* AIE Error codes */
	NPU_STATUS_AIE_SATURATION_ERROR			= 0x1000001,
	NPU_STATUS_AIE_FP_ERROR				= 0x1000002,
	NPU_STATUS_AIE_STREAM_ERROR			= 0x1000003,
	NPU_STATUS_AIE_ACCESS_ERROR			= 0x1000004,
	NPU_STATUS_AIE_BUS_ERROR			= 0x1000005,
	NPU_STATUS_AIE_INSTRUCTION_ERROR		= 0x1000006,
	NPU_STATUS_AIE_ECC_ERROR			= 0x1000007,
	NPU_STATUS_AIE_LOCK_ERROR			= 0x1000008,
	NPU_STATUS_AIE_DMA_ERROR			= 0x1000009,
	NPU_STATUS_AIE_MEM_PARITY_ERROR			= 0x100000a,
	NPU_STATUS_AIE_PWR_CFG_ERROR			= 0x100000b,
	NPU_STATUS_AIE_BACKTRACK_ERROR			= 0x100000c,
	NPU_STATUS_MAX_AIE_STATUS_CODE,
	/* MGMT ERT Error codes */
	NPU_STATUS_MGMT_ERT_SELF_TEST_FAILURE		= 0x2000001,
	NPU_STATUS_MGMT_ERT_HASH_MISMATCH,
	NPU_STATUS_MGMT_ERT_NOAVAIL,
	NPU_STATUS_MGMT_ERT_INVALID_PARAM,
	NPU_STATUS_MGMT_ERT_ENTER_SUSPEND_FAILURE,
	NPU_STATUS_MGMT_ERT_BUSY,
	NPU_STATUS_MGMT_ERT_APPLICATION_ACTIVE,
	NPU_STATUS_MAX_MGMT_ERT_STATUS_CODE,
	/* APP ERT Error codes */
	NPU_STATUS_APP_ERT_FIRST_ERROR			= 0x3000001,
	NPU_STATUS_APP_INVALID_INSTR,
	NPU_STATUS_APP_LOAD_PDI_FAIL,
	NPU_STATUS_MAX_APP_ERT_STATUS_CODE,
	/* NPU RTOS Error Codes */
	NPU_STATUS_INVALID_INPUT_BUFFER			= 0x4000001,
	NPU_STATUS_INVALID_COMMAND,
	NPU_STATUS_INVALID_PARAM,
	NPU_STATUS_INVALID_OPERATION                    = 0x4000006,
	NPU_STATUS_ASYNC_EVENT_MSGS_FULL,
	NPU_STATUS_MAX_RTOS_STATUS_CODE,
	NPU_STATUS_MAX_NPU_STATUS_CODE
};

struct assign_mgmt_pasid_req {
	u16	pasid;
	u16	reserved;
} __packed;

struct assign_mgmt_pasid_resp {
	enum npu_msg_status	status;
} __packed;

struct map_host_buffer_req {
	u32		context_id;
	u64		buf_addr;
	u64		buf_size;
} __packed;

struct map_host_buffer_resp {
	enum npu_msg_status	status;
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
	u32	start_col:8;
	u32	num_col:8;
	u32	reserved:16;
	u32	num_cq_pairs_requested:8;
	u32	reserved1:8;
	u32	pasid:16;
	u32	pad[2];
	u32	sec_comm_target_type;
	u32     context_priority;
} __packed;

struct create_ctx_resp {
	enum npu_msg_status	status;
	u32			context_id;
	u32			msix_id:16;
	u32			num_cq_pairs_allocated:8;
	u32			reserved:8;
	struct cq_pair		cq_pair[MAX_CQ_PAIRS];
} __packed;

struct destroy_ctx_req {
	u32	context_id;
} __packed;

struct destroy_ctx_resp {
	enum npu_msg_status	status;
} __packed;

struct execute_buffer_req {
	u32	cu_idx;
	u32	payload[19];
} __packed;

struct execute_buffer_resp {
	enum npu_msg_status	status;
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
	enum npu_msg_status	status;
	struct aie_tile_info	info;
} __packed;

struct aie_version_info_req {
	u32		reserved;
} __packed;

struct aie_version_info_resp {
	enum npu_msg_status	status;
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
	enum npu_msg_status	status;
	u32 size;
} __packed;

struct suspend_req {
	u32		place_holder;
} __packed;

struct suspend_resp {
	enum npu_msg_status	status;
} __packed;

struct resume_req {
	u32		place_holder;
} __packed;

struct resume_resp {
	enum npu_msg_status	status;
} __packed;

struct check_header_hash_req {
	u64		hash_high;
	u64		hash_low;
} __packed;

struct check_header_hash_resp {
	enum npu_msg_status	status;
} __packed;

#if defined(CONFIG_DEBUG_FS)
struct check_self_test_req {
	u32    test_mask;
} __packed;

struct check_self_test_resp {
	enum npu_msg_status status;
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
	enum npu_msg_status	status;
	u32			num_err;
	u32			has_next_err:1;
	u32			reserved:31;
	u32			next_row;
	u32			next_column;
	u32			next_module;
} __packed;

struct protocol_version_req {
	u32		reserved;
} __packed;

struct protocol_version_resp {
	enum npu_msg_status	status;
	u32			major;
	u32			minor;
} __packed;

struct firmware_version_req {
	u32		reserved;
} __packed;

struct firmware_version_resp {
	enum npu_msg_status	status;
	u32			major;
	u32			minor;
	u32			sub;
	u32			build;
} __packed;

#define MAX_NUM_CUS	32
struct config_cu_req {
	u32	num_cus;
	struct {
		u32	pdi_addr:17;
		u32	cu_func:8;
		u32	reserved:7;
	} configs[MAX_NUM_CUS];
} __packed;

struct config_cu_resp {
	enum npu_msg_status	status;
} __packed;

struct set_runtime_cfg_req {
	u32	type;
	u64	value;
} __packed;

struct set_runtime_cfg_resp {
	enum npu_msg_status	status;
} __packed;

struct get_runtime_cfg_req {
	u32	type;
} __packed;

struct get_runtime_cfg_resp {
	enum npu_msg_status	status;
	u64			value;
} __packed;

#endif /* _NPU1_MSG_PRIV_H_ */

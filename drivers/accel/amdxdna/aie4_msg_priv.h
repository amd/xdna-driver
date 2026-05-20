/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2026, Advanced Micro Devices, Inc.
 */

#ifndef _AIE4_MSG_PRIV_H_
#define _AIE4_MSG_PRIV_H_

#include <linux/bitfield.h>
#include <linux/sizes.h>
#include <linux/types.h>

enum aie4_msg_opcode {
	/* Classic/PF/VF common */
	AIE4_MSG_OP_IDENTIFY                         = 0x10002,
	AIE4_MSG_OP_SUSPEND                          = 0x10003,
	AIE4_MSG_OP_QUERY_CERT_FIRMWARE_VERSION      = 0x1000F,

	/* PF only */
	AIE4_MSG_OP_CREATE_VFS                       = 0x20001,
	AIE4_MSG_OP_DESTROY_VFS                      = 0x20002,

	/* Classic/VF */
	AIE4_MSG_OP_CREATE_PARTITION                 = 0x30001,
	AIE4_MSG_OP_DESTROY_PARTITION                = 0x30002,
	AIE4_MSG_OP_CREATE_HW_CONTEXT                = 0x30003,
	AIE4_MSG_OP_DESTROY_HW_CONTEXT               = 0x30004,
	AIE4_MSG_OP_AIE_TILE_INFO                    = 0x30006,
	AIE4_MSG_OP_AIE_VERSION_INFO                 = 0x30007,
	AIE4_MSG_OP_POWER_OVERRIDE                   = 0x3000B,
	AIE4_MSG_OP_AIE_RW_ACCESS                    = 0x3000E,
	AIE4_MSG_OP_AIE_COREDUMP                     = 0x30010,

	/* System Control PF/VF Opcodes */
	AIE4_MSG_OP_ATTACH_WORK_BUFFER               = 0x40001,
	AIE4_MSG_OP_CALIBRATE_CLOCK                  = 0x40006,
};

enum aie4_msg_status {
	AIE4_MSG_STATUS_SUCCESS = 0x0,
	AIE4_MSG_STATUS_ERROR = 0x1,
	AIE4_MSG_STATUS_NOTSUPP = 0x2,
	MAX_AIE4_MSG_STATUS_CODE = 0x4,
};

enum aie4_msg_context_priority_band {
	AIE4_CONTEXT_PRIORITY_BAND_IDLE = 0,
	AIE4_CONTEXT_PRIORITY_BAND_NORMAL,
	AIE4_CONTEXT_PRIORITY_BAND_FOCUS,
	AIE4_CONTEXT_PRIORITY_BAND_REAL_TIME,
	AIE4_CONTEXT_PRIORITY_BAND_COUNT
};

struct aie4_msg_identify_req {
	__u32 rsvd;
} __packed;

struct aie4_msg_identify_resp {
	enum aie4_msg_status status;
	__u32 fw_major;
	__u32 fw_minor;
	__u32 fw_patch;
	__u32 fw_build;
} __packed;

struct aie4_msg_suspend_req {
	__u32 rsvd;
} __packed;

struct aie4_msg_suspend_resp {
	enum aie4_msg_status status;
} __packed;

struct aie4_msg_create_vfs_req {
	__u32 vf_cnt;
} __packed;

struct aie4_msg_create_vfs_resp {
	enum aie4_msg_status status;
} __packed;

struct aie4_msg_destroy_vfs_req {
	__u32 rsvd;
} __packed;

struct aie4_msg_destroy_vfs_resp {
	enum aie4_msg_status status;
} __packed;

struct aie4_msg_create_partition_req {
	__u32 partition_col_start;
	__u32 partition_col_count;
} __packed;

struct aie4_msg_create_partition_resp {
	enum aie4_msg_status status;
	__u32 partition_id;
} __packed;

struct aie4_msg_destroy_partition_req {
	__u32 partition_id;
} __packed;

struct aie4_msg_destroy_partition_resp {
	enum aie4_msg_status status;
} __packed;

struct aie4_msg_create_hw_context_req {
	__u32 partition_id;
	__u32 request_num_tiles;
	__u32 hsa_addr_high;
	__u32 hsa_addr_low;
#define AIE4_MSG_PASID GENMASK(19, 0)
#define AIE4_MSG_PASID_VLD GENMASK(31, 31)
	__u32 pasid;
	__u8 priority_band;
	__u8 priority_level;
	__u16 restore_id;
} __packed;

struct aie4_msg_create_hw_context_resp {
	enum aie4_msg_status status;
	__u32 hw_context_id;
	__u32 doorbell_offset;
	__u32 job_complete_msix_idx;
} __packed;

struct aie4_msg_destroy_hw_context_req {
	__u32 hw_context_id;
#define AIE4_MSG_GRACEFUL_FLAG	GENMASK(0, 0)
	__u32 graceful_flag;
} __packed;

struct aie4_msg_destroy_hw_context_resp {
	enum aie4_msg_status status;
	__u16 restore_id;
	__u16 resvd;
} __packed;

struct aie4_tile_info {
	__u32 size;
	__u16 major;
	__u16 minor;
	__u16 cols;
	__u16 rows;
	__u16 core_rows;
	__u16 mem_rows;
	__u16 shim_rows;
	__u16 core_row_start;
	__u16 mem_row_start;
	__u16 shim_row_start;
	__u16 core_dma_channels;
	__u16 mem_dma_channels;
	__u16 shim_dma_channels;
	__u16 core_locks;
	__u16 mem_locks;
	__u16 shim_locks;
	__u16 core_events;
	__u16 mem_events;
	__u16 shim_events;
	__u16 resvd;
} __packed;

struct aie4_msg_aie4_tile_info_req {
	__u32 resvd;
} __packed;

struct aie4_msg_aie4_tile_info_resp {
	enum aie4_msg_status status;
	struct aie4_tile_info info;
} __packed;

struct aie4_msg_aie4_version_info_req {
	__u32 resvd;
} __packed;

struct aie4_msg_aie4_version_info_resp {
	enum aie4_msg_status status;
	__u16 major;
	__u16 minor;
} __packed;

struct aie4_msg_query_cert_firmware_version_req {
	__u32 resvd;
} __packed;

struct aie4_msg_query_cert_firmware_version_resp {
	enum aie4_msg_status status;
	__u8 major_version;
	__u8 minor_version;
	__u8 git_hash[41];
	__u8 date[11];
	__u8 hotfix;
	__u8 build;
	__u16 host_queue_major;
	__u16 host_queue_minor;
} __packed;

struct aie4_msg_power_override_req {
	__u32 power_mode;
} __packed;

struct aie4_msg_power_override_resp {
	enum aie4_msg_status status;
} __packed;

#define AIE4_WORK_BUFFER_MIN_SIZE      SZ_4M

struct aie4_msg_attach_work_buffer_req {
	__u64 buff_addr;
	__u32 pasid;
	__u32 buff_size;
} __packed;

struct aie4_msg_attach_work_buffer_resp {
	enum aie4_msg_status status;
} __packed;

struct aie4_msg_aie4_coredump_req {
	__u32 context_id;
	__u32 pasid;
	__u32 num_buffers;
	__u32 resvd;
	__u64 buffer_list_addr;
} __packed;

struct aie4_msg_aie4_coredump_resp {
	enum aie4_msg_status status;
	__u32 error_detail[8];
} __packed;

enum aie4_access_type {
	AIE4_ACCESS_TYPE_MEM_READ,
	AIE4_ACCESS_TYPE_MEM_WRITE,
	AIE4_ACCESS_TYPE_REG_READ,
	AIE4_ACCESS_TYPE_REG_WRITE,
	AIE4_ACCESS_TYPE_MAX
};

struct aie4_msg_aie4_debug_access_req {
	__u8 opcode;
	__u8 resvd0;
	__u16 context_id;
	__u8 row;
	__u8 col;
	__u16 resvd1;
	union {
		struct {
			__u64 buffer_addr;
			__u32 buffer_size;
			__u32 mem_addr;
			__u32 mem_size;
			__u32 pasid;
		} __packed mem_access;
		struct {
			__u32 reg_addr;
			__u32 reg_wval;
		} __packed reg_access;
	};
} __packed;

struct aie4_msg_aie4_debug_access_resp {
	enum aie4_msg_status status;
	__u32 reg_rval;
} __packed;

struct aie4_msg_calibrate_clock_req {
	__u64 time_base_ns;
} __packed;

struct aie4_msg_calibrate_clock_resp {
	enum aie4_msg_status status;
} __packed;

#endif /* _AIE4_MSG_PRIV_H_ */

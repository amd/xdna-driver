/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2026, Advanced Micro Devices, Inc.
 */

#ifndef _AIE4_MSG_PRIV_H_
#define _AIE4_MSG_PRIV_H_

#include <linux/bitfield.h>
#include <linux/sizes.h>
#include <linux/types.h>

#include "amdxdna_ctx.h"	/* struct uc_health_info */

enum aie4_msg_opcode {
	/* Classic/PF/VF common */
	AIE4_MSG_OP_IDENTIFY                         = 0x10002,
	AIE4_MSG_OP_SUSPEND                          = 0x10003,
	AIE4_MSG_OP_ASYNC_EVENT_MSG                  = 0x10004,
	AIE4_MSG_OP_GET_TELEMETRY                    = 0x10006,
	AIE4_MSG_OP_SET_RUNTIME_CONFIG               = 0x10007,
	AIE4_MSG_OP_START_FW_TRACE                   = 0x1000A,
	AIE4_MSG_OP_STOP_FW_TRACE                    = 0x1000B,
	AIE4_MSG_OP_SET_FW_TRACE_CATEGORIES          = 0x1000C,
	AIE4_MSG_OP_QUERY_CERT_FIRMWARE_VERSION      = 0x1000F,

	/* PF only */
	AIE4_MSG_OP_CREATE_VFS                       = 0x20001,
	AIE4_MSG_OP_DESTROY_VFS                      = 0x20002,

	/* Classic/VF */
	AIE4_MSG_OP_CREATE_PARTITION                 = 0x30001,
	AIE4_MSG_OP_DESTROY_PARTITION                = 0x30002,
	AIE4_MSG_OP_CREATE_HW_CONTEXT                = 0x30003,
	AIE4_MSG_OP_DESTROY_HW_CONTEXT               = 0x30004,
	AIE4_MSG_OP_CONFIGURE_HW_CONTEXT             = 0x30005,
	AIE4_MSG_OP_AIE_TILE_INFO                    = 0x30006,
	AIE4_MSG_OP_AIE_VERSION_INFO                 = 0x30007,
	AIE4_MSG_OP_POWER_OVERRIDE                   = 0x3000B,
	AIE4_MSG_OP_AIE_RW_ACCESS                    = 0x3000E,
	AIE4_MSG_OP_AIE_COREDUMP                     = 0x30010,
	AIE4_MSG_OP_GET_DPM_FREQ_TABLE               = 0x30012,
	AIE4_MSG_OP_GET_CURRENT_DPM_LEVEL            = 0x30013,

	/* System control */
	AIE4_MSG_OP_ATTACH_WORK_BUFFER               = 0x40001,
	AIE4_MSG_OP_START_FW_LOG                     = 0x40003,
	AIE4_MSG_OP_STOP_FW_LOG                      = 0x40004,
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

struct aie4_msg_runtime_config_force_preemption {
	__u8 enabled;
	__u8 padding[3];
} __packed;

/*
 * Type selector for AIE4_MSG_OP_SET_RUNTIME_CONFIG. Values match the firmware
 * ABI enum npu_msg_runtime_config_type; only the configs the driver programs
 * are enumerated here.
 */
enum aie4_msg_runtime_config_type {
	AIE4_RUNTIME_CONFIG_FORCE_PREEMPTION		= 0x1,
	AIE4_RUNTIME_CONFIG_FW_LOG_LEVEL		= 0x5,
	AIE4_RUNTIME_CONFIG_CTX_SWITCH_HYSTERESIS	= 0xD,
	AIE4_MAX_RUNTIME_CONFIG
};

struct aie4_msg_set_runtime_cfg_req {
	__u32 type;
	__u8 data[4];
} __packed;

struct aie4_msg_set_runtime_cfg_resp {
	enum aie4_msg_status status;
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
#define AIE4_MSG_GRACEFUL_FLAG GENMASK(0, 0)
	__u32 graceful_flag;
} __packed;

struct aie4_msg_destroy_hw_context_resp {
	enum aie4_msg_status status;
	__u16 restore_id;
	__u16 resvd;
} __packed;

enum aie4_msg_configure_hw_context_property {
	AIE4_CONFIGURE_HW_CONTEXT_PROPERTY_PRIORITY_BAND,
	AIE4_CONFIGURE_HW_CONTEXT_PROPERTY_SCHEDULING,
	AIE4_CONFIGURE_HW_CONTEXT_PROPERTY_DPM,
	AIE4_CONFIGURE_HW_CONTEXT_PROPERTY_CERT_LOG_BUFFER,
	AIE4_CONFIGURE_HW_CONTEXT_PROPERTY_CERT_DEBUG_BUFFER,
	AIE4_CONFIGURE_HW_CONTEXT_PROPERTY_CERT_TRACE_BUFFER,
	AIE4_CONFIGURE_HW_CONTEXT_PROPERTY_CERT_DEBUG_QUEUE,
	AIE4_CONFIGURE_HW_CONTEXT_PROPERTY_HANDLE,
};

#define AIE4_MAX_NUM_CERTS	6

struct aie4_msg_context_config_cert_logging_info {
	__u64 paddr;
	__u32 size;
} __packed;

struct aie4_msg_context_config_cert_logging {
#define AIE4_MSG_CERT_LOG_NUM	GENMASK(7, 0)
	__u32 num;
	struct aie4_msg_context_config_cert_logging_info info[AIE4_MAX_NUM_CERTS];
} __packed;

struct aie4_msg_configure_hw_context_req {
	__u32 hw_context_id;
	__u32 property;
	struct aie4_msg_context_config_cert_logging cert_logging;
} __packed;

struct aie4_msg_configure_hw_context_resp {
	enum aie4_msg_status status;
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

#define AIE4_MAX_DPM_LEVEL_COUNT	10

struct aie4_dpm_table {
	__u32 num_levels;
	__u32 values[AIE4_MAX_DPM_LEVEL_COUNT];
} __packed;

/* AIE4_MSG_OP_GET_DPM_FREQ_TABLE */
struct aie4_msg_get_dpm_freq_table_req {
	__u32 rsvd;
} __packed;

struct aie4_msg_get_dpm_freq_table_resp {
	enum aie4_msg_status status;
	struct aie4_dpm_table aieclk_table;
	struct aie4_dpm_table npuhclk_table;
} __packed;

/* AIE4_MSG_OP_GET_CURRENT_DPM_LEVEL */
struct aie4_msg_get_dpm_level_req {
	__u32 rsvd;
} __packed;

struct aie4_msg_get_dpm_level_resp {
	enum aie4_msg_status status;
	__u32 aieclk_dpm_level;
	__u32 npuhclk_dpm_level;
} __packed;

#define AIE4_WORK_BUFFER_MIN_SIZE      SZ_4M

/* Telemetry type for AIE4_MSG_OP_GET_TELEMETRY. */
enum aie4_msg_telemetry_type {
	AIE4_TELEMETRY_TYPE_DISABLED = 0,
	AIE4_TELEMETRY_TYPE_PERF_COUNTER,
	AIE4_TELEMETRY_TYPE_MAX,
};

#define AIE4_MIN_TELEMETRY_BUFF_SIZE	SZ_128K

/* AIE4_MSG_OP_GET_TELEMETRY */
struct aie4_msg_get_telemetry_req {
	__u32 type;
	__u64 buf_addr;
	__u32 pasid;
	__u32 buf_size;
	__u32 hw_context_id;
} __packed;

struct aie4_msg_get_telemetry_resp {
	enum aie4_msg_status status;
} __packed;

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

/*
 * Asynchronous error reporting definitions.
 *
 * These mirror the documented external mailbox API (see the mpnpu-api
 * npu_msg_priv.h npu_async_* and npu_msg_app_health_report definitions). They
 * must stay in sync with that header; do not include npu_msg_priv.h directly.
 */

/* Maximum number of uCs reported in an app health report. */
#define AIE4_MPNPUFW_MAX_UC_COUNT	6

/* AIE4_MSG_OP_ASYNC_EVENT_MSG: register one async event report buffer. */
struct aie4_msg_async_event_config_req {
	__u64 buff_addr;
	__u32 pasid;
	__u32 buff_size;
} __packed;

/*
 * Async event report header written by firmware into the mailbox response.
 * @status: enum aie4_msg_status.
 * @type: enum aie4_msg_async_event_type.
 */
struct aie4_msg_async_event_msg_event {
	__u32 status;
	__u32 type;
} __packed;

/* The async event types returned in each async response message. */
enum aie4_msg_async_event_type {
	AIE4_ASYNC_EVENT_TYPE_AIE_ERROR,
	AIE4_ASYNC_EVENT_TYPE_EXCEPTION,
	AIE4_ASYNC_EVENT_TYPE_CTX_ERROR,
	AIE4_ASYNC_EVENT_TYPE_PWR_ERROR,
	MAX_AIE4_ASYNC_EVENT_TYPE,
};

/* The async context error types. */
enum aie4_msg_async_ctx_error_type {
	AIE4_ASYNC_EVENT_CTX_ERR_HWSCH_FAILURE,
	AIE4_ASYNC_EVENT_CTX_ERR_STOP_FAILURE,
	AIE4_ASYNC_EVENT_CTX_ERR_AIE_FAILURE,
	AIE4_ASYNC_EVENT_CTX_ERR_PREEMPTION_TIMEOUT,
	AIE4_ASYNC_EVENT_CTX_ERR_NEW_PROCESS_FAILURE,
	AIE4_ASYNC_EVENT_CTX_ERR_UC_CRITICAL_ERROR,
	AIE4_ASYNC_EVENT_CTX_ERR_UC_COMPLETION_TIMEOUT,
};

/* struct uc_health_info (per-uC health entry) is defined in amdxdna_ctx.h. */

/* Field masks for the packed @version and @ctx_num_uc words below. */
#define AIE4_APP_HEALTH_MAJOR_VER	GENMASK(15, 0)
#define AIE4_APP_HEALTH_MINOR_VER	GENMASK(31, 16)
#define AIE4_APP_HEALTH_CTX_STATUS	GENMASK(15, 0)
#define AIE4_APP_HEALTH_NUM_UC		GENMASK(31, 16)

/*
 * App health report stored in the async report buffer on a context error.
 * @version: health report structure version, packed as
 *           AIE4_APP_HEALTH_MAJOR_VER | AIE4_APP_HEALTH_MINOR_VER.
 * @context_id: context ID copied from the request.
 * @ctx_num_uc: context status and uC count, packed as
 *              AIE4_APP_HEALTH_CTX_STATUS | AIE4_APP_HEALTH_NUM_UC. The status
 *              is the enum hw_ctx_status tracked by the scheduler.
 * @runlist_read_idx: index of the most recently executed run list entry.
 * @uc_info: per-uC health information.
 */
struct aie4_msg_app_health_report {
	__u32 version;
	__u32 context_id;
	__u32 ctx_num_uc;
	__u32 runlist_read_idx;
	struct uc_health_info uc_info[AIE4_MPNPUFW_MAX_UC_COUNT];
};

/* The data shared in the async report buffer after a context error. */
struct aie4_async_ctx_error {
	__u32 ctx_id;
	__u32 error_type;
	union {
		struct aie4_msg_app_health_report app_health_report;
	};
};

/* Dynamic firmware log levels. */
enum aie4_fw_log_level {
	AIE4_FW_LOG_LEVEL_OFF,
	AIE4_FW_LOG_LEVEL_ERR,
	AIE4_FW_LOG_LEVEL_WRN,
	AIE4_FW_LOG_LEVEL_INF,
	AIE4_FW_LOG_LEVEL_DBG,
	AIE4_FW_LOG_LEVEL_MAX,
};

struct aie4_msg_start_fw_log_req {
	__u64	buff_addr;
	__u32	buff_size;
	__u32	log_level;
	__u32	reserved;
} __packed;

struct aie4_msg_start_fw_log_resp {
	enum aie4_msg_status status;
} __packed;

struct aie4_msg_stop_fw_log_req {
	__u32	resv;
} __packed;

struct aie4_msg_stop_fw_log_resp {
	enum aie4_msg_status status;
} __packed;

/* Maximum trailing per-type payload (struct npu_msg_runtime_config_*) in the
 * firmware ABI; today the largest is npu_msg_runtime_config_event_trace_status
 * at 12 bytes. Rounded up to leave headroom for future configs.
 */
#define AIE4_RUNTIME_CFG_MAX_DATA_SIZE 16

struct aie4_msg_runtime_config_fw_log_level {
	__u32 log_level;
} __packed;

/*
 * Context switch hysteresis configuration.
 *
 * @timeout_us: Hysteresis time in microseconds for keeping a context loaded
 *              in the AIE after it becomes idle, or 0 to disable hysteresis.
 */
struct aie4_msg_runtime_config_ctx_switch_hysteresis {
	__u32 timeout_us;
} __packed;

enum aie4_fw_trace_destination {
	AIE4_FW_TRACE_DESTINATION_DRAM,
};

enum aie4_fw_trace_timestamp {
	AIE4_FW_TRACE_TIMESTAMP_NONE,
	AIE4_FW_TRACE_TIMESTAMP_NS_OFFSET,
};

struct aie4_msg_start_fw_trace_req {
	__u64	categories;
	__u32	destination;
	__u32	timestamp;
	__u64	buff_addr;
	__u32	buff_size;
	__u32	reserved;
} __packed;

struct aie4_msg_start_fw_trace_resp {
	enum aie4_msg_status status;
} __packed;

struct aie4_msg_stop_fw_trace_req {
	__u32	reserved;
} __packed;

struct aie4_msg_stop_fw_trace_resp {
	enum aie4_msg_status status;
} __packed;

struct aie4_msg_set_fw_trace_categories_req {
	__u64	categories;
} __packed;

struct aie4_msg_set_fw_trace_categories_resp {
	enum aie4_msg_status status;
} __packed;

/* MSI address mask used for the AIE4 DPT (FW log / FW trace) IRQ. */
#define AIE4_DPT_MSI_ADDR_MASK		GENMASK(23, 0)

#endif /* _AIE4_MSG_PRIV_H_ */

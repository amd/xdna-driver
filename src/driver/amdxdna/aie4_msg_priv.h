/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2024-2026, Advanced Micro Devices, Inc.
 * All Rights Reserved.
 */

#ifndef _AIE4_MSG_PRIV_H_
#define _AIE4_MSG_PRIV_H_

#pragma pack(push, 4)

/**
 * PROTOCOL_MAJOR and PROTOCOL_MINOR indicate the protocol version of
 * the driver API.
 *
 * PROTOCOL_MAJOR needs to be updated any time an API change breaks
 * compatibility with a driver, including any time that an existing command
 * changes. For example, any field is added/removed to/from an existing command.
 *
 * PROTOCOL_MINOR needs to be updated any time an API change doesn't break
 * compatibility with a driver, including any time a new command is added, or
 * new options to an existing command.
 */

/**
 * --------------------------------
 * - Protocol Version History -
 * --------------------------------
 * v1.4:
 * - Initial imported revision
 *
 * v1.5:
 * - Definition of self-test command
 *
 * v1.6:
 * - Definition of new self-test interface
 *
 * v2.0:
 * - Updates for SR-IOV support
 *
 * v2.1:
 * - Update PASID definition
 *
 * v2.2:
 * - Add destroy_vfs req/resp messages
 * - Add PASID to other structs that address DRAM
 *
 * v2.3:
 * - Add clock set message
 * - Add power cntrl message
 *
 * v3.0:
 * - Change the semantics of aie4_msg_create_hw_context_resp.doorbell_offset
 *
 * v3.1:
 * - Added CERT debug/logging messages
 *
 * v3.2:
 * - Add AIE4 debug access message
 *
 * v3.3:
 * - Added DRAM logging config message
 *
 * v3.4:
 * - Replace tabs with spaces in the whole file, no actual changes
 *
 * v3.5:
 * - Add runtime configuration commands
 *
 * v3.6:
 * - Add support for event trace:
 *   - aie4_msg_calibrate_clock_trace_req/resp
 *   - aie4_msg_start_event_trace_req
 *   - aie4_msg_stop_event_trace_req/resp
 *   - aie4_msg_set_event_trace_categories_req/resp
 *   - Related enums for destination and timestamp modes
 *
 * v3.7:
 *   - Add L1MMU runtime config
 *
 * v3.8:
 * - Add a message to take in a DRAM buffer used to clear AXI2SDP memory.
 *
 * v3.9:
 * - Add runtime config to prevent partition teardown when CERT goes IDLE.
 *
 * v3.10:
 * - Add DPM override runtime config
 *
 * v3.11:
 * - Add CERT timeout runtime config
 *
 * v3.12:
 * - Add DRAM logging runtime config
 *
 * v3.13:
 * - Add shim dma address to self test request msg
 *
 * v3.14:
 * - Add the context handle config
 *
 * v3.15:
 * - Add App Health Check
 *
 * v3.16:
 * - Add event trace enabled runtime config
 *
 * v3.17:
 * - Add Coredump
 *
 * v3.18:
 * - Add runtime config to set DPM enable
 *
 * v3.19:
 * - Narrow the context handle bitwidth to 16 bits
 *
 * v3.20:
 * - Add hw_context_id to aie4_debug_access requests
 *
 * v4.0:
 * - Removed AIE4_MSG_OP_SET_CLOCK_MODE and AIE4_MSG_OP_SET_POWER_CNTRL messages
 * - Flipped order of pasid struct bitfields
 *
 * v4.1:
 * - Changed AIE4_MSG_OP_MEMORY_CLEAR_BUFFER to AIE4_MSG_OP_DRAM_WORK_BUFFER
 * - Gave names to anonymous unions and structs
 * - Use fixed-size array length in aie4_msg_app_health_report
 *
 * v4.2:
 * - Add runtime config to UTL
 *
 * v5.0:
 * - Rename event trace runtime config and report also the enabled categories.
 *
 * v5.1
 * - Changed all references to "DRAM log level" to instead specify "dynamic log level"
 *
 * v5.2
 * - Add runtime config to set error handling mode
 *
 * v5.3:
 * - Add runtime config to put the HWS in debug mode.
 *
 * v5.4:
 * - Add context timeout/disable runtime config
 *
 * v5.5:
 * - Modify pragma aligned to 4 (reduce text section size)
 *
 * v5.6:
 * - Add async buffer definitions for context error
 *
 * v5.7:
 * - Add async buffer definitions for app health report
 *
 * v5.8:
 * - Modify calibrate_clock request/response: take time base in ns.
 *
 * v5.9:
 * - Add telemetry struct
 *
 * v5.10:
 * - Fix MAX_NUM_SUPERVISORS error
 *
 * v5.11:
 * - Added Deep_Sleep in to telemetry struct
 *
 * v5.12:
 * - Add context switch hysteresis runtime config
 *
 * v5.13:
 * - Change context switch hysteresis timeout to microseconds
 *
 */
#define PROTOCOL_MAJOR  5
#define PROTOCOL_MINOR  13

/**
 * opcodes between driver and firmware
 *
 * Note: in order to support basic compatibility check, we define basic principle below:
 *       1) All opcodes cannot be changed once being added;
 *       2) AIE4_MSG_OP_IDENTIFY should not be changed nor obsoleted;
 *       3) All other opcodes can only be obsoleted;
 *       4) Add new opcode for new operation;
 *       5) Any obsoleted or unknown opcodes, firmware will return AIE4_MSG_STATUS_NOTSUPP;
 *       6) Bump protocol_major when driver cannot work with existing or new opcode;
 *          Bump protocol_minor when driver can ignore an opcode;
 */
enum aie4_msg_opcode {
	AIE4_MSG_OP_ECHO                             = 0x10001,
	AIE4_MSG_OP_IDENTIFY                         = 0x10002,
	AIE4_MSG_OP_SUSPEND                          = 0x10003,
	AIE4_MSG_OP_ASYNC_EVENT_MSG                  = 0x10004,
	AIE4_MSG_OP_RUN_SELFTEST                     = 0x10005,
	AIE4_MSG_OP_GET_TELEMETRY                    = 0x10006,
	AIE4_MSG_OP_SET_RUNTIME_CONFIG               = 0x10007,
	AIE4_MSG_OP_GET_RUNTIME_CONFIG               = 0x10008,
	AIE4_MSG_OP_CALIBRATE_CLOCK                  = 0x10009,
	AIE4_MSG_OP_START_EVENT_TRACE                = 0x1000a,
	AIE4_MSG_OP_STOP_EVENT_TRACE                 = 0x1000b,
	AIE4_MSG_OP_SET_EVENT_TRACE_CATEGORIES       = 0x1000c,
	AIE4_MSG_OP_DRAM_WORK_BUFFER                 = 0x1000d,
	AIE4_MSG_OP_RELEASE_DRAM_WORK_BUFFER         = 0x1000e,

	AIE4_MSG_OP_DRAM_LOGGING_START               = 0x20004,
	AIE4_MSG_OP_DRAM_LOGGING_STOP                = 0x20005,

	AIE4_MSG_OP_CREATE_PARTITION                 = 0x30001,
	AIE4_MSG_OP_DESTROY_PARTITION                = 0x30002,
	AIE4_MSG_OP_CREATE_HW_CONTEXT                = 0x30003,
	AIE4_MSG_OP_DESTROY_HW_CONTEXT               = 0x30004,
	AIE4_MSG_OP_CONFIGURE_HW_CONTEXT             = 0x30005,
	AIE4_MSG_OP_AIE_TILE_INFO                    = 0x30006,
	AIE4_MSG_OP_AIE_VERSION_INFO                 = 0x30007,
	AIE4_MSG_OP_AIE_COLUMN_INFO                  = 0x30008,
	AIE4_MSG_OP_SETUP_PRIORITY_BANDS_SCHEDULING  = 0x30009,
	AIE4_MSG_OP_POWER_HINT                       = 0x3000A,
	AIE4_MSG_OP_POWER_OVERRIDE                   = 0x3000B,
	AIE4_MSG_OP_AIE_DEBUG_ACCESS                 = 0x3000E,
	AIE4_MSG_OP_GET_APP_HEALTH_STATUS            = 0x3000F,
	AIE4_MSG_OP_AIE_COREDUMP                     = 0x30010,
};

/** The status that is returned with each response message. */
enum aie4_msg_status {
	AIE4_MSG_STATUS_SUCCESS = 0x0,
	AIE4_MSG_STATUS_ERROR = 0x1,
	AIE4_MSG_STATUS_NOTSUPP = 0x2,
	AIE4_MSG_STATUS_ASYNC_EVENT_MSGS_FULL = 0x3,
	MAX_AIE4_MSG_STATUS_CODE = 0x4,
};

/** Context priority band names */
enum aie4_msg_context_priority_band {
	AIE4_CONTEXT_PRIORITY_BAND_IDLE = 0,
	AIE4_CONTEXT_PRIORITY_BAND_NORMAL,
	AIE4_CONTEXT_PRIORITY_BAND_FOCUS,
	AIE4_CONTEXT_PRIORITY_BAND_REAL_TIME,
	AIE4_CONTEXT_PRIORITY_BAND_COUNT
};

/** Max amount of uCs supported by the system */
#define AIE4_MPNPUFW_MAX_UC_COUNT    (6)

/**
 * The 32-bit PASID format
 *
 * @raw:       The entire 32-bit raw value
 * @pasid_vld: Flag that this is valid PASID and transactions should be tagged
 * @pasid:     The PASID
 */
union aie4_msg_pasid {
	u32 raw;
	struct {
		u32 pasid     : 20;
		u32 revd      : 11;
		u32 pasid_vld : 1;
	} f;
};

/**
 * AIE4_MSG_OP_ECHO
 * A test command echo values from request back to the caller.
 *
 * @val1: The first value to be echo'd.
 * @val2: The second value to be echo'd.
 */
struct aie4_msg_echo_req {
	u32 val1;
	u32 val2;
};

/**
 * AIE4_MSG_OP_ECHO
 * Echo command response.
 *
 * @status: enum aie4_msg_status.
 * @val1:   The first response value.
 * @val2:   The second response value.
 */
struct aie4_msg_echo_resp {
	enum aie4_msg_status status;
	u32 val1;
	u32 val2;
};

/**
 * AIE4_MSG_OP_IDENTIFY
 * Identify firmware version.
 */
struct aie4_msg_identify_req {
	u32 resvd;
};

/**
 * AIE4_MSG_OP_IDENTIFY
 * Identify response with firmware's current version.
 *
 * @status:         enum aie4_msg_status.
 * @fw_major:       firmware major number
 * @fw_minor:       firmware minor number
 * @fw_patch:       firmware patch number
 * @fw_build:       firmware build number
 */
struct aie4_msg_identify_resp {
	enum aie4_msg_status status;
	u32 fw_major;
	u32 fw_minor;
	u32 fw_patch;
	u32 fw_build;
};

/**
 * AIE4_MSG_OP_SUSPEND
 * Suspend NPU request.
 */
struct aie4_msg_suspend_req {
	u32 resvd;
};

/**
 * AIE4_MSG_OP_SUSPEND
 * Response to suspend request.
 *
 * @status: enum aie4_msg_status
 */
struct aie4_msg_suspend_resp {
	enum aie4_msg_status status;
};

/** Dynamic Logging levels */
enum aie4_msg_dynamic_log_level {
	AIE4_DYNAMIC_LOG_NONE = 0,
	AIE4_DYNAMIC_LOG_ERR = 1,
	AIE4_DYNAMIC_LOG_WRN = 2,
	AIE4_DYNAMIC_LOG_INF = 3,
	AIE4_DYNAMIC_LOG_DBG = 4,
};

/**
 * AIE4_MSG_OP_DRAM_LOGGING_START
 * Starts logging into DRAM
 *
 * @buff_addr: Address of DRAM logging buffer
 * @buff_size: Size of request buffer.
 * @log_level: Dynamic logging level.
 * @pasid:     PASID
 */
struct aie4_msg_dram_logging_start_req {
	u64 buff_addr;
	u32 buff_size;
	u32 log_level;
	union aie4_msg_pasid pasid;
};

/**
 * AIE4_MSG_OP_DRAM_LOGGING_STOP
 * Stops DRAM logging.
 *
 * @resv: Reserved
 */
struct aie4_msg_dram_logging_stop_req {
	u32 resv;
};

/**
 * AIE4_MSG_OP_DRAM_LOGGING_START and
 * AIE4_MSG_OP_DRAM_LOGGING_STOP response
 *
 * @status: enum aie4_msg_status.
 */
struct aie4_msg_dram_logging_start_resp {
	enum aie4_msg_status status;
};

struct aie4_msg_dram_logging_stop_resp {
	enum aie4_msg_status status;
};

/**
 * AIE4_MSG_OP_CREATE_VFS
 * All VFs have been created on the host system, so firmware needs to be
 * configured to interact with them.
 *
 * This message cannot be called multiple times without first destroying
 * all the VFs in firmware; all VFs are intended to be created and
 * destroyed at the same time.
 *
 * This message is intended to take the minimal, non-optional configuration,
 * and any additional configuration can be done with the
 * AIE4_MSG_OP_CONFIGURE_VF message.
 *
 * @param vf_cnt Number of VFs to create (1 - 4).
 *
 * @note Each VF created will default to being assigned all AIE4 columns
 *       for use, so all VFs will share time on the AIE4.
 */
struct aie4_msg_create_vfs_req {
	u32 vf_cnt;
};

/**
 * AIE4_MSG_OP_CREATE_VFS
 * @status: enum aie4_msg_status.
 *     Returns error if VFs already exist (because all VFs are created/destroyed
 *     at the same time, in single calls to firmware), or if the number of VFs
 *     requested was invalid.
 */
struct aie4_msg_create_vfs_resp {
	enum aie4_msg_status status;
};

/**
 * AIE4_MSG_OP_DESTROY_VFS
 * Destroy all VF configuration in the firmware.
 *
 * This message cannot be called multiple times without first creating
 * VFs in firmware; all VFs are intended to be created and
 * destroyed at the same time.
 */
struct aie4_msg_destroy_vfs_req {
	u32 rsvd;
};

/**
 * AIE4_MSG_OP_DESTROY_VFS
 * @status: enum aie4_msg_status.
 *     Returns error if VFs don't exist (because all VFs are created/destroyed
 *     at the same time, in single calls to firmware).
 */
struct aie4_msg_destroy_vfs_resp {
	enum aie4_msg_status status;
};

/**
 * AIE4_MSG_OP_CONFIGURE_VF
 * Configure additional non-default settings for a specific VF
 *
 * @param vf_id The VF this configuration applies to
 * TBD: configurable settings
 */
struct aie4_msg_configure_vf_req {
	u32 vf_id;
};

/**
 * AIE4_MSG_OP_CONFIGURE_VF
 * Configure VF settings response.
 *
 * @status: enum aie4_msg_status.
 */
struct aie4_msg_configure_vf_resp {
	enum aie4_msg_status status;
};

/**
 * AIE4_MSG_OP_CREATE_PARTITION
 * Create a static spatial partition.
 *
 * Each driver must create a static spatial partition before
 * creating any hardware contexts, because each hardware
 * context must specify a static spatial partition that it
 * runs on.
 *
 * @partition_col_start: The starting column of the static spatial partition
 * @partition_col_count: The number of columns in the static spatial partition
 */
struct aie4_msg_create_partition_req {
	u32 partition_col_start;
	u32 partition_col_count;
};

/**
 * AIE4_MSG_OP_CREATE_PARTITION
 * Create static spatial partition response
 * @status: enum aie4_msg_status.
 *     Error will be returned if the column configuration is invalid.
 * @partition_id: The partition identifier
 */
struct aie4_msg_create_partition_resp {
	enum aie4_msg_status status;
	u32 partition_id;
};

/**
 * AIE4_MSG_OP_DESTROY_PARTITION
 * Destroy static partition Request.
 * This also destroys all hardware contexts that were created
 * to run on the static spatial partition.
 *
 * @partition_id: The hardware context ID.
 */
struct aie4_msg_destroy_partition_req {
	u32 partition_id;
};

/**
 * AIE4_MSG_OP_DESTROY_PARTITION
 * Destroy static partition Response.
 *
 * @status: enum aie4_msg_status.
 *     Error will be returned if the partition_id is invalid (e.g. a static
 *     spatial partition with that partition_id doesn't exist).
 */
struct aie4_msg_destroy_partition_resp {
	enum aie4_msg_status status;
};

/**
 * AIE4_MSG_OP_CREATE_HW_CONTEXT
 * Create Hardware Context Request.
 *
 * This message is intended to take the minimal, non-optional configuration,
 * and any additional configuration can be done with the
 * AIE4_MSG_OP_CONFIGURE_HW_CONTEXT message.
 *
 * @partition_id:      The associated partition_id from aie4_msg_create_partition_resp.
 * @request_num_tiles: The number of compute tiles this hardware context runs on. Assumed:
 *                     - 1, 2, 3 = dual mode application using part of 1 column.
 *                     - 4 = single mode application using 1 column.
 *                     - 8 = single mode application using 2 columns.
 *                     - 12 = single mode application using 3 columns.
 * @hsa_addr_high:     The high 32 bits of the HSA queue address.
 * @hsa_addr_low:      The low 32 bits of the HSA queue address.
 * @pasid:             The PASID.
 * @priority_band:     The enum aie4_msg_context_priority_band.
 */
struct aie4_msg_create_hw_context_req {
	u32 partition_id;
	u32 request_num_tiles;
	u32 hsa_addr_high;
	u32 hsa_addr_low;
	union aie4_msg_pasid pasid;
	u32 priority_band;
};

/**
 * AIE4_MSG_OP_CREATE_HW_CONTEXT
 * Create Hardware Context Response.
 *
 * @status:                enum aie4_msg_status.
 * @hw_context_id:         The ID used to refer to the hardware context.
 * @doorbell_offset:       The offset, within the PCIe Aperture1, that the driver should
 *                         write to in order to trigger a doorbell for this hardware context.
 * @job_complete_msix_idx: The MSI-X index that will be triggered when this hardware
 *                         context has completed a job.
 */
struct aie4_msg_create_hw_context_resp {
	enum aie4_msg_status status;
	u32 hw_context_id;
	u32 doorbell_offset;
	u32 job_complete_msix_idx;
};

/**
 * AIE4_MSG_OP_DESTROY_HW_CONTEXT
 * Destroy Hardware Context Request.
 *
 * @hw_context_id: The hardware context ID.
 * @graceful_flag: Gracefully destroy this context, which means waiting until a preemption
 *                 point or a job boundary before the job is stopped.
 */
struct aie4_msg_destroy_hw_context_req {
	u32 hw_context_id;
	u32 graceful_flag:1;
	u32 resvd1:31;
};

/**
 * AIE4_MSG_OP_DESTROY_HW_CONTEXT
 * Destroy Hardware Context Response.
 *
 * @status: enum aie4_msg_status.
 */
struct aie4_msg_destroy_hw_context_resp {
	enum aie4_msg_status status;
};

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

struct aie4_msg_context_config_scheduling {
	/**
	 * The context quantum, in 100ns units.
	 * This value defaults to 5ms.
	 */
	u32 quantum;

	/**
	 * Specifies context priority relative to other contexts within
	 * the same process. Valid values are between -7 and +7.
	 * This value defaults to 0.
	 */
	s32 in_process_priority;

	/**
	 *  When the context belongs to the realtime priority band, indicates
	 * the priority level (0..31) within the realtime band. For all other
	 * bands, this value is ignored.
	 * This value defaults to 0.
	 */
	u32 realtime_band_priority_level;
};

struct aie4_msg_context_config_dpm {
	/** Giga-operations per workload */
	u32 egops;

	/** Workloads per second that this hardware context will run at */
	u32 fps;

	/** Total bytes transferred for 1 workload */
	u32 data_movement;

	/** Maximum time within which workload must be completed */
	u32 latency_in_us;
};

struct aie4_msg_context_config_cert_logging_info {
	/** Log buffer physical address */
	u64 paddr;

	/** Log buffer size */
	u32 size;
};

/** CERT log/debug buffer information. */
struct aie4_msg_context_config_cert_logging {
	/**
	 * Number of buffers that will be configured
	 * Set to 0 to disable this logging/debug mode
	 */
	u32 num : 8;
	u32 rsvd : 24;

	/** Logging information for each core */
	struct aie4_msg_context_config_cert_logging_info info[6];
};

/** Handle information */
struct aie4_msg_context_config_handle {
	u64 handle     : 16;
	u64 reserved   : 48;
};

/**
 * AIE4_MSG_OP_CONFIGURE_HW_CONTEXT
 * Configure an existing hardware context.
 *
 * @hw_context_id:      The hardware context to configure.
 * @property:           The enum aie4_msg_configure_hw_context_property being configured
 */
struct aie4_msg_configure_hw_context_req {
	u32 hw_context_id;
	u32 property;

	union {
		/**
		 * Data for AIE4_CONFIGURE_HW_CONTEXT_PROPERTY_PRIORITY_BAND property
		 * @see enum aie4_msg_context_priority_band for valid values
		 */
		u32 priority_band;

		/** Data for AIE4_CONFIGURE_HW_CONTEXT_PROPERTY_SCHEDULING property. */
		struct aie4_msg_context_config_scheduling scheduling;

		/** Data for AIE4_CONFIGURE_HW_CONTEXT_PROPERTY_DPM property. */
		struct aie4_msg_context_config_dpm dpm;

		/*
		 * Data for the AIE4_CONFIGURE_HW_CONTEXT_PROPERTY_CERT_
		 * {LOG, DEBUG, TRACE}_BUFFER properties.
		 */
		struct aie4_msg_context_config_cert_logging cert_logging;

		/** Data for the AIE4_CONFIGURE_HW_CONTEXT_HANDLE property */
		struct aie4_msg_context_config_handle handle;
	};
};

/**
 * AIE4_MSG_OP_CONFIGURE_HW_CONTEXT
 * Configure context response.
 *
 * @status: enum aie4_msg_status.
 */
struct aie4_msg_configure_hw_context_resp {
	enum aie4_msg_status status;
};

/** AIE tile info. */
struct aie4_tile_info {
	u32 size;
	u16 major;
	u16 minor;
	u16 cols;
	u16 rows;
	u16 core_rows;
	u16 mem_rows;
	u16 shim_rows;
	u16 core_row_start;
	u16 mem_row_start;
	u16 shim_row_start;
	u16 core_dma_channels;
	u16 mem_dma_channels;
	u16 shim_dma_channels;
	u16 core_locks;
	u16 mem_locks;
	u16 shim_locks;
	u16 core_events;
	u16 mem_events;
	u16 shim_events;
	u16 resvd;
};

/**
 * AIE4_MSG_OP_AIE_TILE_INFO
 * AIE tile info request.
 */
struct aie4_msg_aie4_tile_info_req {
	u32 resvd;
};

/**
 * AIE4_MSG_OP_AIE_TILE_INFO
 * AIE tile info response.
 *
 * @status: enum aie4_msg_status.
 * @info:   struct aie4_tile_info.
 */
struct aie4_msg_aie4_tile_info_resp {
	enum aie4_msg_status status;
	struct aie4_tile_info info;
};

/**
 * AIE4_MSG_OP_AIE_VERSION_INFO
 * AIE version info request.
 */
struct aie4_msg_aie4_version_info_req {
	u32 resvd;
};

/**
 * AIE4_MSG_OP_AIE_VERSION_INFO
 * AIE version info response.
 *
 * @status: enum aie4_msg_status.
 * @major:  aie version major number.
 * @minor:  aie version minor number.
 */
struct aie4_msg_aie4_version_info_resp {
	enum aie4_msg_status status;
	u16 major;
	u16 minor;
};

/**
 * AIE4_MSG_OP_AIE_COLUMN_INFO
 * AIE column info request.
 *
 * @dump_buff_addr: dump buffer address.
 * @dump_buff_size: dump buffer size.
 * @pasid:          The PASID.
 * @num_cols:       number of columns.
 * @aie4_bitmap:    bitmap of aie4.
 */
struct aie4_msg_aie4_column_info_req {
	u64 dump_buff_addr;
	u32 dump_buff_size;
	union aie4_msg_pasid pasid;
	u32 num_cols;
	u32 aie4_bitmap;
};

/**
 * AIE4_MSG_OP_AIE_COLUMN_INFO
 * AIE column info response.
 *
 * @status: enum aie4_msg_status.
 * @size:   size of response.
 */
struct aie4_msg_aie4_column_info_resp {
	enum aie4_msg_status status;
	u32 size;
};

/**
 * AIE4_MSG_OP_AIE_DEBUG_ACCESS
 * AIE debug access opcode.
 */
enum aie4_aie_debug_op {
	AIE4_AIE_DBG_OP_BLOCK_READ,
	AIE4_AIE_DBG_OP_BLOCK_WRITE,
	AIE4_AIE_DBG_OP_REG_READ,
	AIE4_AIE_DBG_OP_REG_WRITE,
	AIE4_AIE_MAX_DBG_OP
};

/**
 * AIE4_MSG_OP_AIE_DEBUG_ACCESS
 * AIE debug access request.
 *
 * @opcode: access opcode (see @ref enum aie4_aie_debug_op)
 * @row:    AIE tile row
 * @col:    AIE tile column
 */
struct aie4_msg_aie4_debug_access_req {
	/* Opcode */
	u32 opcode:8;

	/* Context ID */
	u32 hw_context_id:8;

	/* Pair row & col determines Loc of AIE Tiles */
	u32 row:8;
	u32 col:8;

	union {
		struct {
			/* Destination to store read data or Source to write data */
			u64 buffer_addr;
			/* size in bytes of the backing buffer */
			u32 buffer_size;
			/* Address in data memory to read or write */
			u32 mem_addr;
			/* size in bytes to read/write data from/to given memory address */
			u32 mem_size;
			/* PASID information */
			union aie4_msg_pasid pasid;
		} mem_access;

		struct {
			/* Debug register offset address to read or write request */
			u32 reg_addr;
			/* Value to write into Debug register */
			u32 reg_wval;
		} reg_access;
	};
};

/**
 * AIE4_MSG_OP_AIE_DEBUG_ACCESS
 * AIE debug access response.
 *
 * @status:     enum aie4_msg_status.
 */
struct aie4_msg_aie4_debug_access_resp {
	enum aie4_msg_status status;

	union {
		struct {
			/* Debug register Read Value */
			u32 reg_rval;
		} reg_access;
	};
};

/**
 * AIE4_MSG_OP_AIE_COREDUMP
 * @buffer_address: buffer address
 * @buffer_size:    buffer size
 * Each buffer in the buffer list should be
 *     1. Buffer size >= 8kB and <= 64MB
 *     2. Buffer size a power of two
 *     3. Buffer aligned to its size
 */
struct coredump_buffer_list_entry {
	u64 buffer_address;
	u32 buffer_size;
	u32 reserved;
};

/**
 * AIE4_MSG_OP_AIE_COREDUMP
 * @context_id:     hw context ID.
 * @pasid:          The PASID to be used for the buffer list as well as each of the entries.
 * @num_buffers:    The number of struct coredump_buffer_list_entry's in the buffer list.
 * @reserved:       reserved for future use.
 * @buffer_list_addr: address of the buffer list in DRAM.
 * Driver will allocate a buffer list to avoid allocating one large contiguous buffer
 * The buffer for storing the buffer list should adhere to the same limitations as struct
 * coredump_buffer_list_entry above:
 *      1. Buffer size >= 8kB and <= 64MB
 *      2. Buffer size a power of two
 *      3. Buffer aligned to its size
 * The buffer list size should be equal to NEXT_POWER_OF_TWO
 * (num_buffers * sizeof(struct coredump_buffer_list_entry))
 */
struct aie4_msg_aie4_coredump_req {
	u32 context_id;
	union aie4_msg_pasid pasid;
	u32 num_buffers;
	u32 reserved;
	u64 buffer_list_addr;
};

/**
 * AIE4_MSG_OP_AIE_COREDUMP
 * @status:         enum aie4_msg_status.
 * @error_detail:   error message if status is not success
 *
 * If the total size of the buffers in buffer list is smaller
 * than the required size to dump the whole AIE partition, we
 * return errors with the required size.
 */
struct aie4_msg_aie4_coredump_resp {
	enum aie4_msg_status status;
	u32 error_detail[8];
};

/**
 * AIE4_MSG_OP_SETUP_PRIORITY_BANDS_SCHEDULING
 * After adapter startup and before scheduling the first GPU work item,
 * the OS sets up the GPU scheduler priority band configuration. In
 * addition, this call can be made in the middle of GPU work execution,
 * and the GPU scheduler needs to use the new value during the next
 * yield calculation.
 */
struct aie4_msg_runtime_config_setup_scheduling_priority_bands_req {
	/**
	 * Default quantum in 100ns units for scheduling across processes
	 * within a priority band.
	 */
	u64 process_quantum_for_band[AIE4_CONTEXT_PRIORITY_BAND_COUNT];

	/**
	 * For normal priority band, specifies the target GPU percentage
	 * in situations when it's starved by the focus band. Valid values
	 * are between 0 and 50, with the default value on desktop
	 * systems being 10.
	 */
	u32 target_normal_band_percentage;
};

/**
 * AIE4_MSG_OP_SETUP_PRIORITY_BANDS_SCHEDULING
 * Response to aie4_msg_runtime_config_setup_scheduling_priority_bands_req
 *
 * @status: enum aie4_msg_status.
 */
struct aie4_msg_runtime_config_setup_scheduling_priority_bands_resp {
	enum aie4_msg_status status;
};

/** For changing the power slider value */
enum aie4_msg_power_hint {
	AIE4_AC_PERF = 0x0,  /* Best Performance */
	AIE4_AC_BAL  = 0x1,  /* Balanced */
	AIE4_AC_VSS  = 0x2,  /* Best Efficiency */
	AIE4_AC_NINT = 0x3,  /* Best Efficiency */

	AIE4_DC_PERF = 0x4,  /* Best Performance */
	AIE4_DC_BAL  = 0x5,  /* Balanced */
	AIE4_DC_VSS  = 0x6,  /* Best Efficiency */
	AIE4_DC_NINT = 0x7,  /* Best Efficiency */

	AIE4_POWER_HINT_COUNT,
};

/**
 * AIE4_MSG_OP_POWER_HINT
 * Adjust power hint
 *
 * @power_hint: The enum aie4_msg_power_hint power slider hint
 */
struct aie4_msg_power_hint_req {
	u32 power_hint;
};

/**
 * AIE4_MSG_OP_POWER_HINT
 * Response to aie4_msg_power_hint_req
 *
 * @status: enum aie4_msg_status.
 */
struct aie4_msg_power_hint_resp {
	enum aie4_msg_status status;
};

/**
 * For the xrtsmi override
 * Firmware will default into the POWER_MODE_DEFAULT state.
 */
enum aie4_msg_power_override {
	AIE4_POWER_MODE_DEFAULT     = 0x0,
	AIE4_POWER_MODE_USER_LOW    = 0x1,
	AIE4_POWER_MODE_USER_MEDIUM = 0x2,
	AIE4_POWER_MODE_USER_HIGH   = 0x3,
	AIE4_POWER_MODE_USER_TURBO  = 0x4,
	AIE4_POWER_MODE_COUNT,
};

/**
 * AIE4_MSG_OP_POWER_OVERRIDE
 * Power Override request
 *
 * @power_mode: The enum aie4_msg_power_override requested power mode override
 */
struct aie4_msg_power_override_req {
	u32 power_mode;
};

/**
 * AIE4_MSG_OP_POWER_OVERRIDE
 * Response to aie4_msg_power_override_req
 *
 * @status: enum aie4_msg_status.
 */
struct aie4_msg_power_override_resp {
	enum aie4_msg_status status;
};

/**
 * Self test Result codes
 */
enum aie4_msg_selftest_result {
	AIE4_MSG_SELFTEST_RESULT_OK,
	AIE4_MSG_SELFTEST_RESULT_ERROR,
};

#define SELF_TEST_NAME_LEN      (sizeof(u32) * 4)

/**
 * AIE4_MSG_OP_RUN_SELFTEST
 * Self test request.
 * The provided shim dma dram addr needs to be
 * aligned to 4096 and have a 256K size
 */
struct aie4_msg_selftest_req {
	u32 selftest_id;
	u32 timeout;
	union {
		u64 log_dram_address;
		u64 shim_dma_dram_address;
	};
	u64 hsa_dram_address;
	union aie4_msg_pasid pasid;
};

/**
 * AIE4_MSG_OP_RUN_SELFTEST
 * Self test response.
 *
 * @status:           enum aie4_msg_status.
 * @selftest_name:    ASCII test name identified
 * @selftest_id:      selftest ID
 * @selftest_result:  enum aie4_msg_selftest_result
 * @selftest_data:    test-specific data return
 */
struct aie4_msg_selftest_resp {
	enum aie4_msg_status status;
	u8 selftest_name[SELF_TEST_NAME_LEN];
	u32 selftest_id;
	u32 selftest_result;
	u32 selftest_data[10];
};

#define TRACE_COUNT_API 16
#define MAX_NUM_SUPERVISORS_API 4
#define TOTAL_NUM_UC_API 6
#define CONFIG_NPUFW_NUM_COLUMNS_API 3

// Define telemetry_opcodes_t before it's used in aie4_telemetry_t
struct telemetry_opcodes {
	// Updated by hypervisor in hyp_handle_command().
	u32 hyp_opcode[TRACE_COUNT_API];
	// Updated by syscall from supervisor in sup_handle_command().
	u32 sup_opcode[MAX_NUM_SUPERVISORS_API][TRACE_COUNT_API];

	// opcode counters (16-bit to minimize SRAM usage, wraps safely at UINT16_MAX)
	struct {
		u16 hyp_at;
		u16 sup_at[MAX_NUM_SUPERVISORS_API];
#if ((MAX_NUM_SUPERVISORS_API + 1) % 2) != 0
		u16 reserved; // Padding to make size multiple of 32 bits
#endif
	} counters;

};

// Clock mode info for different domains
struct clk_deep_slp {
	u8 ipuaie;
	u8 ipuhclk;
	u8 nbif;
	u8 axi2sdp;
	u8 mpipu;
	u8 reserved[3]; // Padding to make size multiple of 32 bits
};

struct aie4_telemetry {
	// Control counter
	u8    enabled;

	u8 reserved[3]; // Padding to make size multiple of 32 bits

	struct clk_deep_slp deep_slp;

	// Interrupts updated from mpfw_comm_isr().
	u64 l1_interrupt;

	// The number of times a thread was started when returning from an
	// interrupt/exception. called from yield_manager_handle_context_execution_start()
	// recorded per Supervisor + (1) Hypervisor
	u64 context_starting[MAX_NUM_SUPERVISORS_API + 1];

	// The number of times a thread was scheduled by in schedule_next in HW Scheduler.
	// recorded per Supervisor + (1) Hypervisor
	u64 scheduler_scheduled[MAX_NUM_SUPERVISORS_API + 1];

	// The number of DMA requests made. Currently only hypervisor can make DMA requests.
	u64 did_dma;

	// The number of times a partition was acquired by a supervisor context.
	u64 resource_acquired[MAX_NUM_SUPERVISORS_API];

	// Telemetry opcodes.
	struct telemetry_opcodes opcodes;

	// Preemption counters
	u64 preemption_frame_boundary_counter[TOTAL_NUM_UC_API];
	u64 preemption_checkpoint_event_counter[TOTAL_NUM_UC_API];
};

/* The telemetry types requestable for CERT PERF counter. */
enum aie4_msg_telemetry_type {
	AIE4_TELEMETRY_TYPE_DISABLED = 0,
	AIE4_TELEMETRY_TYPE_PERF_COUNTER,
	AIE4_TELEMETRY_TYPE_MAX_SIZE,
};

/**
 * AIE4_MSG_OP_GET_TELEMETRY
 * AIE get telemetry request.
 *
 * @type:           enum telemetry_type.
 * @buf_addr:       buffer address.
 * @pasid:          The PASID.
 * @buf_size:       buffer size.
 * @hw_context_id:  hw context ID.
 */
struct aie4_msg_get_telemetry_req {
	u32 type;
	u64 buf_addr;
	union aie4_msg_pasid pasid;
	u32 buf_size;
	u32 hw_context_id;
};

/**
 * AIE4_MSG_OP_GET_TELEMETRY
 * AIE get telemetry response.
 *
 * @status: enum aie4_msg_status.
 */
struct aie4_msg_get_telemetry_resp {
	enum aie4_msg_status status;
};

/**
 * AIE4_MSG_OP_CALIBRATE_CLOCK_TRACE request structure.
 *
 * @time_base_ns: Time base in ns.
 */
struct aie4_msg_calibrate_clock_trace_req {
	u64 time_base_ns;
};

/**
 * AIE4_MSG_OP_CALIBRATE_CLOCK_TRACE response structure.
 *
 * @status: enum aie4_msg_status.
 */
struct aie4_msg_calibrate_clock_trace_resp {
	enum aie4_msg_status status;
};

/** * Event trace destination options.  */
enum aie4_msg_event_trace_destination {
	AIE4_MSG_EVENT_TRACE_DEST_DRAM,
	AIE4_MSG_EVENT_TRACE_DEST_COUNT
};

/**
 * Event trace timestamp options.
 *
 * @AIE4_MSG_EVENT_TRACE_TIMESTAMP_NONE:
 *          The timestamp value will be all 0's.
 * @AIE4_MSG_EVENT_TRACE_TIMESTAMP_NS_OFFSET:
 *          The timestamp value will be a nanosecond offset
 *          from the base offset value calibrated with AIE4_MSG_CALIBRATE_CLOCK.
 */
enum aie4_msg_event_trace_timestamp {
	AIE4_MSG_EVENT_TRACE_TIMESTAMP_NONE,
	AIE4_MSG_EVENT_TRACE_TIMESTAMP_NS_OFFSET,
	AIE4_MSG_EVENT_TRACE_TIMESTAMP_COUNT
};

/**
 * AIE4_MSG_OP_START_EVENT_TRACE request structure.
 *
 * The DRAM buffer will be treated as a ring buffer, with the last 4096
 * bytes containing metadata, not actual log entries, which means:
 * - The DRAM has (dram_buffer_size - 4096) usable bytes (dram_buffer_size_usable).
 * - The size of the buffer must be a power of 2 bytes between 128KB and 64MB,
 *   and the buffer must not overlap across a 64MB boundary. This is due to
 *   HUBIF_DA TLB limitations within the MPIPU.
 *
 * The format of the metadata:
 * - u64 tail_offset
 * - u64 head_offset
 * - u32 version
 * - u32 configuration
 * - The rest is reserved
 *
 * - head_offset is the byte offset where the next log entry will be placed.
 *   This value forever increases, so to determine the byte offset within the
 *   buffer, you need to take `head_offset % (dram_buffer_size_usable)`.
 * - tail_offset is the byte offset to the next valid log entry.
 *   This value forever increases, so to determine the byte offset within the
 *   buffer, you need to take `tail_offset % (dram_buffer_size_usable)`.
 * - head_offset == tail_offset means it's empty
 * - head_offset - tail_offset > dram_buffer_size_usable means there was an
 *   overflow in data written to the dram buffer, and some data has been
 *   lost.
 * - configuration[bit0] == 1 if timestamping is enabled, 0 otherwise.
 * - Note: the MPIPU is not capable of atomically writing head_offset
 *   in the DRAM buffer, so there is a very small race condition window
 *   where only half of the value might be updated.
 *
 *   If the driver can't keep up with firmware writing the DRAM buffer, it
 *   has several options, including:
 *   - Stop the firmware logging and consume the latest
 *     data in the buffer, which is probably the most relevant.
 *   - Discard everything in the buffer by setting tail_offset = head_offset.
 *
 * @event_trace_categories: Specify the traces to be included. EVENT_TRACE_CATEGORY_* bits
 *  that are set will be traced.
 * @event_trace_dest: Specify the trace destination (enum aie4_msg_event_trace_destination).
 * @event_trace_timestamp: Specify the timestamp source to use
 *  (enum aie4_msg_event_trace_timestamp).
 * @dram_buffer_address: Address of the DRAM buffer used as a ring buffer for trace data.
 * @dram_buffer_size: Size of the DRAM buffer. Must be a power of 2 between 128KB and 64MB.
 * @pasid: The PASID needed to access the DRAM buffer.
 */
struct aie4_msg_start_event_trace_req {
	u64 event_trace_categories;
	u32 event_trace_dest;
	u32 event_trace_timestamp;

	u64 dram_buffer_address;
	u32 dram_buffer_size;
	union aie4_msg_pasid pasid;
};

struct aie4_msg_start_event_trace_resp {
	enum aie4_msg_status status;
};

/**
 * AIE4_MSG_OP_GET_APP_HEALTH_STATUS
 * App Health Check return status.
 *
 * @APP_HEALTH_CHECK_SUCCESS:
 *          The app_health request was successful
 * @APP_HEALTH_CHECK_INVALID_PARAM:
 *          Either request was not the right size or context id was invalid
 * @APP_HEALTH_CHECK_DRAM_BUFFER_SIZE_INVALID:
 *          Indicates buffer size from driver is invalid
 * @APP_HEALTH_CHECK_NOAVAIL:
 *          TLB failed, or PASID not available
 */
enum app_health_status {
	APP_HEALTH_CHECK_SUCCESS = 0,
	APP_HEALTH_CHECK_INVALID_PARAM,
	APP_HEALTH_CHECK_DRAM_BUFFER_SIZE_INVALID,
	APP_HEALTH_CHECK_NOAVAIL,
};

/**
 * AIE4_MSG_OP_GET_APP_HEALTH_STATUS
 * Hardware context status states.
 *
 * @CTX_STATUS_UNASSIGNED:
 *          Hardware context has not been created or has been removed.
 * @CTX_STATUS_ERROR:
 *          Hardware context has triggered an error. It is important that this
 *          state is less than CTX_STATUS_IDLE, as it indicates the context is not valid.
 * @CTX_STATUS_IDLE:
 *          Hardware context has been created but currently has no work to do.
 * @CTX_STATUS_RUNNABLE:
 *          Hardware context has work to do and is ready to run.
 * @CTX_STATUS_RUNNING:
 *          Hardware context is currently running.
 * @CTX_STATUS_PREEMPTING:
 *          Hardware context has requested preemption and is waiting for acknowledgment from uC
 */
enum hw_ctx_status {
	CTX_STATUS_UNASSIGNED = 0,
	CTX_STATUS_ERROR,
	CTX_STATUS_IDLE,
	CTX_STATUS_RUNNABLE,
	CTX_STATUS_RUNNING,
	CTX_STATUS_PREEMPTING,
};

/**
 * AIE4_MSG_OP_GET_APP_HEALTH_STATUS
 * App health check message to help driver and XRT debug exceptions and/or to
 * monitor the health of a hardware context application.
 *
 * @context_id: The unique identifier for the hardware context.
 * @pasid: The PASID
 * @report_buff_addr: The dram address of the buffer where the health report will be stored.
 * @report_buff_size: The size of the dram buffer allocated for the health report.
 */
struct aie4_msg_app_health_req {
	u32 context_id;
	union aie4_msg_pasid pasid;
	u64 report_buff_addr;
	u32 report_buff_size;
};

/**
 * AIE4_MSG_OP_GET_APP_HEALTH_STATUS
 * @status: enum aie4_msg_status.
 * @app_health_status: enum app_health_status
 * @min_buffer_size: 0 if success, expected buffer size if app_health_status is
 * APP_HEALTH_CHECK_DRAM_BUFFER_SIZE_INVALID
 * In case the report_buff_size in request is too small, Firmware should
 * return error code APP_HEALTH_CHECK_DRAM_BUFFER_SIZE_INVALID and
 * put the expected minimum buffer size in error_detail[1]
 */
struct aie4_msg_app_health_resp {
	enum aie4_msg_status status;
	union {
		u32 error_detail[8];
		struct {
			u32 app_health_status;
			u32 min_buffer_size;
		} s;
	} u;
};

/**
 * AIE4_MSG_OP_GET_APP_HEALTH_STATUS
 * The struct that will be stored in the provided DRAM buffer.
 * @major_version: The major version of the health report structure (16 bits).
 * @minor_version: The minor version of the health report structure (16 bits).
 * @context_id: The context ID copied from the request, used to identify the application context.
 * @ctx_status: The enum hw_ctx_status of the requested context as tracked by the hardware
 *  scheduler.
 * @num_uc: The number of uC included in the health report.
 * @uc_info: Array containing health information for each uC.
 */
struct aie4_msg_app_health_report {
	u32 major_version : 16;
	u32 minor_version : 16;
	u32 context_id;
	u32 ctx_status;
	u32 num_uc;
	struct uc_health_info uc_info[AIE4_MPNPUFW_MAX_UC_COUNT];
};

/** The async event types returned in each async response message. */
enum aie4_msg_async_event_type {
	AIE4_ASYNC_EVENT_TYPE_AIE_ERROR,
	AIE4_ASYNC_EVENT_TYPE_EXCEPTION,
	AIE4_ASYNC_EVENT_TYPE_CTX_ERROR,
	MAX_AIE4_ASYNC_EVENT_TYPE,
};

/**
 * AIE4_MSG_OP_ASYNC_EVENT_MSG
 * Async event message config.
 * No response is sent for this message.
 *
 * @buff_addr: Address of request buffer.
 * @pasid:     The PASID.
 * @buff_size: size of request buffer.
 */
struct aie4_msg_async_event_config_req {
	u64 buff_addr;
	union aie4_msg_pasid pasid;
	u32 buff_size;
};

/**
 * AIE4_MSG_OP_ASYNC_EVENT_MSG
 * Async event message.
 * Sent asynchronously when an error or exception occur.
 *
 * @status: enum aie4_msg_status.
 * @type:   enum async_event_type.
 */
struct aie4_msg_async_event_config_resp {
	enum aie4_msg_status status;
	u32 type;
};

/* The async context error types */
enum aie4_msg_async_ctx_error_type {
	AIE4_ASYNC_EVENT_CTX_ERR_HWSCH_FAILURE,
	AIE4_ASYNC_EVENT_CTX_ERR_STOP_FAILURE,
	AIE4_ASYNC_EVENT_CTX_ERR_PREEMPTION_FAILURE,
	AIE4_ASYNC_EVENT_CTX_ERR_PREEMPTION_TIMEOUT,
	AIE4_ASYNC_EVENT_CTX_ERR_NEW_PROCESS_FAILURE,
	AIE4_ASYNC_EVENT_CTX_ERR_UC_CRITICAL_ERROR,
	AIE4_ASYNC_EVENT_CTX_ERR_UC_COMPLETION_TIMEOUT,
};

/* The data shared on async buffers after a context error */
struct aie4_async_ctx_error {
	u32 ctx_id;
	u32 error_type;
	union {
		struct aie4_msg_app_health_report app_health_report;
	};
};

/**
 * AIE4_MSG_OP_STOP_EVENT_TRACE
 * Stop event trace request.
 *
 * Firmware will stop tracing all events, flush any remaining logs
 * in SRAM, and unmap the DRAM buffer used for tracing.
 *
 * @resvd: Reserved for future use.
 */
struct aie4_msg_stop_event_trace_req {
	u32 resvd;
};

struct aie4_msg_stop_event_trace_resp {
	enum aie4_msg_status status;
};

/**
 * Request structure for setting event trace categories.
 *
 * @event_trace_categories:
 *      Bitmask to specify the traces to be included.
 *      EVENT_TRACE_CATEGORY_* bits that are set will be traced.
 *      These categories are defined in the master yaml file used
 *      to auto-generate the trace header file.
 */
struct aie4_msg_set_event_trace_categories_req {
	u64 event_trace_categories;
};

struct aie4_msg_set_event_trace_categories_resp {
	enum aie4_msg_status status;
};

/**
 * @ipuaie_clk        0 to disable the override, != 0 to enable it.
 * @ipuh_clk          0 to disable the override, != 0 to enable it.
 * @nbif_ds_allow_clk 0 to disable the override, != 0 to enable it.
 * @axi2sdp_clk       0 to disable the override, != 0 to enable it.
 * @common_pwr        0 to disable the override, != 0 to enable it.
 * @l1mmu_pwr         0 to disable the override, != 0 to enable it.
 * @aie_pwr           0 to disable the override, != 0 to enable it.
 *
 * @note The struct is padded out to be a multiple of 4 bytes.
 */
struct aie4_msg_runtime_config_clock_power_override {
	u8 ipuaie_clk;
	u8 ipuh_clk;
	u8 nbif_ds_allow_clk;
	u8 axi2sdp_clk;
	u8 common_pwr;
	u8 l1mmu_pwr;
	u8 aie_pwr;
	u8 padding;
};

/**
 * @enabled 0 to disable force preemption, != 0 to enable force preemption.
 *
 * @note The struct is padded out to be a multiple of 4 bytes.
 */
struct aie4_msg_runtime_config_force_preemption {
	u8 enabled;
	u8 padding[3];
};

/**
 * L1MMU prefetch range configuration.
 *
 * @prefetch_range: Hardware prefetch range value for L1MMU.
 */
struct aie4_msg_runtime_config_l1mmu_prefetch_range {
	u32 prefetch_range;
};

/**
 * @brief Runtime configuration for DPM override.
 *
 * @force_dpm:
 *   - 1: Override the DPM levels for IPUHCLK and IPUAIECLK.
 *   - 0: Do not override; use default DPM behavior.
 *
 * @forced_ipuhclk_dpm_level: DPM level to force for the IPUHCLK clock domain if override is
 *  enabled.
 * @forced_ipuaieclk_dpm_level:  DPM level to force for the IPUAIECLK clock domain if override
 *  is enabled.
 *
 * @note The struct is padded out to be a multiple of 4 bytes.
 */
struct aie4_msg_runtime_config_dpm_override {
	u8 force_dpm;
	u8 forced_ipuhclk_dpm_level;
	u8 forced_ipuaieclk_dpm_level;
	u8 padding;
};

/**
 * @enabled 0 to tear down partitions on IDLE, != 0 to keep partitions running.
 *
 * @note The struct is padded out to be a multiple of 4 bytes.
 */
struct aie4_msg_runtime_config_keep_partitions {
	u8 enabled;
	u8 padding[3];
};

/**
 * Dynamic logging level configuration.
 *
 * @dynamic_logging_level: dynamic logging level.
 */
struct aie4_msg_runtime_config_dynamic_logging_level {
	u32 log_level;
};

/**
 * CERT timeout configuration.
 *
 * @timeout_ms: Timeout in milliseconds for CERT operations.
 */
struct aie4_msg_runtime_config_cert_timeout {
	u32 timeout_ms;
};

/**
 * Event trace current status for the calling function.
 *
 * @enabled 1 to indicate event trace is currently enabled, 0 otherwise.
 * @categories Bitmask for the current enabled categories.
 */
struct aie4_msg_runtime_config_event_trace_status {
	u8 enabled;
	u8 padding[3];
	u64 categories;
};

/** For changing the DPM state */
enum aie4_msg_runtime_dpm_enable {
	AIE4_DPM_DISABLE = 0x0,
	AIE4_DPM_ENABLE = 0x1,
};

/**
 * DPM Enable configuration.
 *
 * @state: The DPM's enabling status.
 *   - 1: Enable.
 *   - 0: Disable.
 */
struct aie4_msg_runtime_config_dpm_enable {
	u32 state;
};

/** For changing the UTL state */
enum aie4_msg_runtime_utl {
	AIE4_UTL_DISABLE = 0x0,
	AIE4_UTL_ENABLE = 0x1,
};

/**
 * UTL configuration.
 *
 * @state: The UTL's configuration status.
 *   - 1: Enable.
 *   - 0: Disable.
 */
struct aie4_msg_runtime_config_utl_enable {
	u32 state;
};

/** For changing the runtime error handling mode */
enum aie4_msg_runtime_error_handling_mode {
	AIE4_ERROR_HANDLING_MODE_NORMAL = 0x0,
	AIE4_ERROR_HANDLING_MODE_DEBUG = 0x1,

	AIE4_ERROR_HANDLING_MODE_COUNT
};

/**
 * Error handling configuration.
 *
 * @mode: The error handling mode.
 *   - 0: Normal error handling.
 *   - 1: Debug error handling.
 */
struct aie4_msg_runtime_config_error_handling {
	u32 mode;
};

/**
 * Enable/disable the HWS debug mode.
 */
enum aie4_msg_runtime_config_hws_debug_mode_enable {
	AIE4_RUNTIME_HWS_DEBUG_MODE_DISABLE = 0,
	AIE4_RUNTIME_HWS_DEBUG_MODE_ENABLE
};

/**
 * @brief Runtime configuration for hardware scheduler debug mode
 *
 * This structure defines the configuration parameters for enabling and
 * controlling the hardware scheduler (HWS) debug mode in NPUFW.
 *
 * @enable != 0 to enable the debug mode, 0 to disable it
 * @ctx_id The hardware context ID for which to enable debug mode
 */
struct aie4_msg_runtime_config_hws_debug_mode {
	u8  enable;
	u8  ctx_id;
	u16 reserved;
};

/**
 * Context timeout configuration.
 *
 * @context_timeout_ms: Context timeout in milliseconds, or 0 to disable context timeouts
 */
struct aie4_msg_runtime_config_context_timeout {
	u32 timeout_ms;
};

/**
 * Context switch hysteresis configuration.
 *
 * @timeout_us: Hysteresis time in microseconds for keeping a context loaded
 *              in the AIE after it becomes idle, or 0 to disable hysteresis
 */
struct aie4_msg_runtime_config_ctx_switch_hysteresis {
	u32 timeout_us;
};

enum aie4_msg_runtime_config_type {
	AIE4_RUNTIME_CONFIG_CLOCK_POWER_OVERRIDE,
	AIE4_RUNTIME_CONFIG_FORCE_PREEMPTION,
	AIE4_RUNTIME_CONFIG_L1MMU_PREFETCH_RANGE,
	AIE4_RUNTIME_CONFIG_KEEP_PARTITIONS,
	AIE4_RUNTIME_CONFIG_DPM_OVERRIDE,
	AIE4_RUNTIME_CONFIG_DYNAMIC_LOGGING_LEVEL,
	AIE4_RUNTIME_CONFIG_CERT_TIMEOUT,
	AIE4_RUNTIME_CONFIG_EVENT_TRACE_STATUS,
	AIE4_RUNTIME_CONFIG_DPM_ENABLE,
	AIE4_RUNTIME_CONFIG_UTL_ENABLE,
	AIE4_RUNTIME_CONFIG_ERROR_HANDLING,
	AIE4_RUNTIME_CONFIG_HWS_DEBUG_MODE,
	AIE4_RUNTIME_CONFIG_CONTEXT_TIMEOUT,
	AIE4_RUNTIME_CONFIG_CTX_SWITCH_HYSTERESIS,

	AIE4_MAX_RUNTIME_CONFIG
};

/**
 * AIE4_MSG_OP_SET_RUNTIME_CONFIG
 * Allows control of various runtime configurations.
 *
 * @type: enum aie4_msg_runtime_config_type.
 * @note In addition to passing the `type`, the caller needs
 *       to pass the struct associated with `type` immediately
 *       after `type`. The valid combinations are:
 *       - AIE4_RUNTIME_CONFIG_CLOCK_POWER_OVERRIDE: aie4_msg_runtime_config_clock_power_override
 *       - AIE4_RUNTIME_CONFIG_FORCE_PREEMPTION: aie4_msg_runtime_config_force_preemption
 *       - AIE4_RUNTIME_CONFIG_L1MMU_PREFETCH_RANGE: aie4_msg_runtime_config_l1mmu_prefetch_range
 *       - AIE4_RUNTIME_CONFIG_KEEP_PARTITIONS: aie4_msg_runtime_config_keep_partitions
 *       - AIE4_RUNTIME_CONFIG_DPM_OVERRIDE: aie4_msg_runtime_config_dpm_override
 *       - AIE4_RUNTIME_CONFIG_DYNAMIC_LOGGING_LEVEL: aie4_msg_runtime_config_dynamic_logging_level
 *       - AIE4_RUNTIME_CONFIG_CERT_TIMEOUT: aie4_msg_runtime_config_cert_timeout
 *       - AIE4_RUNTIME_CONFIG_EVENT_TRACE_STATUS: aie4_msg_runtime_config_event_trace_status
 *       - AIE4_RUNTIME_CONFIG_DPM_ENABLE: aie4_msg_runtime_config_dpm_enable
 *       - AIE4_RUNTIME_CONFIG_UTL_ENABLE: aie4_msg_runtime_config_utl_enable
 *       - AIE4_RUNTIME_CONFIG_ERROR_HANDLING: aie4_msg_runtime_config_error_handling
 *       - AIE4_RUNTIME_CONFIG_HWS_DEBUG_MODE: aie4_msg_runtime_config_hws_debug_mode
 *
 *      This is done so that the 'interface' to the driver doesn't
 *      have to change regardless of which runtime configuration options
 *      are added in the future.
 *
 *      The `total_msg_size` header value can be checked to make sure
 *      that the total size of the `type` parameter plus the associated
 *      data is valid.
 */
struct aie4_msg_set_runtime_cfg_req {
	u32 type;
	u8 data[4]; // Additional data here.
};

/**
 * AIE4_MSG_OP_SET_RUNTIME_CONFIG
 * Runtime config response
 *
 * @status: enum aie4_msg_status.
 */
struct aie4_msg_set_runtime_cfg_resp {
	enum aie4_msg_status status;
};

/**
 * AIE4_MSG_OP_GET_RUNTIME_CONFIG
 * Get the state of runtime configurations.
 *
 * @type: enum aie4_msg_runtime_config_type.
 */
struct aie4_msg_get_runtime_cfg_req {
	u32 type;
};

/**
 * AIE4_MSG_OP_GET_RUNTIME_CONFIG
 * Runtime config response
 *
 * @status: enum aie4_msg_status.
 * @note In addition to returning `status`, the struct associated with
 *       `type` from the `aie4_msg_get_runtime_cfg_req` is returned immediately
 *       after `status`.
 */
struct aie4_msg_get_runtime_cfg_resp {
	enum aie4_msg_status status;
	// Additional data here.
};

#define AIE4_MPNPUFW_DRAM_WORK_BUFFER_MIN_SIZE    (4 * 1024 * 1024)  /* 4 MB */

/**
 * AIE4_MSG_OP_DRAM_WORK_BUFFER
 * Specifies the DRAM buffer that the mpnpufw requires for runtime.
 * This must be set before any contexts can be created.
 *
 * @buff_addr: The buffer address. This must be aligned to @buff_size
 * @pasid: The PASID.
 * @buff_size: The buffer size.  The valid sizes are:
 *                4 MB, 8 MB, 16 MB, 32 MB, or 64 MB
 */
struct aie4_msg_dram_work_buffer_req {
	u64 buff_addr;
	union aie4_msg_pasid pasid;
	u32 buff_size;
};

/**
 * AIE4_MSG_OP_DRAM_WORK_BUFFER
 * DRAM buffer response
 *
 * @status: enum aie4_msg_status.
 */
struct aie4_msg_dram_work_buffer_resp {
	enum aie4_msg_status status;
};

/**
 * AIE4_MSG_OP_RELEASE_DRAM_WORK_BUFFER
 * Instructs the mpnpufw to release the DRAM work buffer so the OS can reclaim
 * the memory. Any features that depend on this buffer will be disabled and no
 * new contexts can be created. All existing contexts must be destroyed before
 * sending this message.
 *
 * @resvd Reserved for future use.
 */
struct aie4_msg_release_dram_work_buffer_req {
	u32 resvd;
};

/**
 * AIE4_MSG_OP_RELEASE_DRAM_WORK_BUFFER
 * Release DRAM work buffer response
 *
 * @status: enum aie4_msg_status
 */
struct aie4_msg_release_dram_work_buffer_resp {
	enum aie4_msg_status status;
};

#pragma pack(pop)

#endif /* _AIE4_AIE4_MSG_PRIV_H_ */

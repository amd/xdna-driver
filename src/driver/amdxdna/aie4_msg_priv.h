/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2024-2025, Advanced Micro Devices, Inc.
 * All Rights Reserved.
 */

#ifndef _AIE4_MSG_PRIV_H_
#define _AIE4_MSG_PRIV_H_

#pragma pack(push, 1)

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

#define PROTOCOL_MAJOR	5
#define PROTOCOL_MINOR	1

/**
 * opcodes between driver and firmware
 *
 * Note: in order to support basic compatibility check, we define basic principle below:
 *       1) All opcodes cannot be changed once being added;
 *       2) AIE4_MSG_OP_IDENTIFY should not be changed nor obsoleted;
 *       3) All other opcodes can only be obsoleted;
 *       4) Add new opcode for new operation;
 *       5) Any obsoleted or unknown opcodes, firmware will return AIE4_STATUS_NOTSUPP;
 *       6) Bump protocol_major when driver cannot work with existing or new opcode;
 *          Bump protocol_minor when driver can ignore an opcode;
 */
enum aie4_opcode {
	AIE4_MSG_OP_ECHO                             = 0x10001,
	AIE4_MSG_OP_IDENTIFY                         = 0x10002,
	AIE4_MSG_OP_SUSPEND                          = 0x10003,
	AIE4_MSG_OP_ASYNC_EVENT_MSG                  = 0x10004,
	AIE4_MSG_OP_RUN_SELFTEST                     = 0x10005,
	AIE4_MSG_OP_GET_TELEMETRY                    = 0x10006,
	AIE4_MSG_OP_SET_RUNTIME_CONFIG               = 0x10007,
	AIE4_MSG_OP_GET_RUNTIME_CONFIG               = 0x10008,
	AIE4_MSG_OP_CALIBRATE_CLOCK                  = 0x10009,
	AIE4_MSG_OP_FW_TRACE_START                   = 0x1000A,
	AIE4_MSG_OP_FW_TRACE_STOP                    = 0x1000B,
	AIE4_MSG_OP_SET_FW_TRACE_CATEGORIES          = 0x1000C,
	AIE4_MSG_OP_ATTACH_WORK_BUFFER               = 0x1000D,
	AIE4_MSG_OP_DETACH_WORK_BUFFER               = 0x1000E,

	AIE4_MSG_OP_FW_LOG_START                     = 0x20004,
	AIE4_MSG_OP_FW_LOG_STOP                      = 0x20005,

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
	AIE4_MSG_OP_SET_CLOCK_MODE                   = 0x3000C,
	AIE4_MSG_OP_SET_POWER_CNTRL                  = 0x3000D,
	AIE4_MSG_OP_AIE_DEBUG_ACCESS                 = 0x3000E,
};

/** The status that is returned with each response message. */
enum aie4_msg_status {
	AIE4_STATUS_SUCCESS = 0x0,
	AIE4_STATUS_ERROR = 0x1,
	AIE4_STATUS_NOTSUPP = 0x2,
	AIE4_STATUS_ASYNC_EVENT_MSGS_FULL = 0x3,
	MAX_AIE4_STATUS_CODE = 0x4,
};

/** Context priority band names */
enum aie4_context_priority_band {
	CONTEXT_PRIORITY_BAND_IDLE = 0,
	CONTEXT_PRIORITY_BAND_NORMAL,
	CONTEXT_PRIORITY_BAND_FOCUS,
	CONTEXT_PRIORITY_BAND_REAL_TIME,
	CONTEXT_PRIORITY_BAND_COUNT
};

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
		u32 pasid_vld	: 1;
		u32 rsvd	: 11;
		u32 pasid	: 20;
	} f;
};

/**
 * A test command echo values from request back to the caller.
 *
 * @val1: The first value to be echo'd.
 * @val2: The second value to be echo'd.
 */
struct aie4_echo_req {
	u32 val1;
	u32 val2;
};

/**
 * echo command response.
 *
 * @status: enum aie4_msg_status.
 * @val1:   The first response value.
 * @val2:   The second response value.
 */
struct aie4_echo_resp {
	enum aie4_msg_status status;
	u32 val1;
	u32 val2;
};

/**
 * Identify firmware version.
 */
struct aie4_identify_req {
	u32 resvd;
};

/**
 * response firmware's current version.
 *
 * @status:         enum aie4_msg_status.
 * @fw_major:       firmware major number
 * @fw_minor:       firmware minor number
 * @fw_patch:       firmware patch number
 * @fw_build:       firmware build number
 */
struct aie4_identify_resp {
	enum aie4_msg_status status;
	u32 fw_major;
	u32 fw_minor;
	u32 fw_patch;
	u32 fw_build;
};

/**
 * Suspend NPU request.
 */
struct aie4_suspend_req {
	u32 resvd;
};

/**
 * response to suspend request.
 *
 * @status: enum aie4_msg_status
 */
struct aie4_suspend_resp {
	enum aie4_msg_status status;
};

/** The async event types returned in each async response message. */
enum aie4_async_event_type {
	ASYNC_EVENT_TYPE_AIE_ERROR,
	ASYNC_EVENT_TYPE_EXCEPTION,
	MAX_ASYNC_EVENT_TYPE,
};

/* TODO: does this belong in the interface here? */
#define ASYNC_BUF_SIZE		SZ_8K

/**
 * Async event message config.
 * No response is sent for this message.
 *
 * @buff_addr: address of request buffer.
 * @buff_size: size of request buffer.
 */
struct aie4_async_event_msg_config_req {
	u64 buff_addr;
	union aie4_msg_pasid pasid;
	u32 buff_size;
};

/**
 * Async event message.
 * Sent asynchronously when an error or exception occur.
 *
 * @status: enum aie4_msg_status.
 * @type:   enum async_event_type.
 */
struct aie4_async_event_msg_config_resp {
	enum aie4_msg_status status;
	u32 type;
};

enum aie4_fw_log_level {
	AIE4_FW_LOG_LEVEL_NONE = 0,
	AIE4_FW_LOG_LEVEL_ERROR,
	AIE4_FW_LOG_LEVEL_WARN,
	AIE4_FW_LOG_LEVEL_INFO,
	AIE4_FW_LOG_LEVEL_DEBUG,
	AIE4_MAX_FW_LOG_LEVEL
};

/**
 * AIE4_MSG_OP_FW_LOG_START
 * Starts logging into DRAM
 *
 * @buff_addr: Address of DRAM logging buffer
 * @buff_size: Size of request buffer.
 * @log_level: Log level: aie4_msg_dram_log_level
 * @pasid:     PASID
 */
struct aie4_fw_log_start_req {
	u64 buff_addr;
	u32 buff_size;
	u32 log_level;
	union aie4_msg_pasid pasid;
};

/**
 * AIE4_MSG_OP_FW_LOG_START and
 * AIE4_MSG_OP_FW_LOG_STOP response
 *
 * @status: enum aie4_msg_status.
 */
struct aie4_fw_log_start_resp {
	enum aie4_msg_status status;
};

/**
 * AIE4_MSG_OP_FW_LOG_STOP
 * Stops DRAM logging.
 *
 * @resv: Reserved
 */
struct aie4_fw_log_stop_req {
	u32 resv;
};

/**
 * AIE4_MSG_OP_FW_LOG_START and
 * AIE4_MSG_OP_FW_LOG_STOP response
 *
 * @status: enum aie4_msg_status.
 */
struct aie4_fw_log_stop_resp {
	enum aie4_msg_status status;
};

/**
 * AIE4_MSG_OP_CALIBRATE_CLOCK_TRACE response structure.
 *
 * @status: enum aie4_msg_status.
 * @current_ns_offset: The current nanosecond offset of the MPIPU TSC.
 */
struct aie4_calibrate_clock_trace_resp {
	u32 status;
	u64 current_ns_offset;
};

/** * Event trace destination options.  */
enum aie4_fw_trace_destination {
	AIE4_FW_TRACE_DEST_DRAM,
	AIE4_FW_TRACE_DEST_COUNT
};

/**
 * Event trace timestamp options.
 *
 * @AIE4_FW_TRACE_TIMESTAMP_NONE:
 *          The timestamp value will be all 0's.
 * @AIE4_FW_TRACE_TIMESTAMP_NS_OFFSET:
 *          The timestamp value will be a nanosecond offset
 *          from the base offset value calibrated with AIE4_CALIBRATE_CLOCK.
 */
enum aie4_fw_trace_timestamp {
	AIE4_FW_TRACE_TIMESTAMP_NONE,
	AIE4_FW_TRACE_TIMESTAMP_NS_OFFSET,
	AIE4_FW_TRACE_TIMESTAMP_COUNT
};

/**
 * AIE4_MSG_OP_FW_TRACE_START request structure.
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
 * @event_trace_categories: Specify the traces to be included. EVENT_TRACE_CATEGORY_* bits that
 *                          are set will be traced.
 * @event_trace_dest: Specify the trace destination (enum aie4_msg_event_trace_destination).
 * @event_trace_timestamp: Specify the timestamp source to use (enum aie4_msg_event_trace_timestamp)
 * @dram_buffer_address: Address of the DRAM buffer used as a ring buffer for trace data.
 * @dram_buffer_size: Size of the DRAM buffer. Must be a power of 2 between 128KB and 64MB.
 * @pasid: The PASID needed to access the DRAM buffer.
 */
struct aie4_fw_trace_start_req {
	u64 categories;
	u32 destination;
	u32 timestamp;
	u64 buf_addr;
	u32 buf_size;
	union aie4_msg_pasid pasid;
};

struct aie4_fw_trace_start_resp {
	u32 status;
};

/**
 * AIE4_MSG_OP_FW_TRACE_STOP
 * Stop event trace request.
 *
 * Firmware will stop tracing all events, flush any remaining logs
 * in SRAM, and unmap the DRAM buffer used for tracing.
 *
 * @resvd: Reserved for future use.
 */
struct aie4_fw_trace_stop_req {
	u32 resvd;
};

struct aie4_fw_trace_stop_resp {
	u32 status;
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
struct aie4_set_fw_trace_categories_req {
	u64 categories;
};

struct aie4_set_fw_trace_categories_resp {
	u32 status;
};

/**
 * AIE4_MSG_OP_ATTACH_WORK_BUFFER
 * Specifies the DRAM buffer that the mpnpufw requires for runtime.
 * This must be set before any contexts can be created.
 *
 * @buff_addr: The buffer address. This must be aligned to @buff_size
 * @pasid: The PASID.
 * @buff_size: The buffer size.  The valid sizes are: 4 MB, 8 MB, 16 MB, 32 MB, or 64 MB
 */
struct aie4_attach_work_buffer_req {
	u64 buf_addr;
	union aie4_msg_pasid pasid;
#define AIE4_MPNPU_WORK_BUFFER_MIN_SIZE		(4 * 1024 * 1024)  /* 4 MB */
	u32 buf_size;
};

/**
 * AIE4_MSG_OP_ATTACH_WORK_BUFFER
 * DRAM buffer response
 *
 * @status: enum npu_msg_status.
 */
struct aie4_attach_work_buffer_resp {
	u32 status;
};

/**
 * AIE4_MSG_OP_DETACH_WORK_BUFFER
 * Instructs the mpnpufw to release the DRAM work buffer so the OS can reclaim
 * the memory. Any features that depend on this buffer will be disabled and no
 * new contexts can be created. All existing contexts must be destroyed before
 * sending this message.
 *
 * @resvd Reserved for future use.
 */
struct aie4_detach_work_buffer_req {
	u32 resvd;
};

/**
 * AIE4_MSG_OP_DETACH_WORK_BUFFER
 * Release DRAM work buffer response
 *
 * @status: enum npu_msg_status
 */
struct aie4_detach_work_buffer_resp {
	u32 status;
};

/**
 * Create a static spatial partition.
 *
 * Each driver must create a static spatial partition before
 * creating any hardware contexts, because each hardware
 * context must specify a static spatial partition that it
 * runs on.
 *
 * @partition_col_start: The starting partition of the static spatial partition
 * @partition_col_count: The number of columns in the static spatial partition
 */
struct aie4_create_partition_req {
	u32 partition_col_start;
	u32 partition_col_count;
};

/**
 * Create static spatial partition response
 * @status: enum aie4_msg_status.
 *     Error will be returned if the column configuration is invalid.
 * @partition_id: The partition identifier
 */
struct aie4_create_partition_resp {
	enum aie4_msg_status status;
	u32 partition_id;
};

/**
 * Destroy static partition Request.
 * This also destroys all hardware contexts that were created
 * to run on the static spatial partition.
 *
 * @partition_id: The hardware context ID.
 */
struct aie4_destroy_partition_req {
	u32 partition_id;
};

/**
 * Destroy static partition Response.
 *
 * @status: enum aie4_msg_status.
 *     Error will be returned if the partition_id is invalid (e.g. a static
 *     spatial partition with that partition_id doesn't exist).
 */
struct aie4_destroy_partition_resp {
	enum aie4_msg_status status;
};

/**
 * Create Hardware Context Request.
 *
 * This message is intended to take the minimal, non-optional configuration,
 * and any additional configuration can be done with the
 * AIE4_MSG_OP_CONFIGURE_ message.
 *
 * @partition_id:      The associated partition_id from aie4_create_partition_resp.
 * @request_num_tiles: The number of compute tiles this hardware context runs on. Assumed:
 *                     - 1, 2, 3 = dual mode application using part of 1 column.
 *                     - 4 = single mode application using 1 column.
 *                     - 8 = single mode application using 2 columns.
 *                     - 12 = single mode application using 3 columns.
 * @hsa_addr_high:     The high 32 bits of the HSA queue address.
 * @hsa_addr_low:      The low 32 bits of the HSA queue address.
 * @pasid:	       The PASID.
 * @priority_band:     The enum aie4_context_priority_band.
 */
struct aie4_create_hw_context_req {
	u32 partition_id;
	u32 request_num_tiles;
	u32 hsa_addr_high;
	u32 hsa_addr_low;
	union aie4_msg_pasid pasid;
	u32 priority_band;
};

/**
 * Create Hardware Context Response.
 *
 * @status:                enum aie4_msg_status.
 * @hw_context_id:         The ID used to refer to the hardware context.
 * @doorbell_offset:       The offset, within the PCIe BAR3, that the driver should write
 *                         to in order to trigger a doorbell for this hardware context.
 * @job_complete_msix_idx: The MSI-X index that will be triggered when this hardware
 *                         context has completed a job.
 */
struct aie4_create_hw_context_resp {
	enum aie4_msg_status status;
	u32 hw_context_id;
	u32 doorbell_offset;
	u32 job_complete_msix_idx;
};

/**
 * Destroy Hardware Context Request.
 *
 * @hw_context_id: The hardware context ID.
 * @graceful_flag: Gracefully destroy this context.
 */
struct aie4_destroy_hw_context_req {
	u32 hw_context_id;
	u32 graceful_flag:1;
	u32 resvd1:31;
};

/**
 * Destroy Hardware Context Response.
 *
 * @status: enum aie4_msg_status.
 */
struct aie4_destroy_hw_context_resp {
	enum aie4_msg_status status;
};

enum aie4_configure_hw_context_property {
	CONFIGURE_HW_CONTEXT_PROPERTY_PRIORITY_BAND,
	CONFIGURE_HW_CONTEXT_PROPERTY_SCHEDULING,
	CONFIGURE_HW_CONTEXT_PROPERTY_DPM,
	CONFIGURE_HW_CONTEXT_PROPERTY_CERT_LOG_BUFFER,
	CONFIGURE_HW_CONTEXT_PROPERTY_CERT_DEBUG_BUFFER,
	CONFIGURE_HW_CONTEXT_PROPERTY_CERT_TRACE_BUFFER,
	CONFIGURE_HW_CONTEXT_PROPERTY_CERT_DEBUG_QUEUE,
};

struct aie4_contex_config_scheduling {
	/*
	 * The context quantum, in 100ns units.
	 * This value defaults to 5ms.
	 */
	u32 quantum;

	/*
	 * Specifies context priority relative to other contexts within
	 * the same process. Valid values are between -7 and +7.
	 * This value defaults to 0.
	 */
	u32 in_process_priority;

	/*
	 *  When the context belongs to the realtime priority band, indicates
	 * the priority level (0..31) within the realtime band. For all other
	 * bands, this value is ignored.
	 * This value defaults to 0.
	 */
	u32 realtime_band_priority_level;
};

struct aie4_contex_config_dpm {
	u32 egops;
	u32 fps;
	u32 data_movement;
	u32 latency_in_us;
};

#define MAX_NUM_CERTS	6

/** CERT log buffer information (set to 0 to disable logging). */
struct aie4_context_config_cert_logging_info {
	u64 paddr;
	u32 size;
};

/** CERT log/debug buffer information. */
struct aie4_context_config_cert_logging {
	/**
	 * Number of buffers that will be configured
	 * Set to 0 to disable this logging/debug mode
	 */
	u32 num		: 8;
	u32 rsvd	: 24;

	/** Logging information for each core */
	struct aie4_context_config_cert_logging_info info[MAX_NUM_CERTS];
};

/**
 * Configure an existing hardware context.
 *
 * @hw_context_id:      The hardware context to configure.
 * @property:           The enum aie4_configure_hw_context_property being configured
 */
struct aie4_configure_hw_context_req {
	u32 hw_context_id;
	u32 property;

	union {
		/**
		 * Data for CONFIGURE_HW_CONTEXT_PROPERTY_PRIORITY_BAND property
		 * @see enum aie4_context_priority_band for valid values
		 */
		u32 priority_band;

		/** Data for CONFIGURE_HW_CONTEXT_PROPERTY_SCHEDULING property. */
		struct aie4_contex_config_scheduling scheduling;

		/** Data for CONFIGURE_HW_CONTEXT_PROPERTY_DPM property. */
		struct aie4_contex_config_dpm dpm;

		/** Data for the NPU_CONFIGURE_HW_CONTEXT_PROPERTY_CERT_{LOG, DEBUG, TRACE} */
		struct aie4_context_config_cert_logging cert_logging;
	};
};

/**
 * Configure context response.
 *
 * @status: enum aie4_msg_status.
 */
struct aie4_configure_hw_context_resp {
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
 * AIE tile info request.
 */
struct aie4_tile_info_req {
	u32 resvd;
};

/**
 * AIE tile info response.
 *
 * @status: enum aie4_msg_status.
 * @info:   struct aie4_tile_info.
 */
struct aie4_tile_info_resp {
	enum aie4_msg_status status;
	struct aie4_tile_info info;
};

/**
 * AIE version info request.
 */
struct aie4_version_info_req {
	u32 resvd;
};

/**
 * AIE version info response.
 *
 * @status: enum aie4_msg_status.
 * @major:  aie version major number.
 * @minor:  aie version minor number.
 */
struct aie4_version_info_resp {
	enum aie4_msg_status status;
	u16 major;
	u16 minor;
};

/**
 * AIE column info request.
 *
 * @dump_buff_addr: dump buffer address.
 * @dump_buff_size: dump buffer size.
 * @pasid:	    The PASID.
 * @num_cols:       number of columns.
 * @aie4_bitmap:    bitmap of aie4.
 */
struct aie4_column_info_req {
	u64 dump_buff_addr;
	u32 dump_buff_size;
	union aie4_msg_pasid pasid;
	u32 num_cols;
	u32 aie4_bitmap;
};

/**
 * AIE column info response.
 *
 * @status: enum aie4_msg_status.
 * @size:   size of response.
 */
struct aie4_column_info_resp {
	enum aie4_msg_status status;
	u32 size;
};

/**
 * AIE4_MSG_OP_AIE_DEBUG_ACCESS
 * AIE debug access opcode.
 */
enum aie4_debug_op {
	AIE4_DBG_OP_BLOCK_READ,
	AIE4_DBG_OP_BLOCK_WRITE,
	AIE4_DBG_OP_REG_READ,
	AIE4_DBG_OP_REG_WRITE,
	AIE4_MAX_DBG_OP
};

/**
 * AIE4_MSG_OP_AIE_DEBUG_ACCESS
 * AIE debug access request.
 *
 * @opcode: access opcode (see @ref enum aie4_aie_debug_op)
 * @row:    AIE tile row
 * @col:    AIE tile column
 */
struct aie4_debug_access_req {
	/* Opcode */
	u32 opcode:16;

	/* Pair row & col determines Loc of AIE Tiles */
	u32 row:8;
	u32 col:8;

	union {
		struct {
			/* Destination to store read data or Source to write data */
			u64 buffer_addr;
			/* size in bytes of the backing buffer */
			u64 buffer_size;
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
struct aie4_debug_access_resp {
	enum aie4_msg_status status;

	union {
		struct {
			/* Debug register Read Value */
			u32 reg_rval;
		} reg_access;
	};
};

/**
 * After adapter startup and before scheduling the first GPU work item,
 * the OS sets up the GPU scheduler priority band configuration. In
 * addition, this call can be made in the middle of GPU work execution,
 * and the GPU scheduler needs to use the new value during the next
 * yield calculation.
 */
struct aie4_runtime_config_setup_scheduling_priority_bands_req {
	/**
	 * Default quantum in 100ns units for scheduling across processes
	 * within a priority band.
	 */
	u64 process_quantum_for_band[CONTEXT_PRIORITY_BAND_COUNT];

	/**
	 * For normal priority band, specifies the target GPU percentage
	 * in situations when it's starved by the focus band. Valid values
	 * are between 0 and 50, with the default value on desktop
	 * systems being 10.
	 */
	u32 target_normal_band_percentage;
};

/**
 * Response to aie4_runtime_config_setup_scheduling_priority_bands_req
 *
 * @status: enum aie4_msg_status.
 */
struct aie4_runtime_config_setup_scheduling_priority_bands_resp {
	enum aie4_msg_status status;
};

/** For changing the power slider value */
enum aie4_power_hint {
	AC_PERF = 0x0,  /* Best Performance */
	AC_BAL  = 0x1,  /* Balanced */
	AC_VSS  = 0x2,  /* Best Efficiency */
	AC_NINT = 0x3,  /* Best Efficiency */

	DC_PERF = 0x4,  /* Best Performance */
	DC_BAL  = 0x5,  /* Balanced */
	DC_VSS  = 0x6,  /* Best Efficiency */
	DC_NINT = 0x7,  /* Best Efficiency */

	POWER_HINT_COUNT,
};

/**
 * Adjust power hint
 *
 * @power_hint: The enum aie4_power_hint power slider hint
 */
struct aie4_power_hint_req {
	enum aie4_power_hint power_hint;
};

/**
 * Response to aie4_power_hint_req
 *
 * @status: enum aie4_msg_status.
 */
struct aie4_power_hint_resp {
	enum aie4_msg_status status;
};

/**
 * For the xrtsmi override
 * Firmware will default into the POWER_MODE_DEFAULT state.
 */
enum aie4_power_mode {
	NPU_POWER_MODE_DEFAULT     = 0x0,
	NPU_POWER_MODE_USER_LOW    = 0x1,
	NPU_POWER_MODE_USER_MEDIUM = 0x2,
	NPU_POWER_MODE_USER_HIGH   = 0x3,
	NPU_POWER_MODE_USER_TURBO  = 0x4,
	NPU_POWER_MODE_COUNT,
};

/**
 * Power Override request
 *
 * @power_mode: The enum aie4_power_override requested power mode override
 */
struct aie4_power_override_req {
	enum aie4_power_mode power_mode;
};

/**
 * Response to aie4_power_override_req
 *
 * @status: enum aie4_msg_status.
 */
struct aie4_power_override_resp {
	enum aie4_msg_status status;
};

/**
 * Self test Result codes
 */
enum aie4_selftest_result {
	AIE4_SELFTEST_RESULT_OK,
	AIE4_SELFTEST_RESULT_ERROR,
};

#define SELF_TEST_NAME_LEN      (sizeof(u32) * 4)

/**
 * Self test request.
 *
 */
struct aie4_selftest_req {
	u32 selftest_id;
	u32 timeout;
	u64 log_dram_address;
	u64 hsa_dram_address;
	union aie4_msg_pasid passid;
};

/**
 * Self test response.
 *
 * @status:           enum aie4_msg_status.
 * @selftest_name:    ASCII test name identified
 * @selftest_id:      selftest ID
 * @selftest_result:  enum aie4_selftest_result
 * @selftest_data:    test-specific data return
 */
struct aie4_selftest_resp {
	enum aie4_msg_status status;
	u8 selftest_name[SELF_TEST_NAME_LEN];
	u32 selftest_id;
	u32 selftest_result;
	u32 selftest_data[10];
};

/* Telemetry: TBD */
/* The telemetry types requestable for CERT PERF counter. */
enum aie4_telemetry_type {
	TELEMETRY_TYPE_DISABLED = 0,
	TELEMETRY_TYPE_PERF_COUNTER,
	TELEMETRY_TYPE_MAX_SIZE,
};

/*
 * AIE get telemetry request.
 *
 * @type:           enum aie4_telemetry_type.
 * @buf_addr:       buffer address.
 * @pasid:	    The PASID.
 * @buf_size:       buffer size.
 * @hw_context_id:  hw context ID.
 */
struct aie4_get_telemetry_req {
	u32 type;
	u64 buf_addr;
	union aie4_msg_pasid pasid;
	u32 buf_size;
	u32 hw_context_id;
};

/*
 * AIE get telemetry response.
 *
 * @status: enum aie4_msg_status.
 */
struct aie4_get_telemetry_resp {
	enum aie4_msg_status status;
};

enum aie4_clk_control_module {
	NPU_CLK_CONTROL_MODULE_IPUAIE,
	NPU_CLK_CONTROL_MODULE_IPUHCLK,
	NPU_CLK_CONTROL_MODULE_NBIF,
	NPU_CLK_CONTROL_MODULE_AXI2SDP,
	NPU_CLK_CONTROL_MODULE_MPIPU,
	NPU_CLK_CONTROL_MODULE_MAX
};

enum aie4_clk_control_mode_ipuaie {
	NPU_CLK_CONTROL_MODE_IPUAIE_ACTIVE,
	NPU_CLK_CONTROL_MODE_IPUAIE_DEEP_SLEEP,
	NPU_CLK_CONTROL_MODE_IPUAIE_STOPPED,
	NPU_CLK_CONTROL_MODE_IPUAIE_INVALID,
};

enum aie4_clk_control_mode_ipuhclk {
	NPU_CLK_CONTROL_MODE_IPUHCLK_ACTIVE,
	NPU_CLK_CONTROL_MODE_IPUHCLK_ALLOW_DS,
	NPU_CLK_CONTROL_MODE_IPUHCLK_INVALID,
};

enum aie4_clk_control_mode_nbif {
	NPU_CLK_CONTROL_MODE_NBIF_ACTIVE,
	NPU_CLK_CONTROL_MODE_NBIF_ALLOW_DS,
	NPU_CLK_CONTROL_MODE_NBIF_INVALID,
};

enum aie4_clk_control_mode_axi2sdp {
	NPU_CLK_CONTROL_MODE_AXI2SDP_ACTIVE,
	NPU_CLK_CONTROL_MODE_AXI2SDP_STOPPED,
	NPU_CLK_CONTROL_MODE_AXI2SDP_INVALID,
};

enum aie4_clk_control_mode_mpipu {
	NPU_CLK_CONTROL_MODE_MPIPU_ACTIVE,
	NPU_CLK_CONTROL_MODE_MPIPU_ALLOW_DS,
	NPU_CLK_CONTROL_MODE_MPIPU_INVALID,
};

/**
 * AIE4_MSG_OP_SET_CLOCK_MODE
 * Request structure for setting clock mode.
 *
 * @module: The module for which the clock mode is being set.
 * @mode: The requested clock mode.
 */
struct aie4_set_clock_mode_req {
	u32 module;
	u32 mode;
};

/**
 * AIE4_MSG_OP_SET_CLOCK_MODE
 * Clock Mode command response.
 *
 * @status: enum aie4_msg_status.
 */
struct aie4_set_clock_mode_resp {
	enum aie4_msg_status status;
};

/**
 * AIE4_MSG_OP_SET_POWER_CNTRL
 * Allows control over the various power domains
 *
 * @pwr_config: power configuration bits set
 * to control the pwr domains
 */
struct aie4_pwr_cntrl_req {
	u32 pwr_config;
};

/**
 * AIE4_MSG_OP_SET_POWER_CNTRL
 * Power control response
 *
 * @status: enum aie4_msg_status.
 */
struct aie4_pwr_cntrl_resp {
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
 * @brief Runtime configuration for DPM override.
 *
 * @force_dpm:
 *   - 1: Override the DPM levels for IPUHCLK and IPUAIECLK.
 *   - 0: Do not override; use default DPM behavior.
 *
 * @forced_ipuhclk_dpm_level: DPM level to force for the IPUHCLK clock domain if override
 *			      is enabled.
 * @forced_ipuaieclk_dpm_level: DPM level to force for the IPUAIECLK clock domain if
 *				override is enabled.
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
 * L1MMU prefetch range configuration.
 *
 * @prefetch_range: Hardware prefetch range value for L1MMU.
 */
struct aie4_msg_runtime_config_l1mmu_prefetch_range {
	u32 prefetch_range;
};

/**
 * Firmware log level configuration.
 *
 * @fw_log_level: dynamic firmware log level.
 */
struct aie4_msg_runtime_config_fw_log_level {
	u32 level;
};

#define MAX_RUNTIME_CONFIG_SIZE 8

enum aie4_msg_runtime_config_type {
	AIE4_RUNTIME_CONFIG_CLOCK_POWER_OVERRIDE,
	AIE4_RUNTIME_CONFIG_FORCE_PREEMPTION,
	AIE4_RUNTIME_CONFIG_L1MMU_PREFETCH_RANGE,
	AIE4_RUNTIME_CONFIG_KEEP_PARTITIONS,
	AIE4_RUNTIME_CONFIG_DPM_OVERRIDE,
	AIE4_RUNTIME_CONFIG_FW_LOG_LEVEL,
	AIE4_RUNTIME_CONFIG_CERT_TIMEOUT,
	AIE4_RUNTIME_CONFIG_EVENT_TRACE_ENABLED,
	AIE4_RUNTIME_CONFIG_DPM_ENABLE,
	AIE4_MAX_RUNTIME_CONFIG
};

/**
 * AIE4_MSG_OP_SET_RUNTIME_CONFIG
 * Allows control of various runtime configurations.
 *
 * @type: enum aie4_msg_runtime_config_type.
 * @data: In addition to passing the `type`, the caller needs
 *       to pass the struct associated with `type` immediately
 *       after `type`. The valid combinations are:
 *       - NPU_RUNTIME_CONFIG_CLOCK_POWER_OVERRIDE: aie4_msg_runtime_config_clock_power_override
 *       - NPU_RUNTIME_CONFIG_FORCE_PREEMPTION: aie4_msg_runtime_config_force_preemption
 *       - NPU_RUNTIME_CONFIG_L1MMU_PREFETCH_RANGE: aie4_msg_runtime_config_l1mmu_prefetch_range
 *       - NPU_RUNTIME_CONFIG_KEEP_PARTITIONS: npu_msg_runtime_config_keep_partitions
 *       - NPU_RUNTIME_CONFIG_DPM_OVERRIDE: npu_msg_runtime_config_dpm_override
 *       - NPU_RUNTIME_CONFIG_FW_LOG_LEVEL: npu_msg_runtime_config_fw_log_level
 *       - NPU_RUNTIME_CONFIG_CERT_TIMEOUT: npu_msg_runtime_config_cert_timeout
 *
 *      This is done so that the 'interface' to the driver doesn't
 *      have to change regardless of which runtime configuration options
 *      are added in the future.
 *
 *      The `total_msg_size` header value can be checked to make sure
 *      that the total size of the `type` parameter plus the associated
 *      data is valid.
 */
struct aie4_set_runtime_cfg_req {
	u32 type;
	u8 data[4]; //sizeof(u32) for now
};

/**
 * AIE4_MSG_OP_SET_RUNTIME_CONFIG
 * Runtime config response
 *
 * @status: enum aie4_msg_status.
 */
struct aie4_set_runtime_cfg_resp {
	u32 status;
};

/**
 * AIE4_MSG_OP_GET_RUNTIME_CONFIG
 * Get the state of runtime configurations.
 *
 * @type: enum aie4_msg_runtime_config_type.
 */
struct aie4_get_runtime_cfg_req {
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
struct aie4_get_runtime_cfg_resp {
	u32 status;
	// Additional data here.
};

#pragma pack(pop)

#endif /* _AIE4_MSG_PRIV_H_ */

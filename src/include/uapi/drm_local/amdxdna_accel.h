/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/*
 * Copyright (C) 2022-2024, Advanced Micro Devices, Inc.
 */

#ifndef AMDXDNA_ACCEL_H_
#define AMDXDNA_ACCEL_H_

#include <drm/drm.h>
#include <linux/const.h>
#include <linux/stddef.h>

#if defined(__cplusplus)
extern "C" {
#endif

#define AMDXDNA_DRIVER_MAJOR		1
#define AMDXDNA_DRIVER_MINOR		0

#define AMDXDNA_INVALID_CMD_HANDLE	(~0UL)
#define AMDXDNA_INVALID_ADDR		(~0UL)
#define AMDXDNA_INVALID_CTX_HANDLE	0
#define AMDXDNA_INVALID_BO_HANDLE	0
#define AMDXDNA_INVALID_FENCE_HANDLE	0

/*
 * The interface can grow/extend over time.
 * On each struct amdxdna_drm_*, to support potential extension, we defined it
 * like this.
 *
 * Example code:
 *
 * struct amdxdna_drm_example_data {
 *	.ext = (uintptr_t)&example_data_ext;
 *	...
 * };
 *
 * We don't have extension now. The extension struct will define in the future.
 */

enum amdxdna_drm_ioctl_id {
	DRM_AMDXDNA_CREATE_HWCTX,
	DRM_AMDXDNA_DESTROY_HWCTX,
	DRM_AMDXDNA_CONFIG_HWCTX,
	DRM_AMDXDNA_CREATE_BO,
	DRM_AMDXDNA_GET_BO_INFO,
	DRM_AMDXDNA_SYNC_BO,
	DRM_AMDXDNA_EXEC_CMD,
	DRM_AMDXDNA_WAIT_CMD,
	DRM_AMDXDNA_GET_INFO,
	DRM_AMDXDNA_SET_STATE,
	DRM_AMDXDNA_SUBMIT_WAIT,
	DRM_AMDXDNA_SUBMIT_SIGNAL,
	DRM_AMDXDNA_NUM_IOCTLS
};

enum amdxdna_device_type {
	AMDXDNA_DEV_TYPE_UNKNOWN = -1,
	AMDXDNA_DEV_TYPE_KMQ,
	AMDXDNA_DEV_TYPE_UMQ,
};

/**
 * struct qos_info - QoS information for driver.
 * @gops: Giga operations per second.
 * @fps: Frames per second.
 * @dma_bandwidth: DMA bandwidtha.
 * @latency: Frame response latency.
 * @frame_exec_time: Frame execution time.
 * @priority: Request priority.
 *
 * User program can provide QoS hints to driver.
 */
struct amdxdna_qos_info {
	__u32 gops;
	__u32 fps;
	__u32 dma_bandwidth;
	__u32 latency;
	__u32 frame_exec_time;
	__u32 priority;
};

/**
 * struct amdxdna_drm_create_hwctx - Create hardware context.
 * @ext: MBZ.
 * @ext_flags: MBZ.
 * @qos_p: Address of QoS info.
 * @umq_bo: BO handle for user mode queue(UMQ).
 * @log_buf_bo: BO handle for log buffer.
 * @max_opc: Maximum operations per cycle.
 * @num_tiles: Number of AIE tiles.
 * @mem_size: Size of AIE tile memory.
 * @umq_doorbell: Returned offset of doorbell associated with UMQ.
 * @handle: Returned hardware context handle.
 */
struct amdxdna_drm_create_hwctx {
	__u64 ext;
	__u64 ext_flags;
	__u64 qos_p;
	__u32 umq_bo;
	__u32 log_buf_bo;
	__u32 max_opc;
	__u32 num_tiles;
	__u32 mem_size;
	__u32 umq_doorbell;
	__u32 handle;
};

/**
 * struct amdxdna_drm_destroy_hwctx - Destroy hardware context.
 * @handle: Hardware context handle.
 * @pad: MBZ.
 */
struct amdxdna_drm_destroy_hwctx {
	__u32 handle;
	__u32 pad;
};

/**
 * struct amdxdna_cu_config - configuration for one CU
 * @cu_bo: CU configuration buffer bo handle
 * @cu_func: Functional of a CU
 * @pad: MBZ
 */
struct amdxdna_cu_config {
	__u32 cu_bo;
	__u8  cu_func;
	__u8  pad[3];
};

/**
 * struct amdxdna_hwctx_param_config_cu - configuration for CUs in hardware context
 * @num_cus: Number of CUs to configure
 * @pad: MBZ
 * @cu_configs: Array of CU configurations of struct amdxdna_cu_config
 */
struct amdxdna_hwctx_param_config_cu {
	__u16 num_cus;
	__u16 pad[3];
	struct amdxdna_cu_config cu_configs[] __counted_by(num_cus);
};

enum amdxdna_drm_config_hwctx_param {
	DRM_AMDXDNA_HWCTX_CONFIG_CU,
	DRM_AMDXDNA_HWCTX_ASSIGN_DBG_BUF,
	DRM_AMDXDNA_HWCTX_REMOVE_DBG_BUF,
	DRM_AMDXDNA_HWCTX_CONFIG_NUM
};

/**
 * struct amdxdna_drm_config_hwctx - Configure hardware context.
 * @handle: hardware context handle.
 * @param_type: Value in enum amdxdna_drm_config_hwctx_param. Specifies the
 *              structure passed in via param_val.
 * @param_val: A structure specified by the param_type struct member.
 * @param_val_size: Size of the parameter buffer pointed to by the param_val.
 *		    If param_val is not a pointer, driver can ignore this.
 *
 * Note: if the param_val is a pointer pointing to a buffer, the maximum size
 * of the buffer is 4KiB(PAGE_SIZE).
 */
struct amdxdna_drm_config_hwctx {
	__u32 handle;
	__u32 param_type;
	__u64 param_val;
	__u32 param_val_size;
	__u32 pad;
};

/*
 * AMDXDNA_BO_SHMEM:	DRM GEM SHMEM bo
 * AMDXDNA_BO_DEV_HEAP: Shared host memory to device as heap memory
 * AMDXDNA_BO_DEV_BO:	Allocated from BO_DEV_HEAP
 * AMDXDNA_BO_CMD:	User and driver accessible bo
 * AMDXDNA_BO_DMA:	DRM GEM DMA bo
 */
enum amdxdna_bo_type {
	AMDXDNA_BO_INVALID = 0,
	AMDXDNA_BO_SHMEM,
	AMDXDNA_BO_DEV_HEAP,
	AMDXDNA_BO_DEV,
	AMDXDNA_BO_CMD,
	AMDXDNA_BO_DMA,
};

/**
 * struct amdxdna_drm_create_bo - Create a buffer object.
 * @flags: Buffer flags. MBZ.
 * @type: Buffer type.
 * @vaddr: User VA of buffer if applied. MBZ.
 * @size: Size in bytes.
 * @handle: Returned DRM buffer object handle.
 */
struct amdxdna_drm_create_bo {
	__u64	flags;
	__u32	type;
	__u32	_pad;
	__u64	vaddr;
	__u64	size;
	__u32	handle;
};

/**
 * struct amdxdna_drm_get_bo_info - Get buffer object information.
 * @ext: MBZ.
 * @ext_flags: MBZ.
 * @handle: DRM buffer object handle.
 * @map_offset: Returned DRM fake offset for mmap().
 * @vaddr: Returned user VA of buffer. 0 in case user needs mmap().
 * @xdna_addr: Returned XDNA device virtual address.
 */
struct amdxdna_drm_get_bo_info {
	__u64 ext;
	__u64 ext_flags;
	__u32 handle;
	__u32 _pad;
	__u64 map_offset;
	__u64 vaddr;
	__u64 xdna_addr;
};

/**
 * struct amdxdna_drm_sync_bo - Sync buffer object.
 * @handle: Buffer object handle.
 * @direction: Direction of sync, can be from device or to device.
 * @offset: Offset in the buffer to sync.
 * @size: Size in bytes.
 */
struct amdxdna_drm_sync_bo {
	__u32 handle;
#define SYNC_DIRECT_TO_DEVICE	0U
#define SYNC_DIRECT_FROM_DEVICE	1U
	__u32 direction;
	__u64 offset;
	__u64 size;
};

enum amdxdna_cmd_type {
	AMDXDNA_CMD_SUBMIT_EXEC_BUF = 0,
	AMDXDNA_CMD_SUBMIT_DEPENDENCY,
	AMDXDNA_CMD_SUBMIT_SIGNAL,
};

/**
 * struct amdxdna_drm_exec_cmd - Execute command.
 * @ext: MBZ.
 * @ext_flags: MBZ.
 * @hwctx: Hardware context handle.
 * @type: One of command type in enum amdxdna_cmd_type.
 * @cmd_handles: Array of command handles or the command handle itself in case of just one.
 * @args: Array of arguments for all command handles.
 * @cmd_count: Number of command handles in the cmd_handles array.
 * @arg_count: Number of arguments in the args array.
 * @seq: Returned sequence number for this command.
 */
struct amdxdna_drm_exec_cmd {
	__u64 ext;
	__u64 ext_flags;
	__u32 hwctx;
	__u32 type;
	__u64 cmd_handles;
	__u64 args;
	__u32 cmd_count;
	__u32 arg_count;
	__u64 seq;
};

/**
 * struct amdxdna_drm_wait_cmd - Wait exectuion command.
 *
 * @hwctx: hardware context handle.
 * @timeout: timeout in ms, 0 implies infinite wait.
 * @seq: sequence number of the command returned by execute command.
 *
 * Wait a command specified by seq to be completed.
 * Using AMDXDNA_INVALID_CMD_HANDLE as seq means wait till there is a free slot
 * to submit a new command.
 */
struct amdxdna_drm_wait_cmd {
	__u32 hwctx;
	__u32 timeout;
	__u64 seq;
};

/**
 * struct amdxdna_drm_query_aie_status - Query the status of the AIE hardware
 * @buffer: The user space buffer that will return the AIE status
 * @buffer_size: The size of the user space buffer
 * @cols_filled: A bitmap of AIE columns whose data has been returned in the buffer.
 */
struct amdxdna_drm_query_aie_status {
	__u64 buffer; /* out */
	__u32 buffer_size; /* in */
	__u32 cols_filled; /* out */
};

/**
 * struct amdxdna_drm_query_aie_version - Query the version of the AIE hardware
 * @major: The major version number
 * @minor: The minor version number
 */
struct amdxdna_drm_query_aie_version {
	__u32 major; /* out */
	__u32 minor; /* out */
};

/**
 * struct amdxdna_drm_query_aie_tile_metadata - Query the metadata of AIE tile (core, mem, shim)
 * @row_count: The number of rows.
 * @row_start: The starting row number.
 * @dma_channel_count: The number of dma channels.
 * @lock_count: The number of locks.
 * @event_reg_count: The number of events.
 * @pad: MBZ.
 */
struct amdxdna_drm_query_aie_tile_metadata {
	__u16 row_count;
	__u16 row_start;
	__u16 dma_channel_count;
	__u16 lock_count;
	__u16 event_reg_count;
	__u16 pad[3];
};

/**
 * struct amdxdna_drm_query_aie_metadata - Query the metadata of the AIE hardware
 * @col_size: The size of a column in bytes.
 * @cols: The total number of columns.
 * @rows: The total number of rows.
 * @version: The version of the AIE hardware.
 * @core: The metadata for all core tiles.
 * @mem: The metadata for all mem tiles.
 * @shim: The metadata for all shim tiles.
 */
struct amdxdna_drm_query_aie_metadata {
	__u32 col_size;
	__u16 cols;
	__u16 rows;
	struct amdxdna_drm_query_aie_version version;
	struct amdxdna_drm_query_aie_tile_metadata core;
	struct amdxdna_drm_query_aie_tile_metadata mem;
	struct amdxdna_drm_query_aie_tile_metadata shim;
};

/**
 * struct amdxdna_drm_query_clock - Metadata for a clock
 * @name: The clock name.
 * @freq_mhz: The clock frequency.
 * @pad: MBZ.
 */
struct amdxdna_drm_query_clock {
	__u8 name[16];
	__u32 freq_mhz;
	__u32 pad;
};

/**
 * struct amdxdna_drm_query_clock_metadata - Query metadata for clocks
 * @mp_npu_clock: The metadata for MP-NPU clock.
 * @h_clock: The metadata for H clock.
 */
struct amdxdna_drm_query_clock_metadata {
	struct amdxdna_drm_query_clock mp_npu_clock;
	struct amdxdna_drm_query_clock h_clock;
};

enum amdxdna_sensor_type {
	AMDXDNA_SENSOR_TYPE_POWER
};

/**
 * struct amdxdna_drm_query_sensor - The data for single sensor.
 * @label: The name for a sensor.
 * @input: The current value of the sensor.
 * @max: The maximum value possible for the sensor.
 * @average: The average value of the sensor.
 * @highest: The highest recorded sensor value for this driver load for the sensor.
 * @status: The sensor status.
 * @units: The sensor units.
 * @unitm: Translates value member variables into the correct unit via (pow(10, unitm) * value)
 * @type: The sensor type from enum amdxdna_sensor_type
 * @pad: MBZ.
 */
struct amdxdna_drm_query_sensor {
	__u8  label[64];
	__u32 input;
	__u32 max;
	__u32 average;
	__u32 highest;
	__u8  status[64];
	__u8  units[16];
	__s8  unitm;
	__u8  type;
	__u8  pad[6];
};

/**
 * struct amdxdna_drm_query_hwctx - The data for single context.
 * @context_id: The ID for this context.
 * @start_col: The starting column for the partition assigned to this context.
 * @num_col: The number of columns in the partition assigned to this context.
 * @pid: The Process ID of the process that created this context.
 * @command_submissions: The number of commands submitted to this context.
 * @command_completions: The number of commands completed by this context.
 * @migrations: The number of times this context has been moved to a different partition.
 * @preemptions: The number of times this context has been preempted by another context in the
 *               same partition.
 * @pad: MBZ.
 */
struct amdxdna_drm_query_hwctx {
	__u32 context_id;
	__u32 start_col;
	__u32 num_col;
	__u32 pad;
	__s64 pid;
	__u64 command_submissions;
	__u64 command_completions;
	__u64 migrations;
	__u64 preemptions;
	__u64 errors;
};

/**
 * struct amdxdna_drm_aie_mem - The data for AIE memory read/write
 * @col:   The AIE column index
 * @row:   The AIE row index
 * @addr:  The AIE memory address to read/write
 * @size:  The size of bytes to read/write
 * @buf_p: The buffer to store read/write data
 *
 * This is used for DRM_AMDXDNA_READ_AIE_MEM and DRM_AMDXDNA_WRITE_AIE_MEM
 * parameters.
 */
struct amdxdna_drm_aie_mem {
	__u32 col;
	__u32 row;
	__u32 addr;
	__u32 size;
	__u64 buf_p;
};

/**
 * struct amdxdna_drm_aie_reg - The data for AIE register read/write
 * @col: The AIE column index
 * @row: The AIE row index
 * @addr: The AIE register address to read/write
 * @val: The value to write or returned value from AIE
 *
 * This is used for DRM_AMDXDNA_READ_AIE_REG and DRM_AMDXDNA_WRITE_AIE_REG
 * parameters.
 */
struct amdxdna_drm_aie_reg {
	__u32 col;
	__u32 row;
	__u32 addr;
	__u32 val;
};

enum amdxdna_power_mode_type {
	POWER_MODE_DEFAULT, /**< Fallback to calculated DPM */
	POWER_MODE_LOW,     /**< Set frequency to lowest DPM */
	POWER_MODE_MEDIUM,  /**< Set frequency to medium DPM */
	POWER_MODE_HIGH,    /**< Set frequency to highest DPM */
};

/**
 * struct amdxdna_drm_get_power_mode - Get the power mode of the AIE hardware
 * @power_mode: The sensor type from enum amdxdna_power_mode_type
 * @pad: MBZ.
 */
struct amdxdna_drm_get_power_mode {
	__u8 power_mode;
	__u8 pad[7];
};

/**
 * struct amdxdna_drm_query_firmware_version - Query the version of the firmware
 * @major: The major version number
 * @minor: The minor version number
 * @patch: The patch level version number
 * @build: The build ID
 */
struct amdxdna_drm_query_firmware_version {
	__u32 major; /* out */
	__u32 minor; /* out */
	__u32 patch; /* out */
	__u32 build; /* out */
};

enum amdxdna_drm_get_param {
	DRM_AMDXDNA_QUERY_AIE_STATUS,
	DRM_AMDXDNA_QUERY_AIE_METADATA,
	DRM_AMDXDNA_QUERY_AIE_VERSION,
	DRM_AMDXDNA_QUERY_CLOCK_METADATA,
	DRM_AMDXDNA_QUERY_SENSORS,
	DRM_AMDXDNA_QUERY_HW_CONTEXTS,
	DRM_AMDXDNA_READ_AIE_MEM,
	DRM_AMDXDNA_READ_AIE_REG,
	DRM_AMDXDNA_QUERY_FIRMWARE_VERSION,
	DRM_AMDXDNA_GET_POWER_MODE,
	DRM_AMDXDNA_NUM_GET_PARAM,
};

/**
 * struct amdxdna_drm_get_info - Get some information from the AIE hardware.
 * @param: Value in enum amdxdna_drm_get_param. Specifies the structure passed in the buffer.
 * @buffer_size: Size of the input buffer. Size needed/written by the kernel.
 * @buffer: A structure specified by the param struct member.
 */
struct amdxdna_drm_get_info {
	__u32 param; /* in */
	__u32 buffer_size; /* in/out */
	__u64 buffer; /* in/out */
};

/**
 * struct amdxdna_drm_set_power_mode - Set the power mode of the AIE hardware
 * @power_mode: The sensor type from enum amdxdna_power_mode_type
 * @pad: MBZ.
 */
struct amdxdna_drm_set_power_mode {
	__u8 power_mode;
	__u8 pad[7];
};

enum amdxdna_drm_set_param {
	DRM_AMDXDNA_SET_POWER_MODE,
	DRM_AMDXDNA_WRITE_AIE_MEM,
	DRM_AMDXDNA_WRITE_AIE_REG,
	DRM_AMDXDNA_NUM_SET_PARAM,
};

/**
 * struct amdxdna_drm_set_state - Set the state of some component within the AIE hardware.
 * @param: Value in enum amdxdna_drm_set_param. Specifies the structure passed in the buffer.
 * @buffer_size: Size of the input buffer.
 * @buffer: A structure specified by the param struct member.
 */
struct amdxdna_drm_set_state {
	__u32 param; /* in */
	__u32 buffer_size; /* in */
	__u64 buffer; /* in */
};


/**
 * struct amdxdna_drm_syncobjs - Signal or wait on array of DRM timelined sync objects.
 * @handles: Array of handles of sync objects.
 * @points: Array of time points for each sync objects.
 * @count: Number of elements in the above array.
 */
struct amdxdna_drm_syncobjs {
	__u64 handles; /* in */
	__u64 points; /* in */
	__u32 count; /* in */
	__u32 pad;
};

#define DRM_IOCTL_AMDXDNA_CREATE_HWCTX \
	DRM_IOWR(DRM_COMMAND_BASE + DRM_AMDXDNA_CREATE_HWCTX, \
		 struct amdxdna_drm_create_hwctx)

#define DRM_IOCTL_AMDXDNA_DESTROY_HWCTX \
	DRM_IOWR(DRM_COMMAND_BASE + DRM_AMDXDNA_DESTROY_HWCTX, \
		 struct amdxdna_drm_destroy_hwctx)

#define DRM_IOCTL_AMDXDNA_CONFIG_HWCTX \
	DRM_IOWR(DRM_COMMAND_BASE + DRM_AMDXDNA_CONFIG_HWCTX, \
		 struct amdxdna_drm_config_hwctx)

#define DRM_IOCTL_AMDXDNA_CREATE_BO \
	DRM_IOWR(DRM_COMMAND_BASE + DRM_AMDXDNA_CREATE_BO, \
		 struct amdxdna_drm_create_bo)

#define DRM_IOCTL_AMDXDNA_GET_BO_INFO \
	DRM_IOWR(DRM_COMMAND_BASE + DRM_AMDXDNA_GET_BO_INFO, \
		 struct amdxdna_drm_get_bo_info)

#define DRM_IOCTL_AMDXDNA_SYNC_BO \
	DRM_IOWR(DRM_COMMAND_BASE + DRM_AMDXDNA_SYNC_BO, \
		 struct amdxdna_drm_sync_bo)

#define DRM_IOCTL_AMDXDNA_EXEC_CMD \
	DRM_IOWR(DRM_COMMAND_BASE + DRM_AMDXDNA_EXEC_CMD, \
		 struct amdxdna_drm_exec_cmd)

#define DRM_IOCTL_AMDXDNA_WAIT_CMD \
	DRM_IOWR(DRM_COMMAND_BASE + DRM_AMDXDNA_WAIT_CMD, \
		 struct amdxdna_drm_wait_cmd)

#define DRM_IOCTL_AMDXDNA_GET_INFO \
	DRM_IOWR(DRM_COMMAND_BASE + DRM_AMDXDNA_GET_INFO, \
		 struct amdxdna_drm_get_info)

#define DRM_IOCTL_AMDXDNA_SET_STATE \
	DRM_IOWR(DRM_COMMAND_BASE + DRM_AMDXDNA_SET_STATE, \
		 struct amdxdna_drm_set_state)

#define DRM_IOCTL_AMDXDNA_SUBMIT_WAIT \
	DRM_IOWR(DRM_COMMAND_BASE + DRM_AMDXDNA_SUBMIT_WAIT, \
		 struct amdxdna_drm_syncobjs)

#define DRM_IOCTL_AMDXDNA_SUBMIT_SIGNAL \
	DRM_IOWR(DRM_COMMAND_BASE + DRM_AMDXDNA_SUBMIT_SIGNAL, \
		 struct amdxdna_drm_syncobjs)

#if defined(__cplusplus)
} /* extern c end */
#endif

#endif /* AMDXDNA_ACCEL_H_ */

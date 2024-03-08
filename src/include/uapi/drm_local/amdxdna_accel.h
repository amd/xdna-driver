/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/*
 * Copyright (C) 2022-2024, Advanced Micro Devices, Inc.
 */

#ifndef AMDXDNA_ACCEL_H_
#define AMDXDNA_ACCEL_H_

#include <drm/drm.h>
#include <linux/const.h>

#if defined(__cplusplus)
extern "C" {
#endif

#define AMDXDNA_DRIVER_MAJOR	1
#define AMDXDNA_DRIVER_MINOR	0

#define AMDXDNA_INVALID_CMD_HANDLE	(~0UL)
#define AMDXDNA_INVALID_ADDR		(~0UL)

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
	DRM_AMDXDNA_CREATE_BO,
	DRM_AMDXDNA_GET_BO_INFO,
	DRM_AMDXDNA_SYNC_BO,
	DRM_AMDXDNA_EXEC_CMD,
	DRM_AMDXDNA_WAIT_CMD,
	DRM_AMDXDNA_GET_INFO,
	DRM_AMDXDNA_CREATE_HWCTX_UNSECURE,
	DRM_AMDXDNA_ATTACH_BO,
	DRM_AMDXDNA_DETACH_BO,
	DRM_AMDXDNA_CREATE_HWCTX_LEGACY,
	DRM_AMDXDNA_NUM_IOCTLS
};

enum amdxdna_device_type {
	AMDXDNA_DEV_TYPE_UNKNOWN = -1,
	AMDXDNA_DEV_TYPE_KMQ,
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
 * struct amdxdna_ip_name_index - IP name to index mapping.
 * @name_off: IP name string offset in the buffer.
 * @index: IP index.
 */
struct amdxdna_ip_name_index {
	__u32 name_off;
	__u32 index;
};

/**
 * struct amdxdna_drm_create_hwctx_legacy - Create hardware context.
 * @ext: MBZ.
 * @ext_flags: MBZ.
 * @xclbin_uuid: UUID of xclbin binary.
 * @ip_buf_p: Returned IP name array buffer.
 * @ip_buf_size: IP name array buffer size in bytes, driver returns actual
 *               used size.
 * @pad: MBZ.
 * @qos_p: Address of QoS info buffer.
 * @qos_size: QoS info buffer size.
 * @handle: Returned hardware context handle.
 */
struct amdxdna_drm_create_hwctx_legacy {
	__u64 ext;
	__u64 ext_flags;
	__u8  xclbin_uuid[16];
	__u64 ip_buf_p;
	__u32 ip_buf_size;
	__u32 pad;
	__u64 qos_p;
	__u32 qos_size;
	__u32 handle;
};

/**
 * struct amdxdna_create_hwctx - Create hardware context.
 * @ext: MBZ.
 * @ext_flags: MBZ.
 * @qos_p: Address of QoS info buffer.
 * @qos_size: QoS info buffer size.
 * @log_p: Address of log buffer.
 * @log_size: Log buffer size.
 * @umq_p: User Module Queue(UMQ).
 * @umq_doorbell: Address of doorbell register of UMQ.
 * @max_opc: Maximum operations per cycle.
 * @num_cols: number of columns.
 * @handle: Returned hardware context handle.
 */
struct amdxdna_drm_create_hwctx {
    __u64 ext;
    __u64 ext_flags;
    __u64 qos_p;
    __u64 qos_size;
    __u64 log_p;
    __u64 log_size;
    __u64 umq_p;
    __u32 umq_doorbell;
    __u32 max_opc;
    __u32 num_cols;
    __u32 handle;
};

/**
 * struct amdxdna_drm_query_aie_status - Query the status of the AIE hardware
 * @start_col: The index of the first AIE column to get data from
 * @num_col: The number of columns to gather data from, including the starting column
 * @buffer_size: The size of the user space buffer
 * @buffer: The user space buffer that will return the AIE status
 * @cols_filled: A bitmap of AIE columns whose data has been returned in the buffer.
 */
struct amdxdna_drm_query_aie_status {
	__u32 start_col; /* in */
	__u32 num_cols; /* in */
	__u32 buffer_size; /* in */
	__u64 buffer; /* out */
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
	__u8  pad[6];
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

enum amdxdna_drm_get_param {
	DRM_AMDXDNA_QUERY_AIE_STATUS,
	DRM_AMDXDNA_QUERY_AIE_METADATA,
	DRM_AMDXDNA_QUERY_AIE_VERSION,
	DRM_AMDXDNA_QUERY_CLOCK_METADATA,
	DRM_AMDXDNA_QUERY_SENSORS,
	DRM_AMDXDNA_QUERY_HW_CONTEXTS,
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

/* Hack: driver gets xclbin from user directly. */
struct amdxdna_drm_create_hwctx_unsecure {
	__u64	xclbin_p;
	__u64	ip_buf_p;
	__u32	ip_buf_size;
	__u32	pad;
	__u64	qos_p;
	__u32	qos_size;
	__u32	handle;
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

#define AMDXDNA_INVALID_BO_HANDLE 0

enum amdxdna_bo_type {
	AMDXDNA_BO_INVALID = 0,
	AMDXDNA_BO_SHMEM,
	AMDXDNA_BO_DEV_HEAP,
	AMDXDNA_BO_DEV,
	AMDXDNA_BO_CMD,
};

/**
 * struct amdxdna_drm_create_bo - Create a buffer object.
 * @flags: Buffer flags. MBZ.
 * @type: Buffer type.
 * @vaddr: User VA of buffer if applied.
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

/**
 * struct amdxdna_cu_config - CU configure info
 * @xdna_addr: XDNA virtual address of configure memory
 * @cu_func: Functional of CU
 */
struct amdxdna_cu_config {
    __u64 xdna_addr;
    __u8  cu_func;
    __u8  pad[7];
};

/**
 * struct amdxdna_config_cu_cmd - Configure CU command payload
 * @cu_config_p: Address of CU configure info array.
 * @cu_config_size: CU configure info array size in bytes.
 */
struct amdxdna_config_cu_cmd {
    __u64 cu_config_p;
    __u32 cu_config_size;
};

/**
 * struct amdxdna_drm_exec_cmd - Execute command.
 * @ext: MBZ.
 * @ext_flags: MBZ.
 * @hwctx: Hardware context handle.
 * @cmd_bo_handles: Array of command BO handles
 * @arg_bo_handles: Array of BO handles for all BOs referenced by these commands
 * @cmd_bo_count: Number of BO handles in the cmd_bo_handles array
 * @arg_bo_count: Number of BO handles in the arg_bo_handles array
 * @seq: Returned sequence number for this command.
 */
struct amdxdna_drm_exec_cmd {
	__u64 ext;
	__u64 ext_flags;
	__u32 hwctx;
	__u32 _pad;
	__u64 cmd_bo_handles;
	__u64 arg_bo_handles;
	__u32 cmd_bo_count;
	__u32 arg_bo_count;
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
 * struct amdxdna_drm_attach_detach_bo - Attach/detach a BO to/from a context.
 *
 * @hwctx: hardware context handle.
 * @bo: BO handle.
 *
 * Assign/unassign a BO to a hardware context for its exclusive use.
 */
struct amdxdna_drm_attach_detach_bo {
	__u32 bo;
	__u32 hwctx;
};

#define DRM_IOCTL_AMDXDNA_CREATE_HWCTX \
	DRM_IOWR(DRM_COMMAND_BASE + DRM_AMDXDNA_CREATE_HWCTX, \
		 struct amdxdna_drm_create_hwctx)

#define DRM_IOCTL_AMDXDNA_CREATE_HWCTX_LEGACY \
	DRM_IOWR(DRM_COMMAND_BASE + DRM_AMDXDNA_CREATE_HWCTX_LEGACY, \
		 struct amdxdna_drm_create_hwctx_legacy)

#define DRM_IOCTL_AMDXDNA_DESTROY_HWCTX \
	DRM_IOWR(DRM_COMMAND_BASE + DRM_AMDXDNA_DESTROY_HWCTX, \
		 struct amdxdna_drm_destroy_hwctx)

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

#define DRM_IOCTL_AMDXDNA_CREATE_HWCTX_UNSECURE \
	DRM_IOWR(DRM_COMMAND_BASE + DRM_AMDXDNA_CREATE_HWCTX_UNSECURE, \
		 struct amdxdna_drm_create_hwctx_unsecure)

#define DRM_IOCTL_AMDXDNA_GET_INFO \
	DRM_IOWR(DRM_COMMAND_BASE + DRM_AMDXDNA_GET_INFO, \
		 struct amdxdna_drm_get_info)

#define DRM_IOCTL_AMDXDNA_ATTACH_BO \
	DRM_IOWR(DRM_COMMAND_BASE + DRM_AMDXDNA_ATTACH_BO, \
		 struct amdxdna_drm_attach_detach_bo)

#define DRM_IOCTL_AMDXDNA_DETACH_BO \
	DRM_IOWR(DRM_COMMAND_BASE + DRM_AMDXDNA_DETACH_BO, \
		 struct amdxdna_drm_attach_detach_bo)

#if defined(__cplusplus)
} /* extern c end */
#endif

#endif /* AMDXDNA_ACCEL_H_ */

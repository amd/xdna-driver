/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2025, Advanced Micro Devices, Inc.
 */

#ifndef _VE2_MGMT_H_
#define _VE2_MGMT_H_

#include <linux/xlnx-ai-engine.h>
#include <linux/version.h>

struct aie_device;
struct amdxdna_dev;
struct amdxdna_ctx;

#define VE2_COL_SHIFT			25
#define VE2_ROW_SHIFT			20
#define VE2_ADDR(col, row, off) \
	(((col) << VE2_COL_SHIFT) + ((row) << VE2_ROW_SHIFT) + (off))

#define VE2_HANDSHAKE_OFF		0x88000
#define CERT_HANDSHAKE_OFF(col)		VE2_ADDR(col, 0, VE2_HANDSHAKE_OFF)

#define VE2_CERT_WAKEUP_OFF		0xC0000
#define VE2_EVENT_GENERATE_REG		0x00034008
#define VE2_USER_EVENT_ID		0xB6
#define VE2_SHIM_DATA_MEMORY_OFF	0xD0000
#define VE2_PROG_DATA_MEMORY_OFF	0x80000
#define VE2_MEM_TILE_MEMORY_OFF		0x0
#define VE2_CORE_TILE_MEMORY_OFF	0x0
#define HSA_QUEUE_READ_INDEX_OFFSET	0x0
#define HSA_QUEUE_WRITE_INDEX_OFFSET	0x10
#define HSA_QUEUE_NOT_EMPTY		1
#define CERT_IS_IDLE			4

#define SHIM_DATA_MEMORY_OFF(col, row, off) \
	VE2_ADDR(col, row, VE2_SHIM_DATA_MEMORY_OFF + (off))

#define SHIM_PROG_MEMORY_OFF(col, row, off) \
	VE2_ADDR(col, row, VE2_PROG_DATA_MEMORY_OFF + (off))

#define MEM_TILE_MEMORY_OFF(col, row, off) \
	VE2_ADDR(col, row, VE2_MEM_TILE_MEMORY_OFF + (off))

#define CORE_TILE_MEMORY_OFF(col, row, off) \
	VE2_ADDR(col, row, VE2_CORE_TILE_MEMORY_OFF + (off))

/**
 * struct misc_info - Holds miscellaneous context information for VE2 management.
 * @fw_state: Firmware state indicator.
 * @abs_page_index: Absolute page index for memory management.
 * @ppc: Partition per column value.
 */
struct misc_info {
	u32 fw_state;
	u32 abs_page_index;
	u32 ppc;
};

// Read from handshake memory
static inline int
ve2_partition_read_privileged_mem(struct device *aie_dev, u32 col,
				  size_t field_offset, size_t size, void *p_read_mem)
{
	u32 offset;

	offset = CERT_HANDSHAKE_OFF(col) + field_offset;
	return aie_partition_read_privileged_mem(aie_dev, offset, size, p_read_mem);
}

// Write to handshake memory
static inline int
ve2_partition_write_privileged_mem(struct device *aie_dev, u32 col,
				   size_t field_offset, size_t size, void *p_write_mem)
{
	u32 offset;

	offset = CERT_HANDSHAKE_OFF(col) + field_offset;
	return aie_partition_write_privileged_mem(aie_dev, offset, size, p_write_mem);
}

// Wake up cert via UC wakeup
static inline int
ve2_partition_uc_wakeup(struct device *aie_dev, u32 col)
{
	struct aie_location loc = { .col = col };

	return aie_partition_uc_wakeup(aie_dev, &loc);
}

static inline int
ve2_partition_write(struct device *aie_dev,
		    u32 col, u32 row, u32 offset, size_t size, void *buf)
{
	struct aie_location loc = { .col = col, .row = row };

	return aie_partition_write(aie_dev, loc, offset,
			size, buf, 0);
}

static inline int
ve2_partition_read(struct device *aie_dev,
		   u32 col, u32 row, u32 offset, size_t size, void *buf)
{
	struct aie_location loc = { .col = col, .row = row };

	return aie_partition_read(aie_dev, loc, offset, size, buf);
}

static inline int
ve2_partition_initialize(struct device *dev,
			 struct aie_partition_init_args *args)
{
	args->init_opts = (AIE_PART_INIT_OPT_DEFAULT | AIE_PART_INIT_OPT_DIS_TLAST_ERROR) &
		~AIE_PART_INIT_OPT_UC_ENB_MEM_PRIV;
	return aie_partition_initialize(dev, args);
}

static inline int get_ctx_read_index(struct amdxdna_ctx *hwctx, u64 *read_index)
{
	u64 *index_ptr;

	if (!hwctx || !hwctx->priv || !hwctx->priv->hwctx_hsa_queue.hsa_queue_p || !read_index)
		return -EINVAL;

	index_ptr = (u64 *)((char *)hwctx->priv->hwctx_hsa_queue.hsa_queue_p +
			HSA_QUEUE_READ_INDEX_OFFSET);
	*read_index = *index_ptr;

	return 0;
}

static inline int get_ctx_write_index(struct amdxdna_ctx *hwctx, u64 *write_index)
{
	u64 *index_ptr;

	if (!hwctx || !hwctx->priv || !hwctx->priv->hwctx_hsa_queue.hsa_queue_p || !write_index)
		return -EINVAL;

	index_ptr = (u64 *)((char *)hwctx->priv->hwctx_hsa_queue.hsa_queue_p +
			HSA_QUEUE_WRITE_INDEX_OFFSET);
	*write_index = *index_ptr;

	return 0;
}

static inline void update_ctx_write_index(struct amdxdna_ctx *hwctx, int incr_cnt)
{
	struct ve2_hsa_queue *queue;
	struct host_queue_header *header;

	if (!hwctx || !hwctx->priv || !hwctx->priv->hwctx_hsa_queue.hsa_queue_p)
		return;

	queue = &hwctx->priv->hwctx_hsa_queue;
	header = &queue->hsa_queue_p->hq_header;

	mutex_lock(&queue->hq_lock);
	header->write_index += (u64)incr_cnt;
	mutex_unlock(&queue->hq_lock);
}

/**
 * ve2_mgmt_create_partition - Create a VE2 hardware partition for a context.
 * @xdna: Pointer to the device structure (VE2 device instance).
 * @hwctx: Pointer to the hardware context (execution context for partition).
 *
 * Returns 0 on success or a negative error code.
 */
int ve2_mgmt_create_partition(struct amdxdna_dev *xdna, struct amdxdna_ctx *hwctx);

/**
 * ve2_mgmt_destroy_partition - Destroy a VE2 hardware partition for a context.
 * @hwctx: Pointer to the hardware context.
 *
 * Returns 0 on success or a negative error code.
 */

int ve2_mgmt_destroy_partition(struct amdxdna_ctx *hwctx);
/**
 * ve2_get_hwctx - Retrieve the hardware context for a given column.
 * @xdna: Pointer to the device structure.
 * @col: Column index.
 *
 * Returns pointer to the hardware context, or NULL if the column is invalid or not mapped.
 */
struct amdxdna_ctx *ve2_get_hwctx(struct amdxdna_dev *xdna, u32 col);
struct amdxdna_ctx *ve2_get_hwctx(struct amdxdna_dev *xdna, u32 col);

/**
 * notify_fw_cmd_ready - Notify firmware that a command is ready.
 * @hwctx: Pointer to the hardware context.
 *
 * Returns 0 on success or a negative error code.
 * Possible error codes:
 *   -EINVAL: Invalid arguments or context.
 *   -EIO: I/O error during firmware notification.
 *   -ENOMEM: Memory allocation failure.
 */
int notify_fw_cmd_ready(struct amdxdna_ctx *hwctx);

/**
 * ve2_xrs_request - Request XRS resources for a context.
 * @xdna: Pointer to the device structure.
 * @hwctx: Pointer to the hardware context.
 *
 * Returns 0 on success or a negative error code.
 */
int ve2_xrs_request(struct amdxdna_dev *xdna, struct amdxdna_ctx *hwctx);

/**
 * ve2_mgmt_schedule_cmd - Schedule a command for execution.
 * @xdna: Pointer to the device structure.
 * @hwctx: Pointer to the hardware context.
 * @seq: Sequence number for the command.
 *
 * Returns 0 on success or a negative error code.
 */
int ve2_mgmt_schedule_cmd(struct amdxdna_dev *xdna, struct amdxdna_ctx *hwctx, u64 seq);

/**
 * ve2_mgmt_handshake_init - Initialize handshake with firmware for a context.
 * @xdna: Pointer to the device structure.
 * @hwctx: Pointer to the hardware context.
 */
void ve2_mgmt_handshake_init(struct amdxdna_dev *xdna, struct amdxdna_ctx *hwctx);

#endif /* _VE2_MGMT_H_ */

/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2024-2026, Advanced Micro Devices, Inc.
 *
 * VE2 management backend — XRS resource request, AIE partition lifecycle,
 * and command scheduling via the Linux xlnx-aie partition APIs.
 */

#ifndef _VE2_MGMT_H_
#define _VE2_MGMT_H_

#include <linux/list.h>
#include <linux/mutex.h>

struct amdxdna_dev;
struct amdxdna_hwctx;

#define VE2_COL_SHIFT			25
#define VE2_ROW_SHIFT			20
#define VE2_ADDR(col, row, off) \
	(((col) << VE2_COL_SHIFT) + ((row) << VE2_ROW_SHIFT) + (off))
#define VE2_HANDSHAKE_OFF		0x88000
#define CERT_HANDSHAKE_OFF(col)		VE2_ADDR(col, 0, VE2_HANDSHAKE_OFF)
#define VE2_EVENT_GENERATE_REG		0x00034008
#define VE2_USER_EVENT_ID		0xB6

/* VE2 AIE partition column granularity (partitions are 4-column aligned). */
#define VE2_MIN_COL_SUPPORT		4

struct ve2_ctx_fifo_entry {
	struct amdxdna_hwctx		*ctx;
	u64				command_index;
	struct list_head		list;
};

struct amdxdna_mgmtctx {
	struct device			*aie_dev;
	struct amdxdna_hwctx		*active_ctx;
	struct list_head		ctx_command_fifo_head;
	struct workqueue_struct		*work_queue;
	struct work_struct		scheduler_work;
	struct mutex			ctx_lock;/* protects active_ctx, scheduler, fifo */
	u32				start_col;
	u32				num_col;
	struct amdxdna_dev		*xdna;
};

/* Helper functions for reading privileged memory. */
static inline int ve2_partition_read_privileged_mem(struct amdxdna_mgmtctx *mgmtctx,
						    size_t field_off, size_t size, void *buf)
{
	u32 offset = CERT_HANDSHAKE_OFF(mgmtctx->start_col) + field_off;

	return aie_partition_read_privileged_mem(mgmtctx->aie_dev, offset, size, buf);
}

static inline int ve2_aie_read_idle(struct amdxdna_mgmtctx *mgmtctx, u32 *idle)
{
	return ve2_partition_read_privileged_mem(mgmtctx,
						 offsetof(struct handshake, cert_idle_status),
						 sizeof(*idle), idle);
}

static inline int ve2_partition_read(struct device *aie_dev, u32 col, u32 row,
				     u32 offset, size_t size, void *buf)
{
	struct aie_location loc = { .col = col, .row = row };

	return aie_partition_read(aie_dev, loc, offset, size, buf);
}

static inline int ve2_partition_initialize(struct device *dev, struct aie_partition_init_args *args)
{
	return aie_partition_initialize(dev, args);
}

static inline int get_ctx_read_index(struct amdxdna_hwctx *hwctx, u64 *read_index)
{
	struct amdxdna_ctx_priv *vp;
	u64 *index_ptr;

	if (!hwctx || !read_index)
		return -EINVAL;

	vp = ve2_hw_priv(hwctx);
	if (!vp || !vp->hsa_queue.hsa_queue_p)
		return -EINVAL;

	hsa_queue_sync_read_index_for_read(&vp->hsa_queue);
	index_ptr = (u64 *)((char *)vp->hsa_queue.hsa_queue_p + HSA_QUEUE_READ_INDEX_OFFSET);
	*read_index = *index_ptr;

	return 0;
}

/* Request XRS resources and create the AIE management partition for @hwctx. */
int ve2_xrs_request(struct amdxdna_dev *xdna, struct amdxdna_hwctx *hwctx);

/* Tear down the AIE management partition and release XRS resources. */
int ve2_mgmt_destroy_partition(struct amdxdna_hwctx *hwctx);

/* Schedule a command on the host queue commit path. */
int ve2_mgmt_schedule_cmd(struct amdxdna_dev *xdna, struct amdxdna_hwctx *hwctx,
			  u64 command_index);

int notify_fw_cmd_ready(struct amdxdna_mgmtctx *mgmtctx);
#endif /* _VE2_MGMT_H_ */

/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2024-2026, Advanced Micro Devices, Inc.
 *
 * VE2 management backend — XRS resource request, AIE partition lifecycle,
 * and command scheduling through the VE2 AIE adapter.
 */

#ifndef _VE2_MGMT_H_
#define _VE2_MGMT_H_

#include <linux/completion.h>
#include <linux/list.h>
#include <linux/mutex.h>

#include "ve2_aie.h"
#include "ve2_error.h"

struct amdxdna_dev;
struct amdxdna_dev_hdl;
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

/* Size of one AIE tile's address space used for coredump reads. */
#define TILE_ADDRESS_SPACE		0x100000

/* Job entry - inspired by drm_sched_job */
struct ve2_job {
	struct list_head		list;
	struct amdxdna_hwctx		*hwctx;
	u64				seq;
	ktime_t				submit_ts;
};

/* Per-partition scheduler - DRM-inspired design */
struct ve2_scheduler {
	/* Job queue */
	struct list_head		job_queue;       /* Pending jobs */
	spinlock_t			job_lock;        /* Protects job_queue */

	/* Current state */
	struct amdxdna_hwctx		*active_ctx;     /* Currently running */
	bool				ctx_switch_requested;

	/* Workqueue */
	struct workqueue_struct		*wq;
	struct work_struct		sched_work;

	/* Back-pointer */
	struct amdxdna_mgmtctx		*mgmtctx;

	/* Statistics */
	atomic64_t			total_jobs;
	atomic64_t			total_switches;
};

struct amdxdna_mgmtctx {
	struct device			*aie_dev;
	struct amdxdna_hwctx		*active_ctx;
	struct mutex			ctx_lock;/* protects active_ctx and partition lifecycle */
	u32				start_col;
	u32				num_col;
	u32				num_rows;
	u32				partition_id;
	struct amdxdna_dev		*xdna;
	struct amdxdna_async_err_cache	async_errs_cache;/* cache for last async error */
	struct completion		error_cb_completion;/* signalled when error cb finishes */
	atomic_t			error_cb_in_progress;/* set while error cb is running */

	/* DRM-inspired scheduler */
	struct ve2_scheduler		scheduler;
};

extern int enable_debug_queue;

int submit_command_to_dbg_queue(struct amdxdna_hwctx *hwctx, u32 opcode,
				u32 aie_addr, u64 paddr, u32 length);

/* Helper functions for reading privileged memory. */
static inline int ve2_partition_read_privileged_mem(struct amdxdna_mgmtctx *mgmtctx,
						    size_t field_off, size_t size, void *buf)
{
	u32 offset = CERT_HANDSHAKE_OFF(0) + field_off;

	return ve2_aie_priv_read(mgmtctx->aie_dev, offset, size, buf);
}

static inline int ve2_partition_write_privileged_mem(struct amdxdna_mgmtctx *mgmtctx,
						     size_t field_off, size_t size, void *buf)
{
	u32 offset = CERT_HANDSHAKE_OFF(0) + field_off;

	return ve2_aie_priv_write(mgmtctx->aie_dev, offset, size, buf);
}

static inline int ve2_aie_read_idle(struct amdxdna_mgmtctx *mgmtctx, u32 *idle)
{
	return ve2_partition_read_privileged_mem(mgmtctx,
						 offsetof(struct handshake, cert_idle_status),
						 sizeof(*idle), idle);
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

/*
 * write_index is host-owned (the driver is the only writer), so unlike
 * get_ctx_read_index() no dma_sync_single_for_cpu() is needed before reading
 * it back here.
 */
static inline int get_ctx_write_index(struct amdxdna_hwctx *hwctx, u64 *write_index)
{
	struct amdxdna_ctx_priv *vp;

	if (!hwctx || !write_index)
		return -EINVAL;

	vp = ve2_hw_priv(hwctx);
	if (!vp || !vp->hsa_queue.hsa_queue_p)
		return -EINVAL;

	*write_index = vp->hsa_queue.hsa_queue_p->hq_header.write_index;

	return 0;
}

/* Allocate and initialise the per-partition mgmtctx registry (one per column). */
int ve2_mgmtctx_registry_init(struct amdxdna_dev_hdl *hdl);

/* Request XRS resources and create the AIE management partition for @hwctx. */
int ve2_xrs_request(struct amdxdna_dev *xdna, struct amdxdna_hwctx *hwctx);

/* Tear down the AIE management partition and release XRS resources. */
int ve2_mgmt_destroy_partition(struct amdxdna_hwctx *hwctx);

/* Schedule a command on the host queue commit path. */
int ve2_mgmt_schedule_cmd(struct amdxdna_dev *xdna, struct amdxdna_hwctx *hwctx,
			  u64 command_index);

int notify_fw_cmd_ready(struct amdxdna_mgmtctx *mgmtctx);

/**
 * ve2_cache_coredump - Auto-capture an AIE coredump into the per-hwctx cache.
 * @xdna: Pointer to the device structure.
 * @hwctx: Pointer to the hardware context that timed out.
 * @seq: Sequence number of the failing command.
 *
 * Called from the timeout path when the device-wide auto coredump mode is
 * enabled. Keep-latest: overwrites any previously cached dump for this context.
 * Must be called while @hwctx is still the active context on its partition
 * (i.e. from the timeout path).
 *
 * Returns 0 on success or a negative errno.
 */
int ve2_cache_coredump(struct amdxdna_dev *xdna, struct amdxdna_hwctx *hwctx, u64 seq);
#endif /* _VE2_MGMT_H_ */

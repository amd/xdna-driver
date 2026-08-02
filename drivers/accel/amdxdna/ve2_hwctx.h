/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2026, Advanced Micro Devices, Inc.
 *
 * VE2 backend hardware context private state. Pointed to by the core
 * amdxdna_hwctx_priv::hw_priv (see amdxdna_ctx.h), matching the AIE2/AIE4
 * backend convention.
 */

#ifndef _VE2_HWCTX_H_
#define _VE2_HWCTX_H_

#include <linux/ktime.h>
#include <linux/mutex.h>
#include <linux/timer.h>
#include <linux/types.h>
#include <linux/wait.h>

#include "amdxdna_ctx.h"
#include "ve2_host_queue.h"

/*
 * Maximum pending commands per hwctx (must be a power of 2). VE2 (aux) uses 32.
 */
#define HWCTX_MAX_CMDS		32
#define get_job_idx(seq)	((seq) & (HWCTX_MAX_CMDS - 1))

/*
 * Core (bus-agnostic) per-hwctx private state. This type is opaque in
 * amdxdna_ctx.h and defined by each backend; the VE2 backend keeps a small
 * core struct that points at the VE2-specific state via @hw_priv.
 */
struct amdxdna_hwctx_priv {
	void			*hw_priv;	/* struct amdxdna_ctx_priv * */
	wait_queue_head_t	job_free_wq;
};

struct ve2_config_hwctx {
	u64	log_buf_addr;
	u32	log_buf_size;
	u64	debug_buf_addr;
	u32	debug_buf_size;
	u64	dtrace_addr;
	u32	opcode_timeout_config;
	u32	dbg_buf_ddr_offset;
};

/*
 * ve2_coredump_cache - Last AIE coredump auto-captured on command timeout.
 *
 * This cache is per-hardware-context (lives in struct amdxdna_ctx_priv). Auto-
 * capture is gated by the device-wide auto coredump mode (amdxdna_dev.
 * auto_coredump): when enabled, the driver snapshots the AIE partition into
 * @buf when a command on this context times out. Keep-latest: a newer timeout
 * overwrites the previous snapshot. A coredump request is served from this
 * cache and the cache is then cleared (one-shot); the cached dump is also
 * dropped when auto coredump is disabled or when the context is destroyed. If
 * the cache is empty the driver performs a live capture instead.
 */
struct ve2_coredump_cache {
	void		*buf;		/* vmalloc'd snapshot, or NULL */
	u32		size;		/* valid bytes in @buf */
	u64		seq;		/* failing command sequence number */
	u32		start_col;	/* partition start column */
	u32		num_col;	/* partition column count */
	ktime_t		timestamp;	/* capture time */
	bool		valid;		/* @buf holds a captured dump */
	struct mutex	lock;		/* protects all fields above */
};

/* VE2-specific per-hwctx state. Lives at hwctx->priv->hw_priv. */
struct amdxdna_ctx_priv {
	struct mutex			privctx_lock;	/* protect VE2 hwctx state */
	u32				state;
	u32				submitted;
	u32				completed;
	u32				mem_bitmap;
	u32				partition_id;
	bool				misc_intrpt_flag;
	bool				handshake_initialized;	/* CERT handshake done */
	struct amdxdna_sched_job	*pending[HWCTX_MAX_CMDS];

	/* Host queue and completion wait. */
	struct ve2_hsa_queue		hsa_queue;
	wait_queue_head_t		waitq;
	struct timer_list		event_timer;

	/* AIE partition management context backend. */
	struct amdxdna_mgmtctx		*mgmtctx;

	struct ve2_config_hwctx		*hwctx_config;	/* [num_col] */

	/*
	 * Pre-allocated handshake buffer covering all columns. Carved per
	 * column in ve2_prepare_hs_data() to avoid a per-column allocation on
	 * every partition (re)initialisation. NULL falls back to a per-init
	 * allocation.
	 *
	 * DMA-coherent memory allocated from the AIE partition device. Its
	 * per-column dma_addr is handed to aie_partition_initialize() via
	 * aie_op_handshake_data.dma_addr so the AIE driver uses this buffer
	 * directly instead of doing its own per-column dmam_alloc_coherent()
	 * (the latter path is not viable here and fails EXEC_CMD).
	 */
	void				*hs_buf_va;
	dma_addr_t			hs_buf_dma;
	size_t				hs_buf_size;

	/* Last AIE coredump auto-captured on command timeout (per hwctx). */
	struct ve2_coredump_cache	coredump_cache;
};

static inline struct amdxdna_ctx_priv *ve2_hw_priv(struct amdxdna_hwctx *hwctx)
{
	return (hwctx && hwctx->priv) ? hwctx->priv->hw_priv : NULL;
}

int ve2_hwctx_init(struct amdxdna_hwctx *hwctx);
void ve2_hwctx_fini(struct amdxdna_hwctx *hwctx);
int ve2_hwctx_config(struct amdxdna_hwctx *hwctx, u32 type, u64 value, void *buf, u32 size);
int ve2_cmd_submit(struct amdxdna_hwctx *hwctx, struct amdxdna_sched_job *job, u64 *seq);
int ve2_cmd_wait(struct amdxdna_hwctx *hwctx, u64 seq, u32 timeout_ms);

/* verbosity >= this level enables extra VE2 debug dumps (packets, FW state). */
#define VERBOSITY_LEVEL_DBG	2

extern int enable_polling;
extern int ve2_perf_optimization;
extern int verbosity;
extern int partition_size;
extern int start_col;
extern int max_col;
extern unsigned int ve2_hwctx_limit;

#endif /* _VE2_HWCTX_H_ */

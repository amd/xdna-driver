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

#include <linux/mutex.h>
#include <linux/timer.h>
#include <linux/types.h>
#include <linux/wait.h>

#include "amdxdna_ctx.h"
#include "ve2_host_queue.h"

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
};

static inline struct amdxdna_ctx_priv *ve2_hw_priv(struct amdxdna_hwctx *hwctx)
{
	return (hwctx && hwctx->priv) ? hwctx->priv->hw_priv : NULL;
}

int ve2_hwctx_init(struct amdxdna_hwctx *hwctx);
void ve2_hwctx_fini(struct amdxdna_hwctx *hwctx);
int ve2_cmd_submit(struct amdxdna_hwctx *hwctx, struct amdxdna_sched_job *job, u64 *seq);
int ve2_cmd_wait(struct amdxdna_hwctx *hwctx, u64 seq, u32 timeout_ms);

extern int enable_polling;

#endif /* _VE2_HWCTX_H_ */

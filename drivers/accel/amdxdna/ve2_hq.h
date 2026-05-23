/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2026, Advanced Micro Devices, Inc.
 *
 * VE2 host queue command path (ERT_START_DPU / ERT_CMD_CHAIN).
 */

#ifndef _VE2_HQ_H_
#define _VE2_HQ_H_

#include <linux/mutex.h>
#include <linux/timer.h>
#include <linux/types.h>
#include <linux/wait.h>

#include "amdxdna_ctx.h"
#include "ve2_host_queue.h"

#define VE2_RETRY_TIMEOUT_MS	30000
#define HSA_QUEUE_READ_INDEX_OFFSET	0x0

struct ve2_hwctx_priv {
	u32				start_col;
	u32				num_col;
	u32				mem_bitmap;
	u32				state;
	u32				submitted;
	u32				completed;
	struct ve2_hsa_queue		hsa_queue;
	wait_queue_head_t		waitq;
	struct amdxdna_sched_job	*pending[HWCTX_MAX_CMDS];
	struct mutex			privctx_lock;/* protect hwctx private state */
	bool				misc_intrpt_flag;
	struct timer_list		event_timer;
};

extern int enable_polling;

struct ve2_hwctx_priv *ve2_hw_priv(struct amdxdna_hwctx *hwctx);

int ve2_hq_alloc(struct amdxdna_hwctx *hwctx);
void ve2_hq_free(struct amdxdna_hwctx *hwctx);

int ve2_hq_cmd_submit(struct amdxdna_hwctx *hwctx, struct amdxdna_sched_job *job, u64 *seq);
int ve2_hq_cmd_wait(struct amdxdna_hwctx *hwctx, u64 seq, u32 timeout_ms);

#endif /* _VE2_HQ_H_ */

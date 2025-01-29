/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2025, Advanced Micro Devices, Inc.
 */

#ifndef _AMDXDNA_CTX_RUNQUEUE_H_
#define _AMDXDNA_CTX_RUNQUEUE_H_

#include <linux/list.h>
#include <linux/workqueue.h>

#include "amdxdna_ctx.h"

struct amdxdna_ctx_rq {
	struct list_head	conn_list;
	struct list_head	disconn_list;

	struct delayed_work	delay_work;
	struct workqueue_struct	*delay_wq;

	bool			paused;
	u32			connected_cnt;
	u32			max_connected;
};

int amdxdna_rq_init(struct amdxdna_ctx_rq *rq);
void amdxdna_rq_fini(struct amdxdna_ctx_rq *rq);

void amdxdna_rq_add(struct amdxdna_ctx_rq *rq, struct amdxdna_ctx *ctx);
void amdxdna_rq_del(struct amdxdna_ctx_rq *rq, struct amdxdna_ctx *ctx);
int amdxdna_rq_wait_for_run(struct amdxdna_ctx_rq *rq, struct amdxdna_ctx *ctx);

void amdxdna_rq_pause_all(struct amdxdna_ctx_rq *rq);
void amdxdna_rq_run_all(struct amdxdna_ctx_rq *rq);

#endif /* _AMDXDNA_CTX_RUNQUEUE_H_ */

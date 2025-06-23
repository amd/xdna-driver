/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2025, Advanced Micro Devices, Inc.
 */

#ifndef _VE2_OF_H_
#define _VE2_OF_H_

#include "amdxdna_of_drv.h"
#include "ve2_host_queue.h"

#define HWCTX_MAX_CMDS		HOST_QUEUE_ENTRY
#define get_job_idx(seq)	((seq) & (HWCTX_MAX_CMDS - 1))

struct amdxdna_ctx_priv {
	u32			start_col;
	u32			num_col;
	struct device		*aie_dev;
	struct ve2_hsa_queue	hwctx_hsa_queue;
	wait_queue_head_t	waitq;
	struct amdxdna_sched_job *pending[HWCTX_MAX_CMDS];
};

struct amdxdna_dev_priv {
	const char		*fw_path;
	u32			hwctx_limit; /* Hardware determine */
	u32			ctx_limit; /* Driver determine */
};

struct amdxdna_dev_hdl {
	struct amdxdna_dev		*xdna;
	const struct amdxdna_dev_priv	*priv;
	u32				hwctx_limit;
	u32				hwctx_cnt;
	void				*xrs_hdl;
};

/* ve2_of.c */
extern const struct amdxdna_dev_ops ve2_ops;
int ve2_hwctx_init(struct amdxdna_ctx *hwctx);
void ve2_hwctx_fini(struct amdxdna_ctx *hwctx);
int ve2_hwctx_config(struct amdxdna_ctx *hwctx, u32 type, u64 mdata_hdl, void *buf, u32 size);

int ve2_cmd_submit(struct amdxdna_ctx *hwctx, struct amdxdna_sched_job *job, u32 *syncobj_hdls,
		   u64 *syncobj_points, u32 syncobj_cnt, u64 *seq);
int ve2_cmd_wait(struct amdxdna_ctx *hwctx, u64 seq, u32 timeout);
#endif /* _VE2_OF_H_ */

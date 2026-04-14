// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2025-2026, Advanced Micro Devices, Inc.
 */

#include <linux/errno.h>

#include "amdxdna_drv.h"
#include "ve2_aux.h"

struct amdxdna_hwctx;
struct amdxdna_sched_job;
struct amdxdna_gem_obj;

static int ve2_init(struct amdxdna_dev *xdna)
{
	return -EOPNOTSUPP;
}

static void ve2_fini(struct amdxdna_dev *xdna)
{
}

static int ve2_get_aie_info(struct amdxdna_client *client,
			    struct amdxdna_drm_get_info *args)
{
	return -EOPNOTSUPP;
}

static int ve2_set_aie_state(struct amdxdna_client *client,
			     struct amdxdna_drm_set_state *args)
{
	return -EOPNOTSUPP;
}

static int ve2_hwctx_init(struct amdxdna_hwctx *hwctx)
{
	return -EOPNOTSUPP;
}

static void ve2_hwctx_fini(struct amdxdna_hwctx *hwctx)
{
}

static int ve2_hwctx_config(struct amdxdna_hwctx *hwctx, u32 type, u64 value, void *buf, u32 size)
{
	return -EOPNOTSUPP;
}

static int ve2_hwctx_sync_debug_bo(struct amdxdna_hwctx *hwctx, u32 debug_bo_hdl)
{
	return -EOPNOTSUPP;
}

static void ve2_hmm_invalidate(struct amdxdna_gem_obj *abo, unsigned long cur_seq)
{
}

static int ve2_cmd_submit(struct amdxdna_hwctx *hwctx, struct amdxdna_sched_job *job, u64 *seq)
{
	return -EOPNOTSUPP;
}

static int ve2_cmd_wait(struct amdxdna_hwctx *hwctx, u64 seq, u32 timeout_ms)
{
	/*
	 * VE2 cmd_wait will be implemented in a later patch when the DRM
	 * scheduler and hardware context submit path are functional.
	 */
	return -EOPNOTSUPP;
}

static int ve2_get_array(struct amdxdna_client *client,
			 struct amdxdna_drm_get_array *args)
{
	return -EOPNOTSUPP;
}

const struct amdxdna_dev_ops ve2_ops = {
	.init			= ve2_init,
	.fini			= ve2_fini,
	.get_aie_info		= ve2_get_aie_info,
	.set_aie_state		= ve2_set_aie_state,
	.hwctx_init		= ve2_hwctx_init,
	.hwctx_fini		= ve2_hwctx_fini,
	.hwctx_config		= ve2_hwctx_config,
	.hwctx_sync_debug_bo	= ve2_hwctx_sync_debug_bo,
	.hmm_invalidate		= ve2_hmm_invalidate,
	.cmd_submit		= ve2_cmd_submit,
	.cmd_wait		= ve2_cmd_wait,
	.get_array		= ve2_get_array,
};

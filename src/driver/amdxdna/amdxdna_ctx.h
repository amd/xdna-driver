/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2022-2024, Advanced Micro Devices, Inc.
 */

#ifndef _AMDXDNA_CTX_H_
#define _AMDXDNA_CTX_H_

#include <linux/kref.h>
#include <linux/wait.h>
#include <drm/drm_drv.h>
#include <drm/gpu_scheduler.h>
#include "drm_local/amdxdna_accel.h"

struct npu_hwctx;

enum ert_cmd_state {
	ERT_CMD_STATE_INVALID,
	ERT_CMD_STATE_NEW,
	ERT_CMD_STATE_QUEUED,
	ERT_CMD_STATE_RUNNING,
	ERT_CMD_STATE_COMPLETED,
	ERT_CMD_STATE_ERROR,
	ERT_CMD_STATE_ABORT,
	ERT_CMD_STATE_SUBMITTED,
	ERT_CMD_STATE_TIMEOUT,
	ERT_CMD_STATE_NORESPONSE,
};

/* Exec buffer command header format */
struct amdxdna_cmd {
	union {
		struct {
			u32 state:4;
			u32 stat_enabled:1;
			u32 unused:5;
			u32 extra_cu_masks:2;
			u32 count:11;
			u32 opcode:5;
			u32 type:4;
		};
		u32 header;
	};
	u32 cu_mask;
	u32 data[];
};

struct amdxdna_hwctx {
	struct amdxdna_client		*client;
	struct npu_hwctx		*priv;
	char				*name;

	u32				id;
	u32				max_opc;
	u32				num_tiles;
	u32				mem_size;
	u32				fw_ctx_id;
	u32				col_list_len;
	u32				*col_list;
	u32				start_col;
	u32				num_col;
#define HWCTX_STAT_INIT  0
#define HWCTX_STAT_READY 1
#define HWCTX_STAT_STOP  2
	u32				status;
	u32				old_status;

	struct amdxdna_qos_info		     qos;
	struct amdxdna_hwctx_param_config_cu *cus;
};

#define drm_job_to_xdna_job(j) \
	container_of(j, struct amdxdna_sched_job, base)

struct amdxdna_sched_job {
	struct drm_sched_job	base;
	struct kref		refcnt;
	struct amdxdna_hwctx	*hwctx;
	struct mm_struct	*mm;
	/* The fence to notice DRM scheduler that job is done by hardware */
	struct dma_fence	*fence;
	/* user can wait on this fence */
	struct dma_fence	*out_fence;
	int			cu_idx;
	struct amdxdna_cmd	*cmd;
	struct amdxdna_gem_obj	*cmd_abo;
	u64			seq;
	size_t			bo_cnt;
	struct drm_gem_object	*bos[] __counted_by(bo_cnt);
};

static inline u32 amdxdna_hwctx_col_map(struct amdxdna_hwctx *hwctx)
{
	return GENMASK(hwctx->start_col + hwctx->num_col - 1,
		       hwctx->start_col);
}

void amdxdna_job_put(struct amdxdna_sched_job *job);

void amdxdna_hwctx_remove_all(struct amdxdna_client *client);
void amdxdna_hwctx_suspend(struct amdxdna_client *client);
void amdxdna_hwctx_resume(struct amdxdna_client *client);

int amdxdna_drm_create_hwctx_ioctl(struct drm_device *dev, void *data, struct drm_file *filp);
int amdxdna_drm_config_hwctx_ioctl(struct drm_device *dev, void *data, struct drm_file *filp);
int amdxdna_drm_destroy_hwctx_ioctl(struct drm_device *dev, void *data, struct drm_file *filp);
int amdxdna_drm_exec_cmd_ioctl(struct drm_device *dev, void *data, struct drm_file *filp);
int amdxdna_drm_wait_cmd_ioctl(struct drm_device *dev, void *data, struct drm_file *filp);
int amdxdna_drm_create_hwctx_unsec_ioctl(struct drm_device *dev, void *data, struct drm_file *filp);

#endif /* _AMDXDNA_CTX_H_ */

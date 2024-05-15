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

#include "amdxdna_gem.h"

struct amdxdna_hwctx_priv;

enum ert_cmd_opcode {
	ERT_START_CU      = 0,
	ERT_START_DPU     = 18,
};

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

/*
 * Interpretation of the beginning of data payload for ERT_START_DPU in
 * amdxdna_cmd. The rest of the payload in amdxdna_cmd is regular kernel args.
 */
struct amdxdna_cmd_start_dpu {
  uint64_t instruction_buffer;       /* buffer address 2 words */
  uint32_t instruction_buffer_size;  /* size of buffer in bytes */
  uint32_t chained;                  /* MBZ */
  /* Regular kernel args followed here. */
};

/* Exec buffer command header format */
struct amdxdna_cmd {
	union {
		struct {
			u32 state:4;
			u32 unused:6;
			u32 extra_cu_masks:2;
			u32 count:11;
			u32 opcode:5;
			u32 reserved:4;
		};
		u32 header;
	};
	u32 data[] __counted_by(count);
};

struct amdxdna_hwctx {
	struct amdxdna_client		*client;
	struct amdxdna_hwctx_priv	*priv;
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
	u32				umq_bo;
	u32				log_buf_bo;
	u32				dbg_buf_bo;
	u32				doorbell_offset;
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
	u64			seq;
	struct amdxdna_gem_obj	**cmd_bo;
	u32			cmd_bo_cnt;
	size_t			bo_cnt;
	struct drm_gem_object	*bos[] __counted_by(bo_cnt);
};

static inline u32
amdxdna_cmd_get_op(struct amdxdna_sched_job *job, int idx)
{
	struct amdxdna_cmd *cmd = job->cmd_bo[idx]->mem.kva;

	return cmd->opcode;
}

static inline void
amdxdna_cmd_set_state(struct amdxdna_sched_job *job, int idx, enum ert_cmd_state s)
{
	struct amdxdna_cmd *cmd = job->cmd_bo[idx]->mem.kva;

	cmd->state = s;
}

static inline enum ert_cmd_state
amdxdna_cmd_get_state(struct amdxdna_sched_job *job, int idx)
{
	struct amdxdna_cmd *cmd = job->cmd_bo[idx]->mem.kva;

	return cmd->state;
}

static inline void
amdxdna_cmd_set_state_in_range(struct amdxdna_sched_job *job, u32 start, u32 end,
			       enum ert_cmd_state s)
{
	int i;

	for (i = start; i < end; i++)
		amdxdna_cmd_set_state(job, i, s);
}

static inline void
amdxdna_cmd_init_all_state(struct amdxdna_sched_job *job)
{
	struct amdxdna_cmd *cmd;
	int i;

	for (i = 0; i < job->cmd_bo_cnt; i++) {
		cmd = job->cmd_bo[i]->mem.kva;
		amdxdna_cmd_set_state(job, i, ERT_CMD_STATE_NEW);
	}
}

static inline void *
amdxdna_cmd_get_payload(struct amdxdna_sched_job *job, int idx, u32 *size)
{
	struct amdxdna_cmd *cmd = job->cmd_bo[idx]->mem.kva;
	int num_masks = 1 + cmd->extra_cu_masks;

	if (size) {
		if (unlikely(cmd->count <= num_masks))
			return NULL;
		*size = (cmd->count - num_masks) * sizeof(u32);
	}
	return &cmd->data[num_masks];
}

static inline int
amdxdna_cmd_get_cu_idx(struct amdxdna_sched_job *job, int idx)
{
	struct amdxdna_cmd *cmd = job->cmd_bo[idx]->mem.kva;
	u32 *cu_mask;
	int cu_idx;
	int i;

	cu_mask = cmd->data;
	for (i = 0; i < 1 + cmd->extra_cu_masks; i++) {
		cu_idx = ffs(cu_mask[i]) - 1;

		if (cu_idx >= 0)
			break;
	}

	return cu_idx;
}

static inline u32 amdxdna_hwctx_col_map(struct amdxdna_hwctx *hwctx)
{
	return GENMASK(hwctx->start_col + hwctx->num_col - 1,
		       hwctx->start_col);
}

void amdxdna_job_put(struct amdxdna_sched_job *job);

void amdxdna_hwctx_remove_all(struct amdxdna_client *client);
void amdxdna_hwctx_suspend(struct amdxdna_client *client);
void amdxdna_hwctx_resume(struct amdxdna_client *client);

int amdxdna_cmds_submit(struct amdxdna_client *client,
			u32 *cmd_bo_hdls, u32 cmd_bo_cnt,
			u32 *arg_bo_hdls, u32 arg_bo_cnt,
			u32 hwctx_hdl, u64 *seq);

int amdxdna_cmds_wait(struct amdxdna_client *client, u32 hwctx_hdl,
		      u64 seq, u32 timeout);

int amdxdna_drm_create_hwctx_ioctl(struct drm_device *dev, void *data, struct drm_file *filp);
int amdxdna_drm_config_hwctx_ioctl(struct drm_device *dev, void *data, struct drm_file *filp);
int amdxdna_drm_destroy_hwctx_ioctl(struct drm_device *dev, void *data, struct drm_file *filp);
int amdxdna_drm_exec_cmd_ioctl(struct drm_device *dev, void *data, struct drm_file *filp);
int amdxdna_drm_wait_cmd_ioctl(struct drm_device *dev, void *data, struct drm_file *filp);
int amdxdna_drm_create_hwctx_unsec_ioctl(struct drm_device *dev, void *data, struct drm_file *filp);

#endif /* _AMDXDNA_CTX_H_ */

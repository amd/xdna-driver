/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2022-2024, Advanced Micro Devices, Inc.
 */

#ifndef _AMDXDNA_CTX_H_
#define _AMDXDNA_CTX_H_

#include <linux/bitfield.h>
#include <linux/kref.h>
#include <linux/wait.h>
#include <drm/drm_drv.h>
#include <drm/gpu_scheduler.h>
#include "drm_local/amdxdna_accel.h"

#ifdef AMDXDNA_SHMEM
#include "amdxdna_gem.h"
#else
#include "amdxdna_gem_dma.h"
#endif

struct amdxdna_hwctx_priv;

enum ert_cmd_opcode {
	ERT_START_CU		= 0,
	ERT_CMD_CHAIN		= 19,
	ERT_START_NPU		= 20,
	ERT_START_NPU_PREEMPT	= 21,
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
 * Interpretation of the beginning of data payload for ERT_START_NPU in
 * amdxdna_cmd. The rest of the payload in amdxdna_cmd is regular kernel args.
 */
struct amdxdna_cmd_start_npu {
	u64 buffer;       /* instruction buffer address */
	u32 buffer_size;  /* size of buffer in bytes */
	u32 prop_count;	  /* properties count */
	u32 prop_args[];  /* properties and regular kernel arguments */
};

/*
 * Interpretation of the beginning of data payload for ERT_CMD_CHAIN in
 * amdxdna_cmd. The rest of the payload in amdxdna_cmd is cmd BO handles.
 */
struct amdxdna_cmd_chain {
	u32 command_count;
	u32 submit_index;
	u32 error_index;
	u32 reserved[3];
	u64 data[] __counted_by(command_count);
};

/*
 * Interpretation of the beginning of data payload for ERT_START_NPU_PREEMPT in
 * amdxdna_cmd. The rest of the payload in amdxdna_cmd is regular kernel args.
 */
struct amdxdna_cmd_preempt_data {
	u64 inst_buf;	    /* instruction buffer address */
	u64 save_buf;	    /* save buffer address */
	u64 restore_buf;    /* restore buffer address */
	u32 inst_size;	    /* size of instruction buffer in bytes */
	u32 save_size;	    /* size of save buffer in bytes */
	u32 restore_size;   /* size of restore buffer in bytes */
	u32 inst_prop_cnt;  /* properties count */
	u32 prop_args[];    /* properties and regular kernel arguments */
};

/* Exec buffer command header format */
#define AMDXDNA_CMD_STATE		GENMASK(3, 0)
#define AMDXDNA_CMD_EXTRA_CU_MASK	GENMASK(11, 10)
#define AMDXDNA_CMD_COUNT		GENMASK(22, 12)
#define AMDXDNA_CMD_OPCODE		GENMASK(27, 23)
struct amdxdna_cmd {
	u32 header;
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
	u32				doorbell_offset;
#define HWCTX_STAT_INIT  0
#define HWCTX_STAT_READY 1
#define HWCTX_STAT_STOP  2
	u32				status;
	u32				old_status;

	struct amdxdna_qos_info		     qos;
	struct amdxdna_hwctx_param_config_cu *cus;

	/* Submitted and Completed job counter */
	u64				submitted;
	u64				completed ____cacheline_aligned_in_smp;
	/* For TDR worker to keep last completed. low frequency update */
	u64				tdr_last_completed;
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
#define OP_USER			0
#define OP_SYNC_BO		1
#define OP_REG_DEBUG_BO		2
#define OP_UNREG_DEBUG_BO	3
	u32			opcode;
	struct amdxdna_gem_obj	*cmd_bo;
	size_t			bo_cnt;
	struct drm_gem_object	*bos[] __counted_by(bo_cnt);
};

static inline u32
amdxdna_cmd_get_op(struct amdxdna_gem_obj *abo)
{
	struct amdxdna_cmd *cmd = abo->mem.kva;

	return FIELD_GET(AMDXDNA_CMD_OPCODE, cmd->header);
}

static inline void
amdxdna_cmd_set_state(struct amdxdna_gem_obj *abo, enum ert_cmd_state s)
{
	struct amdxdna_cmd *cmd = abo->mem.kva;

	cmd->header &= ~AMDXDNA_CMD_STATE;
	cmd->header |= FIELD_PREP(AMDXDNA_CMD_STATE, s);
}

static inline enum ert_cmd_state
amdxdna_cmd_get_state(struct amdxdna_gem_obj *abo)
{
	struct amdxdna_cmd *cmd = abo->mem.kva;

	return FIELD_GET(AMDXDNA_CMD_STATE, cmd->header);
}

// TODO: need to verify size <= cmd_bo size before return?
static inline void *
amdxdna_cmd_get_payload(struct amdxdna_gem_obj *abo, u32 *size)
{
	struct amdxdna_cmd *cmd = abo->mem.kva;
	u32 num_masks, count;

	if (amdxdna_cmd_get_op(abo) == ERT_CMD_CHAIN)
		num_masks = 0;
	else
		num_masks = 1 + FIELD_GET(AMDXDNA_CMD_EXTRA_CU_MASK, cmd->header);

	if (size) {
		count = FIELD_GET(AMDXDNA_CMD_COUNT, cmd->header);
		if (unlikely(count <= num_masks)) {
			*size = 0;
			return NULL;
		}
		*size = (count - num_masks) * sizeof(u32);
	}
	return &cmd->data[num_masks];
}

static inline int
amdxdna_cmd_get_cu_idx(struct amdxdna_gem_obj *abo)
{
	struct amdxdna_cmd *cmd = abo->mem.kva;
	u32 num_masks, i;
	u32 *cu_mask;
	int cu_idx;

	if (amdxdna_cmd_get_op(abo) == ERT_CMD_CHAIN)
		return -1;

	num_masks = 1 + FIELD_GET(AMDXDNA_CMD_EXTRA_CU_MASK, cmd->header);
	cu_mask = cmd->data;
	for (i = 0; i < num_masks; i++) {
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

int amdxdna_lock_objects(struct amdxdna_sched_job *job, struct ww_acquire_ctx *ctx);
void amdxdna_unlock_objects(struct amdxdna_sched_job *job, struct ww_acquire_ctx *ctx);
int amdxdna_cmd_submit(struct amdxdna_client *client, u32 opcode,
		       u32 cmd_bo_hdls, u32 *arg_bo_hdls, u32 arg_bo_cnt,
		       u32 hwctx_hdl, u64 *seq);

int amdxdna_cmd_wait(struct amdxdna_client *client, u32 hwctx_hdl,
		     u64 seq, u32 timeout);

int amdxdna_drm_create_hwctx_ioctl(struct drm_device *dev, void *data, struct drm_file *filp);
int amdxdna_drm_config_hwctx_ioctl(struct drm_device *dev, void *data, struct drm_file *filp);
int amdxdna_drm_destroy_hwctx_ioctl(struct drm_device *dev, void *data, struct drm_file *filp);
int amdxdna_drm_submit_cmd_ioctl(struct drm_device *dev, void *data, struct drm_file *filp);
int amdxdna_drm_wait_cmd_ioctl(struct drm_device *dev, void *data, struct drm_file *filp);
int amdxdna_drm_create_hwctx_unsec_ioctl(struct drm_device *dev, void *data, struct drm_file *filp);

#endif /* _AMDXDNA_CTX_H_ */

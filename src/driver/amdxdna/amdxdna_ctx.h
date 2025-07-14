/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2022-2025, Advanced Micro Devices, Inc.
 */

#ifndef _AMDXDNA_CTX_H_
#define _AMDXDNA_CTX_H_

#include <linux/bitfield.h>
#include <linux/kref.h>
#include <linux/list.h>
#include <linux/workqueue.h>
#include <drm/drm_drv.h>
#include <drm/gpu_scheduler.h>
#include "drm_local/amdxdna_accel.h"

#ifdef AMDXDNA_OF
#include "amdxdna_gem_of.h"
#else
#include "amdxdna_gem.h"
#endif

struct amdxdna_ctx_priv;

enum ert_cmd_opcode {
	ERT_START_CU			= 0,
	ERT_START_DPU			= 18,
	ERT_CMD_CHAIN			= 19,
	ERT_START_NPU			= 20,
	ERT_START_NPU_PREEMPT		= 21,
	ERT_START_NPU_PREEMPT_ELF	= 22,
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

/*
 * Interpretation of payload for an amdxdna_cmd which has context health data
 *
 * @version:          context health data version
 * @txn_op_idx:       index of last TXN control code executed
 * @ctx_pc:           program counter for that context
 *
 * Field              Default value  Comment
 * txn_op_idx:        0xFFFFFFFF     there is no txn control code is running or the
 *                                   last txn control code op idx is not captured
 * ctx_pc:            0              context .text program counter is not captured
 *
 * Once an amdxdna_cmd completes with state ERT_CMD_STATE_TIMEOUT, the
 * amdxdna_cmd starting from payload will have the following information.
 */
struct amdxdna_ctx_health_data {
	u32 version; /* MBZ */
	u32 txn_op_idx;
	u32 ctx_pc;
};

/* Exec buffer command header format */
#define AMDXDNA_CMD_STATE		GENMASK(3, 0)
#define AMDXDNA_CMD_EXTRA_CU_MASK	GENMASK(11, 10)
#define AMDXDNA_CMD_COUNT		GENMASK(22, 12)
#define AMDXDNA_CMD_OPCODE		GENMASK(27, 23)
struct amdxdna_cmd {
	u32 header;
	u32 data[];
};

struct amdxdna_ctx {
	struct amdxdna_client		*client;
	struct amdxdna_ctx_priv		*priv;
	char				*name;

	u32				id;
	u32				max_opc;
	u32				num_tiles;
	u32				mem_size;
	u32				col_list_len;
	u32				*col_list;
	u32				start_col;
	u32				num_col;
	u32				umq_bo;
	u32				log_buf_bo;
	u32				doorbell_offset;

	struct amdxdna_qos_info		     qos;
	struct amdxdna_ctx_param_config_cu *cus;

	/* Submitted, completed, freed job counter */
	u64				submitted;
	u64				completed ____cacheline_aligned_in_smp;
	/* Counter for freed job */
	atomic64_t			job_free_cnt;
	/* For context runqueue to keep last completed. low frequency update */
	u64				last_completed;
	/* For command completion notification. */
	u32				syncobj_hdl;
	struct amdxdna_ctx_health_data	health_data;
	bool				health_reported;

	struct list_head		entry;
	struct list_head		parts_work_entry;
	struct work_struct		dispatch_work;
	struct work_struct		yield_work;
};

#define drm_job_to_xdna_job(j) \
	container_of(j, struct amdxdna_sched_job, base)

struct amdxdna_job_bo {
	struct drm_gem_object   *obj;
	bool			locked;
};

struct amdxdna_sched_job {
	struct drm_sched_job	base;
	struct kref		refcnt;
	struct amdxdna_ctx	*ctx;
	struct mm_struct	*mm;
	/* The fence to notice DRM scheduler that job is done by hardware */
	struct dma_fence	*fence;
	/* user can wait on this fence */
	struct dma_fence	*out_fence;
	bool			job_done;
	u64			seq;
#define OP_USER			0
#define OP_SYNC_BO		1
#define OP_REG_DEBUG_BO		2
#define OP_UNREG_DEBUG_BO	3
#define OP_NOOP			4
	u32			opcode;
	int			msg_id;
	struct amdxdna_gem_obj	*cmd_bo;
	size_t			bo_cnt;
	struct amdxdna_job_bo	bos[] __counted_by(bo_cnt);
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

static inline void *
amdxdna_cmd_get_data(struct amdxdna_gem_obj *abo, u32 *size)
{
	struct amdxdna_cmd *cmd = abo->mem.kva;

	*size = abo->mem.size - offsetof(struct amdxdna_cmd, data);
	return cmd->data;
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

static inline u32
amdxdna_ctx_col_map(struct amdxdna_ctx *ctx)
{
	return GENMASK(ctx->start_col + ctx->num_col - 1,
		       ctx->start_col);
}

void amdxdna_ctx_wait_jobs(struct amdxdna_ctx *ctx, long timeout);
void amdxdna_sched_job_cleanup(struct amdxdna_sched_job *job);
void amdxdna_ctx_remove_all(struct amdxdna_client *client);

int amdxdna_lock_objects(struct amdxdna_sched_job *job, struct ww_acquire_ctx *ctx);
void amdxdna_unlock_objects(struct amdxdna_sched_job *job, struct ww_acquire_ctx *ctx);
int amdxdna_cmd_submit(struct amdxdna_client *client, u32 opcode,
		       u32 cmd_bo_hdls, u32 *arg_bo_hdls, u32 arg_bo_cnt,
		       u32 *sync_obj_hdls, u64 *sync_obj_pts, u32 sync_obj_cnt,
		       u32 ctx_hdl, u64 *seq);

int amdxdna_cmd_wait(struct amdxdna_client *client, u32 ctx_hdl,
		     u64 seq, u32 timeout);

int amdxdna_drm_create_ctx_ioctl(struct drm_device *dev, void *data, struct drm_file *filp);
int amdxdna_drm_config_ctx_ioctl(struct drm_device *dev, void *data, struct drm_file *filp);
int amdxdna_drm_destroy_ctx_ioctl(struct drm_device *dev, void *data, struct drm_file *filp);
int amdxdna_drm_submit_cmd_ioctl(struct drm_device *dev, void *data, struct drm_file *filp);
int amdxdna_drm_wait_cmd_ioctl(struct drm_device *dev, void *data, struct drm_file *filp);

#endif /* _AMDXDNA_CTX_H_ */

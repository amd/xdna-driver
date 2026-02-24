/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2022-2026, Advanced Micro Devices, Inc.
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

#include "amdxdna_gem.h"

struct amdxdna_ctx_priv;

enum ert_cmd_opcode {
	ERT_INVALID_CMD	= ~0U,
	ERT_START_CU			= 0,
	ERT_START_DPU			= 18,
	ERT_CMD_CHAIN			= 19,
	ERT_START_NPU			= 20,
	ERT_START_NPU_PREEMPT		= 21,
	ERT_START_NPU_PREEMPT_ELF	= 22,
};

enum ert_cmd_state {
	ERT_CMD_STATE_NEW = 1,
	ERT_CMD_STATE_QUEUED = 2,
	ERT_CMD_STATE_RUNNING = 3,
	ERT_CMD_STATE_COMPLETED = 4,
	ERT_CMD_STATE_ERROR = 5,
	ERT_CMD_STATE_ABORT = 6,
	ERT_CMD_STATE_SUBMITTED = 7,
	ERT_CMD_STATE_TIMEOUT = 8,
	ERT_CMD_STATE_NORESPONSE = 9,
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
 * struct amdxdna_cmd_start_dpu - interpretation of data payload for
 * ERT_START_DPU in amdxdna_cmd.
 */
struct amdxdna_cmd_start_dpu {
	u64 dtrace_buffer;		/* dtrace buffer address 2 words */
	u64 instruction_buffer;		/* buffer address 2 words */
	u32 instruction_buffer_size;	/* size of buffer in bytes */
	u16 uc_index;			/* microblaze controller index */
	u16 chained;			/* number of following amdxdna_cmd_start_dpu elements */
};

/**
 * Interpretation of payload for an amdxdna_cmd which has context health data for npu0
 *
 * @txn_op_idx:                 index of last TXN control code executed
 * @ctx_pc:                     program counter for that context
 * @fatal_error_type:           the fatal error type if context crashes
 * @fatal_error_exception_type: LX7 exception type
 * @fatal_error_exception_pc:   LX7 program counter at the time of the exception
 * @fatal_error_app_module:     module name where the exception occurred
 *
 * Field                       Default value  Comment
 * txn_op_idx:                 0xFFFFFFFF     there is no txn control code is running or the
 *                                            last txn control code op idx is not captured
 * ctx_pc:                     0              context .text program counter is not captured
 * fatal_error_type:           0              no fatal error or fatal error is not captured
 * fatal_error_exception_type: 0
 * fatal_error_exception_pc:   0
 * fatal_error_app_module:     0
 *
 * Once an amdxdna_cmd completes with state ERT_CMD_STATE_TIMEOUT, the
 * amdxdna_cmd starting from payload will have the following information for npu0 gen.
 */
struct amdxdna_ctx_health_data_aie2 {
	u32 txn_op_idx;
	u32 ctx_pc;
	u32 fatal_error_type;
	u32 fatal_error_exception_type;
	u32 fatal_error_exception_pc;
	u32 fatal_error_app_module;
};

/**
 * struct uc_health_info: Health data for each cert
 *
 * @uc_idx:            uC index in this context, 0 is the lead
 * @uc_idle_status:    valid when CERT is CTX_IDEL, represent the reason CERT is idle
 *                     hsa_lite_status register:
 *                         bit 0: HSA queue not empty
 *                         bit 1: preemption save completion
 *                         bit 2: CERT is idle
 * @misc_status:       valid when UCCTX_ERROR, represent the reason UC hangs
 *                         bit 0: uC fw exception
 *                         bit 1: control code hang
 * @fw_state:          uC FW state
 * @page_idx:          page index of the current control code
 * @offset:            bytes offset inside page
 * @restore_page:      in case context is preempted, the page index to be executed on resume
 * @restore_offset:    in case context is preempted, the bytes offset inside restore_page to be
 *                     executed on resume
 * @uc_ear:            in case of uC crash, the exception address of uC
 * @uc_esr:            in case of uC crash, the exception status of uC
 * @uc_pc:             in case of uC crash, the PC of the current uC
 */
struct uc_health_info {
	u32 uc_idx;
	u32 uc_idle_status;
	u32 misc_status;
	u32 fw_state;
	u32 page_idx;
	u32 offset;
	u32 restore_page;
	u32 restore_offset;
	u32 uc_ear;
	u32 uc_esr;
	u32 uc_pc;
};

/**
 * Interpretation of payload for an amdxdna_cmd which has context health data for AIE2PS and AIE4
 *
 * @ctx_state:             context state
 * @num_ucs:               number of uC reported
 * @uc_info:               array for health data for each uC in the context.
 *                         the array size is based on num_certs.
 *
 * Once an amdxdna_cmd completes with state ERT_CMD_STATE_TIMEOUT, the
 * amdxdna_cmd starting from payload will have the following information for aie2ps/aie4 generation.
 */
struct amdxdna_ctx_health_data_aie4 {
	u32 ctx_state;
	u32 num_uc;
	struct uc_health_info uc_info[];
};

/**
 * Interpretation of payload for an amdxdna_cmd
 *
 * @version:               context health data version (1)
 * @npu_gen:               npu generation
 * @aie2:                  context health data for npu generation aie2/aie2p
 * @aie4:                  context health data for npu generation aie2ps/aie4
 *
 * If version is 1, we should use this data structure to parse context health data
 * starting from the amdxdna_cmd payload. And use corresponding data structure based
 * on the npu generation.
 */
struct amdxdna_ctx_health_data {
#define AMDXDNA_CTX_HEALTH_DATA_V0	0
#define AMDXDNA_CTX_HEALTH_DATA_V1	1
	u32 version;
#define AMDXDNA_NPU_GEN_AIE2		0
#define AMDXDNA_NPU_GEN_AIE4		1
	u32 npu_gen;
	union {
		struct amdxdna_ctx_health_data_aie2 aie2;
		struct amdxdna_ctx_health_data_aie4 aie4;
	};
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

#define INVALID_CU_IDX		(~0U)

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
	struct amdxdna_hwctx_param_config_cu *cus;

	/* Submitted, completed, freed job counter */
	u64				submitted;
	u64				completed ____cacheline_aligned_in_smp;
	/* Counter for freed job */
	atomic64_t			job_free_cnt;
	/* For command completion notification. */
	u32				syncobj_hdl;
	struct drm_syncobj		*syncobj;
	struct mutex			io_lock; /* protect job queue and enforce cmd order */
	struct semaphore		io_slot_sem;

	struct amdxdna_ctx_health_data	health_data;
	u32				timeout_run_list_id;
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
	struct list_head	list;
	struct kref		refcnt;
	struct amdxdna_ctx	*ctx;
	struct mm_struct	*mm;
	/* The fence to indicate that job is done by hardware */
	struct dma_fence	*fence;
	/* Job submitter can wait on this fence */
	struct dma_fence	*out_fence;
#define JOB_STATE_INIT			0
#define JOB_STATE_PENDING		1
#define JOB_STATE_SUBMITTING		2
#define JOB_STATE_SUBMITTED		3
#define JOB_STATE_SUBMITTED_CHAIN	4
#define JOB_STATE_DONE			5
	int			state;
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
	struct amdxdna_cmd *cmd = amdxdna_gem_vmap(abo);

	return FIELD_GET(AMDXDNA_CMD_OPCODE, cmd->header);
}

static inline void
amdxdna_cmd_set_state(struct amdxdna_gem_obj *abo, enum ert_cmd_state s)
{
	struct amdxdna_cmd *cmd = amdxdna_gem_vmap(abo);

	cmd->header &= ~AMDXDNA_CMD_STATE;
	cmd->header |= FIELD_PREP(AMDXDNA_CMD_STATE, s);
}

static inline enum ert_cmd_state
amdxdna_cmd_get_state(struct amdxdna_gem_obj *abo)
{
	struct amdxdna_cmd *cmd = amdxdna_gem_vmap(abo);

	return FIELD_GET(AMDXDNA_CMD_STATE, cmd->header);
}

static inline void *
amdxdna_cmd_get_data(struct amdxdna_gem_obj *abo, u32 *size)
{
	struct amdxdna_cmd *cmd = amdxdna_gem_vmap(abo);

	*size = abo->mem.size - offsetof(struct amdxdna_cmd, data);
	return cmd->data;
}

static inline void *
amdxdna_cmd_get_payload(struct amdxdna_gem_obj *abo, u32 *size)
{
	struct amdxdna_cmd *cmd = amdxdna_gem_vmap(abo);
	u32 num_masks, count;

	if (amdxdna_cmd_get_op(abo) == ERT_CMD_CHAIN)
		num_masks = 0;
	else
		num_masks = 1 + FIELD_GET(AMDXDNA_CMD_EXTRA_CU_MASK, cmd->header);

	if (size) {
		count = FIELD_GET(AMDXDNA_CMD_COUNT, cmd->header);
		if (unlikely(count <= num_masks ||
			     count * sizeof(u32) +
			     offsetof(struct amdxdna_cmd, data[0]) >
			     abo->mem.size)) {
			*size = 0;
			return NULL;
		}
		*size = (count - num_masks) * sizeof(u32);
	}
	return &cmd->data[num_masks];
}

static inline struct amdxdna_cmd_chain *
amdxdna_cmd_get_chained_payload(struct amdxdna_gem_obj *cmd_abo, u32 *sub_cmd_cnt)
{
#define	MAX_CHAINED_SUB_CMD	64
	struct amdxdna_cmd_chain *payload;
	u32 payload_len, ccnt;

	payload = amdxdna_cmd_get_payload(cmd_abo, &payload_len);
	if (!payload)
		return NULL;
	if (sub_cmd_cnt) {
		ccnt = payload->command_count;
		if (!ccnt || ccnt > MAX_CHAINED_SUB_CMD ||
		    payload_len < struct_size(payload, data, ccnt))
			return NULL;
		*sub_cmd_cnt = ccnt;
	}
	return payload;
}

static inline u32
amdxdna_cmd_get_cu_idx(struct amdxdna_gem_obj *abo)
{
	struct amdxdna_cmd *cmd = amdxdna_gem_vmap(abo);
	u32 num_masks, i;
	u32 *cu_mask;
	int cu_idx;

	if (amdxdna_cmd_get_op(abo) == ERT_CMD_CHAIN)
		return INVALID_CU_IDX;

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

int amdxdna_ctx_syncobj_create(struct amdxdna_ctx *ctx);
void amdxdna_ctx_syncobj_destroy(struct amdxdna_ctx *ctx);
int amdxdna_cmd_wait(struct amdxdna_client *client, u32 ctx_hdl,
		     u64 seq, u32 timeout);

int amdxdna_drm_create_hwctx_ioctl(struct drm_device *dev, void *data, struct drm_file *filp);
int amdxdna_drm_config_hwctx_ioctl(struct drm_device *dev, void *data, struct drm_file *filp);
int amdxdna_drm_destroy_hwctx_ioctl(struct drm_device *dev, void *data, struct drm_file *filp);
int amdxdna_drm_submit_cmd_ioctl(struct drm_device *dev, void *data, struct drm_file *filp);
int amdxdna_drm_wait_cmd_ioctl(struct drm_device *dev, void *data, struct drm_file *filp);

#endif /* _AMDXDNA_CTX_H_ */

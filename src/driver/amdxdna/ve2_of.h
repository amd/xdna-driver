/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2025, Advanced Micro Devices, Inc.
 */

#ifndef _VE2_OF_H_
#define _VE2_OF_H_

#include "amdxdna_of_drv.h"
#include "ve2_host_queue.h"
#include "ve2_fw.h"

#define HWCTX_MAX_CMDS		HOST_QUEUE_ENTRY
#define get_job_idx(seq)	((seq) & (HWCTX_MAX_CMDS - 1))

#define VERBOSITY_LEVEL_DBG	2
#define VE2_MAX_COL		36

#define aie_calc_part_id(start_col, num_col)	\
	(((start_col) << AIE_PART_ID_START_COL_SHIFT) + \
	 ((num_col) << AIE_PART_ID_NUM_COLS_SHIFT))

extern int enable_polling;
extern int verbosity;
extern int start_col;
extern int partition_size;
extern u32 ve2_hwctx_limit;

struct aie_version {
	u16 major;
	u16 minor;
};

struct aie_tile_metadata {
	u16 row_count;
	u16 row_start;
	u16 dma_channel_count;
	u16 lock_count;
	u16 event_reg_count;
};

struct aie_metadata {
	u32 size;
	u16 cols;
	u16 rows;
	struct aie_version version;
	struct aie_tile_metadata core;
	struct aie_tile_metadata mem;
	struct aie_tile_metadata shim;
};

struct clock_entry {
	char name[16];
	u32 freq_mhz;
};

struct ve2_config_hwctx {
	u64	log_buf_addr;
	u32	log_buf_size;
	u64	debug_buf_addr;
	u32	debug_buf_size;
	u64	dtrace_addr;
	u32	opcode_timeout_config;
};

// Define the node struct for the FIFO queue
struct amdxdna_ctx_command_fifo {
	struct amdxdna_ctx              *ctx;
	u64                             command_index;
	struct list_head                list;
};

struct amdxdna_ctx_priv {
	u32				start_col;
	u32				num_col;
	u32				state;
	struct device			*aie_dev;
	struct aie_partition_init_args	*args;
	struct ve2_hsa_queue		hwctx_hsa_queue;
	struct ve2_config_hwctx		hwctx_config[VE2_MAX_COL];
	wait_queue_head_t		waitq;
	struct amdxdna_sched_job	*pending[HWCTX_MAX_CMDS];
	struct timer_list		event_timer;
	bool			misc_intrpt_flag; /* Hardware sync required */
	struct mutex			privctx_lock; /* protect private ctx */
};

struct amdxdna_dev_priv {
	const char		*fw_path;
	u32			hwctx_limit; /* Hardware determine */
	u32			ctx_limit; /* Driver determine */
};

struct amdxdna_mgmtctx {
	struct amdxdna_dev		*xdna;
	struct amdxdna_ctx		*active_ctx;
	struct device			*mgmt_aiedev;
	u32				start_col;
	u32				mgmt_partid;
	struct aie_partition_init_args	args;
	struct list_head		ctx_command_fifo_head;
	spinlock_t			ctx_lock; /* protect ctx add/remove/update */
	struct work_struct		sched_work;
	struct workqueue_struct		*mgmtctx_workq;
	u32			is_partition_idle; /* Hardware sync required */
	u32			is_context_req; /* Hardware sync required */
	u32			is_idle_due_to_context; /* Hardware sync required */
};

struct amdxdna_dev_hdl {
	struct amdxdna_dev		*xdna;
	const struct amdxdna_dev_priv	*priv;
	u32				hwctx_limit;
	u32				hwctx_cnt;
	void				*xrs_hdl;
	struct ve2_firmware_version	fw_version;
	struct ve2_firmware_status	*fw_slots[VE2_MAX_COL];
	struct amdxdna_mgmtctx          ve2_mgmtctx[VE2_MAX_COL];
};

/* ve2_of.c */
extern const struct amdxdna_dev_ops ve2_ops;
int ve2_hwctx_init(struct amdxdna_ctx *hwctx);
void ve2_hwctx_fini(struct amdxdna_ctx *hwctx);
int ve2_hwctx_config(struct amdxdna_ctx *hwctx, u32 type, u64 mdata_hdl, void *buf, u32 size);
void ve2_free_firmware_slots(struct amdxdna_dev_hdl *xdna_hdl, u32 max_cols);

int ve2_cmd_submit(struct amdxdna_ctx *hwctx, struct amdxdna_sched_job *job, u32 *syncobj_hdls,
		   u64 *syncobj_points, u32 syncobj_cnt, u64 *seq);
int ve2_cmd_wait(struct amdxdna_ctx *hwctx, u64 seq, u32 timeout);

/* ve2_debug.c */
int ve2_set_aie_state(struct amdxdna_client *client, struct amdxdna_drm_set_state *args);
int ve2_get_aie_info(struct amdxdna_client *client, struct amdxdna_drm_get_info *args);
void packet_dump(struct amdxdna_dev *xdna, struct hsa_queue *queue, u64 slot_id);
int ve2_get_array(struct amdxdna_client *client, struct amdxdna_drm_get_array *args);
#endif /* _VE2_OF_H_ */

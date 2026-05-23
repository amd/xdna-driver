/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2024-2026, Advanced Micro Devices, Inc.
 *
 * VE2 AIE backend — direct Linux xlnx-aie partition APIs (temporal sharing).
 */

#ifndef _VE2_AIE_H_
#define _VE2_AIE_H_

#include <linux/mutex.h>
#include <linux/wait.h>

struct amdxdna_dev;
struct amdxdna_hwctx;
struct ve2_aie_context;

struct ve2_ctx_fifo_entry {
	struct ve2_aie_context		*ctx;
	u32				command_index;
	struct ve2_ctx_fifo_entry	*next;
};

struct ve2_aie_mgmtctx {
	struct device			*aie_dev;
	struct ve2_aie_context		*active_ctx;
	struct ve2_ctx_fifo_entry	*fifo_head;
	struct ve2_ctx_fifo_entry	*fifo_tail;
	struct workqueue_struct		*work_queue;
	struct work_struct		scheduler_work;
	spinlock_t			fifo_lock;/* protect command fifo list */
	struct mutex			ctx_lock;/* protect active_ctx and scheduler */
	bool				partition_idle;
	bool				is_context_req;
	bool				is_idle_due_to_context;
	u32				start_col;
	u32				num_col;
	u32				partition_id;
	void				*handshake;
	struct amdxdna_dev		*xdna;
};

struct ve2_aie_context {
	struct ve2_aie_mgmtctx		*mgmtctx;
	struct amdxdna_hwctx		*hwctx;

	struct device			*hsa_dma_dev;
	void				*hsa_queue_va;
	dma_addr_t			hsa_queue_pa;
	u32				hsa_queue_size;
	u32				write_idx;
	u32				read_idx;

	wait_queue_head_t		waitq;
	u64				last_seq;

	bool				in_fifo;
	bool				handshake_initialized;
};

int ve2_aie_hwctx_create(struct amdxdna_dev *xdna, struct amdxdna_hwctx *hwctx,
			 u32 *partition_id, struct ve2_aie_context **aie_ctx);
void ve2_aie_hwctx_destroy(struct amdxdna_dev *xdna, struct ve2_aie_context *aie_ctx,
			   u32 partition_id);

/* Notify firmware after host queue commit (ve2_hq.c). */
int ve2_aie_kick_cmd(struct ve2_aie_context *aie_ctx, u64 command_index);

#endif /* _VE2_AIE_H_ */

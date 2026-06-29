// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2024-2026, Advanced Micro Devices, Inc.
 *
 * VE2 management backend — XRS resource request, AIE partition lifecycle,
 * and command scheduling via the Linux xlnx-aie partition APIs.
 */

#include <linux/device.h>
#include <linux/errno.h>
#include <linux/ktime.h>
#include <linux/slab.h>
#include <linux/wait.h>
#include <linux/workqueue.h>
#include <linux/xlnx-ai-engine.h>

#include "amdxdna_ctx.h"
#include "amdxdna_drv.h"
#include "amdxdna_solver.h"
#include "ve2_aux.h"
#include "ve2_hwctx.h"
#include "ve2_host_queue.h"
#include "ve2_mgmt.h"

static int ve2_create_mgmt_partition(struct amdxdna_dev *xdna, struct amdxdna_hwctx *hwctx,
				     bool create_aie_part);
static void ve2_scheduler_work(struct work_struct *work);
static void ve2_irq_handler(u32 partition_id, void *priv);
static void ve2_aie_error_cb(void *arg);
static struct amdxdna_hwctx *ve2_response_ctx_switch_req(struct amdxdna_mgmtctx *mgmtctx);
static int ve2_request_context_switch(struct amdxdna_mgmtctx *mgmtctx);

int ve2_mgmtctx_registry_init(struct amdxdna_dev_hdl *hdl)
{
	struct amdxdna_dev *xdna = hdl->xdna;
	u32 cols = hdl->aie_dev_info.cols;
	u32 i;

	hdl->ve2_mgmtctx = devm_kcalloc(xdna->ddev.dev, cols,
					sizeof(*hdl->ve2_mgmtctx), GFP_KERNEL);
	if (!hdl->ve2_mgmtctx)
		return -ENOMEM;

	/*
	 * Initialise per-partition locks/state once. The entry indexed by a
	 * lead column is (re)populated with an AIE partition when the first
	 * sharer is created and torn down when the last sharer is destroyed.
	 */
	for (i = 0; i < cols; i++) {
		struct amdxdna_mgmtctx *mgmtctx = &hdl->ve2_mgmtctx[i];

		mgmtctx->xdna = xdna;
		mgmtctx->start_col = i;
		INIT_LIST_HEAD(&mgmtctx->ctx_command_fifo_head);
		mutex_init(&mgmtctx->ctx_lock);
		mutex_init(&mgmtctx->async_errs_cache.lock);
		init_completion(&mgmtctx->error_cb_completion);
		atomic_set(&mgmtctx->error_cb_in_progress, 0);
	}

	return 0;
}

static void cert_setup_partition(struct amdxdna_mgmtctx *mgmtctx,
				 struct amdxdna_hwctx *hwctx, u32 col,
				 struct handshake *cert_hs)
{
	struct amdxdna_ctx_priv *vp = ve2_hw_priv(hwctx);
	struct ve2_config_hwctx *cfg = NULL;
	u64 hsa_addr = U64_MAX;

	if (col == 0 && vp && vp->hsa_queue.hsa_queue_dma_addr)
		hsa_addr = vp->hsa_queue.hsa_queue_dma_addr;

	if (vp && vp->hwctx_config && col < hwctx->num_col)
		cfg = &vp->hwctx_config[col];

	cert_hs->partition_base_address = VE2_ADDR(mgmtctx->start_col, 0, 0);
	cert_hs->aie_info.partition_size = mgmtctx->num_col;
	cert_hs->hsa_addr_high = upper_32_bits(hsa_addr);
	cert_hs->hsa_addr_low = lower_32_bits(hsa_addr);

	if (cfg) {
		cert_hs->log_addr_high = upper_32_bits(cfg->log_buf_addr);
		cert_hs->log_addr_low = lower_32_bits(cfg->log_buf_addr);
		cert_hs->log_buf_size = cfg->log_buf_size;
		cert_hs->dbg_buf.dbg_buf_addr_high = upper_32_bits(cfg->debug_buf_addr);
		cert_hs->dbg_buf.dbg_buf_addr_low = lower_32_bits(cfg->debug_buf_addr);
		cert_hs->dbg_buf.size = cfg->debug_buf_size;
		cert_hs->trace.dtrace_addr_high = upper_32_bits(cfg->dtrace_addr);
		cert_hs->trace.dtrace_addr_low = lower_32_bits(cfg->dtrace_addr);
		cert_hs->opcode_timeout_config = cfg->opcode_timeout_config;
	}

	cert_hs->ctx_switch_req = 0;
	cert_hs->hsa_location = 0;
	cert_hs->mpaie_alive = ALIVE_MAGIC;
}

static void ve2_free_hs_data(struct aie_op_handshake_data *hs_data, u32 max_cols)
{
	if (!hs_data)
		return;

	for (u32 col = 0; col < max_cols; col++) {
		kfree(hs_data[col].addr);
		hs_data[col].addr = NULL;
	}
	kfree(hs_data);
}

static struct aie_op_handshake_data *
ve2_prepare_hs_data(struct amdxdna_mgmtctx *mgmtctx, struct amdxdna_hwctx *hwctx, bool init)
{
	struct amdxdna_dev *xdna = mgmtctx->xdna;
	struct aie_op_handshake_data *hs_data;
	u32 num_col = mgmtctx->num_col;
	struct aie_location aie_loc;

	hs_data = kmalloc_array(num_col, sizeof(*hs_data), GFP_KERNEL);
	if (!hs_data) {
		XDNA_ERR(xdna, "No memory for handshake data allocation");
		return NULL;
	}

	for (u32 col = 0; col < num_col; col++) {
		struct handshake *cert_hs;

		aie_loc.col = col;
		aie_loc.row = 0;
		cert_hs = kzalloc(sizeof(*cert_hs), GFP_KERNEL);
		if (!cert_hs) {
			XDNA_ERR(xdna, "No memory for cert hs packet");
			ve2_free_hs_data(hs_data, col);
			return NULL;
		}
		if (init)
			cert_setup_partition(mgmtctx, hwctx, col, cert_hs);

		hs_data[col].addr = cert_hs;
		hs_data[col].size = sizeof(struct handshake);
		hs_data[col].offset = 0x0;
		hs_data[col].loc = aie_loc;
	}

	return hs_data;
}

static int ve2_xrs_col_list(struct amdxdna_hwctx *hwctx, u32 total_col)
{
	struct amdxdna_dev *xdna = hwctx->client->xdna;
	u32 user_col = hwctx->qos.user_start_col;
	u32 num_col = hwctx->num_tiles;
	u32 first_col = 0;
	u32 entries = 0;
	u32 s, i;

	if (!num_col || num_col > total_col) {
		XDNA_ERR(xdna, "Invalid num_col %u (total_col %u)", num_col, total_col);
		return -EINVAL;
	}

	if (user_col != USER_START_COL_NOT_REQUESTED) {
		if (user_col % VE2_MIN_COL_SUPPORT != 0) {
			XDNA_ERR(xdna, "user_start_col %u not aligned to %u", user_col,
				 VE2_MIN_COL_SUPPORT);
			return -EINVAL;
		}
		if (user_col + num_col > total_col) {
			XDNA_ERR(xdna, "user_start_col %u + num_col %u exceeds total_col %u",
				 user_col, num_col, total_col);
			return -ERANGE;
		}
		first_col = user_col;
	}

	for (s = first_col; s + num_col <= total_col; s += VE2_MIN_COL_SUPPORT)
		entries++;

	if (!entries) {
		XDNA_ERR(xdna, "No valid start col for num_col %u (first_col %u total_col %u)",
			 num_col, first_col, total_col);
		return -EINVAL;
	}

	hwctx->col_list = kmalloc_array(entries, sizeof(*hwctx->col_list), GFP_KERNEL);
	if (!hwctx->col_list)
		return -ENOMEM;

	hwctx->col_list_len = entries;
	for (i = 0, s = first_col; i < entries; i++, s += VE2_MIN_COL_SUPPORT)
		hwctx->col_list[i] = s;

	print_hex_dump_debug("col_list: ", DUMP_PREFIX_OFFSET, 16, 4, hwctx->col_list,
			     entries * sizeof(*hwctx->col_list), false);
	return 0;
}

int ve2_xrs_request(struct amdxdna_dev *xdna, struct amdxdna_hwctx *hwctx)
{
	struct amdxdna_dev_hdl *hdl = ve2_dev_hdl(xdna);
	struct amdxdna_ctx_priv *vp = ve2_hw_priv(hwctx);
	struct solver_state *xrs = xdna->xrs_hdl;
	bool create_aie_part = false;
	int ret;

	if (!vp || !hdl || !xrs)
		return -EINVAL;

	/* Build the candidate start-column list, then let XRS place the partition. */
	ret = ve2_xrs_col_list(hwctx, hdl->aie_dev_info.cols);
	if (ret)
		return ret;

	hwctx->num_col = hwctx->num_tiles;
	mutex_lock(&xrs->xrs_lock);
	ret = amdxdna_alloc_resource(hwctx, &create_aie_part);
	mutex_unlock(&xrs->xrs_lock);
	kfree(hwctx->col_list);
	hwctx->col_list = NULL;
	if (ret) {
		XDNA_ERR(xdna, "XRS resource request failed, ret %d", ret);
		return ret;
	}

	ret = ve2_create_mgmt_partition(xdna, hwctx, create_aie_part);
	if (ret) {
		XDNA_ERR(xdna, "Creating AIE partition failed, ret %d", ret);
		mutex_lock(&xrs->xrs_lock);
		amdxdna_release_resource(hwctx, NULL);
		mutex_unlock(&xrs->xrs_lock);
		return ret;
	}

	vp->handshake_initialized = false;

	return 0;
}

static int ve2_fifo_enqueue(struct amdxdna_mgmtctx *mgmtctx,
			    struct amdxdna_hwctx *hwctx, u64 command_index)
{
	struct ve2_ctx_fifo_entry *node;

	node = kzalloc(sizeof(*node), GFP_KERNEL);
	if (!node)
		return -ENOMEM;

	node->ctx = hwctx;
	node->command_index = command_index;
	INIT_LIST_HEAD(&node->list);
	list_add_tail(&node->list, &mgmtctx->ctx_command_fifo_head);

	return 0;
}

static int ve2_mgmt_handshake_init(struct amdxdna_mgmtctx *mgmtctx,
				   struct amdxdna_hwctx *hwctx)
{
	struct amdxdna_dev *xdna = mgmtctx->xdna;
	struct amdxdna_ctx_priv *vp = ve2_hw_priv(hwctx);
	struct aie_partition_init_args args = { };
	struct aie_op_handshake_data *hs_data;
	u32 num_col = mgmtctx->num_col;
	int col, ret;

	if (!vp)
		return -EINVAL;

	hs_data = ve2_prepare_hs_data(mgmtctx, hwctx, true);
	if (!hs_data) {
		XDNA_ERR(xdna, "preparing cert handshake data failed");
		return -ENOMEM;
	}

	args.handshake = hs_data;
	args.handshake_cols = num_col;
	args.locs = NULL;
	args.num_tiles = 0;
	args.init_opts = (AIE_PART_INIT_OPT_DEFAULT | AIE_PART_INIT_OPT_HANDSHAKE |
			  AIE_PART_INIT_OPT_DIS_TLAST_ERROR) &
			 ~AIE_PART_INIT_OPT_UC_ENB_MEM_PRIV;

	ret = aie_partition_initialize(mgmtctx->aie_dev, &args);
	if (ret < 0) {
		XDNA_ERR(xdna, "aie partition init failed: %d", ret);
		goto release_hs_data;
	}

	for (col = num_col - 1; col >= 0; col--) {
		struct aie_location loc = { .col = col, .row = 0 };

		ret = aie_partition_uc_wakeup(mgmtctx->aie_dev, &loc);
		if (ret)
			goto release_hs_data;
	}

	vp->handshake_initialized = true;
	ret = 0;

release_hs_data:
	ve2_free_hs_data(hs_data, num_col);
	return ret;
}

/*
 * Ask the firmware to save the currently-running context and yield the
 * partition. The CERT acknowledges by going idle, which the scheduler/IRQ
 * path detects to bring in the next context.
 */
#define RR_SHARING BIT(0)
static int ve2_request_context_switch(struct amdxdna_mgmtctx *mgmtctx)
{
	u32 val = 0;

	ve2_partition_read_privileged_mem(mgmtctx, offsetof(struct handshake, ctx_switch_req),
					  sizeof(val), &val);
	val |= RR_SHARING;
	ve2_partition_write_privileged_mem(mgmtctx, offsetof(struct handshake, ctx_switch_req),
					   sizeof(val), &val);
	mgmtctx->is_context_req = 1;

	return 0;
}

/*
 * Bring in the context at the head of the command FIFO once the firmware has
 * acknowledged a switch request (is_idle_due_to_context). Reprograms the
 * handshake to point at the incoming context's host queue and, if the entry
 * after the head belongs to yet another context, arms the next switch.
 * Returns the newly scheduled context, or NULL if the FIFO is empty.
 */
static struct amdxdna_hwctx *ve2_response_ctx_switch_req(struct amdxdna_mgmtctx *mgmtctx)
{
	struct ve2_ctx_fifo_entry *c_ctx, *t_ctx;
	struct amdxdna_hwctx *hwctx = NULL;

	lockdep_assert_held(&mgmtctx->ctx_lock);

	list_for_each_entry_safe(c_ctx, t_ctx, &mgmtctx->ctx_command_fifo_head, list) {
		if (mgmtctx->is_idle_due_to_context) {
			hwctx = c_ctx->ctx;
			mgmtctx->is_partition_idle = 0;
			ve2_mgmt_handshake_init(mgmtctx, hwctx);
			if (mgmtctx->active_ctx == hwctx)
				break;
			mgmtctx->active_ctx = hwctx;
		}

		if (!list_is_last(&c_ctx->list, &mgmtctx->ctx_command_fifo_head) &&
		    c_ctx->ctx != t_ctx->ctx)
			ve2_request_context_switch(mgmtctx);

		break;
	}

	return hwctx;
}

int ve2_mgmt_schedule_cmd(struct amdxdna_dev *xdna, struct amdxdna_hwctx *hwctx,
			  u64 command_index)
{
	struct amdxdna_ctx_priv *vp = ve2_hw_priv(hwctx);
	struct amdxdna_mgmtctx *mgmtctx;
	int ret;

	if (!vp || !vp->mgmtctx)
		return -EINVAL;

	mgmtctx = vp->mgmtctx;

	mutex_lock(&mgmtctx->ctx_lock);

	ret = ve2_fifo_enqueue(mgmtctx, hwctx, command_index);
	if (ret) {
		mutex_unlock(&mgmtctx->ctx_lock);
		return ret;
	}

	if (!mgmtctx->active_ctx) {
		/* First command on this partition: program and activate it. */
		mgmtctx->is_partition_idle = 0;
		ret = ve2_mgmt_handshake_init(mgmtctx, hwctx);
		if (ret) {
			mutex_unlock(&mgmtctx->ctx_lock);
			return ret;
		}
		mgmtctx->active_ctx = hwctx;
	} else if (mgmtctx->active_ctx != hwctx) {
		/*
		 * Another context owns the partition. Switch immediately if it
		 * is idle; otherwise leave the command queued and let the
		 * IRQ/scheduler switch us in once the active context yields.
		 */
		if (mgmtctx->is_partition_idle) {
			mgmtctx->is_partition_idle = 0;
			ve2_response_ctx_switch_req(mgmtctx);
		}
	} else if (mgmtctx->is_idle_due_to_context) {
		/* We are active again after a firmware-side save; reprogram. */
		mgmtctx->is_idle_due_to_context = 0;
		mgmtctx->is_partition_idle = 0;
		ve2_mgmt_handshake_init(mgmtctx, hwctx);
		mgmtctx->active_ctx = hwctx;
	}

	mutex_unlock(&mgmtctx->ctx_lock);

	/* Ring the doorbell on the (now) active context's partition. */
	return notify_fw_cmd_ready(mgmtctx);
}

static bool ve2_check_idle(struct amdxdna_mgmtctx *mgmtctx)
{
	u32 idle_status = 0;

	ve2_aie_read_idle(mgmtctx, &idle_status);

	if (idle_status & CERT_IS_IDLE) {
		XDNA_DBG(mgmtctx->xdna,
			 "%s: active hwctx %p cert_idle_status:%x -->FOUND\n",
			 __func__, mgmtctx->active_ctx, idle_status);
		return true;
	}
	XDNA_DBG(mgmtctx->xdna,
		 "%s: active hwctx %p cert_idle_status:%x -->NOT Found\n",
		 __func__, mgmtctx->active_ctx, idle_status);

	return false;
}

static bool ve2_check_idle_or_queue_not_empty(struct amdxdna_mgmtctx *mgmtctx)
{
	u32 cert_idle_status = 0;

	ve2_partition_read_privileged_mem(mgmtctx, offsetof(struct handshake, cert_idle_status),
					  sizeof(cert_idle_status), &cert_idle_status);

	if (cert_idle_status & HSA_QUEUE_NOT_EMPTY || cert_idle_status & CERT_IS_IDLE) {
		XDNA_DBG(mgmtctx->xdna,
			 "%s: active hwctx %p cert_idle_status:%x -> FOUND\n",
			 __func__, mgmtctx->active_ctx, cert_idle_status);
		return true;
	}
	XDNA_DBG(mgmtctx->xdna,
		 "%s: active hwctx %p cert_idle_status:%x -> Not Found\n",
		 __func__, mgmtctx->active_ctx, cert_idle_status);
	return false;
}

static bool ve2_check_misc_interrupt(struct amdxdna_mgmtctx *mgmtctx)
{
	u32 off = CERT_HANDSHAKE_OFF(0) + offsetof(struct handshake, misc_status);
	u32 misc_status = 0;
	struct amdxdna_ctx_priv *vp;
	int ret;

	ret = aie_partition_read_privileged_mem(mgmtctx->aie_dev, off,
						sizeof(misc_status), &misc_status);
	if (ret || !misc_status)
		return false;

	if (mgmtctx->active_ctx) {
		vp = ve2_hw_priv(mgmtctx->active_ctx);
		if (vp)
			vp->misc_intrpt_flag = true;
	}

	return true;
}

static bool ve2_check_queue_not_empty(struct amdxdna_mgmtctx *mgmtctx)
{
	u32 cert_idle_status = 0;

	ve2_partition_read_privileged_mem(mgmtctx, offsetof(struct handshake, cert_idle_status),
					  sizeof(cert_idle_status), &cert_idle_status);

	return !!(cert_idle_status & HSA_QUEUE_NOT_EMPTY);
}

/*
 * Acknowledge a pending switch request: once the firmware has gone idle in
 * response to ctx_switch_req it is safe to reprogram the handshake for the
 * next context, which ve2_response_ctx_switch_req() then does.
 */
static bool ve2_check_context_req(struct amdxdna_mgmtctx *mgmtctx)
{
	if (mgmtctx->is_context_req) {
		mgmtctx->is_context_req = 0;
		mgmtctx->is_idle_due_to_context = 1;
		return true;
	}

	return false;
}

static void ve2_scheduler_work(struct work_struct *work)
{
	struct amdxdna_mgmtctx *mgmtctx = container_of(work, struct amdxdna_mgmtctx,
						       scheduler_work);
	struct amdxdna_ctx_priv *vp;

	guard(mutex)(&mgmtctx->ctx_lock);

	if (!mgmtctx->active_ctx)
		return;

	vp = ve2_hw_priv(mgmtctx->active_ctx);
	if (!vp)
		return;

	/* If a switch was requested, mark the firmware ready to be reprogrammed. */
	ve2_check_context_req(mgmtctx);

	if (vp->misc_intrpt_flag) {
		XDNA_ERR(mgmtctx->xdna, "MISC interrupt from firmware");
	} else if (ve2_check_queue_not_empty(mgmtctx)) {
		/*
		 * The firmware acked the switch but the active context still has
		 * queued work; bring in the next context, or mark idle if none.
		 */
		if (!ve2_response_ctx_switch_req(mgmtctx))
			mgmtctx->is_partition_idle = 1;
	} else if (ve2_check_idle(mgmtctx)) {
		/* Partition idle: schedule the next pending context, if any. */
		if (!ve2_response_ctx_switch_req(mgmtctx))
			mgmtctx->is_partition_idle = 1;
	} else {
		XDNA_DBG(mgmtctx->xdna, "Scheduler: no action needed, active_ctx=%p",
			 mgmtctx->active_ctx);
	}
}

static void pop_from_ctx_command_fifo_till(struct amdxdna_mgmtctx *mgmtctx,
					   struct amdxdna_hwctx *active_ctx,
					   u64 read_index)
{
	struct ve2_ctx_fifo_entry *c_ctx, *t_ctx;

	list_for_each_entry_safe(c_ctx, t_ctx, &mgmtctx->ctx_command_fifo_head, list) {
		if (c_ctx->ctx != active_ctx) {
			/*
			 * The next queued command belongs to a different context;
			 * ask the firmware to yield so it can be scheduled.
			 */
			ve2_request_context_switch(mgmtctx);
			break;
		}

		if (c_ctx->command_index > read_index)
			break;

		list_del(&c_ctx->list);
		kfree(c_ctx);
	}
}

static void ve2_irq_handler(u32 partition_id, void *priv)
{
	struct amdxdna_mgmtctx *mgmtctx = priv;
	struct amdxdna_hwctx *active_ctx;
	struct amdxdna_ctx_priv *vp;
	u64 read_index;

	guard(mutex)(&mgmtctx->ctx_lock);
	active_ctx = mgmtctx->active_ctx;

	if (!active_ctx)
		return;

	if (get_ctx_read_index(active_ctx, &read_index)) {
		XDNA_ERR(mgmtctx->xdna, "IRQ: failed to get read index");
		return;
	}
	pop_from_ctx_command_fifo_till(mgmtctx, active_ctx, read_index);

	vp = ve2_hw_priv(active_ctx);
	if (vp)
		wake_up_interruptible_all(&vp->waitq);

	if (mgmtctx->work_queue &&
	    (ve2_check_idle_or_queue_not_empty(mgmtctx) || ve2_check_misc_interrupt(mgmtctx))) {
		XDNA_DBG(mgmtctx->xdna, "IRQ: queue sched_work start_col=%u", mgmtctx->start_col);
		queue_work(mgmtctx->work_queue, &mgmtctx->scheduler_work);
	} else {
		XDNA_DBG(mgmtctx->xdna, "IRQ: sched_work not queued start_col=%u (wq=%p)",
			 mgmtctx->start_col, mgmtctx->work_queue);
	}
	XDNA_DBG(mgmtctx->xdna, "completion IRQ: exit read_index=%llu hwctx=%p pid=%d",
		 read_index, active_ctx, active_ctx->client->pid);
}

/*
 * AIE asynchronous error notification callback.
 *
 * Invoked by the xlnx-aie engine driver when the partition reports
 * asynchronous (AIE tile) errors. We cache the most recent error in the
 * mgmtctx so userspace can later query it via GET_ARRAY HW_LAST_ASYNC_ERR,
 * and wake any threads waiting on the active context so a stuck command can
 * unblock and report a timeout/error rather than hang forever.
 */
static void ve2_aie_error_cb(void *arg)
{
	struct amdxdna_mgmtctx *mgmtctx = arg;
	struct amdxdna_async_err_cache *cache;
	struct aie_errors *aie_errs;
	struct amdxdna_dev *xdna;
	int i;

	if (!mgmtctx) {
		pr_err("%s: mgmtctx is not initialized\n", __func__);
		return;
	}

	xdna = mgmtctx->xdna;

	/*
	 * Mark the callback as in progress so a concurrent
	 * GET_ARRAY HW_LAST_ASYNC_ERR query can wait for it to finish caching
	 * the error before reading the cache.
	 */
	atomic_set(&mgmtctx->error_cb_in_progress, 1);
	reinit_completion(&mgmtctx->error_cb_completion);

	mutex_lock(&mgmtctx->ctx_lock);

	if (!mgmtctx->aie_dev) {
		XDNA_ERR(xdna, "%s: AIE partition is not loaded\n", __func__);
		mutex_unlock(&mgmtctx->ctx_lock);
		atomic_set(&mgmtctx->error_cb_in_progress, 0);
		complete(&mgmtctx->error_cb_completion);
		return;
	}

	aie_errs = aie_get_errors(mgmtctx->aie_dev);
	if (IS_ERR_OR_NULL(aie_errs)) {
		XDNA_ERR(xdna, "%s: aie_get_errors returned NULL\n", __func__);
		mutex_unlock(&mgmtctx->ctx_lock);
		atomic_set(&mgmtctx->error_cb_in_progress, 0);
		complete(&mgmtctx->error_cb_completion);
		return;
	}

	/*
	 * Cache the last async error so userspace queries can find it. The
	 * error category/module values come from the AIE engine driver; map
	 * them onto the amdxdna error encoding consumed by userspace.
	 */
	if (aie_errs->num_err > 0) {
		struct aie_error *last_err = &aie_errs->errors[aie_errs->num_err - 1];
		enum amdxdna_error_num err_num;
		enum amdxdna_error_module err_mod;

		switch (last_err->category) {
		case 0: /* AIE_ERROR_SATURATION */
			err_num = AMDXDNA_ERROR_NUM_AIE_SATURATION;
			break;
		case 1: /* AIE_ERROR_FP */
			err_num = AMDXDNA_ERROR_NUM_AIE_FP;
			break;
		case 2: /* AIE_ERROR_STREAM */
			err_num = AMDXDNA_ERROR_NUM_AIE_STREAM;
			break;
		case 3: /* AIE_ERROR_ACCESS */
			err_num = AMDXDNA_ERROR_NUM_AIE_ACCESS;
			break;
		case 4: /* AIE_ERROR_BUS */
			err_num = AMDXDNA_ERROR_NUM_AIE_BUS;
			break;
		case 5: /* AIE_ERROR_INSTRUCTION */
			err_num = AMDXDNA_ERROR_NUM_AIE_INSTRUCTION;
			break;
		case 6: /* AIE_ERROR_ECC */
			err_num = AMDXDNA_ERROR_NUM_AIE_ECC;
			break;
		case 7: /* AIE_ERROR_LOCK */
			err_num = AMDXDNA_ERROR_NUM_AIE_LOCK;
			break;
		case 8: /* AIE_ERROR_DMA */
			err_num = AMDXDNA_ERROR_NUM_AIE_DMA;
			break;
		case 9: /* AIE_ERROR_MEM_PARITY */
			err_num = AMDXDNA_ERROR_NUM_AIE_MEM_PARITY;
			break;
		default:
			err_num = AMDXDNA_ERROR_NUM_UNKNOWN;
			break;
		}

		switch (last_err->module) {
		case 0: /* AIE_MEM_MOD */
			err_mod = AMDXDNA_ERROR_MODULE_AIE_MEMORY;
			break;
		case 1: /* AIE_CORE_MOD */
			err_mod = AMDXDNA_ERROR_MODULE_AIE_CORE;
			break;
		case 2: /* AIE_PL_MOD */
			err_mod = AMDXDNA_ERROR_MODULE_AIE_PL;
			break;
		default:
			err_mod = AMDXDNA_ERROR_MODULE_UNKNOWN;
			break;
		}

		cache = &mgmtctx->async_errs_cache;
		mutex_lock(&cache->lock);
		cache->err.ts_us = ktime_to_us(ktime_get_real());
		cache->err.err_code = AMDXDNA_ERROR_ENCODE(err_num, err_mod);
		cache->err.ex_err_code = AMDXDNA_EXTRA_ERR_ENCODE(last_err->loc.row,
								  last_err->loc.col);
		mutex_unlock(&cache->lock);
	}

	for (i = 0; i < aie_errs->num_err; i++) {
		XDNA_DBG(xdna,
			 "AIE async error: id %d mod %d category %d col %d row %d\n",
			 aie_errs->errors[i].error_id,
			 aie_errs->errors[i].module,
			 aie_errs->errors[i].category,
			 aie_errs->errors[i].loc.col,
			 aie_errs->errors[i].loc.row);
	}

	aie_free_errors(aie_errs);

	/*
	 * Wake up any thread waiting on the active context so a command stuck
	 * waiting on the faulting partition can detect the error and return
	 * instead of hanging indefinitely.
	 */
	if (mgmtctx->active_ctx) {
		struct amdxdna_ctx_priv *vp = ve2_hw_priv(mgmtctx->active_ctx);

		if (vp) {
			vp->misc_intrpt_flag = true;
			wake_up_interruptible_all(&vp->waitq);
			XDNA_ERR(xdna, "AIE error detected, waking up waiting threads\n");
		}
	}

	mutex_unlock(&mgmtctx->ctx_lock);

	/* Error cached and threads woken: let any waiting query proceed. */
	atomic_set(&mgmtctx->error_cb_in_progress, 0);
	complete(&mgmtctx->error_cb_completion);
}

/**
 * ve2_create_mgmt_partition - Create and initialize a management partition for VE2 device
 * @xdna: Pointer to the AMD XDNA device structure
 * @hwctx: Pointer to the hardware context structure
 * @load_act: Pointer to the XRS action load structure containing partition info
 *
 * This function sets up the management context, requests the AIE partition if needed,
 * initializes workqueues for command scheduling, and updates context pointers.
 * Returns 0 on success or a negative error code on failure.
 */
static int ve2_create_mgmt_partition(struct amdxdna_dev *xdna, struct amdxdna_hwctx *hwctx,
				     bool create_aie_part)
{
	struct amdxdna_dev_hdl *xdna_hdl = xdna->dev_handle;
	struct amdxdna_ctx_priv *vp = ve2_hw_priv(hwctx);
	u32 start_col = hwctx->start_col;
	u32 num_col = hwctx->num_col;
	struct amdxdna_mgmtctx *mgmtctx;
	struct aie_partition_req req = { };
	struct device *aie_dev;
	int ret;

	if (!vp || start_col >= xdna_hdl->aie_dev_info.cols)
		return -EINVAL;

	mgmtctx = &xdna_hdl->ve2_mgmtctx[start_col];

	if (create_aie_part) {
		mgmtctx->num_col = num_col;
		mgmtctx->num_rows = xdna_hdl->aie_dev_info.rows;
		mgmtctx->active_ctx = NULL;
		mgmtctx->is_partition_idle = 0;
		mgmtctx->is_context_req = 0;
		mgmtctx->is_idle_due_to_context = 0;
		memset(&mgmtctx->async_errs_cache.err, 0,
		       sizeof(mgmtctx->async_errs_cache.err));

		mgmtctx->work_queue = create_singlethread_workqueue("ve2_aie_sched");
		if (!mgmtctx->work_queue)
			return -ENOMEM;

		INIT_WORK(&mgmtctx->scheduler_work, ve2_scheduler_work);

		req.partition_id = (start_col << AIE_PART_ID_START_COL_SHIFT) |
				   (num_col << AIE_PART_ID_NUM_COLS_SHIFT);
		req.user_event1_complete = ve2_irq_handler;
		req.user_event1_priv = mgmtctx;
		aie_dev = aie_partition_request(&req);
		if (IS_ERR(aie_dev)) {
			ret = PTR_ERR(aie_dev);
			goto destroy_wq;
		}

		mgmtctx->aie_dev = aie_dev;
		mgmtctx->partition_id = req.partition_id;

		ret = aie_register_error_notification(aie_dev, ve2_aie_error_cb, mgmtctx);
		if (ret) {
			XDNA_ERR(xdna, "Failed to register AIE error notification: %d", ret);
			goto release_part;
		}
	} else if (!mgmtctx->aie_dev) {
		XDNA_ERR(xdna, "No AIE partition to share at start_col %u", start_col);
		return -ENODEV;
	}

	vp->mgmtctx = mgmtctx;
	vp->partition_id = mgmtctx->partition_id;

	return 0;

release_part:
	aie_partition_teardown(mgmtctx->aie_dev);
	aie_partition_release(mgmtctx->aie_dev);
	mgmtctx->aie_dev = NULL;
destroy_wq:
	destroy_workqueue(mgmtctx->work_queue);
	mgmtctx->work_queue = NULL;
	return ret;
}

static void ve2_fifo_remove_ctx(struct amdxdna_mgmtctx *mgmtctx, struct amdxdna_hwctx *hwctx)
{
	struct ve2_ctx_fifo_entry *c_ctx, *t_ctx;

	list_for_each_entry_safe(c_ctx, t_ctx, &mgmtctx->ctx_command_fifo_head, list) {
		if (!hwctx || c_ctx->ctx == hwctx) {
			list_del(&c_ctx->list);
			kfree(c_ctx);
		}
	}
}

int ve2_mgmt_destroy_partition(struct amdxdna_hwctx *hwctx)
{
	struct amdxdna_ctx_priv *vp = hwctx ? ve2_hw_priv(hwctx) : NULL;
	bool release_aie_part = false;
	struct amdxdna_mgmtctx *mgmtctx;
	struct solver_state *xrs;

	mgmtctx = vp ? vp->mgmtctx : NULL;
	if (!mgmtctx) {
		/* No partition was created; still release any XRS reservation. */
		if (hwctx) {
			xrs = hwctx->client->xdna->xrs_hdl;
			if (xrs) {
				mutex_lock(&xrs->xrs_lock);
				amdxdna_release_resource(hwctx, NULL);
				mutex_unlock(&xrs->xrs_lock);
			}
		}
		return -EINVAL;
	}

	xrs = hwctx->client->xdna->xrs_hdl;

	/*
	 * Clear active_ctx FIRST to prevent IRQ handler from queueing new work,
	 * remove all FIFO entries for this context to prevent use-after-free,
	 * then cancel any pending work to ensure no work is accessing this context
	 */
	mutex_lock(&mgmtctx->ctx_lock);
	if (mgmtctx->active_ctx == hwctx)
		mgmtctx->active_ctx = NULL;
	/* Remove all FIFO entries for this context before freeing it */
	ve2_fifo_remove_ctx(mgmtctx, hwctx);
	mutex_unlock(&mgmtctx->ctx_lock);

	/* Release the XRS reservation; learn whether we were the last sharer. */
	if (xrs) {
		mutex_lock(&xrs->xrs_lock);
		amdxdna_release_resource(hwctx, &release_aie_part);
		mutex_unlock(&xrs->xrs_lock);
	}

	if (release_aie_part) {
		struct workqueue_struct *wq;

		aie_unregister_error_notification(mgmtctx->aie_dev);

		mutex_lock(&mgmtctx->ctx_lock);
		/* Update the active context as partition doesn't exists any more */
		mgmtctx->active_ctx = NULL;
		wq = mgmtctx->work_queue;
		mgmtctx->work_queue = NULL;
		mutex_unlock(&mgmtctx->ctx_lock);

		aie_partition_teardown(mgmtctx->aie_dev);
		aie_partition_release(mgmtctx->aie_dev);
		mgmtctx->aie_dev = NULL;

		if (wq)
			destroy_workqueue(wq);

		mutex_lock(&mgmtctx->ctx_lock);
		ve2_fifo_remove_ctx(mgmtctx, NULL);
		mutex_unlock(&mgmtctx->ctx_lock);
	}

	vp->mgmtctx = NULL;

	return 0;
}

int notify_fw_cmd_ready(struct amdxdna_mgmtctx *mgmtctx)
{
	u32 event_val = VE2_USER_EVENT_ID;
	struct aie_location loc = { .col = 0, .row = 0 };
	int ret;

	ret = aie_partition_write(mgmtctx->aie_dev, loc, VE2_EVENT_GENERATE_REG,
				  sizeof(event_val), &event_val, 0);
	if (ret < 0)
		return ret;

	/* aie_partition_write returns bytes written on success (typically 4). */
	return 0;
}

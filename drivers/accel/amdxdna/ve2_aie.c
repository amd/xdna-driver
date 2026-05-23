// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2024-2026, Advanced Micro Devices, Inc.
 *
 * VE2 AIE backend — Linux xlnx-aie partition APIs (temporal sharing).
 */

#include <linux/bitops.h>
#include <linux/device.h>
#include <linux/dma-mapping.h>
#include <linux/errno.h>
#include <linux/slab.h>
#include <linux/timekeeping.h>
#include <linux/workqueue.h>
#include <linux/xlnx-ai-engine.h>

#include "amdxdna_ctx.h"
#include "amdxdna_drv.h"
#include "ve2_aie.h"
#include "ve2_aux.h"
#include "ve2_handshake.h"
#include "ve2_hq.h"
#include "ve2_hwctx.h"
#include "ve2_host_queue.h"
#include "ve2_trace.h"

#define VE2_COL_SHIFT			25
#define VE2_ROW_SHIFT			20
#define VE2_ADDR(col, row, off) \
	(((col) << VE2_COL_SHIFT) + ((row) << VE2_ROW_SHIFT) + (off))
#define VE2_HANDSHAKE_OFF		0x88000
#define CERT_HANDSHAKE_OFF(col)		VE2_ADDR(col, 0, VE2_HANDSHAKE_OFF)
#define VE2_EVENT_GENERATE_REG		0x00034008
#define VE2_USER_EVENT_ID		0xB6
#define RR_SHARING			BIT(0)

static int ve2_aie_read_privileged_hs(struct ve2_aie_mgmtctx *mgmtctx, size_t field_off,
				      size_t size, void *buf)
{
	u32 offset = CERT_HANDSHAKE_OFF(0) + field_off;

	return aie_partition_read_privileged_mem(mgmtctx->aie_dev, offset, size, buf);
}

static int ve2_aie_write_privileged_hs(struct ve2_aie_mgmtctx *mgmtctx, size_t field_off,
				       size_t size, void *buf)
{
	u32 offset = CERT_HANDSHAKE_OFF(0) + field_off;

	return aie_partition_write_privileged_mem(mgmtctx->aie_dev, offset, size, buf);
}

static int ve2_aie_read_idle(struct ve2_aie_mgmtctx *mgmtctx, u32 *idle)
{
	return ve2_aie_read_privileged_hs(mgmtctx, offsetof(struct handshake, cert_idle_status),
					  sizeof(*idle), idle);
}

static void ve2_aie_scheduler_work(struct work_struct *work);
static void ve2_aie_irq_handler(u32 partition_id, void *priv);
static int ve2_aie_schedule_context(struct ve2_aie_mgmtctx *mgmtctx,
				    struct ve2_aie_context *hal_ctx, u64 command_index);
static bool ve2_aie_response_ctx_switch_req(struct ve2_aie_mgmtctx *mgmtctx);
static int ve2_aie_handshake_init(struct ve2_aie_mgmtctx *mgmtctx,
				  struct ve2_aie_context *hal_ctx);
static int ve2_aie_notify_firmware(struct ve2_aie_mgmtctx *mgmtctx);

static int ve2_fifo_enqueue(struct ve2_aie_mgmtctx *mgmtctx,
			    struct ve2_aie_context *hal_ctx, u64 command_index)
{
	struct ve2_ctx_fifo_entry *entry;
	unsigned long flags;

	if (hal_ctx->in_fifo)
		return 0;

	entry = kzalloc(sizeof(*entry), GFP_KERNEL);
	if (!entry)
		return -ENOMEM;

	entry->ctx = hal_ctx;
	entry->command_index = command_index;
	entry->next = NULL;

	spin_lock_irqsave(&mgmtctx->fifo_lock, flags);
	if (!mgmtctx->fifo_tail) {
		mgmtctx->fifo_head = entry;
		mgmtctx->fifo_tail = entry;
	} else {
		mgmtctx->fifo_tail->next = entry;
		mgmtctx->fifo_tail = entry;
	}
	hal_ctx->in_fifo = true;
	spin_unlock_irqrestore(&mgmtctx->fifo_lock, flags);

	return 0;
}

static int ve2_aie_request_context_switch(struct ve2_aie_mgmtctx *mgmtctx);

static void ve2_aie_pop_fifo_till(struct ve2_aie_mgmtctx *mgmtctx,
				  struct ve2_aie_context *active_ctx,
				  u64 read_index)
{
	struct ve2_ctx_fifo_entry *entry;
	unsigned long flags;

	while (1) {
		spin_lock_irqsave(&mgmtctx->fifo_lock, flags);
		entry = mgmtctx->fifo_head;
		if (!entry || entry->ctx != active_ctx) {
			spin_unlock_irqrestore(&mgmtctx->fifo_lock, flags);
			if (entry && entry->ctx != active_ctx)
				ve2_aie_request_context_switch(mgmtctx);
			break;
		}

		if (entry->command_index > read_index) {
			spin_unlock_irqrestore(&mgmtctx->fifo_lock, flags);
			break;
		}

		mgmtctx->fifo_head = entry->next;
		if (!mgmtctx->fifo_head)
			mgmtctx->fifo_tail = NULL;
		entry->ctx->in_fifo = false;
		kfree(entry);
		spin_unlock_irqrestore(&mgmtctx->fifo_lock, flags);
	}
}

static int ve2_aie_get_read_index(struct ve2_aie_context *hal_ctx, u64 *read_index)
{
	struct ve2_hwctx_priv *vp;
	u64 *index_ptr;

	if (!hal_ctx || !hal_ctx->hwctx || !read_index)
		return -EINVAL;

	vp = ve2_hw_priv(hal_ctx->hwctx);
	if (!vp || !vp->hsa_queue.hsa_queue_p)
		return -EINVAL;

	hsa_queue_sync_read_index_for_read(&vp->hsa_queue);
	index_ptr = (u64 *)((char *)vp->hsa_queue.hsa_queue_p + HSA_QUEUE_READ_INDEX_OFFSET);
	*read_index = *index_ptr;
	hal_ctx->read_idx = *read_index;

	return 0;
}

static bool ve2_fifo_empty(struct ve2_aie_mgmtctx *mgmtctx)
{
	bool empty;
	unsigned long flags;

	spin_lock_irqsave(&mgmtctx->fifo_lock, flags);
	empty = !mgmtctx->fifo_head;
	spin_unlock_irqrestore(&mgmtctx->fifo_lock, flags);

	return empty;
}

static bool ve2_check_idle(struct ve2_aie_mgmtctx *mgmtctx)
{
	u32 idle_status = 0;
	int ret;

	ret = ve2_aie_read_idle(mgmtctx, &idle_status);
	if (ret)
		return false;

	return !!(idle_status & CERT_IS_IDLE);
}

static bool ve2_check_queue_not_empty(struct ve2_aie_mgmtctx *mgmtctx)
{
	u32 idle_status = 0;
	int ret;

	ret = ve2_aie_read_idle(mgmtctx, &idle_status);
	if (ret)
		return false;

	return !!(idle_status & HSA_QUEUE_NOT_EMPTY);
}

static bool ve2_check_idle_or_queue_not_empty(struct ve2_aie_mgmtctx *mgmtctx)
{
	u32 idle_status = 0;
	int ret;

	ret = ve2_aie_read_idle(mgmtctx, &idle_status);
	if (ret)
		return false;

	return !!(idle_status & (HSA_QUEUE_NOT_EMPTY | CERT_IS_IDLE));
}

static bool ve2_check_misc_interrupt(struct ve2_aie_mgmtctx *mgmtctx)
{
	u32 off = CERT_HANDSHAKE_OFF(mgmtctx->start_col) +
		  offsetof(struct handshake, misc_status);
	u32 misc_status = 0;
	struct ve2_hwctx_priv *vp;
	int ret;

	ret = aie_partition_read_privileged_mem(mgmtctx->aie_dev, off,
						sizeof(misc_status), &misc_status);
	if (ret || !misc_status)
		return false;

	if (mgmtctx->active_ctx && mgmtctx->active_ctx->hwctx) {
		vp = ve2_hw_priv(mgmtctx->active_ctx->hwctx);
		if (vp)
			vp->misc_intrpt_flag = true;
	}

	return true;
}

static int ve2_aie_request_context_switch(struct ve2_aie_mgmtctx *mgmtctx)
{
	u32 val;
	int ret;

	ret = ve2_aie_read_privileged_hs(mgmtctx, offsetof(struct handshake, ctx_switch_req),
					 sizeof(val), &val);
	if (ret)
		return ret;

	val |= RR_SHARING;
	ret = ve2_aie_write_privileged_hs(mgmtctx, offsetof(struct handshake, ctx_switch_req),
					  sizeof(val), &val);
	if (ret)
		return ret;

	mgmtctx->is_context_req = true;
	return 0;
}

static bool ve2_aie_check_context_req(struct ve2_aie_mgmtctx *mgmtctx)
{
	if (!mgmtctx->is_context_req)
		return false;

	mgmtctx->is_context_req = false;
	mgmtctx->is_idle_due_to_context = true;
	return true;
}

static bool ve2_aie_response_ctx_switch_req(struct ve2_aie_mgmtctx *mgmtctx)
{
	struct ve2_ctx_fifo_entry *entry, *next_entry;
	struct ve2_aie_context *scheduled = NULL;
	unsigned long flags;
	int ret;

	lockdep_assert_held(&mgmtctx->ctx_lock);

	spin_lock_irqsave(&mgmtctx->fifo_lock, flags);
	entry = mgmtctx->fifo_head;
	next_entry = entry ? entry->next : NULL;
	spin_unlock_irqrestore(&mgmtctx->fifo_lock, flags);

	if (!entry)
		return false;

	if (mgmtctx->is_idle_due_to_context) {
		scheduled = entry->ctx;
		mgmtctx->partition_idle = false;
		mgmtctx->is_idle_due_to_context = false;

		if (mgmtctx->active_ctx != scheduled) {
			ret = ve2_aie_handshake_init(mgmtctx, scheduled);
			if (ret) {
				XDNA_ERR(mgmtctx->xdna,
					 "Context switch handshake failed ret=%d", ret);
				return false;
			}
			mgmtctx->active_ctx = scheduled;
			ve2_aie_notify_firmware(mgmtctx);
		}
	}

	if (next_entry && entry->ctx != next_entry->ctx)
		ve2_aie_request_context_switch(mgmtctx);

	if (!scheduled)
		return false;
	return true;
}

static void ve2_aie_wake_hwctx(struct ve2_aie_context *hal_ctx)
{
	struct ve2_hwctx_priv *vp;

	if (!hal_ctx)
		return;

	wake_up_all(&hal_ctx->waitq);
	if (hal_ctx->hwctx) {
		vp = ve2_hw_priv(hal_ctx->hwctx);
		if (vp)
			wake_up_interruptible_all(&vp->waitq);
	}
}

static void ve2_aie_error_cb(void *arg)
{
	struct ve2_aie_mgmtctx *mgmtctx = arg;
	struct aie_errors *aie_errs;

	if (!mgmtctx || !mgmtctx->aie_dev)
		return;

	aie_errs = aie_get_errors(mgmtctx->aie_dev);
	if (!IS_ERR_OR_NULL(aie_errs)) {
		if (aie_errs->num_err > 0)
			VE2_TRACE(mgmtctx->xdna, "AIE error cb: %u async errors",
				  aie_errs->num_err);
		aie_free_errors(aie_errs);
	}

	mutex_lock(&mgmtctx->ctx_lock);
	if (mgmtctx->active_ctx)
		ve2_check_misc_interrupt(mgmtctx);
	ve2_aie_wake_hwctx(mgmtctx->active_ctx);
	mutex_unlock(&mgmtctx->ctx_lock);
}

static int ve2_aie_prepare_handshake(struct ve2_aie_context *hal_ctx,
				     struct aie_partition_init_args *args)
{
	struct ve2_aie_mgmtctx *mgmtctx = hal_ctx->mgmtctx;
	struct handshake *hs;
	struct aie_op_handshake_data *hs_data;
	struct aie_location aie_loc;
	u32 lead_col_addr;
	u64 host_time_ns;
	u32 col;
	int ret;

	hs = kcalloc(mgmtctx->num_col, sizeof(*hs), GFP_KERNEL);
	if (!hs)
		return -ENOMEM;

	hs_data = kcalloc(mgmtctx->num_col, sizeof(*hs_data), GFP_KERNEL);
	if (!hs_data) {
		kfree(hs);
		return -ENOMEM;
	}

	lead_col_addr = VE2_ADDR(mgmtctx->start_col, 0, 0);
	host_time_ns = ktime_get_ns();

	for (col = 0; col < mgmtctx->num_col; col++) {
		u64 hsa_addr = U64_MAX;

		memset(&hs[col], 0, sizeof(hs[col]));
		hs[col].host_time_low = (u32)(host_time_ns & U32_MAX);
		hs[col].host_time_high = (u32)(host_time_ns >> 32);
		hs[col].partition_base_address = lead_col_addr;
		hs[col].aie_info.partition_size = mgmtctx->num_col;
		if (col == 0 && hal_ctx->hsa_queue_pa)
			hsa_addr = hal_ctx->hsa_queue_pa;
		hs[col].hsa_addr_high = upper_32_bits(hsa_addr);
		hs[col].hsa_addr_low = lower_32_bits(hsa_addr);
		hs[col].mpaie_alive = ALIVE_MAGIC;

		if (hal_ctx->hwctx)
			ve2_hwctx_fill_hs_config(hal_ctx->hwctx, &hs[col], col);

		aie_loc.col = col;
		aie_loc.row = 0;
		hs_data[col].addr = &hs[col];
		hs_data[col].offset = 0;
		hs_data[col].size = sizeof(hs[col]);
		hs_data[col].loc = aie_loc;
	}

	ret = aie_partition_handshake_update(mgmtctx->aie_dev, hs_data, mgmtctx->num_col);
	if (ret) {
		kfree(hs_data);
		kfree(hs);
		return ret;
	}

	args->handshake = hs_data;
	args->handshake_cols = mgmtctx->num_col;
	args->locs = NULL;
	args->num_tiles = 0;
	args->init_opts = (AIE_PART_INIT_OPT_DEFAULT | AIE_PART_INIT_OPT_HANDSHAKE |
			   AIE_PART_INIT_OPT_DIS_TLAST_ERROR) &
			   ~AIE_PART_INIT_OPT_UC_ENB_MEM_PRIV;

	kfree(mgmtctx->handshake);
	mgmtctx->handshake = hs;

	return 0;
}

static int ve2_aie_notify_firmware(struct ve2_aie_mgmtctx *mgmtctx)
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

static int ve2_aie_handshake_init(struct ve2_aie_mgmtctx *mgmtctx,
				  struct ve2_aie_context *hal_ctx)
{
	struct aie_partition_init_args args = { };
	int col, ret = 0;

	ret = ve2_aie_prepare_handshake(hal_ctx, &args);
	if (ret)
		return ret;

	VE2_TRACE2(mgmtctx->xdna, "handshake: partition_initialize start_col=%u num_col=%u",
		   mgmtctx->start_col, mgmtctx->num_col);
	ret = aie_partition_initialize(mgmtctx->aie_dev, &args);
	if (ret) {
		VE2_TRACE(mgmtctx->xdna, "handshake: partition_initialize FAILED ret=%d", ret);
		kfree(mgmtctx->handshake);
		mgmtctx->handshake = NULL;
		goto cleanup_hs;
	}

	for (col = mgmtctx->num_col; col-- > 0; ) {
		struct aie_location loc = { .col = col, .row = 0 };

		ret = aie_partition_uc_wakeup(mgmtctx->aie_dev, &loc);
		if (ret) {
			VE2_TRACE(mgmtctx->xdna, "handshake: uc_wakeup col=%u FAILED ret=%d",
				  col, ret);
			goto cleanup_hs;
		}
	}

	hal_ctx->handshake_initialized = true;
	VE2_TRACE2(mgmtctx->xdna, "handshake: done hwctx=%p", hal_ctx->hwctx);

cleanup_hs:
	kfree(args.handshake);
	if (ret) {
		kfree(mgmtctx->handshake);
		mgmtctx->handshake = NULL;
	}
	return ret;
}

static int ve2_aie_schedule_context(struct ve2_aie_mgmtctx *mgmtctx,
				    struct ve2_aie_context *hal_ctx, u64 command_index)
{
	int ret;

	hal_ctx->write_idx = command_index;

	VE2_TRACE2(mgmtctx->xdna, "schedule: cmd_idx=%llu active=%p hal=%p",
		   command_index, mgmtctx->active_ctx, hal_ctx);

	mutex_lock(&mgmtctx->ctx_lock);

	if (!mgmtctx->active_ctx) {
		VE2_TRACE(mgmtctx->xdna, "schedule: FIRST cmd activate pid=%d cmd_idx=%llu",
			  hal_ctx->hwctx ? hal_ctx->hwctx->client->pid : -1, command_index);
		mgmtctx->partition_idle = false;
		mgmtctx->active_ctx = hal_ctx;
		if (!hal_ctx->handshake_initialized) {
			ret = ve2_aie_handshake_init(mgmtctx, hal_ctx);
			if (ret) {
				mgmtctx->active_ctx = NULL;
				mutex_unlock(&mgmtctx->ctx_lock);
				return ret;
			}
		}
		mutex_unlock(&mgmtctx->ctx_lock);
		ret = ve2_aie_notify_firmware(mgmtctx);
		if (ret < 0)
			VE2_TRACE(mgmtctx->xdna, "schedule: notify_firmware FAILED ret=%d", ret);
		return ret;
	}

	ret = ve2_fifo_enqueue(mgmtctx, hal_ctx, command_index);
	if (ret) {
		mutex_unlock(&mgmtctx->ctx_lock);
		return ret;
	}

	if (mgmtctx->active_ctx != hal_ctx) {
		if (mgmtctx->partition_idle) {
			mgmtctx->partition_idle = false;
			VE2_TRACE(mgmtctx->xdna,
				  "schedule: ctx switch while idle active=%p new=%p",
				  mgmtctx->active_ctx, hal_ctx);
			ve2_aie_response_ctx_switch_req(mgmtctx);
		} else {
			VE2_TRACE2(mgmtctx->xdna,
				   "schedule: cmd queued active=%p pending=%p",
				   mgmtctx->active_ctx, hal_ctx);
		}
	} else if (mgmtctx->is_idle_due_to_context) {
		mgmtctx->is_idle_due_to_context = false;
		mgmtctx->partition_idle = false;
		ret = ve2_aie_handshake_init(mgmtctx, hal_ctx);
		if (ret) {
			mutex_unlock(&mgmtctx->ctx_lock);
			return ret;
		}
		mgmtctx->active_ctx = hal_ctx;
		mutex_unlock(&mgmtctx->ctx_lock);
		return ve2_aie_notify_firmware(mgmtctx);
	}

	mutex_unlock(&mgmtctx->ctx_lock);
	ret = ve2_aie_notify_firmware(mgmtctx);
	VE2_TRACE2(mgmtctx->xdna, "schedule: notify same ctx ret=%d", ret);
	return ret;
}

static void ve2_aie_scheduler_work(struct work_struct *work)
{
	struct ve2_aie_mgmtctx *mgmtctx = container_of(work, struct ve2_aie_mgmtctx,
						       scheduler_work);
	struct ve2_hwctx_priv *vp;

	mutex_lock(&mgmtctx->ctx_lock);

	if (!mgmtctx->active_ctx || !mgmtctx->active_ctx->hwctx) {
		mutex_unlock(&mgmtctx->ctx_lock);
		return;
	}

	vp = ve2_hw_priv(mgmtctx->active_ctx->hwctx);
	if (vp && vp->misc_intrpt_flag) {
		XDNA_ERR(mgmtctx->xdna, "MISC interrupt from firmware");
		mutex_unlock(&mgmtctx->ctx_lock);
		return;
	}

	ve2_aie_check_context_req(mgmtctx);

	if (ve2_check_queue_not_empty(mgmtctx)) {
		if (!ve2_aie_response_ctx_switch_req(mgmtctx))
			mgmtctx->partition_idle = true;
	} else if (ve2_check_idle(mgmtctx)) {
		if (!ve2_aie_response_ctx_switch_req(mgmtctx))
			mgmtctx->partition_idle = true;
	} else {
		VE2_TRACE2(mgmtctx->xdna, "scheduler: no action needed active=%p",
			   mgmtctx->active_ctx);
	}

	mutex_unlock(&mgmtctx->ctx_lock);
}

static void ve2_aie_irq_handler(u32 partition_id, void *priv)
{
	struct ve2_aie_mgmtctx *mgmtctx = priv;
	struct ve2_aie_context *active_ctx;
	u64 read_index;
	bool queue_sched;

	mutex_lock(&mgmtctx->ctx_lock);
	active_ctx = mgmtctx->active_ctx;
	if (!active_ctx || !active_ctx->hwctx) {
		VE2_TRACE2(mgmtctx->xdna, "IRQ: no active_ctx part_id=0x%x", partition_id);
		mutex_unlock(&mgmtctx->ctx_lock);
		return;
	}

	if (ve2_aie_get_read_index(active_ctx, &read_index)) {
		XDNA_ERR(mgmtctx->xdna, "IRQ: failed to get read index");
		mutex_unlock(&mgmtctx->ctx_lock);
		return;
	}

	VE2_TRACE2(mgmtctx->xdna, "IRQ: part_id=0x%x hwctx=%p read_idx=%llu",
		   partition_id, active_ctx->hwctx, read_index);

	ve2_aie_pop_fifo_till(mgmtctx, active_ctx, read_index);
	ve2_aie_wake_hwctx(active_ctx);
	mutex_unlock(&mgmtctx->ctx_lock);

	queue_sched = ve2_check_idle_or_queue_not_empty(mgmtctx) ||
		      ve2_check_misc_interrupt(mgmtctx);

	if ((queue_sched || !ve2_fifo_empty(mgmtctx)) && mgmtctx->work_queue)
		queue_work(mgmtctx->work_queue, &mgmtctx->scheduler_work);
}

static struct ve2_aie_mgmtctx *ve2_aie_find_mgmtctx(struct amdxdna_dev_hdl *hdl,
						    u32 partition_id)
{
	u32 i;

	if (!hdl->hal_mgmt_slot)
		return NULL;

	for (i = 0; i < hdl->aie_dev_info.cols; i++) {
		struct ve2_aie_mgmtctx *m = hdl->hal_mgmt_slot[i];

		if (m && m->partition_id == partition_id)
			return m;
	}
	return NULL;
}

static int ve2_aie_partition_create(struct amdxdna_dev *xdna, u32 start_col, u32 num_col,
				    u32 *partition_id)
{
	struct amdxdna_dev_hdl *xdna_hdl = xdna->dev_handle;
	struct ve2_aie_mgmtctx *mgmtctx;
	struct aie_partition_req req = { };
	struct device *aie_dev;
	int ret;

	if (!xdna_hdl->hal_mgmt_slot || start_col >= xdna_hdl->aie_dev_info.cols)
		return -EINVAL;

	if (xdna_hdl->hal_mgmt_slot[start_col])
		return -EBUSY;

	mgmtctx = kzalloc(sizeof(*mgmtctx), GFP_KERNEL);
	if (!mgmtctx)
		return -ENOMEM;

	mgmtctx->xdna = xdna;
	mgmtctx->start_col = start_col;
	mgmtctx->num_col = num_col;
	mgmtctx->active_ctx = NULL;
	mgmtctx->fifo_head = NULL;
	mgmtctx->fifo_tail = NULL;
	mgmtctx->is_context_req = false;
	mgmtctx->is_idle_due_to_context = false;
	mgmtctx->partition_idle = true;
	spin_lock_init(&mgmtctx->fifo_lock);
	mutex_init(&mgmtctx->ctx_lock);

	mgmtctx->work_queue = create_singlethread_workqueue("ve2_aie_sched");
	if (!mgmtctx->work_queue) {
		ret = -ENOMEM;
		goto free_mgmtctx;
	}

	INIT_WORK(&mgmtctx->scheduler_work, ve2_aie_scheduler_work);

	req.partition_id = (start_col << AIE_PART_ID_START_COL_SHIFT) |
			   (num_col << AIE_PART_ID_NUM_COLS_SHIFT);
	req.user_event1_complete = ve2_aie_irq_handler;
	req.user_event1_priv = mgmtctx;

	VE2_TRACE(xdna, "partition_create: request start_col=%u num_col=%u", start_col, num_col);
	aie_dev = aie_partition_request(&req);
	if (IS_ERR(aie_dev)) {
		ret = PTR_ERR(aie_dev);
		VE2_TRACE(xdna, "partition_create: request FAILED ret=%d", ret);
		goto destroy_wq;
	}

	mgmtctx->aie_dev = aie_dev;
	mgmtctx->partition_id = req.partition_id;

	ret = aie_register_error_notification(aie_dev, ve2_aie_error_cb, mgmtctx);
	if (ret) {
		XDNA_WARN(xdna, "AIE error notification registration failed, ret %d", ret);
		ret = 0;
	}

	*partition_id = req.partition_id;
	xdna_hdl->hal_mgmt_slot[start_col] = mgmtctx;

	return 0;

destroy_wq:
	destroy_workqueue(mgmtctx->work_queue);
free_mgmtctx:
	kfree(mgmtctx);
	return ret;
}

static int ve2_aie_partition_destroy(struct amdxdna_dev *xdna, u32 partition_id)
{
	struct amdxdna_dev_hdl *xdna_hdl = xdna->dev_handle;
	struct ve2_aie_mgmtctx *mgmtctx;
	struct ve2_ctx_fifo_entry *entry, *next;
	unsigned long flags;
	u32 i;

	mgmtctx = ve2_aie_find_mgmtctx(xdna_hdl, partition_id);
	if (!mgmtctx)
		return -EINVAL;

	for (i = 0; i < xdna_hdl->aie_dev_info.cols; i++) {
		if (xdna_hdl->hal_mgmt_slot[i] == mgmtctx)
			xdna_hdl->hal_mgmt_slot[i] = NULL;
	}

	flush_workqueue(mgmtctx->work_queue);

	spin_lock_irqsave(&mgmtctx->fifo_lock, flags);
	entry = mgmtctx->fifo_head;
	while (entry) {
		next = entry->next;
		kfree(entry);
		entry = next;
	}
	mgmtctx->fifo_head = NULL;
	mgmtctx->fifo_tail = NULL;
	spin_unlock_irqrestore(&mgmtctx->fifo_lock, flags);

	aie_unregister_error_notification(mgmtctx->aie_dev);
	aie_partition_teardown(mgmtctx->aie_dev);
	aie_partition_release(mgmtctx->aie_dev);

	destroy_workqueue(mgmtctx->work_queue);
	mutex_destroy(&mgmtctx->ctx_lock);
	kfree(mgmtctx->handshake);
	kfree(mgmtctx);

	return 0;
}

static int ve2_aie_context_create(struct amdxdna_dev *xdna, struct amdxdna_hwctx *hwctx,
				  struct ve2_aie_context **aie_ctx)
{
	struct amdxdna_dev_hdl *xdna_hdl = xdna->dev_handle;
	struct ve2_aie_context *ctx;
	struct ve2_aie_mgmtctx *mgmtctx;

	if (hwctx->start_col >= xdna_hdl->aie_dev_info.cols)
		return -EINVAL;

	mgmtctx = xdna_hdl->hal_mgmt_slot[hwctx->start_col];
	if (!mgmtctx)
		return -EINVAL;

	ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
	if (!ctx)
		return -ENOMEM;

	ctx->mgmtctx = mgmtctx;
	ctx->hwctx = hwctx;

	{
		struct ve2_hwctx_priv *vp = hwctx ? ve2_hw_priv(hwctx) : NULL;
		struct ve2_hwctx_link *link = hwctx ? hwctx->aux_ctx_priv : NULL;
		u32 mem_bitmap = link ? link->mem_bitmap : 0;

		ctx->hsa_dma_dev = ve2_dma_dev(xdna, mem_bitmap);

		if (vp && vp->hsa_queue.hsa_queue_p) {
			ctx->hsa_queue_va = vp->hsa_queue.hsa_queue_p;
			ctx->hsa_queue_pa = vp->hsa_queue.hsa_queue_mem.dma_addr;
			ctx->hsa_queue_size = sizeof(struct hsa_queue) +
				HOST_QUEUE_ENTRY * sizeof(u64);
			if (vp->hsa_queue.alloc_dev)
				ctx->hsa_dma_dev = vp->hsa_queue.alloc_dev;
			goto hsa_ready;
		}
	}

	ctx->hsa_queue_size = PAGE_SIZE;
	ctx->hsa_queue_va = dma_alloc_coherent(ctx->hsa_dma_dev, ctx->hsa_queue_size,
					       &ctx->hsa_queue_pa, GFP_KERNEL);
	if (!ctx->hsa_queue_va) {
		kfree(ctx);
		return -ENOMEM;
	}

	memset(ctx->hsa_queue_va, 0, ctx->hsa_queue_size);
hsa_ready:
	ctx->write_idx = 0;
	ctx->read_idx = 0;

	init_waitqueue_head(&ctx->waitq);
	ctx->in_fifo = false;
	ctx->handshake_initialized = false;

	*aie_ctx = ctx;

	return 0;
}

static void ve2_aie_context_destroy(struct ve2_aie_context *aie_ctx)
{
	struct ve2_aie_mgmtctx *mgmtctx;

	if (!aie_ctx)
		return;

	mgmtctx = aie_ctx->mgmtctx;
	if (mgmtctx && mgmtctx->active_ctx == aie_ctx)
		mgmtctx->active_ctx = NULL;

	if (aie_ctx->hsa_queue_va && aie_ctx->hsa_dma_dev) {
		struct ve2_hwctx_priv *vp = aie_ctx->hwctx ? ve2_hw_priv(aie_ctx->hwctx) : NULL;
		bool shared = vp && vp->hsa_queue.hsa_queue_p == aie_ctx->hsa_queue_va;

		if (!shared)
			dma_free_coherent(aie_ctx->hsa_dma_dev, aie_ctx->hsa_queue_size,
					  aie_ctx->hsa_queue_va, aie_ctx->hsa_queue_pa);
	}

	kfree(aie_ctx);
}

int ve2_aie_hwctx_create(struct amdxdna_dev *xdna, struct amdxdna_hwctx *hwctx,
			 u32 *partition_id, struct ve2_aie_context **aie_ctx)
{
	int ret;

	VE2_TRACE(xdna, "aie_hwctx_create ENTER start_col=%u num_col=%u",
		  hwctx->start_col, hwctx->num_col);
	ret = ve2_aie_partition_create(xdna, hwctx->start_col, hwctx->num_col, partition_id);
	if (ret)
		return ret;

	ret = ve2_aie_context_create(xdna, hwctx, aie_ctx);
	if (ret) {
		ve2_aie_partition_destroy(xdna, *partition_id);
		return ret;
	}

	VE2_TRACE(xdna, "aie_hwctx_create DONE partition_id=0x%x", *partition_id);
	return 0;
}

void ve2_aie_hwctx_destroy(struct amdxdna_dev *xdna, struct ve2_aie_context *aie_ctx,
			   u32 partition_id)
{
	ve2_aie_context_destroy(aie_ctx);
	ve2_aie_partition_destroy(xdna, partition_id);
}

int ve2_aie_kick_cmd(struct ve2_aie_context *aie_ctx, u64 command_index)
{
	if (!aie_ctx || !aie_ctx->mgmtctx)
		return -EINVAL;

	VE2_TRACE(aie_ctx->mgmtctx->xdna, "kick_cmd: cmd_idx=%llu hwctx=%p",
		  command_index, aie_ctx->hwctx);
	return ve2_aie_schedule_context(aie_ctx->mgmtctx, aie_ctx, command_index);
}

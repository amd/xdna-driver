// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2025, Advanced Micro Devices, Inc.
 */
#include <linux/device.h>
#include <linux/version.h>

#include "amdxdna_ctx.h"
#include "ve2_of.h"
#include "ve2_mgmt.h"
#include "ve2_res_solver.h"

static int ve2_create_mgmt_partition(struct amdxdna_dev *xdna,
				     struct amdxdna_ctx *hwctx,
				     struct xrs_action_load *load_act);

static void cert_setup_partition(struct amdxdna_dev *xdna, struct device *aie_dev,
				 struct ve2_config_hwctx *hwctx_cfg, u32 col,
				 u32 lead_col, u32 partition_size,
				 u64 hsa_addr)
{
	u32 lead_col_addr = VE2_ADDR(lead_col, 0, 0);
	struct handshake cert_comm = { 0 };

	cert_comm.partition_base_address = lead_col_addr;
	cert_comm.aie_info.partition_size = partition_size;
	cert_comm.hsa_addr_high =  upper_32_bits(hsa_addr);
	cert_comm.hsa_addr_low =  lower_32_bits(hsa_addr);

	/* Log Buffer */
	cert_comm.log_addr_high = upper_32_bits(hwctx_cfg->log_buf_addr);
	cert_comm.log_addr_low = lower_32_bits(hwctx_cfg->log_buf_addr);
	cert_comm.log_buf_size = hwctx_cfg->log_buf_size;

	/* Debug Buffer */
	cert_comm.dbg_buf.dbg_buf_addr_high = upper_32_bits(hwctx_cfg->debug_buf_addr);
	cert_comm.dbg_buf.dbg_buf_addr_low = lower_32_bits(hwctx_cfg->debug_buf_addr);
	cert_comm.dbg_buf.size = hwctx_cfg->debug_buf_size;

	/* Dtrace Buffer */
	cert_comm.trace.dtrace_addr_high = upper_32_bits(hwctx_cfg->dtrace_addr);
	cert_comm.trace.dtrace_addr_low = lower_32_bits(hwctx_cfg->dtrace_addr);

	/* Opcode Timeout */
	cert_comm.opcode_timeout_config = hwctx_cfg->opcode_timeout_config;

	cert_comm.ctx_switch_req = 0;
	cert_comm.hsa_location = 0;
	cert_comm.dbg.hsa_addr_high = 0xFFFFFFFF;
	cert_comm.dbg.hsa_addr_low = 0xFFFFFFFF;
	cert_comm.mpaie_alive = ALIVE_MAGIC;

	/* write to cert handshake shared memory */
	ve2_partition_write_privileged_mem(aie_dev, col, 0,
					   sizeof(cert_comm), (void *)&cert_comm);

	/* wake up cert */
	ve2_partition_uc_wakeup(aie_dev, col);
}

static int ve2_xrs_col_list(struct amdxdna_ctx *hwctx, struct alloc_requests *xrs_req, u32 num_col)
{
	struct amdxdna_dev *xdna = hwctx->client->xdna;
	u32 width = num_col;
	int total_col = xrs_get_total_cols(xdna->dev_handle->xrs_hdl);
	int start = 0, end = total_col - num_col;
	int first, last, entries = 0;
	int i;

	if (start_col >= 0) {
		if (start_col + num_col > total_col) {
			XDNA_ERR(xdna, "Invalid start_col_index %d, num col %d",
				 start_col, num_col);
			return -EINVAL;
		}
		first = start_col;
		entries = (end - first) / width + 1;
	} else {
		first = start + (width - start % width) % width;
		last = end - end % width;

		if (last >= first)
			entries = (last - first) / width + 1;

		if (!entries) {
			XDNA_ERR(xdna, "Start %d end %d width %d", start, end, width);
			return -EINVAL;
		}
	}

	XDNA_DBG(xdna, "start %d end %d first %d last %d, entries %d",
		 start, end, first, last, entries);

	xrs_req->cdo.start_cols = kmalloc_array(entries,
						sizeof(*xrs_req->cdo.start_cols),
						GFP_KERNEL);
	if (!xrs_req->cdo.start_cols)
		return -ENOMEM;

	xrs_req->cdo.cols_len = entries;
	for (i = 0; i < entries; i++)
		xrs_req->cdo.start_cols[i] = first + i * width;

	print_hex_dump_debug("col_list: ", DUMP_PREFIX_OFFSET, 16, 4,
			     xrs_req->cdo.start_cols,
			     entries * sizeof(*xrs_req->cdo.start_cols), false);

	return 0;
}

int ve2_xrs_request(struct amdxdna_dev *xdna, struct amdxdna_ctx *hwctx)
{
	struct solver_state *xrs = xdna->dev_handle->xrs_hdl;
	struct xrs_action_load load_act = {0};
	struct amdxdna_ctx_priv *nhwctx = NULL;
	struct alloc_requests *xrs_req;
	int ret;

	if (!xrs)
		return -EINVAL;

	mutex_lock(&xrs->xrs_lock);
	xrs_req = kzalloc(sizeof(*xrs_req), GFP_KERNEL);
	if (!xrs_req) {
		mutex_unlock(&xrs->xrs_lock);
		return -ENOMEM;
	}

	if (partition_size < hwctx->num_tiles)
		xrs_req->cdo.ncols = hwctx->num_tiles;
	else
		xrs_req->cdo.ncols = partition_size;

	XDNA_DBG(xdna, "User requested num_col %d", xrs_req->cdo.ncols);

	ret = ve2_xrs_col_list(hwctx, xrs_req, xrs_req->cdo.ncols);
	if (ret) {
		XDNA_ERR(xdna, "Allocate XRS col resource failed, ret %d", ret);
		goto free_xrs_req;
	}

	xrs_req->rqos.priority = hwctx->qos.priority;
	xrs_req->rid = (uintptr_t)hwctx;
	ret = xrs_allocate_resource(xrs, xrs_req, &load_act);
	if (ret) {
		XDNA_ERR(xdna, "Allocate XRS resource failed, ret %d", ret);
		goto free_start_cols;
	}

	ret = ve2_create_mgmt_partition(xdna, hwctx, &load_act);
	if (ret) {
		XDNA_ERR(xdna, "Creating AIE partition failed, ret %d", ret);
		goto xrs_release;
	}

	nhwctx = hwctx->priv;
	hwctx->start_col = nhwctx->start_col;
	hwctx->num_col = nhwctx->num_col;
	mutex_unlock(&xrs->xrs_lock);

	return 0;

xrs_release:
	xrs_release_resource(xrs, (uintptr_t)hwctx, &load_act);
free_start_cols:
	kfree(xrs_req->cdo.start_cols);
free_xrs_req:
	kfree(xrs_req);
	mutex_unlock(&xrs->xrs_lock);
	return ret;
}

// Function to display the queue
static void ve2_fifo_display_queue(struct amdxdna_mgmtctx *mgmtctx)
{
	struct amdxdna_ctx_command_fifo *c_ctx, *t_ctx;

	list_for_each_entry_safe(c_ctx, t_ctx, &mgmtctx->ctx_command_fifo_head, list)
		XDNA_DBG(mgmtctx->xdna, "CTX : %p command index: %llu\n",
			 c_ctx->ctx, c_ctx->command_index);
}

// Enqueue a context into the FIFO queue
static int ve2_fifo_enqueue(struct amdxdna_mgmtctx *mgmtctx,
			    struct amdxdna_ctx *ctx, u64 command_index)
{
	struct amdxdna_ctx_command_fifo *node;

	node = kzalloc(sizeof(*node), GFP_KERNEL);
	if (!node)
		return -ENOMEM;

	node->ctx = ctx;
	node->command_index = command_index;
	INIT_LIST_HEAD(&node->list);
	list_add_tail(&node->list, &mgmtctx->ctx_command_fifo_head);

	return 0;
}

// Get the context switch request bit
static u32 get_ctx_bit(struct amdxdna_mgmtctx *mgmtctx)
{
	struct device *aie_dev = mgmtctx->mgmt_aiedev;
	u32 val;

	ve2_partition_read_privileged_mem(aie_dev, 0,
					  offsetof(struct handshake, ctx_switch_req),
					  sizeof(u32), &val);
	return val;
}

void ve2_mgmt_handshake_init(struct amdxdna_dev *xdna,
			     struct amdxdna_ctx *hwctx)
{
	struct amdxdna_ctx_priv *nhwctx = hwctx->priv;
	u32 start_col;
	u32 num_col;
	int ret = 0;

	start_col = nhwctx->start_col;
	num_col = nhwctx->num_col;

	XDNA_DBG(xdna, "Handshake init hwctx : %p\n", hwctx);
	ret = ve2_partition_initialize(nhwctx->aie_dev, nhwctx->args);
	if (ret < 0) {
		XDNA_ERR(xdna, "aie partition init failed: %d", ret);
		return;
	}

	/* We should make sure the lead CERT has to start at last */
	for (int col = num_col - 1; col >= 0; col--) {
		u64 hsa_addr = 0xFFFFFFFFFFFFFFFF;

		/*
		 * Only lead cert(the first column[relative]) should be set with HSA Queue
		 */
		if (col == 0) {
			hsa_addr = nhwctx->hwctx_hsa_queue.hsa_queue_mem.dma_addr;
			XDNA_DBG(xdna, "hsa 0x%llx", hsa_addr);
		}

		cert_setup_partition(xdna, nhwctx->aie_dev,
				     &nhwctx->hwctx_config[start_col + col], col,
				     start_col, num_col, hsa_addr);
	}
}

#define RR_SHARING BIT(0)
static int ve2_request_context_switch(struct amdxdna_dev *xdna,
				      struct amdxdna_mgmtctx *mgmtctx)
{
	struct device *aie_dev = mgmtctx->mgmt_aiedev;
	u32 val, pval;

	ve2_partition_read_privileged_mem(aie_dev, 0,
					  offsetof(struct handshake, ctx_switch_req),
					  sizeof(u32), &val);

	pval = val;
	val |= RR_SHARING;
	ve2_partition_write_privileged_mem(aie_dev, 0,
					   offsetof(struct handshake, ctx_switch_req),
					   sizeof(u32), (void *)&val);

	mgmtctx->is_context_req = 1;

	return 0;
}

	static struct amdxdna_ctx *
ve2_response_ctx_switch_req(struct amdxdna_mgmtctx *mgmtctx)
{
	struct amdxdna_dev *xdna = mgmtctx->xdna;
	struct amdxdna_ctx_command_fifo *c_ctx, *t_ctx;
	struct amdxdna_ctx *hwctx = NULL;

	/* Check if already locked */
	lockdep_assert_held(&mgmtctx->ctx_lock);
	XDNA_DBG(xdna, "printing fifo before context switch:\n");

	/* Debug Only */
	//ve2_fifo_displayQueue(mgmtctx);

	/* Top need to be scheduled */
	list_for_each_entry_safe(c_ctx, t_ctx, &mgmtctx->ctx_command_fifo_head, list) {
		if (mgmtctx->is_idle_due_to_context == 1) {
			hwctx = c_ctx->ctx;
			XDNA_DBG(xdna, "NEW context to be schedule next: %p\n", hwctx);
			mgmtctx->is_partition_idle = 0;
			ve2_mgmt_handshake_init(mgmtctx->xdna, hwctx);
			if (mgmtctx->active_ctx == hwctx)
				break;

			mgmtctx->active_ctx = hwctx;
		}

		if (t_ctx && c_ctx->ctx != t_ctx->ctx)
			ve2_request_context_switch(mgmtctx->xdna, mgmtctx);

		break;
	}

	return hwctx;
}

int ve2_mgmt_schedule_cmd(struct amdxdna_dev *xdna, struct amdxdna_ctx *hwctx, u64 seq)
{
	struct amdxdna_mgmtctx  *mgmtctx =
		&xdna->dev_handle->ve2_mgmtctx[hwctx->start_col];
	u64 write_index = 0;
	int ret;

	spin_lock(&mgmtctx->ctx_lock);
	//enqueue ctx and command in ctx_command_fifo
	if (get_ctx_write_index(hwctx, &write_index)) {
		XDNA_ERR(xdna, "Failed to get write index");
		spin_unlock(&mgmtctx->ctx_lock);
		return -EINVAL;
	}

	/* Only enqueue if write_index is valid */
	ret = ve2_fifo_enqueue(mgmtctx, hwctx, write_index);
	if (ret) {
		spin_unlock(&mgmtctx->ctx_lock);
		return ret;
	}

	if (!mgmtctx->active_ctx) {
		mgmtctx->is_partition_idle = 0;
		XDNA_DBG(xdna, "First command request hwctx %p\n", hwctx);
		/* First command request. Initiate the handshake */
		ve2_mgmt_handshake_init(xdna, hwctx);
		mgmtctx->active_ctx = hwctx;
	} else if (mgmtctx->active_ctx != hwctx) {
		if (mgmtctx->is_partition_idle == 1) {
			mgmtctx->is_partition_idle = 0;
			XDNA_DBG(mgmtctx->xdna,
				 "Context switch possible as partition is idle active hwctx:%p ------>\n",
				 mgmtctx->active_ctx);
			ve2_response_ctx_switch_req(mgmtctx);
		} else {
			XDNA_DBG(mgmtctx->xdna,
				 "Commad pushed in queue as active context:%p  new context:%p\n",
				 mgmtctx->active_ctx, hwctx);
		}
	} else {
		if (mgmtctx->is_idle_due_to_context == 1) {
			mgmtctx->is_idle_due_to_context = 0;
			mgmtctx->is_partition_idle = 0;
			ve2_mgmt_handshake_init(xdna, hwctx);
			mgmtctx->active_ctx = hwctx;
		}
	}

	spin_unlock(&mgmtctx->ctx_lock);
	notify_fw_cmd_ready(mgmtctx->active_ctx);

	return 0;
}

static bool ve2_check_context_req(struct amdxdna_mgmtctx  *mgmtctx)
{
	if (mgmtctx->is_context_req == 1) {
		mgmtctx->is_context_req = 0;
		mgmtctx->is_idle_due_to_context = 1;
		return true;
	}

	return false;
}

static bool ve2_check_idle(struct amdxdna_mgmtctx  *mgmtctx)
{
	struct device *aie_dev = mgmtctx->mgmt_aiedev;
	u32 cert_idle_status = 0;
	u32 val = 0;

	ve2_partition_read_privileged_mem(aie_dev, 0,
					  offsetof(struct handshake, cert_idle_status),
					  sizeof(cert_idle_status), (void *)&cert_idle_status);

	/* Make it always true for now */
	if (cert_idle_status & CERT_IS_IDLE) {
		XDNA_DBG(mgmtctx->xdna,
			 "%s: active hwctx %p cert_idle_status:%x cert_ctx_switch_bit:%x -->FOUND\n",
			 __func__, mgmtctx->active_ctx, cert_idle_status, val);
		return true;
	}
	XDNA_DBG(mgmtctx->xdna,
		 "%s: active hwctx %p cert_idle_status:%x cert_ctx_switch_bit:%x -->NOT Found\n",
		 __func__, mgmtctx->active_ctx, cert_idle_status, val);

	return false;
}

static bool ve2_check_queue_not_empty(struct amdxdna_mgmtctx  *mgmtctx)
{
	struct device *aie_dev = mgmtctx->mgmt_aiedev;
	u32 cert_idle_status = 0;
	u32 val = 0;

	ve2_partition_read_privileged_mem(aie_dev, 0,
					  offsetof(struct handshake, cert_idle_status),
					  sizeof(cert_idle_status), (void *)&cert_idle_status);

	/* Make it always true for now */
	if (cert_idle_status & HSA_QUEUE_NOT_EMPTY) {
		XDNA_DBG(mgmtctx->xdna,
			 "%s: active hwctx %p cert_idle_status:%x cert_ctx_switch_bit:%x -->FOUND\n",
			 __func__, mgmtctx->active_ctx, cert_idle_status, val);
		return true;
	}
	XDNA_DBG(mgmtctx->xdna,
		 "%s: active hwctx %p cert_idle_status:%x cert_ctx_switch_bit:%x -->Not Found\n",
		 __func__, mgmtctx->active_ctx, cert_idle_status, val);

	return false;
}

static bool ve2_check_misc_interrupt(struct amdxdna_mgmtctx *mgmtctx)
{
	struct device *aie_dev = mgmtctx->mgmt_aiedev;
	u32 misc_status = 0;

	ve2_partition_read_privileged_mem(aie_dev, 0,
					  offsetof(struct handshake, misc_status),
					  sizeof(misc_status), (void *)&misc_status);
	/*This may occur when control code is hanged or any exception*/
	if (misc_status != 0) {
		if (mgmtctx->active_ctx && mgmtctx->active_ctx->priv)
			mgmtctx->active_ctx->priv->misc_intrpt_flag = true;
		else
			XDNA_ERR(mgmtctx->xdna,
				 "misc_status interrupt: active_ctx or priv is NULL");

		return true;
	}

	return false;
}

static bool ve2_check_idle_or_queue_not_empty(struct amdxdna_mgmtctx  *mgmtctx)
{
	struct device *aie_dev = mgmtctx->mgmt_aiedev;
	u32 cert_idle_status = 0;

	ve2_partition_read_privileged_mem(aie_dev, 0,
					  offsetof(struct handshake, cert_idle_status),
					  sizeof(cert_idle_status),
					  (void *)&cert_idle_status);

	/* Make it always true for now */
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

static void ve2_scheduler_work(struct work_struct *work)
{
	struct amdxdna_mgmtctx *mgmtctx =
		container_of(work, struct amdxdna_mgmtctx, sched_work);

	spin_lock(&mgmtctx->ctx_lock);
	/*
	 * 3 case possible:
	 * 1. it was completion interrupt but idle/queue_not_empty bit was set as cert moved forward
	 * 2. idle bit is set
	 * 3. queue_not_empty bit is set
	 */

	ve2_check_context_req(mgmtctx);

	if (mgmtctx->active_ctx->priv->misc_intrpt_flag) {
		XDNA_ERR(mgmtctx->xdna, "MISC interrupt from firmware!!!\n");
	} else if (ve2_check_queue_not_empty(mgmtctx)) {
		/*
		 * there are more command but cert ack ctx switch bit
		 * we schedule next ctx and if no more ctx are there we set partition idle
		 */
		if (!ve2_response_ctx_switch_req(mgmtctx)) {
			mgmtctx->is_partition_idle = 1;
			/*
			 * no more command in fifo and Partition is IDLE, this can never happen
			 * as we got queue_not_empty bit, that means active ctx should have more
			 * commands.
			 */
			XDNA_DBG(mgmtctx->xdna,
				 "No more command in fifo and Partition is IDLE active hwctx:%p ------> ",
				 mgmtctx->active_ctx);
		}
	} else if (ve2_check_idle(mgmtctx)) {
		/*
		 * 1. no more command and cert is in idle
		 * 2. no more command and cert ack ctx switch bit
		 * in both condition we schedule next ctx and if no more ctx are there we set
		 * partition idle.
		 */
		if (!ve2_response_ctx_switch_req(mgmtctx)) {
			mgmtctx->is_partition_idle = 1;
			XDNA_DBG(mgmtctx->xdna,
				 "No more command in fifo and Partition is IDLE active hwctx:%p ------> ",
				 mgmtctx->active_ctx);
		}
	} else {
		XDNA_ERR(mgmtctx->xdna,
			 "None of the bit (idle/queue_not_empty/misc) was set active ctx:%p\n",
			 mgmtctx->active_ctx);
	}
	spin_unlock(&mgmtctx->ctx_lock);
}

static u32 get_cert_idle_status(struct amdxdna_mgmtctx  *mgmtctx)
{
	struct device *aie_dev = mgmtctx->mgmt_aiedev;
	u32 cert_idle_status = 0;

	ve2_partition_read_privileged_mem(aie_dev, 0,
					  offsetof(struct handshake, cert_idle_status),
					  sizeof(cert_idle_status), (void *)&cert_idle_status);

	return cert_idle_status;
}

static int pop_from_ctx_command_fifo_till(struct amdxdna_mgmtctx *mgmtctx,
					  struct amdxdna_ctx *active_ctx,
					  u64 read_index)
{
	struct amdxdna_ctx_command_fifo *c_ctx, *t_ctx;

	XDNA_DBG(mgmtctx->xdna, "%s for active_ctx:%p read_index:%llu\n",
		 __func__, active_ctx, read_index);
	XDNA_DBG(mgmtctx->xdna, "printing fifo before pop:\n");
	ve2_fifo_display_queue(mgmtctx);
	list_for_each_entry_safe(c_ctx, t_ctx, &mgmtctx->ctx_command_fifo_head, list) {
		if (c_ctx->ctx != active_ctx) {
			XDNA_DBG(mgmtctx->xdna,
				 "POP BREAK as next_ctx=%p != ctx:%p so setting ctx switch bit\n",
				 c_ctx->ctx, c_ctx);
			ve2_request_context_switch(mgmtctx->xdna, mgmtctx);
			break;
		}

		if (c_ctx->command_index <= read_index) {
			XDNA_DBG(mgmtctx->xdna, "POP ctx:%p command index:%llu\n",
				 c_ctx->ctx, c_ctx->command_index);
			list_del(&c_ctx->list);
			kfree(c_ctx);
		} else {
			XDNA_DBG(mgmtctx->xdna,
				 "POP BREAK at temp_ctx:%p command index:%llu active_ctx:%p read_index:%llu\n",
				 c_ctx->ctx, c_ctx->command_index, active_ctx, read_index);
			break;
		}
	}
	return 0;
}

static void ve2_irq_handler(u32 partition_id, void *cb_arg)
{
	struct amdxdna_mgmtctx  *mgmtctx = (struct amdxdna_mgmtctx *)cb_arg;
	u64 read_index = 0, write_index = 0;
	struct amdxdna_ctx *hwctx;
	struct amdxdna_dev *xdna;
	unsigned long flags;

	if (!mgmtctx)
		return;

	xdna = mgmtctx->xdna;
	XDNA_DBG(xdna, "Received an IRQ\n");
	spin_lock_irqsave(&mgmtctx->ctx_lock, flags);

	/* Just wake active hwctx */
	hwctx = mgmtctx->active_ctx;
	if (!hwctx || !hwctx->priv) {
		XDNA_ERR(xdna, "Invalid hwctx");
		spin_unlock_irqrestore(&mgmtctx->ctx_lock, flags);
		return;
	}

	if (get_ctx_read_index(hwctx, &read_index)) {
		XDNA_ERR(xdna, "Failed to get read index");
		return;
	}

	if (get_ctx_write_index(hwctx, &write_index)) {
		XDNA_ERR(xdna, "Failed to get write index");
		return;
	}

	XDNA_DBG(xdna,
		 "In IRQ hwctx %p read_index=%lld, write index=%lld cert_ctx_switch_bit:%u cert_idle_status:%u\n",
		 hwctx, read_index, write_index, get_ctx_bit(mgmtctx),
		 get_cert_idle_status(mgmtctx));

	/* Race condition: what happen if more command completed bet this point and
	 * point waiq get executed(check for command completed). This will only happen
	 * when cert is not in sleep ... that means we got completion interrupt..
	 * if cert move forwared to execute more command that is the expected behaviour..
	 * max to max we will go out of order.
	 */
	pop_from_ctx_command_fifo_till(mgmtctx, hwctx, read_index);

	wake_up_interruptible_all(&hwctx->priv->waitq);

	spin_unlock_irqrestore(&mgmtctx->ctx_lock, flags);

	if (ve2_check_idle_or_queue_not_empty(mgmtctx) ||
	    ve2_check_misc_interrupt(mgmtctx))
		queue_work(mgmtctx->mgmtctx_workq, &mgmtctx->sched_work);
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
static int ve2_create_mgmt_partition(struct amdxdna_dev *xdna,
				     struct amdxdna_ctx *hwctx,
				     struct xrs_action_load *load_act)
{
	struct amdxdna_ctx_priv *nhwctx = hwctx->priv;
	struct aie_partition_req request = { 0 };
	u32 start_col = load_act->part.start_col;
	struct amdxdna_mgmtctx  *mgmtctx =
		&xdna->dev_handle->ve2_mgmtctx[start_col];

	if (load_act->create_aie_part) {
		request.user_event1_complete = ve2_irq_handler;
		request.user_event1_priv = mgmtctx;
		request.partition_id = aie_calc_part_id(load_act->part.start_col,
							load_act->part.ncols);

		mgmtctx->mgmt_aiedev = aie_partition_request(&request);
		if (IS_ERR(mgmtctx->mgmt_aiedev)) {
			XDNA_ERR(xdna, "aie parition request failed for part id %d",
				 request.partition_id);
			return -ENODEV;
		}

		mgmtctx->xdna = xdna;
		mgmtctx->mgmt_partid = request.partition_id;
		mgmtctx->start_col = load_act->part.start_col;
		mgmtctx->args.locs = NULL;
		mgmtctx->args.num_tiles = 0;
		nhwctx->args = &mgmtctx->args;
		nhwctx->aie_dev = mgmtctx->mgmt_aiedev;
		INIT_LIST_HEAD(&mgmtctx->ctx_command_fifo_head);
		/* Create workqueue for scheduling the command */
		mgmtctx->mgmtctx_workq = create_workqueue("ve2_mgmtctx_scheduler");
		if (!mgmtctx->mgmtctx_workq) {
			XDNA_ERR(xdna, "Failed to create Workqueue for scheduler");
			aie_partition_release(mgmtctx->mgmt_aiedev);
			return -ENOMEM;
		}
		INIT_WORK(&mgmtctx->sched_work, ve2_scheduler_work);
	} else {
		nhwctx->aie_dev = mgmtctx->mgmt_aiedev;
		nhwctx->args = &mgmtctx->args;
	}

	nhwctx->start_col = load_act->part.start_col;
	nhwctx->num_col = load_act->part.ncols;
	return 0;
}

// we split ve2_partition_read into multiple call for mem and core tile till aie driver provide
// api to read complete 1MB address space
int ve2_create_coredump(struct amdxdna_dev *xdna,
			struct amdxdna_ctx *hwctx,
			void *buffer,
			u32 size)
{
	struct amdxdna_ctx_priv *nhwctx = hwctx->priv;
	struct amdxdna_mgmtctx  *mgmtctx =
		&xdna->dev_handle->ve2_mgmtctx[start_col];
	struct device *aie_dev = mgmtctx->mgmt_aiedev;
	int rel_size = 0;

	if (mgmtctx->active_ctx != hwctx) {
		XDNA_ERR(xdna, "hwctx %p is not the last scheduled. The last scheduled was %p.\n", hwctx, mgmtctx->active_ctx);
		return -1;
	}

	// TODO: Replace MAX_ROW with dynamic value from aie_get_device_info()
	XDNA_DBG(xdna, "Reading coredump for hwctx num_col:%d\n", nhwctx->num_col);
	for (int col = 0; col < nhwctx->num_col; ++col) {
		int rel_col = col + nhwctx->start_col;
		for (int row = 0; row < MAX_ROW; ++row) {
			if (row == 0) {
				int ret = ve2_partition_read(aie_dev, rel_col, row, 0,
							     TILE_ADDRESS_SPACE, GET_TILE_ADDRESS(buffer, MAX_ROW, row, col));
				XDNA_DBG(xdna, "Read shim tile col:%d row:%d ret: %d.", col + nhwctx->start_col, row, ret);
				if (ret < 0)
					return -EINVAL;
			} else if (row == 1 || row == 2) {
				int ret1 = ve2_partition_read(aie_dev, rel_col, row, 0,
							      MEM_TILE_MEMORY_SIZE, GET_TILE_ADDRESS(buffer, MAX_ROW, row, col));
				int ret2 = ve2_partition_read(aie_dev, rel_col, row, MEM_TILE_FIRST_REG_ADDRESS,
							      TILE_ADDRESS_SPACE - MEM_TILE_FIRST_REG_ADDRESS,
							      GET_TILE_ADDRESS(buffer, MAX_ROW, row, col)+ MEM_TILE_FIRST_REG_ADDRESS);
				XDNA_DBG(xdna, "Read mem tile col:%d row:%d ret: %d.", col + nhwctx->start_col, row, ret1);
				XDNA_DBG(xdna, "Read mem tile col:%d row:%d ret: %d.", col + nhwctx->start_col, row, ret2);
				if (ret1 < 0 || ret2 < 0)
					return -EINVAL;
			} else if (row > 2) {
				int ret1 = ve2_partition_read(aie_dev, rel_col, row, 0, CORE_TILE_MEMORY_SIZE,
							      GET_TILE_ADDRESS(buffer, MAX_ROW, row, col));
				int ret2 = ve2_partition_read(aie_dev, rel_col, row, CORE_TILE_FIRST_REG_ADDRESS,
							      TILE_ADDRESS_SPACE - CORE_TILE_FIRST_REG_ADDRESS,
							      GET_TILE_ADDRESS(buffer, MAX_ROW, row, col) + CORE_TILE_FIRST_REG_ADDRESS);
				XDNA_DBG(xdna, "Read core tile col:%d row:%d ret: %d.", col + nhwctx->start_col, row, ret1);
				XDNA_DBG(xdna, "Read core tile col:%d row:%d ret: %d.", col + nhwctx->start_col, row, ret2);
				if (ret1 < 0 || ret2< 0)
					return -EINVAL;
			}
			rel_size += TILE_ADDRESS_SPACE;
		}
	}

	return rel_size;
}

static int ve2_xrs_release(struct amdxdna_dev *xdna, struct amdxdna_ctx *hwctx,
			   struct xrs_action_load *load_act)
{
	return xrs_release_resource(xdna->dev_handle->xrs_hdl, (uintptr_t)hwctx, load_act);
}

static void cert_clear_partition(struct amdxdna_dev *xdna, struct device *aie_dev, u32 col)
{
	struct handshake cert_comm = { 0 };

	ve2_partition_write_privileged_mem(aie_dev, col, 0,
					   sizeof(cert_comm), (void *)&cert_comm);
}

/**
 * ve2_mgmt_destroy_partition - Destroys a VE2 management partition and releases
 *                              associated resources.
 * @hwctx: Pointer to the hardware context to be destroyed.
 *
 * This function releases the XRS resource, clears the partition handshake memory,
 * tears down and releases the AIE partition, and updates the management context state.
 * It should be called when a hardware context is no longer needed.
 */
int ve2_mgmt_destroy_partition(struct amdxdna_ctx *hwctx)
{
	struct amdxdna_dev *xdna = hwctx->client->xdna;
	struct amdxdna_ctx_priv *nhwctx = hwctx->priv;
	struct amdxdna_mgmtctx  *mgmtctx = NULL;
	u32 start_col = nhwctx->start_col;
	struct xrs_action_load load_act;
	u32 num_col = nhwctx->num_col;
	int ret;

	if (!nhwctx->aie_dev) {
		XDNA_ERR(xdna, "Parition does not have aie device handle");
		return -ENODEV;
	}

	ret = ve2_xrs_release(xdna, hwctx, &load_act);
	if (ret) {
		XDNA_ERR(xdna, "XRS Release failed ret %d", ret);
		return ret;
	}

	mgmtctx = &xdna->dev_handle->ve2_mgmtctx[start_col];
	if (load_act.release_aie_part) {
		for (u32 col = 0; col < num_col; col++)
			cert_clear_partition(xdna, nhwctx->aie_dev, col);

		aie_partition_teardown(nhwctx->aie_dev);
		aie_partition_release(nhwctx->aie_dev);

		spin_lock(&mgmtctx->ctx_lock);
		/* Update the active context as partition doesn't exists any more */
		mgmtctx->active_ctx = NULL;
		spin_unlock(&mgmtctx->ctx_lock);
		destroy_workqueue(mgmtctx->mgmtctx_workq);
	} else {
		spin_lock(&mgmtctx->ctx_lock);
		if (mgmtctx->active_ctx == hwctx)
			mgmtctx->active_ctx = NULL;
		spin_unlock(&mgmtctx->ctx_lock);
	}

	return ret;
}

struct amdxdna_ctx *ve2_get_hwctx(struct amdxdna_dev *xdna, u32 col)
{
	struct amdxdna_client *client;
	struct amdxdna_ctx *hwctx;
	unsigned long hwctx_id;
	u32 start, end;
	int idx;

	list_for_each_entry(client, &xdna->client_list, node) {
		idx = srcu_read_lock(&client->ctx_srcu);
		amdxdna_for_each_ctx(client, hwctx_id, hwctx) {
			start = hwctx->start_col;
			end = start + hwctx->num_col;
			if (col >= start && col < end) {
				XDNA_DBG(xdna, "hwctx found with id %d & pid %d\n",
					 hwctx->id, hwctx->client->pid);
				srcu_read_unlock(&client->ctx_srcu, idx);
				return hwctx;
			}
		}
		srcu_read_unlock(&client->ctx_srcu, idx);
	}

	XDNA_ERR(xdna, "hwctx not found for requested col: %d\n", col);

	return NULL;
}

/*
 * notify_fw_cmd_ready - Notify the firmware that a new command is ready for execution
 * @hwctx: Pointer to the hardware context associated with the command
 *
 * This function writes to the event generation register to signal the firmware
 * that a command is ready to be processed for the specified hardware context.
 * Returns 0 on success or a negative error code on failure.
 */
int notify_fw_cmd_ready(struct amdxdna_ctx *hwctx)
{
	struct amdxdna_dev *xdna = hwctx->client->xdna;
	u32 value = VE2_USER_EVENT_ID;
	int ret;

	ret = ve2_partition_write(hwctx->priv->aie_dev, 0, 0,
				  VE2_EVENT_GENERATE_REG, sizeof(u32),
				  (void *)&(value));
	if (ret < 0)
		XDNA_DBG(xdna, "AIE write on event_generate register throw error %d\n",
			 ret);

	return ret;
}

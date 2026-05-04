// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2025, Advanced Micro Devices, Inc.
 */
#include <linux/device.h>
#include <linux/version.h>
#include <linux/completion.h>
#include <linux/atomic.h>
#include <linux/delay.h>

#include "amdxdna_ctx.h"
#include "ve2_of.h"
#include "ve2_mgmt.h"
#include "ve2_res_solver.h"
#include "amdxdna_error.h"

/* Module parameter: delay in seconds before waking threads on AIE error (for devmem debug) */
static int aie_error_delay_sec;
module_param(aie_error_delay_sec, int, 0644);
MODULE_PARM_DESC(aie_error_delay_sec, "Delay in seconds on AIE error before waking threads (for devmem debug, default=0)");

static int ve2_create_mgmt_partition(struct amdxdna_dev *xdna,
				     struct amdxdna_ctx *hwctx,
				     struct xrs_action_load *load_act);

/* Forward declarations for DRM scheduler and context switching */
/* Forward declarations */
static void ve2_dump_debug_state(struct amdxdna_dev *xdna,
				 struct amdxdna_mgmtctx *mgmtctx);
static int ve2_request_context_switch(struct amdxdna_dev *xdna,
				       struct amdxdna_mgmtctx *mgmtctx);
static bool ve2_check_context_req(struct amdxdna_mgmtctx *mgmtctx);
static bool ve2_check_misc_interrupt(struct amdxdna_mgmtctx *mgmtctx);
static u32 get_cert_idle_status(struct amdxdna_mgmtctx *mgmtctx);

/*
 * ===========================================================================
 * DRM Scheduler Callbacks
 * ===========================================================================
 */

/**
 * ve2_sched_run_job - Execute a job on the hardware
 * @sched_job: DRM scheduler job to execute
 *
 * Called by DRM scheduler when a job should be submitted to HW.
 * Handles context switching if the job's context is different from
 * the currently active context on the partition.
 *
 * DRM SCHEDULER STATE MANAGEMENT:
 * Uses firmware state machine flags to sync with hardware:
 * - is_partition_idle: Set at init, cleared after first job
 * - is_context_req: Set when driver requests context switch, cleared by firmware ACK
 * - is_idle_due_to_context: Set when firmware ACKs context switch request
 *
 * Return: Fence for job completion tracking, or NULL if partition is busy
 */
static struct dma_fence *ve2_sched_run_job(struct drm_sched_job *sched_job)
{
	struct amdxdna_sched_job *job = drm_job_to_xdna_job(sched_job);
	struct amdxdna_ctx *hwctx = job->ctx;
	struct amdxdna_dev *xdna = hwctx->client->xdna;
	struct amdxdna_mgmtctx *mgmtctx;
	struct dma_fence *fence;
	u32 cert_idle_status;
	bool fw_is_idle;
	int ret = 0;

	mgmtctx = &xdna->dev_handle->ve2_mgmtctx[hwctx->start_col];

	/*
	 * Get reference to our completion fence.
	 * The scheduler will wait on this fence. When we signal it (in IRQ handler),
	 * the scheduler knows the job is complete.
	 */
	fence = dma_fence_get(job->fence);

	mutex_lock(&mgmtctx->ctx_lock);

	/* Check for MISC interrupt from firmware */
	ve2_check_misc_interrupt(mgmtctx);
	if (mgmtctx->active_ctx && mgmtctx->active_ctx->priv &&
	    mgmtctx->active_ctx->priv->misc_intrpt_flag) {
		XDNA_ERR(xdna, "MISC interrupt from firmware");
	}

	/* Check context switch request bit from firmware */
	ve2_check_context_req(mgmtctx);

	/* Get firmware idle status to determine if ready for context switch */
	cert_idle_status = get_cert_idle_status(mgmtctx);
	fw_is_idle = (cert_idle_status & CERT_IS_IDLE) != 0;

	/*
	 * THREE-CASE Context Switching State Machine (synced with firmware):
	 * CASE 1: is_partition_idle - First job after partition init
	 * CASE 2: is_idle_due_to_context - Firmware acknowledged context switch request
	 * CASE 3: Different context + firmware idle - Driver-initiated switch
	 */
	if (mgmtctx->is_partition_idle) {
		/* CASE 1: Partition is idle (first job after init) */
		mgmtctx->is_partition_idle = 0;
		ve2_mgmt_handshake_init(xdna, hwctx);
		mgmtctx->active_ctx = hwctx;
	} else if (mgmtctx->is_idle_due_to_context) {
		/* CASE 2: Firmware acknowledged context switch request */
		mgmtctx->is_idle_due_to_context = 0;
		ve2_mgmt_handshake_init(xdna, hwctx);
		mgmtctx->active_ctx = hwctx;
	} else if (mgmtctx->active_ctx != hwctx) {
		/* CASE 3: Different context - check if firmware is idle */
		if (!fw_is_idle) {
			/* Firmware busy - cannot switch yet, retry later */
			mutex_unlock(&mgmtctx->ctx_lock);
			dma_fence_put(fence);
			return NULL;
		}

		/* Firmware idle - safe to request context switch */
		ret = ve2_request_context_switch(xdna, mgmtctx);
		if (ret) {
			XDNA_ERR(xdna, "Context switch request failed: ret=%d", ret);
			dma_fence_set_error(fence, ret);
			goto unlock;
		}

		ve2_mgmt_handshake_init(xdna, hwctx);
		mgmtctx->active_ctx = hwctx;
	} else {
		/* Same context - reinit if firmware is idle */
		if (fw_is_idle) {
			ve2_mgmt_handshake_init(xdna, hwctx);
		}
	}

	/* Notify firmware that command is ready */
	ret = notify_fw_cmd_ready(hwctx);
	if (ret < 0)
		XDNA_ERR(xdna, "notify_fw_cmd_ready failed: ret=%d", ret);

unlock:
	mutex_unlock(&mgmtctx->ctx_lock);
	return fence;
}

/**
 * ve2_sched_free_job - Free job resources
 * @sched_job: DRM scheduler job to free
 *
 * Called by DRM scheduler after job completion or cancellation.
 */
static void ve2_sched_free_job(struct drm_sched_job *sched_job)
{
	struct amdxdna_sched_job *job = drm_job_to_xdna_job(sched_job);

	/*
	 * Only cleanup scheduler state here.
	 * job->fence, job->out_fence, and job itself are released by
	 * amdxdna_sched_job_cleanup() which is called from the common job
	 * release path (ve2_job_put -> amdxdna_job_release).
	 */
	drm_sched_job_cleanup(sched_job);

	/* Release job reference - may trigger amdxdna_sched_job_cleanup if last ref */
	ve2_job_put(job);
}

/**
 * ve2_sched_job_timedout - Handle job timeout
 * @sched_job: DRM scheduler job that timed out
 *
 * Called by DRM scheduler when a job exceeds its timeout.
 * Dumps debug state and initiates recovery.
 *
 * Return: DRM_GPU_SCHED_STAT_ENODEV to reset the device
 */
static enum drm_gpu_sched_stat ve2_sched_job_timedout(struct drm_sched_job *sched_job)
{
	struct amdxdna_sched_job *job = drm_job_to_xdna_job(sched_job);
	struct amdxdna_ctx *hwctx = job->ctx;
	struct amdxdna_dev *xdna = hwctx->client->xdna;
	struct amdxdna_mgmtctx *mgmtctx;

	mgmtctx = &xdna->dev_handle->ve2_mgmtctx[hwctx->start_col];



	/* Print HSA queue address and read/write index for manual inspection */
	if (hwctx->priv && hwctx->priv->hwctx_hsa_queue.hsa_queue_p) {
		struct ve2_hsa_queue *queue = &hwctx->priv->hwctx_hsa_queue;
		u64 read_idx = 0, write_idx = 0, reserved_wr = 0;

		/* Read the actual values from the queue header */
		read_idx = queue->hsa_queue_p->hq_header.read_index;
		write_idx = queue->hsa_queue_p->hq_header.write_index;
		reserved_wr = queue->reserved_write_index;
	} else {
		XDNA_ERR(xdna, "[TS] !!!TIMEOUT!!! No HSA queue for hwctx=%p (priv=%p)",
			 hwctx, hwctx->priv);
	}

	/* Dump debug state */
	ve2_dump_debug_state(xdna, mgmtctx);

	/*
	 * Mark context as having a MISC interrupt to prevent further submissions
	 * This matches the existing timeout behavior
	 */
	if (hwctx->priv) {
		hwctx->priv->misc_intrpt_flag = true;
	}

	/*
	 * Return ENODEV to signal device needs reset.
	 * DRM scheduler will stop scheduling on this entity.
	 */
	return DRM_GPU_SCHED_STAT_ENODEV;
}

static const struct drm_sched_backend_ops ve2_sched_ops = {
	.run_job	= ve2_sched_run_job,
	.free_job	= ve2_sched_free_job,
	.timedout_job	= ve2_sched_job_timedout,
};

/*
 * ===========================================================================
 * Context Switching
 * ===========================================================================
 */

static void cert_setup_partition(struct amdxdna_dev *xdna,
				 struct amdxdna_ctx_priv *nhwctx,
				 u32 col, struct handshake *cert_hs)
{
	struct ve2_config_hwctx *hwctx_cfg = &nhwctx->hwctx_config[col];
	u64 hsa_addr = 0xFFFFFFFFFFFFFFFF;
	u32 start_col = nhwctx->start_col;
	u32 num_col = nhwctx->num_col;
	u32 lead_col_addr;
	u64 host_time_ns;

	/* Store current host time */
	host_time_ns = ktime_get_ns();
	cert_hs->host_time_low  = (u32)(host_time_ns & 0xFFFFFFFF);
	cert_hs->host_time_high = (u32)(host_time_ns >> 32);

	if (col == 0)
		hsa_addr = nhwctx->hwctx_hsa_queue.hsa_queue_mem.dma_addr;

	lead_col_addr = VE2_ADDR(start_col, 0, 0);

	cert_hs->partition_base_address = lead_col_addr;
	cert_hs->aie_info.partition_size = num_col;
	cert_hs->hsa_addr_high =  upper_32_bits(hsa_addr);
	cert_hs->hsa_addr_low =  lower_32_bits(hsa_addr);
	cert_hs->log_addr_high = upper_32_bits(hwctx_cfg->log_buf_addr);
	cert_hs->log_addr_low = lower_32_bits(hwctx_cfg->log_buf_addr);
	cert_hs->log_buf_size = hwctx_cfg->log_buf_size;
	cert_hs->dbg_buf.dbg_buf_addr_high = upper_32_bits(hwctx_cfg->debug_buf_addr);
	cert_hs->dbg_buf.dbg_buf_addr_low = lower_32_bits(hwctx_cfg->debug_buf_addr);
	cert_hs->dbg_buf.size = hwctx_cfg->debug_buf_size;

	/* Dtrace Buffer */
	cert_hs->trace.dtrace_addr_high = upper_32_bits(hwctx_cfg->dtrace_addr);
	cert_hs->trace.dtrace_addr_low = lower_32_bits(hwctx_cfg->dtrace_addr);

	/* Opcode Timeout */
	cert_hs->opcode_timeout_config = hwctx_cfg->opcode_timeout_config;

	cert_hs->ctx_switch_req = 0;
	cert_hs->hsa_location = 0;
	cert_hs->dbg.hsa_addr_high = 0xFFFFFFFF;
	cert_hs->dbg.hsa_addr_low = 0xFFFFFFFF;
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
	hs_data = NULL;
}

static struct aie_op_handshake_data *ve2_prepare_hs_data(struct amdxdna_dev *xdna,
							 struct amdxdna_ctx_priv *nhwctx,
							 bool init)
{
	struct aie_op_handshake_data *hs_data;
	u32 num_col = nhwctx->num_col;
	struct aie_location aie_loc;

	hs_data = kmalloc_array(num_col, sizeof(*hs_data), GFP_KERNEL);
	if (!hs_data) {
		XDNA_ERR(xdna, "No memory for handshake data allocation\n");
		return NULL;
	}

	for (u32 col = 0; col < num_col; col++) {
		struct handshake *cert_hs;

		aie_loc.col = col;
		cert_hs = kmalloc(sizeof(*cert_hs), GFP_KERNEL);
		if (!cert_hs) {
			XDNA_ERR(xdna, "No memory for cert hs packet\n");
			/* Free previously allocated handshakes */
			ve2_free_hs_data(hs_data, col);
			return NULL;
		}
		memset(cert_hs, 0, sizeof(*cert_hs));
		if (init)
			cert_setup_partition(xdna, nhwctx, col, cert_hs);

		hs_data[col].addr = (void *)cert_hs;
		hs_data[col].size = sizeof(struct handshake);
		hs_data[col].offset = 0x0;
		hs_data[col].loc = aie_loc;
	}

	return hs_data;
}

int ve2_xrs_col_list(struct amdxdna_dev *xdna, struct alloc_requests *xrs_req,
		     u32 num_col)
{
	int total_col = xrs_get_total_cols(xdna->dev_handle->xrs_hdl);
	int i, start;
	int max_start = total_col - num_col;
	int entries = 0;

	if (start_col > 0) {
		if (start_col + num_col > total_col) {
			XDNA_ERR(xdna, "Invalid start_col_index %d, num col %d",
				 start_col, num_col);
			return -EINVAL;
		}

		for (start = start_col; start <= max_start; start += MIN_COL_SUPPORT)
			entries++;
	} else {
		for (start = 0; start <= max_start; start += MIN_COL_SUPPORT)
			entries++;
	}

	if (entries == 0) {
		XDNA_ERR(xdna, "No valid start_col found for num_col %d in total_col %d",
			 num_col, total_col);
		return -EINVAL;
	}

	xrs_req->cdo.start_cols = kmalloc_array(entries,
						sizeof(*xrs_req->cdo.start_cols),
						GFP_KERNEL);
	if (!xrs_req->cdo.start_cols)
		return -ENOMEM;

	xrs_req->cdo.cols_len = entries;
	for (i = 0, start = (start_col > 0 ? start_col : 0); start <= max_start;
	     start += MIN_COL_SUPPORT, i++)
		xrs_req->cdo.start_cols[i] = start;

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

	XDNA_DBG(xdna, "XRS request: ncols=%u (partition_size=%d, num_tiles=%u)",
		 xrs_req->cdo.ncols, partition_size, hwctx->num_tiles);

	ret = ve2_xrs_col_list(xdna, xrs_req, xrs_req->cdo.ncols);
	if (ret) {
		XDNA_ERR(xdna, "Allocate XRS col resource failed, ret %d", ret);
		mutex_unlock(&xrs->xrs_lock);
		goto free_xrs_req;
	}

	xrs_req->rqos.priority = hwctx->qos.priority;

	/* Validate user_start_col if set */
	if (hwctx->qos.user_start_col != USER_START_COL_NOT_REQUESTED) {
		/* Check alignment: start_col must be a multiple of MIN_COL_SUPPORT (4) */
		if (hwctx->qos.user_start_col % MIN_COL_SUPPORT != 0) {
			XDNA_ERR(xdna, "user_start_col %u not aligned to %u",
				 hwctx->qos.user_start_col, MIN_COL_SUPPORT);
			mutex_unlock(&xrs->xrs_lock);
			ret = -EINVAL;
			goto free_start_cols;
		}

		/* Check bounds: start_col + ncols must not exceed total columns */
		if (hwctx->qos.user_start_col + xrs_req->cdo.ncols > xrs->cfg.total_col) {
			XDNA_ERR(xdna, "user_start_col %u + ncols %u exceeds total %u",
				 hwctx->qos.user_start_col, xrs_req->cdo.ncols, xrs->cfg.total_col);
			mutex_unlock(&xrs->xrs_lock);
			ret = -ERANGE;
			goto free_start_cols;
		}
	}
	xrs_req->rqos.user_start_col = hwctx->qos.user_start_col;
	xrs_req->rid = (uintptr_t)hwctx;
	ret = xrs_allocate_resource(xrs, xrs_req, &load_act);
	if (ret) {
		XDNA_ERR(xdna, "Allocate XRS resource failed, ret %d", ret);
		mutex_unlock(&xrs->xrs_lock);
		goto free_start_cols;
	}

	ret = ve2_create_mgmt_partition(xdna, hwctx, &load_act);
	if (ret) {
		XDNA_ERR(xdna, "Creating AIE partition failed, ret %d", ret);
		mutex_unlock(&xrs->xrs_lock);
		goto xrs_release;
	}

	nhwctx = hwctx->priv;
	hwctx->start_col = nhwctx->start_col;
	hwctx->num_col = nhwctx->num_col;
	/* Allocate hwctx_config array based on number of columns for this context */
	nhwctx->hwctx_config = kcalloc(nhwctx->num_col,
				       sizeof(*nhwctx->hwctx_config), GFP_KERNEL);
	if (!nhwctx->hwctx_config) {
		XDNA_ERR(xdna, "Failed to allocate hwctx_config");
		mutex_unlock(&xrs->xrs_lock);
		ret = -ENOMEM;
		goto destroy_partition;
	}
	mutex_unlock(&xrs->xrs_lock);

	kfree(xrs_req->cdo.start_cols);
	kfree(xrs_req);
	return 0;

destroy_partition:
	ve2_mgmt_destroy_partition(hwctx);
xrs_release:
	xrs_release_resource(xrs, (uintptr_t)hwctx, &load_act);
free_start_cols:
	kfree(xrs_req->cdo.start_cols);
free_xrs_req:
	kfree(xrs_req);
	XDNA_ERR(xdna, "XRS Request Failed. Ret %d", ret);
	return ret;
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
	struct aie_op_handshake_data *hs_data;
	u32 start_col;
	u32 num_col;
	int ret = 0;

	start_col = nhwctx->start_col;
	num_col = nhwctx->num_col;

	hs_data = ve2_prepare_hs_data(xdna, nhwctx, true);
	if (!hs_data) {
		XDNA_ERR(xdna, "preparing cert handshake data failed ");
		return;
	}
	nhwctx->args->handshake_cols = num_col;
	nhwctx->args->handshake = (struct aie_op_handshake_data *)hs_data;
	nhwctx->args->init_opts = (AIE_PART_INIT_OPT_DEFAULT | AIE_PART_INIT_OPT_HANDSHAKE |
		AIE_PART_INIT_OPT_DIS_TLAST_ERROR) & ~AIE_PART_INIT_OPT_UC_ENB_MEM_PRIV;
	XDNA_DBG(xdna, "Handshake init hwctx : %p\n", hwctx);
	XDNA_DBG(xdna,
		 "partition init: start_col=%u num_col=%u hwctx=%p pid=%d",
		 start_col, num_col, hwctx, hwctx->client->pid);
	XDNA_DBG(xdna,
		 "handshake: ve2_partition_initialize enter start_col=%u num_col=%u hwctx=%p",
		 start_col, num_col, hwctx);
	trace_amdxdna_trace_point("XRT_PROFILING_TRACE_PARTITION_INIT",
				  hwctx->client->pid, start_col, hwctx->priv->id, num_col);
	ret = ve2_partition_initialize(nhwctx->aie_dev, nhwctx->args);
	XDNA_DBG(xdna,
		 "partition init: aie_partition_initialize returned %d (start_col=%u num_col=%u hwctx=%p)",
		 ret, start_col, num_col, hwctx);
	if (ret < 0) {
		XDNA_DBG(xdna, "handshake: ve2_partition_initialize failed ret=%d", ret);
		XDNA_ERR(xdna, "aie partition init failed: %d", ret);
		goto release_hs_data;
	}
	trace_amdxdna_trace_point("XRT_PROFILING_TRACE_PARTITION_DONE",
				  hwctx->client->pid, start_col, hwctx->priv->id, num_col);

	XDNA_DBG(xdna, "handshake: ve2_partition_initialize ok hwctx=%p", hwctx);

	for (int col = num_col - 1; col >= 0; col--)
		ve2_partition_uc_wakeup(nhwctx->aie_dev, col);

	XDNA_DBG(xdna, "partition uc_wakeup done cols=%u hwctx=%p", num_col, hwctx);

release_hs_data:
	ve2_free_hs_data(hs_data, num_col);
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

static bool ve2_check_context_req(struct amdxdna_mgmtctx  *mgmtctx)
{
	if (mgmtctx->is_context_req == 1) {
		mgmtctx->is_context_req = 0;
		mgmtctx->is_idle_due_to_context = 1;
		return true;
	}

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

static u32 get_cert_idle_status(struct amdxdna_mgmtctx  *mgmtctx)
{
	struct device *aie_dev = mgmtctx->mgmt_aiedev;
	u32 cert_idle_status = 0;

	ve2_partition_read_privileged_mem(aie_dev, 0,
					  offsetof(struct handshake, cert_idle_status),
					  sizeof(cert_idle_status), (void *)&cert_idle_status);

	return cert_idle_status;
}

static void ve2_irq_handler(u32 partition_id, void *cb_arg)
{
	struct amdxdna_mgmtctx  *mgmtctx = (struct amdxdna_mgmtctx *)cb_arg;
	u64 read_index = 0, write_index = 0;
	struct amdxdna_ctx *hwctx;
	struct amdxdna_dev *xdna;

	if (!mgmtctx)
		return;

	xdna = mgmtctx->xdna;
	XDNA_DBG(xdna, "IRQ received: partition_id=%u, start_col=%u",
		 partition_id, mgmtctx->start_col);
	mutex_lock(&mgmtctx->ctx_lock);

	/* Just wake active hwctx */
	hwctx = mgmtctx->active_ctx;
	if (!hwctx || !hwctx->priv) {
		XDNA_ERR(xdna, "Invalid hwctx");
		mutex_unlock(&mgmtctx->ctx_lock);
		return;
	}

	XDNA_DBG(xdna,
		 "completion IRQ: enter start_col=%u hwctx=%p pid=%d",
		 mgmtctx->start_col, hwctx, hwctx->client->pid);

	trace_amdxdna_trace_point("XRT_PROFILING_TRACE_ENTER",
				  hwctx->client->pid,
				  mgmtctx->start_col, hwctx->priv->id, 0);
	if (get_ctx_read_index(hwctx, &read_index)) {
		XDNA_ERR(xdna, "Failed to get read index");
		mutex_unlock(&mgmtctx->ctx_lock);
		return;
	}

	if (get_ctx_write_index(hwctx, &write_index)) {
		XDNA_ERR(xdna, "Failed to get write index");
		mutex_unlock(&mgmtctx->ctx_lock);
		return;
	}

	XDNA_DBG(xdna, "IRQ: hwctx=%p, read_idx=%llu, write_idx=%llu, ctx_bit=%u, idle_status=0x%x",
		 hwctx, read_index, write_index, get_ctx_bit(mgmtctx),
		 get_cert_idle_status(mgmtctx));

	/* Race condition: what happen if more command completed bet this point and
	 * point waiq get executed(check for command completed). This will only happen
	 * when cert is not in sleep ... that means we got completion interrupt..
	 * if cert move forwarded to execute more command that is the expected behaviour..
	 * max to max we will go out of order.
	 */

	wake_up_interruptible_all(&hwctx->priv->waitq);

	trace_amdxdna_trace_point("XRT_PROFILING_TRACE_EXIT",
				  hwctx->client->pid,
				  hwctx->priv->id, write_index,
				  read_index);

	mutex_unlock(&mgmtctx->ctx_lock);

	XDNA_DBG(xdna,
		 "completion IRQ: exit read_index=%llu write_index=%llu hwctx=%p pid=%d",
		 (unsigned long long)read_index, (unsigned long long)write_index,
		 hwctx, hwctx->client->pid);
}

/**
 * ve2_dump_debug_state - Dump HSA queue state and handshake data for debugging
 * @xdna: Pointer to the AMD XDNA device structure
 * @mgmtctx: Pointer to the management context
 *
 * This function dumps critical debug information when an AIE error occurs,
 * including HSA queue indices, completion states, and firmware handshake data.
 */
static void ve2_dump_debug_state(struct amdxdna_dev *xdna,
				 struct amdxdna_mgmtctx *mgmtctx)
{
	struct amdxdna_ctx *hwctx = mgmtctx->active_ctx;
	struct amdxdna_ctx_priv *priv;
	struct ve2_hsa_queue *hq;
	struct hsa_queue *queue;
	struct handshake *hs = NULL;
	int i;
	int ret;

	if (!hwctx || !hwctx->priv) {
		XDNA_WARN(xdna, "=== DEBUG DUMP: No active context ===\n");
		return;
	}

	priv = hwctx->priv;
	hq = &priv->hwctx_hsa_queue;
	queue = hq->hsa_queue_p;

	if (!queue) {
		XDNA_WARN(xdna, "=== DEBUG DUMP: No HSA queue allocated ===\n");
		return;
	}

	/* Use XDNA_WARN (non-ratelimited) so the full dump is visible. */
	XDNA_WARN(xdna, "=== VE2 DEBUG DUMP START (hwctx=%p) ===\n", hwctx);

	/* hq_lock protects read_index, write_index, reserved_write_index (ve2_host_queue.h) */
	mutex_lock(&hq->hq_lock);

	/* Sync read_index before reading (device writes this) */
	hsa_queue_sync_read_index_for_read(hq);
	/* Note: write_index is written by CPU, so no sync needed for reading */

	/* Dump HSA queue header */
	XDNA_WARN(xdna, "HSA Queue Header:\n");
	XDNA_WARN(xdna, "  read_index:     %llu\n", queue->hq_header.read_index);
	XDNA_WARN(xdna, "  write_index:    %llu\n", queue->hq_header.write_index);
	XDNA_WARN(xdna, "  reserved_write: %llu\n", hq->reserved_write_index);
	XDNA_WARN(xdna, "  capacity:       %u\n", queue->hq_header.capacity);
	XDNA_WARN(xdna, "  data_address:   0x%llx\n", queue->hq_header.data_address);
	XDNA_WARN(xdna, "  dma_addr:       0x%llx\n", hq->hsa_queue_mem.dma_addr);

	/* Calculate pending commands */
	XDNA_WARN(xdna, "  pending_cmds:   %llu\n",
		  queue->hq_header.write_index - queue->hq_header.read_index);

	/* Dump completion status for all slots */
	XDNA_WARN(xdna, "HSA Queue Completion Status:\n");
	for (i = 0; i < HOST_QUEUE_ENTRY; i++) {
		/* Sync completion memory before reading (device may have written) */
		hsa_queue_sync_completion_for_read(hq, i);
		u64 completion = hq->hq_complete.hqc_mem[i];

		if (completion != 0)
			XDNA_WARN(xdna, "  slot[%2d]: state=%llu\n", i, completion);
	}

	/* Dump packet info for pending slots */
	XDNA_WARN(xdna, "HSA Queue Packet Details:\n");
	for (i = 0; i < HOST_QUEUE_ENTRY; i++) {
		struct host_queue_packet *pkt = &queue->hq_entry[i];
		u64 completion = hq->hq_complete.hqc_mem[i];
		u64 expected_signal = hq->hq_complete.hqc_dma_addr + i * sizeof(u64);

		/* Show all non-invalid packets OR packets with unexpected state */
		if (pkt->xrt_header.common_header.type != HOST_QUEUE_PACKET_TYPE_INVALID ||
		    completion != 0) {
			XDNA_WARN(xdna,
				  "  slot[%2d]: type=%u opcode=%u count=%u chain=%u dist=%u indir=%u\n",
				  i,
				  pkt->xrt_header.common_header.type,
				  pkt->xrt_header.common_header.opcode,
				  pkt->xrt_header.common_header.count,
				  pkt->xrt_header.common_header.chain_flag,
				  pkt->xrt_header.common_header.distribute,
				  pkt->xrt_header.common_header.indirect);
			XDNA_WARN(xdna, "           signal=0x%llx (expected=0x%llx) state=%llu\n",
				  pkt->xrt_header.completion_signal, expected_signal, completion);
			/* Check for signal mismatch - indicates potential corruption */
			if (pkt->xrt_header.common_header.type != HOST_QUEUE_PACKET_TYPE_INVALID &&
			    pkt->xrt_header.completion_signal != expected_signal) {
				XDNA_WARN(xdna,
					  "  *** SIGNAL MISMATCH! Possible packet corruption ***\n");
			}
			/* Check for invalid opcode - potential corruption */
			if (pkt->xrt_header.common_header.type != HOST_QUEUE_PACKET_TYPE_INVALID &&
			    pkt->xrt_header.common_header.opcode != HOST_QUEUE_PACKET_EXEC_BUF) {
				XDNA_WARN(xdna,
					  "  *** INVALID OPCODE %u! Expected %u. Possible corruption ***\n",
					  pkt->xrt_header.common_header.opcode,
					  HOST_QUEUE_PACKET_EXEC_BUF);
			}
			/* Check for invalid count */
			if (pkt->xrt_header.common_header.type != HOST_QUEUE_PACKET_TYPE_INVALID &&
			    !pkt->xrt_header.common_header.indirect &&
			    pkt->xrt_header.common_header.count != sizeof(struct exec_buf)) {
				XDNA_WARN(xdna,
					  "  *** INVALID COUNT %u! Expected %zu. Possible corruption ***\n",
					  pkt->xrt_header.common_header.count,
					  sizeof(struct exec_buf));
			}

			/* Dump exec_buf data (instruction buffer addresses)
			 * for non-indirect packets
			 */
			if (!pkt->xrt_header.common_header.indirect) {
				struct exec_buf *ebp = (struct exec_buf *)pkt->data;
				u64 instr_addr = ((u64)ebp->dpu_control_code_host_addr_high << 32) |
						 ebp->dpu_control_code_host_addr_low;
				u64 dtrace_addr = ((u64)ebp->dtrace_buf_host_addr_high << 32) |
						  ebp->dtrace_buf_host_addr_low;

				XDNA_WARN(xdna,
					  "           instr_addr=0x%llx dtrace=0x%llx args_len=%u\n",
					  instr_addr, dtrace_addr, ebp->args_len);

				/* Flag potentially invalid addresses */
				if (!instr_addr)
					XDNA_WARN(xdna,
						  "  *** ZERO INSTRUCTION ADDR! Possible corruption ***\n");
			}
		}
	}

	mutex_unlock(&hq->hq_lock);

	/* Read and dump handshake data from firmware */
	hs = kzalloc(sizeof(*hs), GFP_KERNEL);
	if (!hs) {
		XDNA_WARN(xdna, "No memory for handshake; skipping handshake/VM dump\n");
		return;
	}
	ret = ve2_partition_read_privileged_mem(priv->aie_dev, 0, 0, sizeof(*hs), hs);
	if (ret) {
		XDNA_WARN(xdna,
			  "Failed to read firmware handshake data (ret=%d); skipping handshake/VM dump\n",
			  ret);
		kfree(hs);
		return;
	}

	XDNA_WARN(xdna, "Firmware Handshake Data:\n");
	XDNA_WARN(xdna, "  mpaie_alive:        0x%x %s\n", hs->mpaie_alive,
		  (hs->mpaie_alive == ALIVE_MAGIC) ? "(ALIVE)" : "(NOT ALIVE!)");
	XDNA_WARN(xdna, "  partition_base:     0x%x\n", hs->partition_base_address);
	XDNA_WARN(xdna, "  partition_size:     %u cols\n", hs->aie_info.partition_size);
	XDNA_WARN(xdna, "  hsa_addr:           0x%x%08x\n", hs->hsa_addr_high, hs->hsa_addr_low);
	XDNA_WARN(xdna, "  ctx_switch_req:     0x%x\n", hs->ctx_switch_req);
	XDNA_WARN(xdna, "  cert_idle_status:   0x%x\n", hs->cert_idle_status);
	XDNA_WARN(xdna, "  misc_status:        0x%x\n", hs->misc_status);
	XDNA_WARN(xdna, "  runlist_read_idx:   0x%x\n", hs->runlist_read_idx);
	XDNA_WARN(xdna, "  doorbell_pending:   %u\n", hs->doorbell_pending);

	/* Dump VM state (firmware execution context) */
	XDNA_WARN(xdna, "Firmware VM State:\n");
	XDNA_WARN(xdna, "  fw_state:           0x%x\n", hs->vm.fw_state);
	XDNA_WARN(xdna, "  abs_page_index:     0x%x\n", hs->vm.abs_page_index);
	XDNA_WARN(xdna, "  ppc:                0x%x\n", hs->vm.ppc);

	/* Dump exception info if any */
	if (hs->exception.ear || hs->exception.esr || hs->exception.pc) {
		XDNA_WARN(xdna, "Firmware Exception:\n");
		XDNA_WARN(xdna, "  EAR (addr):         0x%x\n", hs->exception.ear);
		XDNA_WARN(xdna, "  ESR (status):       0x%x\n", hs->exception.esr);
		XDNA_WARN(xdna, "  PC:                 0x%x\n", hs->exception.pc);
	}

	/* Dump firmware counters for insight into workload */
	XDNA_WARN(xdna, "Firmware Counters:\n");
	XDNA_WARN(xdna, "  c_job_launched:     %u\n", hs->counter.c_job_launched);
	XDNA_WARN(xdna, "  c_job_finished:     %u\n", hs->counter.c_job_finished);
	XDNA_WARN(xdna, "  c_hsa_pkt:          %u\n", hs->counter.c_hsa_pkt);
	XDNA_WARN(xdna, "  c_opcode:           %u\n", hs->counter.c_opcode);
	XDNA_WARN(xdna, "  c_doorbell:         %u\n", hs->counter.c_doorbell);
	XDNA_WARN(xdna, "  c_page:             %u\n", hs->counter.c_page);

	/* Dump DMA addresses for debugging DMA errors */
	XDNA_WARN(xdna, "Last DMA Addresses:\n");
	XDNA_WARN(xdna, "  dm2mm:              0x%x%08x\n",
		  hs->last_ddr_dm2mm_addr_high, hs->last_ddr_dm2mm_addr_low);
	XDNA_WARN(xdna, "  mm2dm:              0x%x%08x\n",
		  hs->last_ddr_mm2dm_addr_high, hs->last_ddr_mm2dm_addr_low);

	/* Dump context save/restore state */
	XDNA_WARN(xdna, "Context Save State:\n");
	XDNA_WARN(xdna, "  restore_page_idx:   %u\n",
		  hs->ctx_save.contents.restore_page.page_index);
	XDNA_WARN(xdna, "  cmd_chain_failure:  %u\n",
		  hs->ctx_save.contents.restore_page.cmd_chain_failure);

	XDNA_WARN(xdna, "=== VE2 DEBUG DUMP END ===\n");
	kfree(hs);
}

static void ve2_aie_error_cb(void *arg)
{
	struct amdxdna_mgmtctx *mgmtctx = arg;
	struct aie_errors *aie_errs;
	struct amdxdna_dev *xdna;
	int i;

	if (!mgmtctx) {
		pr_err("%s: mgmt hwctx is not initialized\n", __func__);
		return;
	}

	xdna = mgmtctx->xdna;
	/* Mark error callback as in progress */
	atomic_set(&mgmtctx->error_cb_in_progress, 1);
	reinit_completion(&mgmtctx->error_cb_completion);

	mutex_lock(&mgmtctx->ctx_lock);

	if (!mgmtctx->mgmt_aiedev) {
		XDNA_ERR(xdna, "%s: AIE partition is not loaded\n", __func__);
		mutex_unlock(&mgmtctx->ctx_lock);
		atomic_set(&mgmtctx->error_cb_in_progress, 0);
		complete(&mgmtctx->error_cb_completion);
		return;
	}
	aie_errs = aie_get_errors(mgmtctx->mgmt_aiedev);
	if (IS_ERR_OR_NULL(aie_errs)) {
		XDNA_ERR(xdna, "%s: aie_get_errors returns NULL\n", __func__);
		mutex_unlock(&mgmtctx->ctx_lock);
		atomic_set(&mgmtctx->error_cb_in_progress, 0);
		complete(&mgmtctx->error_cb_completion);
		return;
	}

	/* Cache the last async error FIRST, before logging, to ensure user space
	 * queries can find it immediately even if logging hasn't completed yet.
	 */
	if (aie_errs->num_err > 0) {
		struct amdxdna_async_error *record = &mgmtctx->async_errs_cache.err;
		struct aie_error *last_err = &aie_errs->errors[aie_errs->num_err - 1];
		enum amdxdna_error_num err_num;
		enum amdxdna_error_module err_mod;
		u64 err_code;
		u64 current_time_us = ktime_to_us(ktime_get_real());

		/* Convert category to amdxdna error number */
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

		/* Convert module to amdxdna error module */
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

		err_code = AMDXDNA_CRITICAL_ERROR_CODE_BUILD(err_num, err_mod);

		mutex_lock(&mgmtctx->async_errs_cache.lock);
		record->ts_us = current_time_us;
		record->err_code = err_code;
		record->ex_err_code = AMDXDNA_ERROR_EXTRA_CODE_BUILD(last_err->loc.row,
								     last_err->loc.col);
		mutex_unlock(&mgmtctx->async_errs_cache.lock);
	}

	/* Log error details after caching to ensure cache is available for queries */
	for (i = 0; i < aie_errs->num_err; i++) {
		XDNA_DBG(xdna, "Display AIE asynchronous Error data:\n");
		XDNA_DBG(xdna, "error_id %d Mod %d, category %d, Col %d, Row %d\n",
			 aie_errs->errors[i].error_id,
			 aie_errs->errors[i].module,
			 aie_errs->errors[i].category,
			 aie_errs->errors[i].loc.col,
			 aie_errs->errors[i].loc.row);
	}

	aie_free_errors(aie_errs);

	/* Dump HSA queue and handshake data for debugging */
	if (verbosity >= VERBOSITY_LEVEL_DBG)
		ve2_dump_debug_state(xdna, mgmtctx);

	/*
	 * Optional delay for devmem debugging - allows user to dump debug information.
	 * Set via: echo N > /sys/module/amdxdna/parameters/aie_error_delay_sec
	 * Release ctx_lock before sleeping to avoid blocking other threads.
	 */
	if (aie_error_delay_sec > 0) {
		XDNA_WARN(xdna, "*** WAITING %d SECONDS ***\n", aie_error_delay_sec);
		mutex_unlock(&mgmtctx->ctx_lock);
		ssleep(aie_error_delay_sec);
		mutex_lock(&mgmtctx->ctx_lock);
		XDNA_WARN(xdna, "*** WAIT COMPLETE, RESUMING ***\n");
	}

	/*
	 * Set misc_intrpt_flag and wake up waiting threads so they don't hang
	 * indefinitely when an AIE error occurs. This allows ve2_cmd_wait() to
	 * detect the error via check_read_index() and return with timeout status.
	 */
	if (mgmtctx->active_ctx && mgmtctx->active_ctx->priv) {
		mgmtctx->active_ctx->priv->misc_intrpt_flag = true;
		wake_up_interruptible_all(&mgmtctx->active_ctx->priv->waitq);
		XDNA_ERR(xdna, "AIE error detected, waking up waiting threads\n");
	}

	mutex_unlock(&mgmtctx->ctx_lock);

	/* Mark error callback as complete and signal waiting threads */
	atomic_set(&mgmtctx->error_cb_in_progress, 0);
	complete(&mgmtctx->error_cb_completion);
}

/*
 * ===========================================================================
 * DRM Scheduler Initialization (only used when use_drm_scheduler=1)
 * ===========================================================================
 */

/**
 * ve2_init_drm_scheduler - Initialize DRM GPU scheduler for a partition
 * @mgmtctx: Management context for the partition
 *
 * Sets up the DRM scheduler with temporal sharing (hw_jobs_limit=1).
 * Only ONE context runs at a time per partition.
 *
 * Return: 0 on success, negative error code on failure
 */
static int ve2_init_drm_scheduler(struct amdxdna_mgmtctx *mgmtctx)
{
	struct drm_gpu_scheduler *sched = &mgmtctx->sched;
	unsigned long timeout_ms = 2000;  /* 2 second timeout */
	int ret;

	XDNA_DBG(mgmtctx->xdna, "Initializing DRM scheduler for partition start_col=%u",
		 mgmtctx->start_col);

	/*
	 * Initialize DRM scheduler for this partition.
	 * hw_jobs_limit = 1 for temporal sharing (time-division multiplexing).
	 * Only ONE context runs at a time per partition. When a job completes,
	 * we context-switch to the next waiting context.
	 */
	ret = drm_sched_init(sched, &ve2_sched_ops,
			     NULL,					/* No parent workqueue */
			     DRM_SCHED_PRIORITY_COUNT,			/* num_rqs (priority count) */
			     1,						/* hw_jobs_limit: 1 for temporal sharing */
			     0,						/* hang_limit (0 = disabled) */
			     msecs_to_jiffies(timeout_ms),		/* timeout */
			     NULL,					/* timeout_wq */
			     NULL,					/* atomic_timeout_wq */
			     "ve2_mgmt",				/* name */
			     mgmtctx->xdna->ddev.dev);			/* dev */
	if (ret) {
		XDNA_ERR(mgmtctx->xdna, "Failed to init DRM scheduler: %d", ret);
		return ret;
	}

	return 0;
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
	int ret = 0;

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
		mutex_init(&mgmtctx->ctx_lock);
		mutex_init(&mgmtctx->async_errs_cache.lock);
		memset(&mgmtctx->async_errs_cache.err, 0, sizeof(mgmtctx->async_errs_cache.err));
		init_completion(&mgmtctx->error_cb_completion);
		atomic_set(&mgmtctx->error_cb_in_progress, 0);

		mgmtctx->is_partition_idle = 1;
		mgmtctx->is_context_req = 0;
		mgmtctx->is_idle_due_to_context = 0;
		mgmtctx->active_ctx = NULL;

		/* Initialize DRM scheduler */
		ret = ve2_init_drm_scheduler(mgmtctx);
		if (ret) {
			XDNA_ERR(xdna, "Failed to initialize DRM scheduler: %d", ret);
			aie_partition_release(mgmtctx->mgmt_aiedev);
			return ret;
		}

		/* Register AIE error call back function. */
		ret = aie_register_error_notification(nhwctx->aie_dev, ve2_aie_error_cb, mgmtctx);
		XDNA_DBG(xdna, "Registered AIE error call back function, ret : %d\n", ret);
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
		XDNA_ERR(xdna,
			 "hwctx %p is not the last scheduled. The last scheduled was %p.\n",
			 hwctx, mgmtctx->active_ctx);
		return -1;
	}

	XDNA_DBG(xdna, "Reading coredump for hwctx num_col:%d\n", nhwctx->num_col);
	rel_size = ve2_partition_coredump(aie_dev, size, buffer);
	if (rel_size < 0) {
		XDNA_ERR(xdna, "Failed to read coredump, err:%d\n", rel_size);
		return -EINVAL;
	}
	XDNA_DBG(xdna, "Reading coredump ret:%d\n", rel_size);

	return rel_size;
}

static int ve2_xrs_release(struct amdxdna_dev *xdna, struct amdxdna_ctx *hwctx,
			   struct xrs_action_load *load_act)
{
	return xrs_release_resource(xdna->dev_handle->xrs_hdl, (uintptr_t)hwctx, load_act);
}

static void cert_clear_partition(struct amdxdna_dev *xdna, struct amdxdna_ctx_priv *nhwctx)
{
	struct device *aie_dev = nhwctx->aie_dev;
	u32 num_col = nhwctx->num_col;
	int ret = 0;
	struct aie_op_handshake_data *hs_data;

	hs_data = ve2_prepare_hs_data(xdna, nhwctx, false);
	if (!hs_data) {
		XDNA_ERR(xdna, "No memory for hs_data\n");
		return;
	}

	ret = aie_partition_handshake_update(aie_dev, hs_data, num_col);
	if (ret < 0)
		XDNA_ERR(xdna, "aie partition handshake update failed, ret: %d\n", ret);
	ve2_free_hs_data(hs_data, num_col);
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
	struct solver_state *xrs = xdna->dev_handle->xrs_hdl;
	int ret;

	if (!nhwctx->aie_dev) {
		XDNA_ERR(xdna, "Partition does not have aie device handle");
		return -ENODEV;
	}

	mutex_lock(&xrs->xrs_lock);
	ret = ve2_xrs_release(xdna, hwctx, &load_act);
	if (ret) {
		XDNA_ERR(xdna, "XRS Release failed ret %d", ret);
		goto unlock_xrs_lock;
	}

	mgmtctx = &xdna->dev_handle->ve2_mgmtctx[start_col];
	if (load_act.release_aie_part) {
		cert_clear_partition(xdna, nhwctx);
		mutex_lock(&mgmtctx->ctx_lock);
		/* Update the active context as partition doesn't exists any more */
		mgmtctx->active_ctx = NULL;
		mutex_unlock(&mgmtctx->ctx_lock);

		/* Cleanup DRM scheduler */
		drm_sched_fini(&mgmtctx->sched);

		aie_unregister_error_notification(nhwctx->aie_dev);
		XDNA_DBG(xdna, "%s: Un-registered ve2_aie_error_cb() callback\n", __func__);
		aie_partition_teardown(nhwctx->aie_dev);
		aie_partition_release(nhwctx->aie_dev);
	} else {
		mutex_lock(&mgmtctx->ctx_lock);
		if (mgmtctx->active_ctx == hwctx)
			mgmtctx->active_ctx = NULL;
		mutex_unlock(&mgmtctx->ctx_lock);
	}

unlock_xrs_lock:
	mutex_unlock(&xrs->xrs_lock);
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
		XDNA_ERR(xdna, "Failed to write event_generate register, err=%d", ret);

	return ret;
}

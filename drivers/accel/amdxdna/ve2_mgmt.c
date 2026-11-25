// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2024-2026, Advanced Micro Devices, Inc.
 *
 * VE2 management backend — XRS resource request, AIE partition lifecycle,
 * and command scheduling through the VE2 AIE adapter.
 */

#include <linux/delay.h>
#include <linux/device.h>
#include <linux/errno.h>
#include <linux/ktime.h>
#include <linux/moduleparam.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/wait.h>
#include <linux/workqueue.h>

#include "amdxdna_ctx.h"
#include "amdxdna_pci_drv.h"
#include "amdxdna_solver.h"
#include "trace/events/amdxdna.h"
#include "ve2_aie.h"
#include "ve2_aux.h"
#include "ve2_hwctx.h"
#include "ve2_host_queue.h"
#include "ve2_mgmt.h"

/*
 * Debug aid: dump the HSA queue and firmware handshake state when an AIE
 * async error is reported. Off by default to avoid log spam; enable via
 * /sys/module/amdxdna/parameters/dbg_dump_on_error.
 */
static bool dbg_dump_on_error;
module_param(dbg_dump_on_error, bool, 0644);
MODULE_PARM_DESC(dbg_dump_on_error,
		 "Dump HSA queue + firmware handshake state on AIE error (default=0)");

/*
 * Debug aid: delay (in seconds) before waking waiting threads on an AIE
 * error, giving a chance to inspect device memory via devmem. Default 0.
 */
static int aie_error_delay_sec;
module_param(aie_error_delay_sec, int, 0644);
MODULE_PARM_DESC(aie_error_delay_sec,
		 "Delay in seconds on AIE error before waking threads (for devmem debug, default=0)");

static int ve2_create_mgmt_partition(struct amdxdna_dev *xdna, struct amdxdna_hwctx *hwctx,
				     bool create_aie_part);
static void ve2_irq_handler(u32 partition_id, void *priv);
static void ve2_aie_error_cb(void *arg);
static void ve2_dump_debug_state(struct amdxdna_dev *xdna, struct amdxdna_mgmtctx *mgmtctx);
static int ve2_request_context_switch(struct amdxdna_mgmtctx *mgmtctx);
static void ve2_sched_remove_ctx_jobs(struct ve2_scheduler *sched, struct amdxdna_hwctx *hwctx);
static void ve2_sched_timeout_pending_jobs(struct amdxdna_hwctx *hwctx);
static void ve2_sched_handshake_init_failed(struct ve2_scheduler *sched,
					    struct amdxdna_hwctx *hwctx, int ret);

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
	u64 dbg_addr = U64_MAX;

	if (col == 0 && vp && vp->hsa_queue.hsa_queue_dma_addr)
		hsa_addr = vp->hsa_queue.hsa_queue_dma_addr;
	if (col == 0 && enable_debug_queue && vp && vp->dbg_queue.dbg_queue_dma_addr)
		dbg_addr = vp->dbg_queue.dbg_queue_dma_addr;

	if (vp && vp->hwctx_config && col < hwctx->num_col)
		cfg = &vp->hwctx_config[col];

	cert_hs->partition_base_address = VE2_ADDR(mgmtctx->start_col, 0, 0);
	cert_hs->aie_info.partition_size = mgmtctx->num_col;
	cert_hs->hsa_addr_high = upper_32_bits(hsa_addr);
	cert_hs->hsa_addr_low = lower_32_bits(hsa_addr);
	if (enable_debug_queue) {
		cert_hs->dbg.hsa_addr_high = upper_32_bits(dbg_addr);
		cert_hs->dbg.hsa_addr_low = lower_32_bits(dbg_addr);
	} else {
		/* No debug HSA queue: mark the debug HSA address explicitly invalid. */
		cert_hs->dbg.hsa_addr_high = 0xFFFFFFFF;
		cert_hs->dbg.hsa_addr_low = 0xFFFFFFFF;
	}

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
		/* Restore the debug-buffer DDR write offset saved at the last switch-out. */
		cert_hs->save_dbg_buf_offset = cfg->dbg_buf_ddr_offset;
	}

	cert_hs->ctx_switch_req = 0;
	cert_hs->hsa_location = 0;
	cert_hs->mpaie_alive = ALIVE_MAGIC;

	XDNA_DBG(mgmtctx->xdna,
		 "DBG queue handshake: hwctx=%u col=%u enable=%u dbg_dma=0x%llx hs_dbg=0x%x%08x",
		 hwctx->id, col, enable_debug_queue,
		 vp ? (u64)vp->dbg_queue.dbg_queue_dma_addr : 0ULL,
		 cert_hs->dbg.hsa_addr_high, cert_hs->dbg.hsa_addr_low);
}

static void ve2_cert_update_host_time(struct amdxdna_mgmtctx *mgmtctx, u32 num_col)
{
	u64 host_time = ktime_get_ns();
	u32 hi = upper_32_bits(host_time);
	u32 lo = lower_32_bits(host_time);
	u32 col;

	for (col = 0; col < num_col; col++) {
		u32 addr = CERT_HANDSHAKE_OFF(col) +
			   offsetof(struct handshake, host_time_high);

		ve2_aie_priv_write(mgmtctx->aie_dev, addr, sizeof(hi), &hi);

		addr = CERT_HANDSHAKE_OFF(col) + offsetof(struct handshake, host_time_low);
		ve2_aie_priv_write(mgmtctx->aie_dev, addr, sizeof(lo), &lo);
	}
}

static void ve2_free_hs_data(struct ve2_aie_handshake *hs_data, u32 max_cols)
{
	/*
	 * The per-column cert_hs storage is either carved from the hwctx
	 * pre-allocated handshake buffer (freed in ve2_hwctx_fini) or allocated
	 * contiguously with the descriptor array in the fallback path. In both
	 * cases a single kfree() of the descriptor array is sufficient.
	 */
	kfree(hs_data);
}

static struct ve2_aie_handshake *
ve2_prepare_hs_data(struct amdxdna_mgmtctx *mgmtctx, struct amdxdna_hwctx *hwctx, bool init)
{
	struct amdxdna_ctx_priv *vp = ve2_hw_priv(hwctx);
	struct amdxdna_dev *xdna = mgmtctx->xdna;
	size_t col_size = sizeof(struct handshake);
	struct ve2_aie_handshake *hs_data;
	u32 num_col = mgmtctx->num_col;
	struct handshake *cert_hs;

	if (vp && vp->hs_buf_va) {
		/* Fast path: carve each cert_hs out of the pre-allocated buffer. */
		hs_data = kmalloc_array(num_col, sizeof(*hs_data), GFP_KERNEL);
		if (!hs_data) {
			XDNA_ERR(xdna, "No memory for handshake data allocation");
			return NULL;
		}

		for (u32 col = 0; col < num_col; col++) {
			cert_hs = (struct handshake *)((u8 *)vp->hs_buf_va + col * col_size);
			if (init) {
				memset(cert_hs, 0, col_size);
				cert_setup_partition(mgmtctx, hwctx, col, cert_hs);
			}
			hs_data[col].addr = cert_hs;
			/*
			 * hs_buf_va is DMA-coherent memory; hand the AIE driver
			 * the matching per-column dma_addr so it uses this
			 * buffer directly instead of doing its own per-column
			 * dmam_alloc_coherent().
			 */
			hs_data[col].dma_addr = vp->hs_buf_dma + col * col_size;
			hs_data[col].size = col_size;
			hs_data[col].offset = 0x0;
			hs_data[col].col = col;
			hs_data[col].row = 0;
		}
	} else {
		/* Fallback: single allocation for the descriptor array + cert_hs. */
		size_t total_size = num_col * sizeof(*hs_data) + num_col * col_size;

		hs_data = kzalloc(total_size, GFP_KERNEL);
		if (!hs_data) {
			XDNA_ERR(xdna, "No memory for handshake data allocation");
			return NULL;
		}

		cert_hs = (struct handshake *)(hs_data + num_col);
		for (u32 col = 0; col < num_col; col++) {
			if (init)
				cert_setup_partition(mgmtctx, hwctx, col, &cert_hs[col]);
			hs_data[col].addr = &cert_hs[col];
			hs_data[col].size = col_size;
			hs_data[col].offset = 0x0;
			hs_data[col].col = col;
			hs_data[col].row = 0;
		}
	}

	return hs_data;
}

/*
 * Effective partition width (columns) for a context. The @partition_size test
 * module parameter can widen the request: the partition uses the larger of the
 * user-requested @num_tiles and @partition_size (default 4).
 */
static u32 ve2_effective_num_col(u32 num_tiles)
{
	if (partition_size > 0 && (u32)partition_size > num_tiles)
		return (u32)partition_size;

	return num_tiles;
}

static int ve2_xrs_col_list(struct amdxdna_hwctx *hwctx, u32 total_col)
{
	struct amdxdna_dev *xdna = hwctx->client->xdna;
	u32 user_col = hwctx->qos.user_start_col;
	u32 num_col = hwctx->num_col;
	u32 first_col = 0;
	u32 entries = 0;
	u32 s, i;

	if (!num_col || num_col > total_col) {
		XDNA_ERR(xdna, "Invalid num_col %u (total_col %u)", num_col, total_col);
		return -EINVAL;
	}

	if (user_col != USER_START_COL_NOT_REQUESTED) {
		if (user_col + num_col > total_col) {
			XDNA_ERR(xdna, "user_start_col %u + num_col %u exceeds total_col %u",
				 user_col, num_col, total_col);
			return -ERANGE;
		}

		/*
		 * A pinned start column is a hard requirement, not merely a
		 * preferred starting point: the resource solver must place
		 * (or share) the partition at exactly this column, or fail.
		 * Offer only this single candidate so it can never end up
		 * silently placed/shared elsewhere.
		 */
		hwctx->col_list = kmalloc(sizeof(*hwctx->col_list), GFP_KERNEL);
		if (!hwctx->col_list)
			return -ENOMEM;

		hwctx->col_list_len = 1;
		hwctx->col_list[0] = user_col;

		print_hex_dump_debug("col_list: ", DUMP_PREFIX_OFFSET, 16, 4, hwctx->col_list,
				     sizeof(*hwctx->col_list), false);
		return 0;
	} else if (start_col > 0) {
		/*
		 * Test-only override: force the lead column to @start_col (and
		 * only offer candidate start columns from there onwards).
		 */
		if ((u32)start_col + num_col > total_col) {
			XDNA_ERR(xdna, "start_col %d + num_col %u exceeds total_col %u",
				 start_col, num_col, total_col);
			return -ERANGE;
		}
		first_col = (u32)start_col;
	}

	for (s = first_col; s + num_col <= total_col; s++)
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
	for (i = 0, s = first_col; i < entries; i++, s++)
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

	/*
	 * Determine the partition width (honouring the partition_size test
	 * override) before building the candidate start-column list, then let
	 * XRS place the partition.
	 */
	hwctx->num_col = ve2_effective_num_col(hwctx->num_tiles);

	ret = ve2_xrs_col_list(hwctx, hdl->aie_dev_info.cols);
	if (ret)
		return ret;

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

static int ve2_mgmt_handshake_init(struct amdxdna_mgmtctx *mgmtctx,
				   struct amdxdna_hwctx *hwctx)
{
	struct amdxdna_dev *xdna = mgmtctx->xdna;
	struct amdxdna_ctx_priv *vp = ve2_hw_priv(hwctx);
	struct ve2_aie_handshake *hs_data;
	enum ve2_aie_init_mode init_mode;
	u32 num_col = mgmtctx->num_col;
	int ret;

	if (!vp)
		return -EINVAL;

	/*
	 * When switching away from a different active context, save its
	 * firmware-updated debug-buffer DDR write offset (per column) so it can
	 * resume tracing at the correct position the next time it is scheduled.
	 */
	if (mgmtctx->active_ctx && mgmtctx->active_ctx != hwctx) {
		struct amdxdna_ctx_priv *avp = ve2_hw_priv(mgmtctx->active_ctx);

		if (avp && avp->hwctx_config) {
			u32 acol;

			for (acol = 0; acol < mgmtctx->active_ctx->num_col; acol++) {
				u32 off = 0;
				u32 addr = CERT_HANDSHAKE_OFF(acol) +
					   offsetof(struct handshake, save_dbg_buf_offset);

				if (ve2_aie_priv_read(mgmtctx->aie_dev, addr,
						      sizeof(off), &off) >= 0)
					avp->hwctx_config[acol].dbg_buf_ddr_offset = off;
			}
		}
	}

	hs_data = ve2_prepare_hs_data(mgmtctx, hwctx, true);
	if (!hs_data) {
		XDNA_ERR(xdna, "preparing cert handshake data failed");
		return -ENOMEM;
	}

	if (!ve2_perf_optimization)
		init_mode = VE2_AIE_INIT_RUNTIME;
	else
		init_mode = VE2_AIE_INIT_RUNTIME_PERF;

	trace_xdna_partition_init_start(hwctx->name, hwctx->id, mgmtctx->start_col, num_col);
	ret = ve2_aie_partition_initialize(mgmtctx->aie_dev, init_mode, hs_data, num_col);
	trace_xdna_partition_init_done(hwctx->name, hwctx->id, mgmtctx->start_col, num_col, ret);
	if (ret < 0) {
		XDNA_ERR(xdna, "aie partition init failed: %d", ret);
		goto release_hs_data;
	}

	/*
	 * Refresh host_time_high/low now that the (slow) partition init has
	 * completed, so CERT reads an up-to-date value as soon as it wakes up.
	 */
	ve2_cert_update_host_time(mgmtctx, num_col);

	/* Wake up the lead UC only */
	ret = ve2_aie_partition_wake_lead_uc(mgmtctx->aie_dev);
	if (ret)
		goto release_hs_data;

	vp->handshake_initialized = true;
	/*
	 * The partition has been re-initialized and CERT restarted for this
	 * context, so a previously latched MISC/exception condition no longer
	 * describes the hardware. A poisoned context will not normally reach
	 * here: ve2_cmd_submit() rejects with -ENOTRECOVERABLE first.
	 */
	if (vp->misc_intrpt_flag) {
		XDNA_DBG(xdna, "Clearing misc_intrpt_flag after partition re-init hwctx=%p",
			 hwctx);
		vp->misc_intrpt_flag = false;
		vp->misc_status_latched = 0;
	}
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

	return 0;
}

static void ve2_clear_context_switch_req(struct amdxdna_mgmtctx *mgmtctx)
{
	u32 val = 0;

	ve2_partition_write_privileged_mem(mgmtctx, offsetof(struct handshake, ctx_switch_req),
					   sizeof(val), &val);
}

/* ================================================================
 * DRM-Inspired Scheduler Implementation
 * ================================================================*/

/* CERT Status - comprehensive read */
struct cert_status {
	u32 cert_idle_status;   /* Bits: CERT_IS_IDLE(4), HSA_QUEUE_NOT_EMPTY(1) */
	u32 completion_status;  /* Bits: COMPLETION_STATUS_DONE(1) */
	bool is_idle;           /* CERT sleeping, queue empty */
	bool queue_not_empty;   /* CERT processing or queue has work */
	bool completion_done;   /* Command completion available */
};

static void ve2_read_cert_status(struct amdxdna_mgmtctx *mgmtctx, struct cert_status *status)
{
	memset(status, 0, sizeof(*status));

	/* Read cert_idle_status field */
	ve2_partition_read_privileged_mem(mgmtctx,
					  offsetof(struct handshake, cert_idle_status),
					  sizeof(status->cert_idle_status),
					  &status->cert_idle_status);

	/* Read completion_status field */
	ve2_partition_read_privileged_mem(mgmtctx,
					  offsetof(struct handshake, completion_status),
					  sizeof(status->completion_status),
					  &status->completion_status);

	/* Decode status bits */
	status->is_idle = (status->cert_idle_status & CERT_IS_IDLE) != 0;
	status->queue_not_empty = (status->cert_idle_status & HSA_QUEUE_NOT_EMPTY) != 0;
	status->completion_done = (status->completion_status & COMPLETION_STATUS_DONE) != 0;
}

/* Caller holds ctx_lock; publish before ringing the doorbell so a racing IRQ sees it. */
static void ve2_sched_publish_active_ctx(struct ve2_scheduler *sched, struct amdxdna_hwctx *hwctx)
{
	struct amdxdna_mgmtctx *mgmtctx = sched->mgmtctx;

	mgmtctx->active_ctx = hwctx;
	sched->ctx_switch_requested = false;
	notify_fw_cmd_ready(mgmtctx);
}

/*
 * Takes hwctx, not the ve2_job: the job is only ever looked at under
 * job_lock (ve2_sched_work_drm() snapshots job->hwctx before releasing it),
 * since ve2_sched_reap_confirmed() can free it concurrently from IRQ context.
 */
static void ve2_sched_start_context(struct ve2_scheduler *sched, struct amdxdna_hwctx *hwctx)
{
	struct amdxdna_mgmtctx *mgmtctx = sched->mgmtctx;
	int ret;

	/* Lock ctx_lock to prevent race with concurrent doorbell/reprogram */
	mutex_lock(&mgmtctx->ctx_lock);

	/* Program handshake for this context
	 * Note: First time on partition, handshake uninitialized - no idle check needed.
	 * CERT is waiting for handshake init before it can report status.
	 */
	ret = ve2_mgmt_handshake_init(mgmtctx, hwctx);
	if (ret)
		goto fail;

	ve2_sched_publish_active_ctx(sched, hwctx);

	mutex_unlock(&mgmtctx->ctx_lock);
	return;

fail:
	mutex_unlock(&mgmtctx->ctx_lock);
	ve2_sched_handshake_init_failed(sched, hwctx, ret);
}

/* See ve2_sched_start_context(): takes hwctx, not the ve2_job, for the same reason. */
static bool ve2_sched_switch_context(struct ve2_scheduler *sched, struct amdxdna_hwctx *hwctx)
{
	struct amdxdna_mgmtctx *mgmtctx = sched->mgmtctx;
	int ret;

	/* Lock ctx_lock to prevent race with concurrent doorbell/reprogram */
	mutex_lock(&mgmtctx->ctx_lock);

	/*
	 * Verify CERT has actually halted before reprogramming handshake. Per
	 * CERT's CTX_SWITCH_PENDING branch, it halts unconditionally once it
	 * honors ctx_switch_req and reports either IDLE_STATUS or
	 * QUEUE_NOT_EMPTY_STATUS depending on whether its own queue still had
	 * leftover work - both mean it is safe (and necessary) to reprogram now.
	 */
	{
		struct cert_status status;

		ve2_read_cert_status(mgmtctx, &status);
		if (!status.is_idle && !status.queue_not_empty) {
			mutex_unlock(&mgmtctx->ctx_lock);
			/* Leave job in queue, will retry when CERT halts */
			return false;
		}
	}

	/* Reprogram handshake for new context - safe, CERT confirmed idle */
	ret = ve2_mgmt_handshake_init(mgmtctx, hwctx);
	if (ret)
		goto fail;

	ve2_clear_context_switch_req(mgmtctx);

	ve2_sched_publish_active_ctx(sched, hwctx);

	mutex_unlock(&mgmtctx->ctx_lock);

	atomic64_inc(&sched->total_switches);

	return true;

fail:
	mutex_unlock(&mgmtctx->ctx_lock);
	ve2_sched_handshake_init_failed(sched, hwctx, ret);

	return false;
}

static bool ve2_check_misc_interrupt(struct amdxdna_mgmtctx *mgmtctx)
{
	u32 off = CERT_HANDSHAKE_OFF(0) + offsetof(struct handshake, misc_status);
	u32 misc_status = 0;
	struct amdxdna_ctx_priv *vp;
	int ret;

	/* ve2_aie_error_cb() can latch this without the register ever being set. */
	vp = mgmtctx->active_ctx ? ve2_hw_priv(mgmtctx->active_ctx) : NULL;
	if (vp && vp->misc_intrpt_flag)
		return true;

	ret = ve2_aie_priv_read(mgmtctx->aie_dev, off, sizeof(misc_status), &misc_status);
	if (ret < 0 || !misc_status)
		return false;

	/* Stale level bit with no context to attribute it to; don't block scheduling. */
	if (!vp)
		return false;

	vp->misc_status_latched = misc_status;
	vp->misc_intrpt_flag = true;
	XDNA_ERR(mgmtctx->xdna,
		 "misc_status 0x%x on col %u: marking hwctx %u (pid %d) unusable",
		 misc_status, mgmtctx->start_col, mgmtctx->active_ctx->id,
		 mgmtctx->active_ctx->client->pid);

	return true;
}

static void ve2_sched_timeout_pending_jobs(struct amdxdna_hwctx *hwctx)
{
	struct amdxdna_ctx_priv *vp;
	int i;

	if (!hwctx)
		return;

	vp = ve2_hw_priv(hwctx);
	if (!vp)
		return;

	mutex_lock(&vp->privctx_lock);
	for (i = 0; i < HWCTX_MAX_CMDS; i++) {
		struct amdxdna_sched_job *job = vp->pending[i];

		if (!job)
			continue;
		XDNA_ERR(hwctx->client->xdna, "marking pending job seq=%llu TIMEOUT", job->seq);
		amdxdna_cmd_set_state(job->cmd_bo, ERT_CMD_STATE_TIMEOUT);
	}
	mutex_unlock(&vp->privctx_lock);
}

/* handshake init failed for @hwctx; poison it like an AIE fault would. */
static void ve2_sched_handshake_init_failed(struct ve2_scheduler *sched,
					    struct amdxdna_hwctx *hwctx, int ret)
{
	struct amdxdna_ctx_priv *vp = ve2_hw_priv(hwctx);

	XDNA_ERR(hwctx->client->xdna, "handshake init failed for hwctx %u (pid %d): %d",
		 hwctx->id, hwctx->client->pid, ret);

	if (!vp)
		return;

	vp->misc_intrpt_flag = true;
	wake_up_interruptible_all(&vp->waitq);
	ve2_hwctx_fail_pending_jobs(hwctx);
	ve2_sched_remove_ctx_jobs(sched, hwctx);

	/* Other contexts may be queued behind the one that just failed; nothing
	 * else will prompt the scheduler to look at them.
	 */
	queue_work(sched->wq, &sched->sched_work);
}

/*
 * Pop jobs for @active_ctx confirmed dispatched by @read_index (mirrors
 * pop_from_ctx_command_fifo_till() pre-rewrite). Returns true if the new
 * head belongs to a different context (a switch decision may be needed).
 */
static bool ve2_sched_reap_confirmed(struct ve2_scheduler *sched,
				     struct amdxdna_hwctx *active_ctx, u64 read_index)
{
	struct ve2_job *job, *tmp;
	unsigned long flags;
	bool boundary;

	spin_lock_irqsave(&sched->job_lock, flags);
	list_for_each_entry_safe(job, tmp, &sched->job_queue, list) {
		if (job->hwctx != active_ctx || job->seq > read_index)
			break;
		list_del(&job->list);
		kfree(job);
		atomic64_inc(&sched->total_jobs);
	}

	job = list_first_entry_or_null(&sched->job_queue, struct ve2_job, list);
	boundary = job && job->hwctx != active_ctx;
	spin_unlock_irqrestore(&sched->job_lock, flags);

	return boundary;
}

/*
 * A command's HSA packet goes live before its ve2_job is inserted, so CERT
 * can complete it before ve2_sched_reap_confirmed() ever sees it queued -
 * and if that context gets no further IRQ, nothing reaps it. Check the head
 * against its own context's read index here too, discarding already-done
 * entries, so a later context's job can't be stranded behind one.
 *
 * Returns the hwctx of the first genuinely pending head job, or NULL.
 */
static struct amdxdna_hwctx *ve2_sched_reconcile_head(struct ve2_scheduler *sched)
{
	for (;;) {
		struct amdxdna_hwctx *hwctx;
		unsigned long flags;
		struct ve2_job *job;
		u64 read_index, seq;

		spin_lock_irqsave(&sched->job_lock, flags);
		job = list_first_entry_or_null(&sched->job_queue, struct ve2_job, list);
		if (job) {
			hwctx = job->hwctx;
			seq = job->seq;
		}
		spin_unlock_irqrestore(&sched->job_lock, flags);

		if (!job)
			return NULL;

		if (get_ctx_read_index(hwctx, &read_index) || seq > read_index)
			return hwctx;

		spin_lock_irqsave(&sched->job_lock, flags);
		job = list_first_entry_or_null(&sched->job_queue, struct ve2_job, list);
		if (job && job->hwctx == hwctx && job->seq == seq) {
			list_del(&job->list);
			kfree(job);
			atomic64_inc(&sched->total_jobs);
		} else {
			job = NULL;
		}
		spin_unlock_irqrestore(&sched->job_lock, flags);

		/*
		 * CERT can complete a command before ve2_hwctx_add_job() ever
		 * runs (the HSA packet goes live first), so the IRQ that
		 * confirmed it found nothing in vp->pending[] yet and skipped
		 * queuing the completion worker. Nudge it now that the job
		 * is visible there, or a poll-only client could wait forever.
		 */
		if (job)
			ve2_hwctx_queue_completion(hwctx);
	}
}

static void ve2_sched_work_drm(struct work_struct *work)
{
	struct ve2_scheduler *sched = container_of(work, struct ve2_scheduler, sched_work);
	struct amdxdna_mgmtctx *mgmtctx = sched->mgmtctx;
	struct cert_status cert_status;
	struct amdxdna_hwctx *hwctx;

	/* Serialize against ve2_mgmt_destroy_partition() clearing active_ctx. */
	mutex_lock(&mgmtctx->ctx_lock);
	if (ve2_check_misc_interrupt(mgmtctx)) {
		ve2_sched_timeout_pending_jobs(mgmtctx->active_ctx);
		mutex_unlock(&mgmtctx->ctx_lock);
		return;
	}
	mutex_unlock(&mgmtctx->ctx_lock);

	hwctx = ve2_sched_reconcile_head(sched);
	if (!hwctx)
		return;

	if (!mgmtctx->active_ctx && !mgmtctx->wedged) {
		/* Case 1: IDLE → RUNNING (first context on this partition)
		 * On first use, handshake is uninitialized - program it now.
		 * No CERT idle check needed: CERT is waiting for handshake init.
		 */
		ve2_sched_start_context(sched, hwctx);
		return;
	}

	/*
	 * Wedged: active_ctx is NULL but CERT never confirmed yielding the
	 * context that used to be active, so the fast path above is not safe.
	 * Case 3 below handles it instead - it works with active_ctx == NULL
	 * too, and only reprograms once CERT itself reports idle/queue_not_empty.
	 */

	if (mgmtctx->active_ctx == hwctx && !sched->ctx_switch_requested) {
		/* Case 2: Same context - just wake CERT (handshake already programmed)
		 * Excluded while a switch is pending: CERT is waiting on the switch
		 * ack, not a plain doorbell.
		 */
		mutex_lock(&mgmtctx->ctx_lock);
		notify_fw_cmd_ready(mgmtctx);
		mutex_unlock(&mgmtctx->ctx_lock);
		return;
	}

	/* Case 3: Different context - need switch
	 * Use cooperative scheduling: let CERT finish current work before switching.
	 */
	if (sched->ctx_switch_requested) {
		/*
		 * CERT honors ctx_switch_req by halting unconditionally and
		 * reporting either IDLE_STATUS or QUEUE_NOT_EMPTY_STATUS
		 * depending on whether its own queue still had leftover
		 * work - both mean it is safe (and necessary) to reprogram
		 * now; it will not come back on its own.
		 */
		ve2_read_cert_status(mgmtctx, &cert_status);
		if (cert_status.is_idle || cert_status.queue_not_empty)
			ve2_sched_switch_context(sched, hwctx);
		return;
	}

	/* First job from different context - request switch, don't preempt */
	mutex_lock(&mgmtctx->ctx_lock);
	ve2_request_context_switch(mgmtctx);
	/*
	 * Set the flag before ringing the doorbell, both under
	 * ctx_lock: the IRQ handler takes ctx_lock and checks
	 * this flag to decide whether to re-arm the scheduler,
	 * so an IRQ landing right after the doorbell must see
	 * it already true, or the wakeup is lost until the
	 * next submit or IRQ.
	 */
	sched->ctx_switch_requested = true;
	notify_fw_cmd_ready(mgmtctx);
	mutex_unlock(&mgmtctx->ctx_lock);
	/* Leave job in queue - will switch when CERT halts */
}

/* Scheduler initialization and cleanup */
static int ve2_scheduler_init(struct amdxdna_mgmtctx *mgmtctx)
{
	struct ve2_scheduler *sched = &mgmtctx->scheduler;
	char wq_name[32];

	INIT_LIST_HEAD(&sched->job_queue);
	spin_lock_init(&sched->job_lock);

	sched->ctx_switch_requested = false;
	sched->mgmtctx = mgmtctx;

	atomic64_set(&sched->total_jobs, 0);
	atomic64_set(&sched->total_switches, 0);

	/* Ordered: one workqueue per partition, jobs run in submission order. */
	snprintf(wq_name, sizeof(wq_name), "ve2_sched_%u", mgmtctx->start_col);
	sched->wq = alloc_ordered_workqueue(wq_name, WQ_MEM_RECLAIM);
	if (!sched->wq) {
		XDNA_ERR(mgmtctx->xdna, "Failed to create scheduler workqueue (col=%u)",
			 mgmtctx->start_col);
		return -ENOMEM;
	}

	INIT_WORK(&sched->sched_work, ve2_sched_work_drm);

	return 0;
}

static void ve2_scheduler_fini(struct amdxdna_mgmtctx *mgmtctx)
{
	struct ve2_scheduler *sched = &mgmtctx->scheduler;
	struct ve2_job *job, *tmp;
	unsigned long flags;

	if (!sched->wq)
		return;

	cancel_work_sync(&sched->sched_work);
	destroy_workqueue(sched->wq);
	sched->wq = NULL;

	spin_lock_irqsave(&sched->job_lock, flags);
	list_for_each_entry_safe(job, tmp, &sched->job_queue, list) {
		list_del(&job->list);
		kfree(job);
	}
	spin_unlock_irqrestore(&sched->job_lock, flags);
}

/*
 * Remove any jobs still queued for @hwctx (or every job, if @hwctx is NULL)
 * before it is freed by the caller, so ve2_sched_work_drm() can never later
 * dereference a dangling job->hwctx.
 */
static void ve2_sched_remove_ctx_jobs(struct ve2_scheduler *sched, struct amdxdna_hwctx *hwctx)
{
	struct ve2_job *job, *tmp;
	unsigned long flags;

	spin_lock_irqsave(&sched->job_lock, flags);
	list_for_each_entry_safe(job, tmp, &sched->job_queue, list) {
		if (!hwctx || job->hwctx == hwctx) {
			list_del(&job->list);
			kfree(job);
		}
	}
	spin_unlock_irqrestore(&sched->job_lock, flags);
}

struct ve2_sched_remove_ctx_jobs_work {
	struct work_struct	work;
	struct ve2_scheduler	*sched;
	struct amdxdna_hwctx	*hwctx;
};

static void ve2_sched_remove_ctx_jobs_fn(struct work_struct *work)
{
	struct ve2_sched_remove_ctx_jobs_work *rw =
		container_of(work, struct ve2_sched_remove_ctx_jobs_work, work);

	ve2_sched_remove_ctx_jobs(rw->sched, rw->hwctx);
}

/* Run on sched->wq so this can't race ve2_sched_work_drm()'s use of job_queue. */
static void ve2_sched_remove_ctx_jobs_sync(struct ve2_scheduler *sched,
					   struct amdxdna_hwctx *hwctx)
{
	struct ve2_sched_remove_ctx_jobs_work rw;

	if (!sched->wq) {
		ve2_sched_remove_ctx_jobs(sched, hwctx);
		return;
	}

	INIT_WORK_ONSTACK(&rw.work, ve2_sched_remove_ctx_jobs_fn);
	rw.sched = sched;
	rw.hwctx = hwctx;
	queue_work(sched->wq, &rw.work);
	flush_work(&rw.work);
	destroy_work_on_stack(&rw.work);
}

int ve2_mgmt_schedule_cmd(struct amdxdna_dev *xdna, struct amdxdna_hwctx *hwctx,
			  u64 command_index)
{
	struct amdxdna_ctx_priv *vp = ve2_hw_priv(hwctx);
	struct amdxdna_mgmtctx *mgmtctx;
	struct ve2_scheduler *sched;
	struct ve2_job *job;
	unsigned long flags;

	if (!vp || !vp->mgmtctx)
		return -EINVAL;

	mgmtctx = vp->mgmtctx;

	trace_xdna_mgmt_schedule_cmd_start(hwctx->name, hwctx->id, mgmtctx->start_col,
					   command_index);

	sched = &mgmtctx->scheduler;

	/*
	 * Create job and enqueue for scheduler.
	 * Scheduler will reprogram handshake (if needed), then wake CERT.
	 * DO NOT ring doorbell here - scheduler does it AFTER reprogramming!
	 */
	job = kzalloc(sizeof(*job), GFP_KERNEL);
	if (!job) {
		trace_xdna_mgmt_schedule_cmd_done(hwctx->name, hwctx->id,
						  mgmtctx->start_col, command_index, -ENOMEM);
		return -ENOMEM;
	}

	job->hwctx = hwctx;
	job->seq = command_index;

	spin_lock_irqsave(&sched->job_lock, flags);
	list_add_tail(&job->list, &sched->job_queue);
	spin_unlock_irqrestore(&sched->job_lock, flags);

	queue_work(sched->wq, &sched->sched_work);

	trace_xdna_mgmt_schedule_cmd_done(hwctx->name, hwctx->id, mgmtctx->start_col,
					  command_index, 0);
	return 0;
}

static void ve2_irq_handler(u32 partition_id, void *priv)
{
	struct amdxdna_mgmtctx *mgmtctx = priv;
	struct amdxdna_hwctx *active_ctx;
	struct amdxdna_ctx_priv *vp;
	u64 write_index = 0;
	u64 read_index;
	struct ve2_scheduler *sched = &mgmtctx->scheduler;
	struct cert_status cert_status;
	bool misc_fault;
	bool boundary;

	guard(mutex)(&mgmtctx->ctx_lock);
	active_ctx = mgmtctx->active_ctx;

	if (!active_ctx)
		return;

	trace_xdna_irq_enter(active_ctx->name, mgmtctx->partition_id, active_ctx->id);

	/* Read comprehensive CERT status */
	ve2_read_cert_status(mgmtctx, &cert_status);

	if (get_ctx_read_index(active_ctx, &read_index)) {
		XDNA_ERR(mgmtctx->xdna, "IRQ: failed to get read index");
		return;
	}

	boundary = ve2_sched_reap_confirmed(sched, active_ctx, read_index);

	/* Latch before waking waiters: check_read_index() tests misc_intrpt_flag. */
	misc_fault = ve2_check_misc_interrupt(mgmtctx);

	/* Wake waiters for completed commands */
	vp = ve2_hw_priv(active_ctx);
	if (vp)
		wake_up_interruptible_all(&vp->waitq);

	ve2_hwctx_queue_completion(active_ctx);

	get_ctx_write_index(active_ctx, &write_index);
	trace_xdna_irq_exit(active_ctx->name, mgmtctx->partition_id, active_ctx->id,
			    read_index, write_index);

	/*
	 * Determine WHY CERT interrupted us and set appropriate flags.
	 *
	 * CERT's CTX_SWITCH_PENDING branch (cert/hsa/xrt_handler.c) halts
	 * unconditionally once it honors ctx_switch_req, regardless of whether
	 * its own queue was empty: it reports QUEUE_NOT_EMPTY_STATUS instead of
	 * IDLE_STATUS when it had leftover work, then disables its own wake
	 * interrupt and sleeps waiting for the driver to reprogram and reset it.
	 * Either status value means "safe to switch now" when a switch is
	 * pending, so both must re-arm the scheduler here.
	 */
	if (misc_fault) {
		queue_work(sched->wq, &sched->sched_work);
	} else if (boundary) {
		/* Reaping confirmed jobs surfaced a different-context head job */
		queue_work(sched->wq, &sched->sched_work);
	} else if (sched->ctx_switch_requested && (cert_status.is_idle || cert_status.queue_not_empty)) {
		/* CERT responded to our context switch request */
		queue_work(sched->wq, &sched->sched_work);
	}
	/* Otherwise CERT either just completed a command (still active, no
	 * scheduler trigger needed) or went idle with no switch requested (it
	 * just finished work; the scheduler will be triggered by the next
	 * command submission).
	 */
}

/**
 * ve2_dump_debug_state - Dump HSA queue state and handshake data for debugging
 * @xdna: Pointer to the AMD XDNA device structure
 * @mgmtctx: Pointer to the management context
 *
 * Dumps critical debug information (HSA queue indices, per-slot completion and
 * packet details, and the firmware handshake region) for the currently active
 * context. Intended to be called from the AIE error path when enabled via the
 * dbg_dump_on_error module parameter. Must be called with mgmtctx->ctx_lock held.
 */
static void ve2_dump_debug_state(struct amdxdna_dev *xdna, struct amdxdna_mgmtctx *mgmtctx)
{
	struct amdxdna_hwctx *hwctx = mgmtctx->active_ctx;
	struct amdxdna_ctx_priv *priv;
	struct ve2_hsa_queue *hq;
	struct hsa_queue *queue;
	struct handshake *hs;
	int i, ret;

	priv = ve2_hw_priv(hwctx);
	if (!hwctx || !priv) {
		XDNA_WARN(xdna, "=== DEBUG DUMP: No active context ===\n");
		return;
	}

	hq = &priv->hsa_queue;
	queue = hq->hsa_queue_p;
	if (!queue) {
		XDNA_WARN(xdna, "=== DEBUG DUMP: No HSA queue allocated ===\n");
		return;
	}

	XDNA_WARN(xdna, "=== VE2 DEBUG DUMP START (hwctx=%p) ===\n", hwctx);

	mutex_lock(&hq->hq_lock);

	/* read_index is written by the device; sync before reading. */
	hsa_queue_sync_read_index_for_read(hq);

	XDNA_WARN(xdna, "HSA Queue Header:\n");
	XDNA_WARN(xdna, "  read_index:     %llu\n", queue->hq_header.read_index);
	XDNA_WARN(xdna, "  write_index:    %llu\n", queue->hq_header.write_index);
	XDNA_WARN(xdna, "  reserved_write: %llu\n", hq->reserved_write_index);
	XDNA_WARN(xdna, "  capacity:       %u\n", queue->hq_header.capacity);
	XDNA_WARN(xdna, "  data_address:   0x%llx\n", queue->hq_header.data_address);
	XDNA_WARN(xdna, "  dma_addr:       0x%llx\n", (u64)hq->hsa_queue_dma_addr);
	XDNA_WARN(xdna, "  pending_cmds:   %llu\n",
		  queue->hq_header.write_index - queue->hq_header.read_index);

	XDNA_WARN(xdna, "HSA Queue Completion Status:\n");
	for (i = 0; i < HOST_QUEUE_ENTRY; i++) {
		u64 completion;

		hsa_queue_sync_completion_for_read(hq, i);
		completion = hq->hq_complete.hqc_mem[i];
		if (completion != 0)
			XDNA_WARN(xdna, "  slot[%2d]: state=%llu\n", i, completion);
	}

	XDNA_WARN(xdna, "HSA Queue Packet Details:\n");
	for (i = 0; i < HOST_QUEUE_ENTRY; i++) {
		struct host_queue_packet *pkt = &queue->hq_entry[i];
		u64 completion = hq->hq_complete.hqc_mem[i];
		u64 expected_signal = hq->hq_complete.hqc_dma_addr + i * sizeof(u64);

		if (pkt->xrt_header.common_header.type == HOST_QUEUE_PACKET_TYPE_INVALID &&
		    completion == 0)
			continue;

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

		if (pkt->xrt_header.common_header.type == HOST_QUEUE_PACKET_TYPE_INVALID)
			continue;

		if (pkt->xrt_header.completion_signal != expected_signal)
			XDNA_WARN(xdna, "  *** SIGNAL MISMATCH! Possible packet corruption ***\n");
		if (pkt->xrt_header.common_header.opcode != HOST_QUEUE_PACKET_EXEC_BUF)
			XDNA_WARN(xdna, "  *** INVALID OPCODE %u! Expected %u ***\n",
				  pkt->xrt_header.common_header.opcode, HOST_QUEUE_PACKET_EXEC_BUF);

		if (!pkt->xrt_header.common_header.indirect) {
			struct exec_buf *ebp = (struct exec_buf *)pkt->data;
			u64 instr_addr = ((u64)ebp->dpu_control_code_host_addr_high << 32) |
					 ebp->dpu_control_code_host_addr_low;
			u64 dtrace_addr = ((u64)ebp->dtrace_buf_host_addr_high << 32) |
					  ebp->dtrace_buf_host_addr_low;

			XDNA_WARN(xdna, "           instr_addr=0x%llx dtrace=0x%llx args_len=%u\n",
				  instr_addr, dtrace_addr, ebp->args_len);
			if (!instr_addr)
				XDNA_WARN(xdna, "  *** ZERO INSTR ADDR! Possible corruption ***\n");
		}
	}

	mutex_unlock(&hq->hq_lock);

	hs = kzalloc_obj(*hs);
	if (!hs) {
		XDNA_WARN(xdna, "No memory for handshake; skipping handshake/VM dump\n");
		return;
	}

	ret = ve2_partition_read_privileged_mem(mgmtctx, 0, sizeof(*hs), hs);
	if (ret < 0) {
		XDNA_WARN(xdna, "Failed to read firmware handshake (ret=%d); skipping dump\n", ret);
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

	XDNA_WARN(xdna, "Firmware VM State:\n");
	XDNA_WARN(xdna, "  fw_state:           0x%x\n", hs->vm.fw_state);
	XDNA_WARN(xdna, "  abs_page_index:     0x%x\n", hs->vm.abs_page_index);
	XDNA_WARN(xdna, "  ppc:                0x%x\n", hs->vm.ppc);

	if (hs->exception.ear || hs->exception.esr || hs->exception.pc) {
		XDNA_WARN(xdna, "Firmware Exception:\n");
		XDNA_WARN(xdna, "  EAR (addr):         0x%x\n", hs->exception.ear);
		XDNA_WARN(xdna, "  ESR (status):       0x%x\n", hs->exception.esr);
		XDNA_WARN(xdna, "  PC:                 0x%x\n", hs->exception.pc);
	}

	XDNA_WARN(xdna, "Firmware Counters:\n");
	XDNA_WARN(xdna, "  c_job_launched:     %u\n", hs->counter.c_job_launched);
	XDNA_WARN(xdna, "  c_job_finished:     %u\n", hs->counter.c_job_finished);
	XDNA_WARN(xdna, "  c_hsa_pkt:          %u\n", hs->counter.c_hsa_pkt);
	XDNA_WARN(xdna, "  c_opcode:           %u\n", hs->counter.c_opcode);
	XDNA_WARN(xdna, "  c_doorbell:         %u\n", hs->counter.c_doorbell);
	XDNA_WARN(xdna, "  c_page:             %u\n", hs->counter.c_page);

	XDNA_WARN(xdna, "Last DMA Addresses:\n");
	XDNA_WARN(xdna, "  dm2mm:              0x%x%08x\n",
		  hs->last_ddr_dm2mm_addr_high, hs->last_ddr_dm2mm_addr_low);
	XDNA_WARN(xdna, "  mm2dm:              0x%x%08x\n",
		  hs->last_ddr_mm2dm_addr_high, hs->last_ddr_mm2dm_addr_low);

	XDNA_WARN(xdna, "Context Save State:\n");
	XDNA_WARN(xdna, "  restore_page_idx:   %u\n",
		  hs->ctx_save.contents.restore_page.page_index);
	XDNA_WARN(xdna, "  cmd_chain_failure:  %u\n",
		  hs->ctx_save.contents.restore_page.cmd_chain_failure);

	XDNA_WARN(xdna, "=== VE2 DEBUG DUMP END ===\n");
	kfree(hs);
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
	struct ve2_aie_errors *aie_errs;
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

	aie_errs = ve2_aie_get_errors(mgmtctx->aie_dev);
	if (IS_ERR(aie_errs)) {
		XDNA_ERR(xdna, "%s: failed to get AIE errors: %ld\n",
			 __func__, PTR_ERR(aie_errs));
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
		struct ve2_aie_error *last_err = &aie_errs->errors[aie_errs->num_err - 1];
		enum amdxdna_error_num err_num;
		enum amdxdna_error_module err_mod;

		switch (last_err->category) {
		case VE2_AIE_ERROR_SATURATION:
			err_num = AMDXDNA_ERROR_NUM_AIE_SATURATION;
			break;
		case VE2_AIE_ERROR_FP:
			err_num = AMDXDNA_ERROR_NUM_AIE_FP;
			break;
		case VE2_AIE_ERROR_STREAM:
			err_num = AMDXDNA_ERROR_NUM_AIE_STREAM;
			break;
		case VE2_AIE_ERROR_ACCESS:
			err_num = AMDXDNA_ERROR_NUM_AIE_ACCESS;
			break;
		case VE2_AIE_ERROR_BUS:
			err_num = AMDXDNA_ERROR_NUM_AIE_BUS;
			break;
		case VE2_AIE_ERROR_INSTRUCTION:
			err_num = AMDXDNA_ERROR_NUM_AIE_INSTRUCTION;
			break;
		case VE2_AIE_ERROR_ECC:
			err_num = AMDXDNA_ERROR_NUM_AIE_ECC;
			break;
		case VE2_AIE_ERROR_LOCK:
			err_num = AMDXDNA_ERROR_NUM_AIE_LOCK;
			break;
		case VE2_AIE_ERROR_DMA:
			err_num = AMDXDNA_ERROR_NUM_AIE_DMA;
			break;
		case VE2_AIE_ERROR_MEM_PARITY:
			err_num = AMDXDNA_ERROR_NUM_AIE_MEM_PARITY;
			break;
		default:
			err_num = AMDXDNA_ERROR_NUM_UNKNOWN;
			break;
		}

		switch (last_err->module) {
		case VE2_AIE_ERROR_MODULE_MEMORY:
			err_mod = AMDXDNA_ERROR_MODULE_AIE_MEMORY;
			break;
		case VE2_AIE_ERROR_MODULE_CORE:
			err_mod = AMDXDNA_ERROR_MODULE_AIE_CORE;
			break;
		case VE2_AIE_ERROR_MODULE_PL:
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
		cache->err.ex_err_code = AMDXDNA_EXTRA_ERR_ENCODE(last_err->row,
								  last_err->col);
		mutex_unlock(&cache->lock);
	}

	for (i = 0; i < aie_errs->num_err; i++) {
		XDNA_DBG(xdna,
			 "AIE async error: id %d mod %d category %d col %d row %d\n",
			 aie_errs->errors[i].error_id,
			 aie_errs->errors[i].module,
			 aie_errs->errors[i].category,
			 aie_errs->errors[i].col,
			 aie_errs->errors[i].row);
	}

	ve2_aie_free_errors(aie_errs);

	/* Optional deep dump of HSA queue + firmware handshake state. */
	if (dbg_dump_on_error || verbosity >= VERBOSITY_LEVEL_DBG)
		ve2_dump_debug_state(xdna, mgmtctx);

	/*
	 * Optional delay for devmem debugging: give the user a window to dump
	 * device state before threads are woken. Release ctx_lock while sleeping
	 * so other paths are not blocked.
	 */
	if (aie_error_delay_sec > 0) {
		XDNA_WARN(xdna, "*** AIE error: waiting %d seconds for debug ***\n",
			  aie_error_delay_sec);
		mutex_unlock(&mgmtctx->ctx_lock);
		ssleep(aie_error_delay_sec);
		mutex_lock(&mgmtctx->ctx_lock);
		XDNA_WARN(xdna, "*** AIE error: wait complete, resuming ***\n");
	}

	/*
	 * Wake up any thread waiting on the active context so a command stuck
	 * waiting on the faulting partition can detect the error and return
	 * instead of hanging indefinitely.
	 */
	if (mgmtctx->active_ctx) {
		struct amdxdna_ctx_priv *vp = ve2_hw_priv(mgmtctx->active_ctx);

		if (vp) {
			if (!vp->misc_intrpt_flag)
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
	struct device *aie_dev;
	int ret;

	if (!vp || start_col >= xdna_hdl->aie_dev_info.cols)
		return -EINVAL;

	mgmtctx = &xdna_hdl->ve2_mgmtctx[start_col];

	if (create_aie_part) {
		mgmtctx->num_col = num_col;
		mgmtctx->num_rows = xdna_hdl->aie_dev_info.rows;
		mgmtctx->active_ctx = NULL;
		mgmtctx->wedged = false;
		memset(&mgmtctx->async_errs_cache.err, 0,
		       sizeof(mgmtctx->async_errs_cache.err));

		/* Initialize DRM-inspired scheduler */
		ret = ve2_scheduler_init(mgmtctx);
		if (ret)
			return ret;

		aie_dev = ve2_aie_partition_request(start_col, num_col, ve2_irq_handler,
						    mgmtctx, &mgmtctx->partition_id);
		if (IS_ERR(aie_dev)) {
			ret = PTR_ERR(aie_dev);
			goto destroy_wq;
		}

		mgmtctx->aie_dev = aie_dev;

		ret = ve2_aie_register_error_cb(aie_dev, ve2_aie_error_cb, mgmtctx);
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
	ve2_aie_partition_teardown(mgmtctx->aie_dev);
	ve2_aie_partition_release(mgmtctx->aie_dev);
	mgmtctx->aie_dev = NULL;
destroy_wq:
	ve2_scheduler_fini(mgmtctx);
	return ret;
}

/*
 * Zero out the CERT handshake memory for every column of a partition that is
 * about to be torn down (last sharer releasing it). Mirrors the legacy
 * driver's cert_clear_partition(): without this, stale handshake state
 * (ctx_switch_req, hsa addr, debug/trace buffer pointers, etc. from the
 * previous occupant) can persist in AIE memory across a partition
 * teardown/re-request cycle on the same columns.
 */
static void ve2_clear_partition_handshake(struct amdxdna_mgmtctx *mgmtctx,
					  struct amdxdna_hwctx *hwctx)
{
	struct amdxdna_dev *xdna = mgmtctx->xdna;
	struct ve2_aie_handshake *hs_data;
	int ret;

	hs_data = ve2_prepare_hs_data(mgmtctx, hwctx, false);
	if (!hs_data) {
		XDNA_ERR(xdna, "No memory for hs_data while clearing partition handshake");
		return;
	}

	ret = ve2_aie_partition_handshake_update(mgmtctx->aie_dev, hs_data,
						 mgmtctx->num_col);
	if (ret < 0)
		XDNA_ERR(xdna, "aie partition handshake update failed, ret: %d", ret);

	ve2_free_hs_data(hs_data, mgmtctx->num_col);
}

void ve2_mgmt_quiesce_ctx(struct amdxdna_hwctx *hwctx)
{
	struct amdxdna_ctx_priv *vp = ve2_hw_priv(hwctx);

	if (!vp || !vp->mgmtctx)
		return;

	ve2_sched_remove_ctx_jobs_sync(&vp->mgmtctx->scheduler, hwctx);
}

/* Max wait for CERT to yield @hwctx before giving up and proceeding anyway. */
#define VE2_QUIESCE_TIMEOUT_MS 5000

/*
 * If @hwctx is still the active context, ask CERT to yield it and wait
 * (bounded) for confirmation. Without this, re-arming the scheduler for the
 * next context right after clearing active_ctx can hit the Case 1 "first
 * use" path, which skips the idle check and would reprogram the handshake
 * while CERT may still be executing @hwctx.
 *
 * Returns false only if @hwctx was the active context and CERT never
 * confirmed yielding it - the caller must not re-arm the scheduler in that
 * case, since CERT may still be executing @hwctx.
 */
static bool ve2_mgmt_quiesce_active_ctx(struct amdxdna_mgmtctx *mgmtctx,
					struct amdxdna_hwctx *hwctx)
{
	unsigned long deadline;
	struct cert_status status;

	mutex_lock(&mgmtctx->ctx_lock);
	if (mgmtctx->active_ctx != hwctx) {
		mutex_unlock(&mgmtctx->ctx_lock);
		return true;
	}
	ve2_read_cert_status(mgmtctx, &status);
	if (!status.is_idle && !status.queue_not_empty) {
		ve2_request_context_switch(mgmtctx);
		mgmtctx->scheduler.ctx_switch_requested = true;
		notify_fw_cmd_ready(mgmtctx);
	}
	mutex_unlock(&mgmtctx->ctx_lock);

	deadline = jiffies + msecs_to_jiffies(VE2_QUIESCE_TIMEOUT_MS);
	while (time_before(jiffies, deadline)) {
		bool done;

		mutex_lock(&mgmtctx->ctx_lock);
		/*
		 * Once the scheduler has already switched to another sharer,
		 * cert_status reflects that sharer's activity, not whether
		 * hwctx was yielded - polling it further would eventually
		 * misreport a timeout even though hwctx was safely switched
		 * away from.
		 */
		if (mgmtctx->active_ctx != hwctx) {
			mutex_unlock(&mgmtctx->ctx_lock);
			return true;
		}
		ve2_read_cert_status(mgmtctx, &status);
		done = status.is_idle || status.queue_not_empty;
		mutex_unlock(&mgmtctx->ctx_lock);

		if (done)
			return true;
		schedule_timeout_uninterruptible(msecs_to_jiffies(1));
	}

	XDNA_ERR(mgmtctx->xdna, "Timed out waiting for CERT to yield hwctx %u on col %u",
		 hwctx->id, mgmtctx->start_col);

	mutex_lock(&mgmtctx->ctx_lock);
	mgmtctx->wedged = true;
	mutex_unlock(&mgmtctx->ctx_lock);

	return false;
}

int ve2_mgmt_destroy_partition(struct amdxdna_hwctx *hwctx)
{
	struct amdxdna_ctx_priv *vp = hwctx ? ve2_hw_priv(hwctx) : NULL;
	bool release_aie_part = false;
	struct amdxdna_mgmtctx *mgmtctx;
	struct solver_state *xrs;
	bool quiesced;

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

	/* Remove queued jobs before clearing active_ctx, or a scheduler pass can
	 * republish active_ctx to this (about to be freed) hwctx in between.
	 */
	ve2_sched_remove_ctx_jobs_sync(&mgmtctx->scheduler, hwctx);

	quiesced = ve2_mgmt_quiesce_active_ctx(mgmtctx, hwctx);

	mutex_lock(&mgmtctx->ctx_lock);
	if (mgmtctx->active_ctx == hwctx) {
		mgmtctx->active_ctx = NULL;
		mgmtctx->scheduler.ctx_switch_requested = false;
	}
	mutex_unlock(&mgmtctx->ctx_lock);

	/* Release the XRS reservation; learn whether we were the last sharer. */
	if (xrs) {
		mutex_lock(&xrs->xrs_lock);
		amdxdna_release_resource(hwctx, &release_aie_part);
		mutex_unlock(&xrs->xrs_lock);
	}

	if (release_aie_part) {
		ve2_clear_partition_handshake(mgmtctx, hwctx);

		ve2_aie_unregister_error_cb(mgmtctx->aie_dev);

		mutex_lock(&mgmtctx->ctx_lock);
		/* Update the active context as partition doesn't exists any more */
		mgmtctx->active_ctx = NULL;
		mgmtctx->scheduler.ctx_switch_requested = false;
		mutex_unlock(&mgmtctx->ctx_lock);

		/* Stop scheduler before teardown so it can't touch aie_dev afterwards.
		 * Not under ctx_lock: cancel_work_sync() would deadlock against
		 * scheduler work blocked waiting on it.
		 */
		ve2_scheduler_fini(mgmtctx);

		ve2_aie_partition_teardown(mgmtctx->aie_dev);
		ve2_aie_partition_release(mgmtctx->aie_dev);
		mgmtctx->aie_dev = NULL;
	} else if (quiesced) {
		/* Partition still shared; re-arm scheduler for other contexts' queued jobs. */
		queue_work(mgmtctx->scheduler.wq, &mgmtctx->scheduler.sched_work);
	}
	/*
	 * Else: CERT never confirmed yielding hwctx. Leave the scheduler
	 * un-armed rather than risk Case 1 reprogramming the handshake while
	 * CERT may still be executing it; other queued contexts stay pending
	 * until an unrelated IRQ or submission re-triggers the scheduler.
	 */

	vp->mgmtctx = NULL;

	/*
	 * release_aie_part physically tears down and releases the AIE
	 * partition regardless of quiesced, which resets CERT at the hardware
	 * level - safe for the caller to free hwctx's DMA buffers either way.
	 * Otherwise, if CERT never confirmed yielding, tell the caller not to:
	 * it may still be executing hwctx on the partition other contexts
	 * keep sharing.
	 */
	return (!release_aie_part && !quiesced) ? -EBUSY : 0;
}

int notify_fw_cmd_ready(struct amdxdna_mgmtctx *mgmtctx)
{
	u32 event_val = VE2_USER_EVENT_ID;
	int ret;

	ret = ve2_aie_write(mgmtctx->aie_dev, 0, 0, VE2_EVENT_GENERATE_REG,
			    sizeof(event_val), &event_val);
	if (ret < 0)
		return ret;

	/* The adapter returns the underlying byte count on success. */
	return 0;
}

int ve2_cache_coredump(struct amdxdna_dev *xdna, struct amdxdna_hwctx *hwctx, u64 seq)
{
	struct amdxdna_ctx_priv *vp = ve2_hw_priv(hwctx);
	struct ve2_coredump_cache *cache;
	struct amdxdna_mgmtctx *mgmtctx;
	void *buf, *old_buf;
	u32 size;
	int ret;

	if (!vp || !vp->mgmtctx) {
		XDNA_WARN(xdna, "Auto coredump: hwctx %u has no partition", hwctx->id);
		return -EINVAL;
	}

	cache = &vp->coredump_cache;
	mgmtctx = vp->mgmtctx;

	size = hwctx->num_col * mgmtctx->num_rows * TILE_ADDRESS_SPACE;
	if (!size) {
		XDNA_WARN(xdna, "Auto coredump: zero size for hwctx %u", hwctx->id);
		return -EINVAL;
	}

	XDNA_INFO(xdna,
		  "Auto coredump: capture start hwctx %u pid %u seq %llu start_col %u num_col %u size %u",
		  hwctx->id, hwctx->client->pid, seq, hwctx->start_col, hwctx->num_col, size);

	buf = vmalloc(size);
	if (!buf)
		return -ENOMEM;

	/* hwctx is the active ctx on this partition during the timeout path. */
	ret = ve2_aie_coredump(mgmtctx->aie_dev, size, buf);
	if (ret < 0) {
		XDNA_ERR(xdna, "Auto coredump capture failed for hwctx %u, err:%d",
			 hwctx->id, ret);
		vfree(buf);
		return ret;
	}

	/*
	 * Keep-latest: swap in the new snapshot, then free the previous one.
	 * The cache is per-hwctx and is consumed (cleared) on the next coredump
	 * read; it is also dropped when auto coredump is disabled or when the
	 * context is destroyed.
	 */
	mutex_lock(&cache->lock);
	old_buf = cache->buf;
	cache->buf = buf;
	cache->size = ret;
	cache->seq = seq;
	cache->start_col = hwctx->start_col;
	cache->num_col = hwctx->num_col;
	cache->timestamp = ktime_get();
	cache->valid = true;
	mutex_unlock(&cache->lock);

	XDNA_INFO(xdna,
		  "Auto coredump cached OK: hwctx %u pid %u seq %llu size %d%s",
		  hwctx->id, hwctx->client->pid, seq, ret,
		  old_buf ? " [overwrote previous dump]" : "");

	vfree(old_buf);

	return 0;
}

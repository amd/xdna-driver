// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2023-2026, Advanced Micro Devices, Inc.
 */

#include <drm/drm_device.h>
#include <drm/drm_print.h>
#include <linux/bitfield.h>
#include <linux/bits.h>
#include <linux/kernel.h>
#include <linux/ktime.h>
#include <linux/minmax.h>
#include <linux/mutex.h>
#include <linux/srcu.h>

#include "aie.h"
#include "aie4_msg_priv.h"
#include "aie4_pci.h"
#include "amdxdna_ctx.h"
#include "amdxdna_error.h"
#include "amdxdna_pci_drv.h"

/*
 * The async event scaffolding, GET_ARRAY query and the generic category /
 * module to driver-error mapping are shared with aie2 and live in
 * amdxdna_error.c. This file adds the aie4 specific pieces: the mailbox register
 * call, the MAX status code sentinel, the aie4 (AIE4/MDS generation) event_id to
 * category tables, and the aie4 only context-error handling (app health report
 * logging plus context reset).
 */

static enum amdxdna_error_num aie4_ctx_error_num(u32 error_type)
{
	switch (error_type) {
	case AIE4_ASYNC_EVENT_CTX_ERR_HWSCH_FAILURE:
	case AIE4_ASYNC_EVENT_CTX_ERR_STOP_FAILURE:
		return AMDXDNA_ERROR_NUM_KDS_CU;
	case AIE4_ASYNC_EVENT_CTX_ERR_AIE_FAILURE:
	case AIE4_ASYNC_EVENT_CTX_ERR_PREEMPTION_TIMEOUT:
	case AIE4_ASYNC_EVENT_CTX_ERR_NEW_PROCESS_FAILURE:
	case AIE4_ASYNC_EVENT_CTX_ERR_UC_CRITICAL_ERROR:
	case AIE4_ASYNC_EVENT_CTX_ERR_UC_COMPLETION_TIMEOUT:
		return AMDXDNA_ERROR_NUM_KDS_EXEC;
	default:
		return AMDXDNA_ERROR_NUM_UNKNOWN;
	}
}

static struct amdxdna_hwctx *hw_ctx_id2hwctx(struct aie_device *aie, u32 hw_ctx_id,
					     int *srcu_idx)
{
	struct amdxdna_dev *xdna = aie->xdna;
	struct amdxdna_client *client;
	struct amdxdna_hwctx *hwctx;
	unsigned long hwctx_idx;
	int idx;

	drm_WARN_ON(&xdna->ddev, !mutex_is_locked(&xdna->dev_lock));
	amdxdna_for_each_client(xdna, client) {
		idx = srcu_read_lock(&client->hwctx_srcu);
		amdxdna_for_each_hwctx(client, hwctx_idx, hwctx) {
			if (hwctx->priv && hwctx->priv->hw_ctx_id == hw_ctx_id) {
				/* Released by the caller. */
				*srcu_idx = idx;
				return hwctx;
			}
		}
		srcu_read_unlock(&client->hwctx_srcu, idx);
	}
	XDNA_WARN(xdna, "Could not find context for hw_ctx_id=%u", hw_ctx_id);
	return NULL;
}

/*
 * When a critical context error occurs, find the matching context and reset it
 * by destroying then recreating it.
 */
static void aie4_ctx_reset(struct aie_device *aie, u32 hw_ctx_id)
{
	struct amdxdna_dev *xdna = aie->xdna;
	struct amdxdna_hwctx *hwctx;
	int ret, idx;

	mutex_lock(&xdna->dev_lock);

	hwctx = hw_ctx_id2hwctx(aie, hw_ctx_id, &idx);
	if (hwctx) {
		/*
		 * Reset the context by destroy then recreate it. Destroy marks the
		 * context DISCONNECTED; complete any parked in-flight jobs (as timed
		 * out) before recreating so their fences are signaled and the read
		 * index advances, releasing waiters in aie4_cmd_wait() with an
		 * error. Otherwise the recreate flips the context back to CONNECTED
		 * and the waiter can never observe completion, hanging the
		 * submitter.
		 */
		aie4_hwctx_destroy(hwctx);
		if (hwctx->priv->kernel_submit)
			aie4_hwctx_cleanup_running_jobs(hwctx, true);
		ret = aie4_hwctx_create(hwctx);
		if (ret)
			XDNA_ERR(xdna, "Reset hw_ctx_id=%u ctx failed, ret %d",
				 hw_ctx_id, ret);
		srcu_read_unlock(&hwctx->client->hwctx_srcu, idx);
	}

	mutex_unlock(&xdna->dev_lock);
}

static void aie4_async_ctx_error_cache(struct aie_device *aie,
				       struct aie4_async_ctx_error *ctx_err)
{
	enum amdxdna_error_num err_num = aie4_ctx_error_num(ctx_err->error_type);
	struct aie4_msg_app_health_report *health = &ctx_err->app_health_report;
	struct amdxdna_async_error *record = &aie->last_async_err;
	struct amdxdna_dev *xdna = aie->xdna;
	struct amdxdna_hwctx *hwctx;
	struct uc_health_info *uc;
	u32 ctx_status;
	u32 num_uc;
	int idx;
	int i;

	ctx_status = FIELD_GET(AIE4_APP_HEALTH_CTX_STATUS, health->ctx_num_uc);
	num_uc = FIELD_GET(AIE4_APP_HEALTH_NUM_UC, health->ctx_num_uc);

	/* Log the health report information to aid debugging. */
	XDNA_ERR(xdna, "Context health report:");
	XDNA_ERR(xdna, "\tVersion: %u.%u",
		 (u32)FIELD_GET(AIE4_APP_HEALTH_MAJOR_VER, health->version),
		 (u32)FIELD_GET(AIE4_APP_HEALTH_MINOR_VER, health->version));
	XDNA_ERR(xdna, "\tContext status: %u", ctx_status);
	XDNA_ERR(xdna, "\tActive uC count: %u", num_uc);
	XDNA_ERR(xdna, "\tRunlist read index: %u", health->runlist_read_idx);

	for (i = 0; i < min_t(u32, num_uc, AIE4_MPNPUFW_MAX_UC_COUNT); i++) {
		uc = &health->uc_info[i];
		XDNA_ERR(xdna, "\tuC[%u]: idx: %u fw_state: %u page: %u offset: 0x%x",
			 i, uc->uc_idx, uc->fw_state, uc->page_idx, uc->offset);
		/* Parse idle_status bits */
		if (uc->uc_idle_status) {
			XDNA_ERR(xdna, "\t\tIdle status: 0x%x %s%s%s",
				 uc->uc_idle_status,
				 (uc->uc_idle_status & BIT(0)) ? "HSA_queue_not_empty " : "",
				 (uc->uc_idle_status & BIT(1)) ? "preempt_done " : "",
				 (uc->uc_idle_status & BIT(2)) ? "CERT_idle" : "");
		}
		/* Parse misc_status bits */
		if (uc->misc_status) {
			XDNA_ERR(xdna, "\t\tMisc status: 0x%x %s%s",
				 uc->misc_status,
				 (uc->misc_status & BIT(0)) ? "FW_EXCEPTION " : "",
				 (uc->misc_status & BIT(1)) ? "CTRL_CODE_HANG" : "");
		}
		/* Exception details */
		if (uc->misc_status & BIT(0)) {
			XDNA_ERR(xdna, "\t\tException: PC: 0x%x EAR: 0x%x ESR: 0x%x",
				 uc->uc_pc, uc->uc_ear, uc->uc_esr);
			/*
			 * PC  = Program Counter at crash (instruction address)
			 * EAR = Exception Address Register (faulting memory address)
			 * ESR = Exception Status Register (arch-specific exception info)
			 */
		}
	}

	mutex_lock(&xdna->dev_lock);
	record->err_code = AMDXDNA_ERROR_ENCODE(err_num, AMDXDNA_ERROR_MODULE_AIE_CORE);
	record->ts_us = ktime_to_us(ktime_get_real());
	/*
	 * Reuse the __u64 ex_err_code field with a context-error encoding
	 * distinct from the tile-error row/col encoding: high 32 bits are the
	 * firmware context status, low 32 bits are the context id. The two
	 * encodings are disambiguated by the KDS category in err_code.
	 */
	record->ex_err_code = AMDXDNA_EXTRA_ERR_CTX_ENCODE(ctx_status, ctx_err->ctx_id);

	/*
	 * Cache the full report on the owning kernel-mode context so the
	 * timeout/recovery path can attach it to the failing command. Only
	 * kernel-mode contexts consume it and have an initialized io_lock, which
	 * serializes this multi-word write against that reader. The device-level
	 * last_async_err above stays unconditional so GET_ARRAY works for all
	 * contexts.
	 */
	hwctx = hw_ctx_id2hwctx(aie, ctx_err->ctx_id, &idx);
	if (hwctx) {
		struct amdxdna_hwctx_priv *priv = hwctx->priv;

		if (priv->kernel_submit) {
			mutex_lock(&priv->io_lock);
			memcpy(&priv->cached_ctx_error, ctx_err, sizeof(*ctx_err));
			priv->cached_ctx_error_valid = true;
			mutex_unlock(&priv->io_lock);
		}
		srcu_read_unlock(&hwctx->client->hwctx_srcu, idx);
	}
	mutex_unlock(&xdna->dev_lock);
}

/*
 * Dispatch on the async event type read from the mailbox response. Returns true
 * when the event was consumed here (the shared AIE tile decode is then skipped),
 * false to let the caller run the shared tile decode.
 */
bool aie4_handle_dev_event(struct aie_device *aie, u32 type, void *vaddr)
{
	struct amdxdna_dev *xdna = aie->xdna;
	struct aie4_async_ctx_error *ctx_err;

	switch (type) {
	case AIE4_ASYNC_EVENT_TYPE_AIE_ERROR:
		/* Let the caller run the shared AIE tile error decode. */
		return false;
	case AIE4_ASYNC_EVENT_TYPE_EXCEPTION:
		/* Type-only notification (no payload defined by the firmware). */
		XDNA_ERR(xdna, "Firmware reported a fatal exception event");
		return true;
	case AIE4_ASYNC_EVENT_TYPE_CTX_ERROR:
		ctx_err = vaddr;
		XDNA_DBG(xdna, "Context error: ctx_id: %u error_type: %u",
			 ctx_err->ctx_id, ctx_err->error_type);
		/* Cache the error/health first, then recover the context. */
		aie4_async_ctx_error_cache(aie, ctx_err);
		aie4_ctx_reset(aie, ctx_err->ctx_id);
		return true;
	case AIE4_ASYNC_EVENT_TYPE_PWR_ERROR:
		/*
		 * PWR_ERROR is a type-only notification (no payload) sent right
		 * before the firmware halts, so there is nothing to cache.
		 */
		XDNA_ERR(xdna, "Firmware reported a power error, device is halting");
		return true;
	default:
		XDNA_WARN(xdna, "Unhandled/unknown async event type %u, skipping", type);
		return true;
	}
}

/* aie4 core and mem module error events (combined table). */
static const struct aie_error_event aie4_core_mem_error_events[] = {
	AIE_ERROR_EVENT(95U,  AIE_ERROR_STREAM, "Control packet error"),
	AIE_ERROR_EVENT(96U,  AIE_ERROR_BUS, "AXI-MM slave error"),
	AIE_ERROR_EVENT(97U,  AIE_ERROR_ACCESS, "Stream read collision"),
	AIE_ERROR_EVENT(98U,  AIE_ERROR_ACCESS, "DM address out of range"),
	AIE_ERROR_EVENT(100U, AIE_ERROR_ECC, "PM ECC error scrub 2bit"),
	AIE_ERROR_EVENT(102U, AIE_ERROR_ECC, "PM ECC error 2bit"),
	AIE_ERROR_EVENT(103U, AIE_ERROR_ACCESS, "PM address out of range"),
	AIE_ERROR_EVENT(104U, AIE_ERROR_ACCESS, "DM access to unavailable"),
	AIE_ERROR_EVENT(105U, AIE_ERROR_LOCK, "Lock access to unavailable"),
	AIE_ERROR_EVENT(108U, AIE_ERROR_INSTRUCTION, "Data error"),
	AIE_ERROR_EVENT(109U, AIE_ERROR_STREAM, "Stream switch port parity error"),
	AIE_ERROR_EVENT(110U, AIE_ERROR_BUS, "Processor bus error"),
	AIE_ERROR_EVENT(112U, AIE_ERROR_ECC, "DM ECC error scrub 2bit"),
	AIE_ERROR_EVENT(114U, AIE_ERROR_ECC, "DM ECC error 2bit"),
	AIE_ERROR_EVENT(115U, AIE_ERROR_MEM_PARITY, "DM parity error"),
	AIE_ERROR_EVENT(116U, AIE_ERROR_DMA, "DMA error"),
	{ }
};

/* aie4 shim (PL) module error events. */
static const struct aie_error_event aie4_shim_tile_error_events[] = {
	AIE_ERROR_EVENT(153U, AIE_ERROR_BUS, "AXI-MM slave tile error"),
	AIE_ERROR_EVENT(154U, AIE_ERROR_STREAM, "Control packet error"),
	AIE_ERROR_EVENT(155U, AIE_ERROR_STREAM, "Stream switch port parity error"),
	AIE_ERROR_EVENT(156U, AIE_ERROR_BUS, "NSU error"),
	AIE_ERROR_EVENT(157U, AIE_ERROR_DMA, "DMA error"),
	AIE_ERROR_EVENT(158U, AIE_ERROR_LOCK, "Lock error"),
	AIE_ERROR_EVENT(160U, AIE_ERROR_DMA, "DMA HW error"),
	AIE_ERROR_EVENT(161U, AIE_ERROR_DMA, "uC module A error"),
	AIE_ERROR_EVENT(162U, AIE_ERROR_DMA, "uC module B error"),
	AIE_ERROR_EVENT(163U, AIE_ERROR_BUS, "uC module A AXI-MM error"),
	AIE_ERROR_EVENT(164U, AIE_ERROR_BUS, "uC module B AXI-MM error"),
	AIE_ERROR_EVENT(167U, AIE_ERROR_ECC, "uC module A ECC error 2bit"),
	AIE_ERROR_EVENT(168U, AIE_ERROR_ECC, "uC module B ECC error 2bit"),
	{ }
};

/* aie4 mem tile module error events. */
static const struct aie_error_event aie4_mem_tile_error_events[] = {
	AIE_ERROR_EVENT(164U, AIE_ERROR_ECC, "DM ECC error scrub 2bit"),
	AIE_ERROR_EVENT(166U, AIE_ERROR_ECC, "DM ECC error 2bit"),
	AIE_ERROR_EVENT(167U, AIE_ERROR_DMA, "DMA S2MM error"),
	AIE_ERROR_EVENT(168U, AIE_ERROR_DMA, "DMA MM2S error"),
	AIE_ERROR_EVENT(169U, AIE_ERROR_STREAM, "Stream switch port parity error"),
	AIE_ERROR_EVENT(170U, AIE_ERROR_STREAM, "Control packet error"),
	AIE_ERROR_EVENT(171U, AIE_ERROR_BUS, "AXI-MM slave error"),
	AIE_ERROR_EVENT(172U, AIE_ERROR_LOCK, "Lock error"),
	{ }
};

/*
 * core and mem both point at the combined table because AIE4 merges the
 * core-tile core and mem module error broadcast switch.
 */
const struct aie_error_lut_set aie4_error_luts = {
	.shim		= aie4_shim_tile_error_events,
	.core		= aie4_core_mem_error_events,
	.mem_tile	= aie4_mem_tile_error_events,
	.mem		= aie4_core_mem_error_events,
};

int aie4_async_event_register(struct aie_device *aie, dma_addr_t addr, u32 size,
			      void *handle, int (*cb)(void *, void __iomem *, size_t))
{
	struct amdxdna_dev_hdl *ndev = aie->xdna->dev_handle;

	return aie4_register_asyn_event_msg(ndev, addr, size, handle, cb);
}

int aie4_get_array_async_error(struct amdxdna_dev_hdl *ndev,
			       struct amdxdna_drm_get_array *args)
{
	struct amdxdna_dev *xdna = ndev->aie.xdna;

	drm_WARN_ON(&xdna->ddev, !mutex_is_locked(&xdna->dev_lock));

	return amdxdna_get_array_last_async_error(&ndev->aie, args);
}

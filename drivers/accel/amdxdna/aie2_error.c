// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2023-2026, Advanced Micro Devices, Inc.
 */

#include <drm/drm_device.h>
#include <drm/drm_print.h>
#include <linux/kernel.h>
#include <linux/mutex.h>

#include "aie.h"
#include "aie2_msg_priv.h"
#include "aie2_pci.h"
#include "amdxdna_error.h"
#include "amdxdna_pci_drv.h"

/*
 * The async event scaffolding, worker, mailbox callback, GET_ARRAY query and
 * the generic category / module to driver-error mapping and stringify are
 * shared with aie4 and live in amdxdna_error.c. This file provides the aie2
 * specific pieces: the mailbox register call and the aie2 event_id to category
 * tables. The async status sentinel value (MAX_AIE2_STATUS_CODE) is wired into
 * dev_info.async_max_status_code by the npu*_regs.c device tables.
 *
 * Map an AIE tile error event id to an error category for the aie2
 * generation. These are the enabled fatal error events per module;
 * correctable and non-fatal events are omitted. The category assignment is
 * the driver's choice.
 */
static const struct aie_error_event aie2_mem_error_events[] = {
	AIE_ERROR_EVENT(88U,  AIE_ERROR_ECC, "DM ECC error scrub 2bit"),
	AIE_ERROR_EVENT(90U,  AIE_ERROR_ECC, "DM ECC error 2bit"),
	AIE_ERROR_EVENT(91U,  AIE_ERROR_MEM_PARITY, "DM parity error bank 2"),
	AIE_ERROR_EVENT(92U,  AIE_ERROR_MEM_PARITY, "DM parity error bank 3"),
	AIE_ERROR_EVENT(93U,  AIE_ERROR_MEM_PARITY, "DM parity error bank 4"),
	AIE_ERROR_EVENT(94U,  AIE_ERROR_MEM_PARITY, "DM parity error bank 5"),
	AIE_ERROR_EVENT(95U,  AIE_ERROR_MEM_PARITY, "DM parity error bank 6"),
	AIE_ERROR_EVENT(96U,  AIE_ERROR_MEM_PARITY, "DM parity error bank 7"),
	AIE_ERROR_EVENT(97U,  AIE_ERROR_DMA, "DMA S2MM 0 error"),
	AIE_ERROR_EVENT(98U,  AIE_ERROR_DMA, "DMA S2MM 1 error"),
	AIE_ERROR_EVENT(99U,  AIE_ERROR_DMA, "DMA MM2S 0 error"),
	AIE_ERROR_EVENT(100U, AIE_ERROR_DMA, "DMA MM2S 1 error"),
	AIE_ERROR_EVENT(101U, AIE_ERROR_LOCK, "Lock error"),
	{ }
};

static const struct aie_error_event aie2_core_error_events[] = {
	AIE_ERROR_EVENT(55U, AIE_ERROR_ACCESS, "PM reg access failure"),
	AIE_ERROR_EVENT(56U, AIE_ERROR_STREAM, "Stream packet parity error"),
	AIE_ERROR_EVENT(57U, AIE_ERROR_STREAM, "Control packet error"),
	AIE_ERROR_EVENT(58U, AIE_ERROR_BUS, "AXI-MM slave error"),
	AIE_ERROR_EVENT(59U, AIE_ERROR_INSTRUCTION, "Instruction decompression error"),
	AIE_ERROR_EVENT(60U, AIE_ERROR_ACCESS, "DM address out of range"),
	AIE_ERROR_EVENT(62U, AIE_ERROR_ECC, "PM ECC error scrub 2bit"),
	AIE_ERROR_EVENT(64U, AIE_ERROR_ECC, "PM ECC error 2bit"),
	AIE_ERROR_EVENT(65U, AIE_ERROR_ACCESS, "PM address out of range"),
	AIE_ERROR_EVENT(66U, AIE_ERROR_ACCESS, "DM access to unavailable"),
	AIE_ERROR_EVENT(67U, AIE_ERROR_LOCK, "Lock access to unavailable"),
	AIE_ERROR_EVENT(70U, AIE_ERROR_INSTRUCTION, "Sparsity overflow"),
	AIE_ERROR_EVENT(71U, AIE_ERROR_STREAM, "Stream switch port parity error"),
	AIE_ERROR_EVENT(72U, AIE_ERROR_BUS, "Processor bus error"),
	{ }
};

static const struct aie_error_event aie2_mem_tile_error_events[] = {
	AIE_ERROR_EVENT(130U, AIE_ERROR_ECC, "DM ECC error scrub 2bit"),
	AIE_ERROR_EVENT(132U, AIE_ERROR_ECC, "DM ECC error 2bit"),
	AIE_ERROR_EVENT(133U, AIE_ERROR_DMA, "DMA S2MM error"),
	AIE_ERROR_EVENT(134U, AIE_ERROR_DMA, "DMA MM2S error"),
	AIE_ERROR_EVENT(135U, AIE_ERROR_STREAM, "Stream switch port parity error"),
	AIE_ERROR_EVENT(136U, AIE_ERROR_STREAM, "Stream packet parity error"),
	AIE_ERROR_EVENT(137U, AIE_ERROR_STREAM, "Control packet error"),
	AIE_ERROR_EVENT(138U, AIE_ERROR_BUS, "AXI-MM slave error"),
	AIE_ERROR_EVENT(139U, AIE_ERROR_LOCK, "Lock error"),
	{ }
};

static const struct aie_error_event aie2_shim_tile_error_events[] = {
	AIE_ERROR_EVENT(64U, AIE_ERROR_BUS, "AXI-MM slave tile error"),
	AIE_ERROR_EVENT(65U, AIE_ERROR_STREAM, "Control packet error"),
	AIE_ERROR_EVENT(66U, AIE_ERROR_STREAM, "Stream switch port parity error"),
	AIE_ERROR_EVENT(67U, AIE_ERROR_BUS, "AXI-MM decode NSU error"),
	AIE_ERROR_EVENT(68U, AIE_ERROR_BUS, "AXI-MM slave NSU error"),
	AIE_ERROR_EVENT(69U, AIE_ERROR_BUS, "AXI-MM unsupported traffic"),
	AIE_ERROR_EVENT(70U, AIE_ERROR_BUS, "AXI-MM unsecure access in secure mode"),
	AIE_ERROR_EVENT(71U, AIE_ERROR_BUS, "AXI-MM byte strobe error"),
	AIE_ERROR_EVENT(72U, AIE_ERROR_DMA, "DMA S2MM error"),
	AIE_ERROR_EVENT(73U, AIE_ERROR_DMA, "DMA MM2S error"),
	AIE_ERROR_EVENT(74U, AIE_ERROR_LOCK, "Lock error"),
	{ }
};

const struct aie_error_lut_set aie2_error_luts = {
	.shim		= aie2_shim_tile_error_events,
	.core		= aie2_core_error_events,
	.mem_tile	= aie2_mem_tile_error_events,
	.mem		= aie2_mem_error_events,
};

int aie2_async_event_register(struct aie_device *aie, dma_addr_t addr, u32 size,
			      void *handle, int (*cb)(void *, void __iomem *, size_t))
{
	struct amdxdna_dev_hdl *ndev = aie->xdna->dev_handle;

	return aie2_register_asyn_event_msg(ndev, addr, size, handle, cb);
}

int aie2_get_array_async_error(struct amdxdna_dev_hdl *ndev,
			       struct amdxdna_drm_get_array *args)
{
	struct amdxdna_dev *xdna = ndev->aie.xdna;

	drm_WARN_ON(&xdna->ddev, !mutex_is_locked(&xdna->dev_lock));

	return amdxdna_get_array_last_async_error(&ndev->aie, args);
}

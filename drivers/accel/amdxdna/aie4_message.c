// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2026, Advanced Micro Devices, Inc.
 */

#include "drm/amdxdna_accel.h"
#include <drm/drm_print.h>
#include <drm/gpu_scheduler.h>
#include <linux/bitfield.h>
#include <linux/mutex.h>

#include "aie.h"
#include "aie4_msg_priv.h"
#include "aie4_pci.h"
#include "amdxdna_ctx.h"
#include "amdxdna_mailbox.h"
#include "amdxdna_mailbox_helper.h"
#include "amdxdna_pci_drv.h"

int aie4_suspend_fw(struct amdxdna_dev_hdl *ndev)
{
	DECLARE_AIE_MSG(aie4_msg_suspend, AIE4_MSG_OP_SUSPEND);
	int ret;

	ret = aie_send_mgmt_msg_wait(&ndev->aie, &msg);
	if (ret)
		XDNA_ERR(ndev->aie.xdna, "Failed to suspend fw, ret %d", ret);

	return ret;
}

int aie4_query_aie_metadata(struct amdxdna_dev_hdl *ndev,
			    struct amdxdna_drm_query_aie_metadata *metadata)
{
	DECLARE_AIE_MSG(aie4_msg_aie4_tile_info, AIE4_MSG_OP_AIE_TILE_INFO);
	int ret;

	ret = aie_send_mgmt_msg_wait(&ndev->aie, &msg);
	if (ret)
		return ret;

	metadata->col_size = resp.info.size;
	metadata->cols = resp.info.cols;
	metadata->rows = resp.info.rows;

	metadata->version.major = resp.info.major;
	metadata->version.minor = resp.info.minor;

	metadata->core.row_count = resp.info.core_rows;
	metadata->core.row_start = resp.info.core_row_start;
	metadata->core.dma_channel_count = resp.info.core_dma_channels;
	metadata->core.lock_count = resp.info.core_locks;
	metadata->core.event_reg_count = resp.info.core_events;

	metadata->mem.row_count = resp.info.mem_rows;
	metadata->mem.row_start = resp.info.mem_row_start;
	metadata->mem.dma_channel_count = resp.info.mem_dma_channels;
	metadata->mem.lock_count = resp.info.mem_locks;
	metadata->mem.event_reg_count = resp.info.mem_events;

	metadata->shim.row_count = resp.info.shim_rows;
	metadata->shim.row_start = resp.info.shim_row_start;
	metadata->shim.dma_channel_count = resp.info.shim_dma_channels;
	metadata->shim.lock_count = resp.info.shim_locks;
	metadata->shim.event_reg_count = resp.info.shim_events;

	return 0;
}

int aie4_attach_work_buffer(struct amdxdna_dev_hdl *ndev, dma_addr_t addr, u32 size)
{
	DECLARE_AIE_MSG(aie4_msg_attach_work_buffer, AIE4_MSG_OP_ATTACH_WORK_BUFFER);
	struct amdxdna_dev *xdna = ndev->aie.xdna;
	int ret;

	req.buff_addr = addr;
	req.buff_size = size;

	ret = aie_send_mgmt_msg_wait(&ndev->aie, &msg);
	if (ret)
		XDNA_ERR(xdna, "Failed to attach work buffer, ret %d", ret);
	else
		XDNA_DBG(xdna, "Attached work buffer, size %d", size);

	return ret;
}

int aie4_get_aie_coredump(struct amdxdna_hwctx *hwctx,
			  struct amdxdna_msg_buf_hdl *list_hdl,
			  u32 num_bufs)
{
	DECLARE_AIE_MSG(aie4_msg_aie4_coredump, AIE4_MSG_OP_AIE_COREDUMP);
	struct amdxdna_dev_hdl *ndev = hwctx->client->xdna->dev_handle;
	struct amdxdna_dev *xdna = hwctx->client->xdna;
	int ret;

	req.context_id = hwctx->fw_ctx_id;
	req.pasid = FIELD_PREP(AIE4_MSG_PASID, hwctx->client->pasid) |
		    FIELD_PREP(AIE4_MSG_PASID_VLD, 1);
	req.num_buffers = num_bufs;
	req.buffer_list_addr = to_dma_addr(list_hdl, 0);

	ret = aie_send_mgmt_msg_wait(&ndev->aie, &msg);
	if (ret)
		XDNA_ERR(xdna, "Get coredump got status 0x%x", resp.status);

	return ret;
}

int aie4_rw_aie_reg(struct amdxdna_hwctx *hwctx, bool is_read,
		    u8 row, u8 col, u32 addr, u32 *value)
{
	DECLARE_AIE_MSG(aie4_msg_aie4_debug_access, AIE4_MSG_OP_AIE_RW_ACCESS);
	struct amdxdna_dev_hdl *ndev = hwctx->client->xdna->dev_handle;
	struct amdxdna_dev *xdna = hwctx->client->xdna;
	enum aie4_access_type type;
	int ret;

	type = is_read ? AIE4_ACCESS_TYPE_REG_READ : AIE4_ACCESS_TYPE_REG_WRITE;

	req.opcode = type;
	req.context_id = hwctx->fw_ctx_id;
	req.row = row;
	req.col = col;
	req.reg_access.reg_addr = addr;
	if (!is_read)
		req.reg_access.reg_wval = *value;

	ret = aie_send_mgmt_msg_wait(&ndev->aie, &msg);
	if (ret) {
		XDNA_ERR(xdna, "AIE reg %s failed, ret %d",
			 is_read ? "read" : "write", ret);
		return ret;
	}

	if (is_read)
		*value = resp.reg_rval;

	return 0;
}

int aie4_rw_aie_mem(struct amdxdna_hwctx *hwctx, bool is_read,
		    u8 row, u8 col, u32 aie_addr,
		    dma_addr_t dram_addr, u32 size)
{
	DECLARE_AIE_MSG(aie4_msg_aie4_debug_access, AIE4_MSG_OP_AIE_RW_ACCESS);
	struct amdxdna_dev_hdl *ndev = hwctx->client->xdna->dev_handle;
	struct amdxdna_dev *xdna = hwctx->client->xdna;
	enum aie4_access_type type;
	int ret;

	type = is_read ? AIE4_ACCESS_TYPE_MEM_READ : AIE4_ACCESS_TYPE_MEM_WRITE;

	req.opcode = type;
	req.context_id = hwctx->fw_ctx_id;
	req.row = row;
	req.col = col;
	req.mem_access.buffer_addr = dram_addr;
	req.mem_access.buffer_size = size;
	req.mem_access.mem_addr = aie_addr;
	req.mem_access.mem_size = size;
	req.mem_access.pasid = FIELD_PREP(AIE4_MSG_PASID, hwctx->client->pasid) |
			       FIELD_PREP(AIE4_MSG_PASID_VLD, 1);

	ret = aie_send_mgmt_msg_wait(&ndev->aie, &msg);
	if (ret) {
		XDNA_ERR(xdna, "AIE mem %s failed, ret %d",
			 is_read ? "read" : "write", ret);
		return ret;
	}

	return 0;
}

void aie4_msg_init(struct amdxdna_dev_hdl *ndev)
{
	if (AIE_FEATURE_ON(&ndev->aie, AIE4_GET_COREDUMP))
		ndev->aie.msg_ops.get_coredump = aie4_get_aie_coredump;

	if (AIE_FEATURE_ON(&ndev->aie, AIE4_RW_ACCESS)) {
		ndev->aie.msg_ops.rw_reg = aie4_rw_aie_reg;
		ndev->aie.msg_ops.rw_mem = aie4_rw_aie_mem;
	}
}

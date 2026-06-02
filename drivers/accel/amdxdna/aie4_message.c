// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2026, Advanced Micro Devices, Inc.
 */

#include "drm/amdxdna_accel.h"
#include <drm/drm_cache.h>
#include <drm/drm_print.h>
#include <drm/gpu_scheduler.h>
#include <linux/bitfield.h>
#include <linux/ktime.h>
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

int aie4_calibrate_clock(struct amdxdna_dev_hdl *ndev)
{
	DECLARE_AIE_MSG(aie4_msg_calibrate_clock, AIE4_MSG_OP_CALIBRATE_CLOCK);
	int ret;

	if (!AIE_FEATURE_ON(&ndev->aie, AIE4_CALIBRATE_CLOCK)) {
		XDNA_DBG(ndev->aie.xdna, "Calibrate clock not supported, skipped");
		return 0;
	}

	req.time_base_ns = ktime_get_real_ns();

	ret = aie_send_mgmt_msg_wait(&ndev->aie, &msg);
	if (ret) {
		XDNA_ERR(ndev->aie.xdna, "Calibrate clock failed, ret %d", ret);
		return ret;
	}

	return 0;
}

int aie4_query_aie_version(struct amdxdna_dev_hdl *ndev,
			   struct amdxdna_drm_query_aie_version *aie_version)
{
	DECLARE_AIE_MSG(aie4_msg_aie4_version_info, AIE4_MSG_OP_AIE_VERSION_INFO);
	struct amdxdna_dev *xdna = ndev->aie.xdna;
	int ret;

	ret = aie_send_mgmt_msg_wait(&ndev->aie, &msg);
	if (ret)
		return ret;

	XDNA_DBG(xdna, "Query AIE version - major: %u minor: %u",
		 resp.major, resp.minor);

	aie_version->major = resp.major;
	aie_version->minor = resp.minor;

	return 0;
}

int aie4_query_npu_firmware_version(struct amdxdna_dev_hdl *ndev,
				    struct amdxdna_drm_query_firmware_version *fw_version)
{
	DECLARE_AIE_MSG(aie4_msg_identify, AIE4_MSG_OP_IDENTIFY);
	int ret;

	ret = aie_send_mgmt_msg_wait(&ndev->aie, &msg);
	if (ret)
		return ret;

	fw_version->major = resp.fw_major;
	fw_version->minor = resp.fw_minor;
	fw_version->patch = resp.fw_patch;
	fw_version->build = resp.fw_build;

	return 0;
}

int aie4_query_cert_firmware_version(struct amdxdna_dev_hdl *ndev,
				     struct amdxdna_drm_query_firmware_version *cert_version)
{
	DECLARE_AIE_MSG(aie4_msg_query_cert_firmware_version,
			AIE4_MSG_OP_QUERY_CERT_FIRMWARE_VERSION);
	int ret;

	ret = aie_send_mgmt_msg_wait(&ndev->aie, &msg);
	if (ret)
		return ret;

	cert_version->major = resp.major_version;
	cert_version->minor = resp.minor_version;
	cert_version->patch = resp.hotfix;
	cert_version->build = resp.build;

	return 0;
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

int aie4_msg_set_power_mode(struct amdxdna_dev_hdl *ndev, u8 power_mode)
{
	DECLARE_AIE_MSG(aie4_msg_power_override, AIE4_MSG_OP_POWER_OVERRIDE);
	int ret;

	req.power_mode = power_mode;

	ret = aie_send_mgmt_msg_wait(&ndev->aie, &msg);
	if (ret)
		return ret;

	return 0;
}

int aie4_configure_hw_context_cert_log(struct amdxdna_dev_hdl *ndev,
				       u32 hw_context_id, u32 property,
				       const struct aie4_msg_context_config_cert_logging *cl)
{
	DECLARE_AIE_MSG(aie4_msg_configure_hw_context, AIE4_MSG_OP_CONFIGURE_HW_CONTEXT);
	struct amdxdna_dev *xdna = ndev->aie.xdna;
	int ret;

	req.hw_context_id = hw_context_id;
	req.property = property;
	req.cert_logging = *cl;

	ret = aie_send_mgmt_msg_wait(&ndev->aie, &msg);
	if (ret)
		XDNA_ERR(xdna, "CERT log configure failed, ctx %u property %u ret %d",
			 hw_context_id, property, ret);

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

static int aie4_query_telemetry(struct aie_device *aie, char __user *buf, u32 size,
				struct amdxdna_drm_query_telemetry_header *header)
{
	DECLARE_AIE_MSG(aie4_msg_get_telemetry, AIE4_MSG_OP_GET_TELEMETRY);
	struct amdxdna_dev *xdna = aie->xdna;
	struct amdxdna_msg_buf_hdl *buf_hdl;
	int ret;

	if (header->type >= AIE4_TELEMETRY_TYPE_MAX)
		return -EINVAL;

	buf_hdl = amdxdna_alloc_msg_buff(xdna,
					 clamp_t(u32, size,
						 AIE4_MIN_TELEMETRY_BUFF_SIZE, SZ_4M));
	if (IS_ERR(buf_hdl))
		return PTR_ERR(buf_hdl);

	req.type = header->type;
	req.buf_addr = to_dma_addr(buf_hdl, 0);
	req.buf_size = to_buf_size(buf_hdl);
	/* Kernel DMA buffer in the default domain: leave the PASID valid bit clear. */
	req.pasid = 0;
	req.hw_context_id = 0;

	memset(to_cpu_addr(buf_hdl, 0), 0, to_buf_size(buf_hdl));
	drm_clflush_virt_range(to_cpu_addr(buf_hdl, 0), to_buf_size(buf_hdl));

	ret = aie_send_mgmt_msg_wait(aie, &msg);
	if (ret) {
		XDNA_ERR(xdna, "Get telemetry failed, ret %d", ret);
		goto free_buf;
	}

	drm_clflush_virt_range(to_cpu_addr(buf_hdl, 0), to_buf_size(buf_hdl));

	size = min(size, to_buf_size(buf_hdl));
	if (copy_to_user(buf, to_cpu_addr(buf_hdl, 0), size)) {
		XDNA_ERR(xdna, "Failed to copy telemetry to user space");
		ret = -EFAULT;
		goto free_buf;
	}

	header->major = 0;
	header->minor = 0;

free_buf:
	amdxdna_free_msg_buff(buf_hdl);
	return ret;
}

void aie4_msg_init(struct amdxdna_dev_hdl *ndev)
{
	if (AIE_FEATURE_ON(&ndev->aie, AIE4_GET_COREDUMP))
		ndev->aie.msg_ops.get_coredump = aie4_get_aie_coredump;

	if (AIE_FEATURE_ON(&ndev->aie, AIE4_RW_ACCESS)) {
		ndev->aie.msg_ops.rw_reg = aie4_rw_aie_reg;
		ndev->aie.msg_ops.rw_mem = aie4_rw_aie_mem;
	}

	ndev->aie.msg_ops.query_telemetry = aie4_query_telemetry;
	/* aie4 has no fw_ctx_id <-> hwctx_id map and no per-ctx FW health. */
	ndev->aie.hwctx_limit = 0;
}

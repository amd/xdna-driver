// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2023-2026, Advanced Micro Devices, Inc.
 */

#include "aie4_pci.h"
#include "amdxdna_mailbox.h"
#include "amdxdna_mgmt.h"
#include "aie4_message.h"

#include "aie4_msg_priv.h"

#ifdef AMDXDNA_DEVEL
#define TX_TIMEOUT 60000 /* milliseconds */
#define RX_TIMEOUT 60000 /* milliseconds */
#else
#define TX_TIMEOUT 2000 /* milliseconds */
#define RX_TIMEOUT 5000 /* milliseconds */
#endif

#define ASYNC_BUF_SIZE		SZ_8K

int aie4_xdna_msg_cb(void *handle, void __iomem *data, size_t size)
{
	struct xdna_notify *cb_arg = handle;
	int ret;

	if (unlikely(!data))
		goto out;

	if (unlikely(cb_arg->size != size)) {
		cb_arg->error = -EINVAL;
		goto out;
	}

	memcpy_fromio(cb_arg->data, data, cb_arg->size);
	print_hex_dump_debug("resp data: ", DUMP_PREFIX_OFFSET,
			     16, 4, cb_arg->data, cb_arg->size, true);
out:
	ret = cb_arg->error;
	complete(&cb_arg->comp);
	return ret;
}

static int xdna_send_msg_wait(struct amdxdna_dev *xdna,
			      struct mailbox_channel *chann,
			      struct xdna_mailbox_msg *msg)
{
	struct xdna_notify *hdl = msg->handle;
	int ret;

	ret = xdna_mailbox_send_msg(chann, msg, TX_TIMEOUT);
	if (ret) {
		XDNA_ERR(xdna, "Send message failed, ret %d", ret);
		return ret;
	}

	ret = wait_for_completion_timeout(&hdl->comp,
					  msecs_to_jiffies(RX_TIMEOUT));
	if (!ret) {
		XDNA_ERR(xdna, "Wait for completion timeout");
		return -ETIME;
	}

	return hdl->error;
}

int aie4_send_msg_wait(struct amdxdna_dev_hdl *ndev,
		       struct xdna_mailbox_msg *msg)
{
	struct amdxdna_dev *xdna = ndev->xdna;
	struct xdna_notify *hdl = msg->handle;
	int ret;

	drm_WARN_ON(&xdna->ddev, !mutex_is_locked(&ndev->aie4_lock));

	if (!ndev->mgmt_chann)
		return -ENODEV;

	ret = xdna_send_msg_wait(xdna, ndev->mgmt_chann, msg);
	if (ret)
		return ret;

	if (*hdl->data != AIE4_MSG_STATUS_SUCCESS) {
		XDNA_ERR(xdna, "command opcode 0x%x failed, status 0x%x",
			 msg->opcode, *hdl->data);
		return -EINVAL;
	}

	return 0;
}

int aie4_suspend_fw(struct amdxdna_dev_hdl *ndev)
{
	DECLARE_AIE4_MSG(aie4_msg_suspend, AIE4_MSG_OP_SUSPEND);
	int ret;

	ret = aie4_send_msg_wait(ndev, &msg);
	if (ret) {
		XDNA_ERR(ndev->xdna, "Failed to suspend fw, ret %d", ret);
		return ret;
	}

	return ret;
}

int aie4_force_preemption(struct amdxdna_dev_hdl *ndev)
{
	DECLARE_AIE4_MSG(aie4_msg_set_runtime_cfg, AIE4_MSG_OP_SET_RUNTIME_CONFIG);
	struct aie4_msg_runtime_config_force_preemption *force_preempt;
	u32 type = AIE4_RUNTIME_CONFIG_FORCE_PREEMPTION;
	int ret;

	req.type = type;
	force_preempt = (struct aie4_msg_runtime_config_force_preemption *)req.data;
	force_preempt->enabled = 1;

	msg.send_size = sizeof(req.type) + sizeof(*force_preempt);

	ret = aie4_send_msg_wait(ndev, &msg);
	if (ret) {
		XDNA_ERR(ndev->xdna, "Failed to set runtime config, ret %d", ret);
		return ret;
	}

	return 0;
}

int aie4_check_firmware_version(struct amdxdna_dev_hdl *ndev)
{
	DECLARE_AIE4_MSG(aie4_msg_identify, AIE4_MSG_OP_IDENTIFY);
	struct amdxdna_dev *xdna = ndev->xdna;
	int ret;

	ret = aie4_send_msg_wait(ndev, &msg);
	if (ret) {
		XDNA_ERR(xdna, "Failed to get protocol version, ret %d", ret);
		return ret;
	}

	xdna->fw_ver.major = resp.fw_major;
	xdna->fw_ver.minor = resp.fw_minor;
	xdna->fw_ver.sub = resp.fw_patch;
	xdna->fw_ver.build = resp.fw_build;

	XDNA_DBG(xdna, "FW version: %d.%d.%d.%d", xdna->fw_ver.major,
		 xdna->fw_ver.minor, xdna->fw_ver.sub, xdna->fw_ver.build);

	return 0;
}

int aie4_query_aie_status(struct amdxdna_dev_hdl *ndev, char __user *buf,
			  u32 size, u32 *cols_filled)
{
	DECLARE_AIE4_MSG(aie4_msg_aie4_column_info, AIE4_MSG_OP_AIE_COLUMN_INFO);
	struct amdxdna_dev *xdna = ndev->xdna;
	struct amdxdna_mgmt_dma_hdl *dma_hdl;
	struct amdxdna_client *client;
	struct amdxdna_ctx *ctx;
	unsigned long ctx_id;
	u32 aie_bitmap = 0;
	dma_addr_t addr;
	int ret, idx;

	if (!access_ok(buf, size)) {
		XDNA_ERR(xdna, "Failed to access status buffer size %d", size);
		return -EFAULT;
	}

	dma_hdl = amdxdna_mgmt_buff_alloc(xdna, size, DMA_FROM_DEVICE);
	if (IS_ERR(dma_hdl))
		return PTR_ERR(dma_hdl);

	/* Go through each context and mark the AIE columns that are active */
	list_for_each_entry(client, &xdna->client_list, node) {
		idx = srcu_read_lock(&client->ctx_srcu);
		amdxdna_for_each_ctx(client, ctx_id, ctx)
			aie_bitmap |= amdxdna_ctx_col_map(ctx);
		srcu_read_unlock(&client->ctx_srcu, idx);
	}

	*cols_filled = 0;

	addr = amdxdna_mgmt_buff_get_dma_addr(dma_hdl);
	if (!addr) {
		XDNA_ERR(xdna, "Invalid DMA address: %lld", addr);
		return -EINVAL;
	}

	req.dump_buff_addr = addr;
	req.dump_buff_size = size;
	// req.pasid = ; need to implement pasid
	req.num_cols = hweight32(aie_bitmap);
	req.aie4_bitmap = aie_bitmap;

	amdxdna_mgmt_buff_clflush(dma_hdl, 0, 0);
	ret = aie4_send_msg_wait(ndev, &msg);
	if (ret) {
		XDNA_ERR(xdna, "Error during NPU query, status %d", ret);
		goto fail;
	}

	if (resp.status != AIE4_MSG_STATUS_SUCCESS) {
		XDNA_ERR(xdna, "Query NPU status failed, status 0x%x", resp.status);
		ret = -EINVAL;
		goto fail;
	}
	XDNA_DBG(xdna, "Query NPU status completed");

	if (size < resp.size) {
		ret = -EINVAL;
		XDNA_ERR(xdna, "Bad buffer size. Available: %u. Needs: %u", size, resp.size);
		goto fail;
	}

	if (copy_to_user(buf, amdxdna_mgmt_buff_get_cpu_addr(dma_hdl, 0), resp.size)) {
		ret = -EFAULT;
		XDNA_ERR(xdna, "Failed to copy NPU status to user space");
		goto fail;
	}

	*cols_filled = aie_bitmap;
fail:
	amdxdna_mgmt_buff_free(dma_hdl);
	return ret;
}

int aie4_query_aie_version(struct amdxdna_dev_hdl *ndev, struct aie_version *version)
{
	DECLARE_AIE4_MSG(aie4_msg_aie4_version_info, AIE4_MSG_OP_AIE_VERSION_INFO);
	struct amdxdna_dev *xdna = ndev->xdna;
	int ret;

	ret = aie4_send_msg_wait(ndev, &msg);
	if (ret)
		return ret;

	XDNA_DBG(xdna, "Query AIE version - major: %u minor: %u completed",
		 resp.major, resp.minor);

	version->major = resp.major;
	version->minor = resp.minor;

	return 0;
}

int aie4_query_aie_metadata(struct amdxdna_dev_hdl *ndev, struct aie_metadata *metadata)
{
	DECLARE_AIE4_MSG(aie4_msg_aie4_tile_info, AIE4_MSG_OP_AIE_TILE_INFO);
	int ret;

	ret = aie4_send_msg_wait(ndev, &msg);
	if (ret)
		return ret;

	metadata->size = resp.info.size;
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

int aie4_query_aie_telemetry(struct amdxdna_dev_hdl *ndev, u32 type, u32 pasid, dma_addr_t addr,
			     u32 size)
{
	DECLARE_AIE4_MSG(aie4_msg_get_telemetry, AIE4_MSG_OP_GET_TELEMETRY);
	struct amdxdna_dev *xdna = ndev->xdna;
	int ret;

	if (type >= AIE4_TELEMETRY_TYPE_MAX_SIZE) {
		XDNA_ERR(xdna, "Invalid telemetry type %d", type);
		return -EINVAL;
	}

	req.type = type;
	req.buf_addr = addr;
	req.pasid.raw = pasid;
	req.buf_size = size;
	req.hw_context_id = 0; // Fix me for next fw release when per ctx telemetry is supported

	ret = aie4_send_msg_wait(ndev, &msg);
	if (ret) {
		XDNA_ERR(xdna, "Failed to get telemetry, ret %d", ret);
		return ret;
	}

	return 0;
}

int aie4_set_pm_msg(struct amdxdna_dev_hdl *ndev, u32 target)
{
	DECLARE_AIE4_MSG(aie4_msg_power_override, AIE4_MSG_OP_POWER_OVERRIDE);
	int ret;

	req.power_mode = target;

	ret = aie4_send_msg_wait(ndev, &msg);
	if (ret)
		return ret;

	return 0;
}

int aie4_calibrate_clock(struct amdxdna_dev_hdl *ndev)
{
	DECLARE_AIE4_MSG(aie4_msg_calibrate_clock_trace, AIE4_MSG_OP_CALIBRATE_CLOCK);
	int ret;

	req.time_base_ns = ktime_get_real_ns();

	ret = aie4_send_msg_wait(ndev, &msg);
	if (ret) {
		XDNA_ERR(ndev->xdna, "Calibrate clock failed, ret %d", ret);
		return ret;
	}

	XDNA_DBG(ndev->xdna, "System clock calibrated with firmware");
	return 0;
}

int aie4_register_asyn_event_msg(struct amdxdna_dev_hdl *ndev,
				 struct amdxdna_mgmt_dma_hdl *dma_hdl, void *handle,
				 int (*cb)(void*, void __iomem *, size_t))
{
	struct aie4_msg_async_event_config_req req = { 0 };
	struct xdna_mailbox_msg msg = {
		.send_data = (u8 *)&req,
		.send_size = sizeof(req),
		.handle = handle,
		.opcode = AIE4_MSG_OP_ASYNC_EVENT_MSG,
		.notify_cb = cb,
	};
	dma_addr_t addr;

	addr = amdxdna_mgmt_buff_get_dma_addr(dma_hdl);
	if (!addr) {
		XDNA_ERR(ndev->xdna, "Invalid DMA address: %lld", addr);
		return -EINVAL;
	}

	req.buff_addr = addr;
	req.buff_size = ASYNC_BUF_SIZE;

	XDNA_DBG(ndev->xdna, "Register addr 0x%llx size 0x%x", req.buff_addr, req.buff_size);
	return xdna_mailbox_send_msg(ndev->mgmt_chann, &msg, TX_TIMEOUT);
}

int aie4_start_fw_log(struct amdxdna_dev_hdl *ndev, struct amdxdna_mgmt_dma_hdl *dma_hdl, u8 level,
		      size_t size, u32 *msi_idx, u32 *msi_address)
{
	DECLARE_AIE4_MSG(aie4_msg_dram_logging_start, AIE4_MSG_OP_DRAM_LOGGING_START);
	struct amdxdna_dev *xdna = ndev->xdna;
	dma_addr_t addr;
	int ret;

	addr = amdxdna_mgmt_buff_get_dma_addr(dma_hdl);
	if (!addr) {
		XDNA_ERR(xdna, "Invalid DMA address: %lld", addr);
		return -EINVAL;
	}

	req.buff_size = size;
	req.buff_addr = addr;
	req.log_level = level;

	ret = aie4_send_msg_wait(ndev, &msg);
	if (ret) {
		XDNA_ERR(xdna, "Start fw log failed, ret 0x%x", resp.status);
		return -EINVAL;
	}

	/*
	 * TODO: Unlike aie2, current version of FW interface doesn't define MSI info in the
	 * response. Return the MSI info once implemented
	 */
	*msi_address = 0;
	*msi_idx = 0;

	return 0;
}

int aie4_set_ctx_hysteresis(struct amdxdna_dev_hdl *ndev, u32 timeout_us)
{
	DECLARE_AIE4_MSG(aie4_msg_set_runtime_cfg, AIE4_MSG_OP_SET_RUNTIME_CONFIG);
	struct aie4_msg_runtime_config_ctx_switch_hysteresis *hyst;
	int ret;

	req.type = AIE4_RUNTIME_CONFIG_CTX_SWITCH_HYSTERESIS;
	hyst = (struct aie4_msg_runtime_config_ctx_switch_hysteresis *)req.data;
	hyst->timeout_us = timeout_us;

	msg.send_size = sizeof(req.type) + sizeof(*hyst);

	ret = aie4_send_msg_wait(ndev, &msg);
	if (ret) {
		XDNA_ERR(ndev->xdna, "Failed to set runtime config, ret %d", ret);
		return ret;
	}

	XDNA_DBG(ndev->xdna, "Context hysteresis set to %dus", timeout_us);

	return 0;
}

int aie4_set_ctx_timeout(struct amdxdna_dev_hdl *ndev, u32 timeout_ms)
{
	DECLARE_AIE4_MSG(aie4_msg_set_runtime_cfg, AIE4_MSG_OP_SET_RUNTIME_CONFIG);
	struct aie4_msg_runtime_config_context_timeout *ctx_timeout;
	int ret;

	req.type = AIE4_RUNTIME_CONFIG_CONTEXT_TIMEOUT;
	ctx_timeout = (struct aie4_msg_runtime_config_context_timeout *)req.data;
	ctx_timeout->timeout_ms = timeout_ms;

	msg.send_size = sizeof(req.type) + sizeof(*ctx_timeout);

	ret = aie4_send_msg_wait(ndev, &msg);
	if (ret) {
		XDNA_ERR(ndev->xdna, "Failed to set runtime config, ret %d", ret);
		return ret;
	}

	XDNA_DBG(ndev->xdna, "Context timeout set to %dms", timeout_ms);

	return 0;
}

int aie4_set_log_level(struct amdxdna_dev_hdl *ndev, u8 level)
{
	DECLARE_AIE4_MSG(aie4_msg_set_runtime_cfg, AIE4_MSG_OP_SET_RUNTIME_CONFIG);
	struct aie4_msg_runtime_config_dynamic_logging_level *log;
	u32 type = AIE4_RUNTIME_CONFIG_DYNAMIC_LOGGING_LEVEL;
	int ret;

	req.type = type;
	log = (struct aie4_msg_runtime_config_dynamic_logging_level *)req.data;
	log->log_level = level;

	msg.send_size = sizeof(req.type) + sizeof(*log);

	ret = aie4_send_msg_wait(ndev, &msg);
	if (ret) {
		XDNA_ERR(ndev->xdna, "Failed to set runtime config, ret %d", ret);
		return ret;
	}

	return 0;
}

int aie4_stop_fw_log(struct amdxdna_dev_hdl *ndev)
{
	DECLARE_AIE4_MSG(aie4_msg_dram_logging_stop, AIE4_MSG_OP_DRAM_LOGGING_STOP);
	int ret;

	ret = aie4_send_msg_wait(ndev, &msg);
	if (ret) {
		XDNA_ERR(ndev->xdna, "Start fw log failed, ret 0x%x", resp.status);
		return -EINVAL;
	}

	return 0;
}

int aie4_start_fw_trace(struct amdxdna_dev_hdl *ndev, struct amdxdna_mgmt_dma_hdl *dma_hdl,
			size_t size, u32 categories, u32 *msi_idx, u32 *msi_address)
{
	DECLARE_AIE4_MSG(aie4_msg_start_event_trace, AIE4_MSG_OP_START_EVENT_TRACE);
	struct amdxdna_dev *xdna = ndev->xdna;
	dma_addr_t addr;
	int ret;

	addr = amdxdna_mgmt_buff_get_dma_addr(dma_hdl);
	if (!addr) {
		XDNA_ERR(xdna, "Invalid DMA address: %lld", addr);
		return -EINVAL;
	}

	req.event_trace_dest = AIE4_MSG_EVENT_TRACE_DEST_DRAM;
	req.event_trace_timestamp = AIE4_MSG_EVENT_TRACE_TIMESTAMP_NS_OFFSET;
	req.event_trace_categories = categories;
	req.dram_buffer_size = size;
	req.dram_buffer_address = addr;
	req.pasid.raw = 0;

	ret = aie4_send_msg_wait(ndev, &msg);
	if (ret) {
		XDNA_ERR(xdna, "start fw trace failed, ret 0x%x", resp.status);
		return -EINVAL;
	}

	/*
	 * TODO: Unlike aie2, current version of FW interface doesn't define MSI info in the
	 * response. Return the MSI info once implemented
	 */
	*msi_address = 0;
	*msi_idx = 0;
	return 0;
}

int aie4_set_trace_categories(struct amdxdna_dev_hdl *ndev, u32 categories)
{
	DECLARE_AIE4_MSG(aie4_msg_set_event_trace_categories,
			 AIE4_MSG_OP_SET_EVENT_TRACE_CATEGORIES);
	struct amdxdna_dev *xdna = ndev->xdna;
	int ret;

	req.event_trace_categories = categories;

	ret = aie4_send_msg_wait(ndev, &msg);
	if (ret) {
		XDNA_ERR(xdna, "Failed to set fw trace categories, ret 0x%x", resp.status);
		return -EINVAL;
	}

	return 0;
}

int aie4_stop_fw_trace(struct amdxdna_dev_hdl *ndev)
{
	DECLARE_AIE4_MSG(aie4_msg_stop_event_trace, AIE4_MSG_OP_STOP_EVENT_TRACE);
	struct amdxdna_dev *xdna = ndev->xdna;
	int ret;

	ret = aie4_send_msg_wait(ndev, &msg);
	if (ret) {
		XDNA_ERR(xdna, "stop fw trace failed, ret 0x%x", resp.status);
		return -EINVAL;
	}

	return 0;
}

int aie4_attach_work_buffer(struct amdxdna_dev_hdl *ndev, u32 pasid, dma_addr_t addr, u32 size)
{
	DECLARE_AIE4_MSG(aie4_msg_dram_work_buffer, AIE4_MSG_OP_DRAM_WORK_BUFFER);
	struct amdxdna_dev *xdna = ndev->xdna;
	int ret;

	if (size < AIE4_MPNPUFW_DRAM_WORK_BUFFER_MIN_SIZE || !addr) {
		XDNA_ERR(xdna, "Invalid work buffer address 0x%llx or size %d", addr, size);
		return -EINVAL;
	}

	req.buff_addr = addr;
	req.buff_size = size;
	req.pasid.raw = pasid;

	ret = aie4_send_msg_wait(ndev, &msg);
	if (ret) {
		XDNA_ERR(xdna, "Failed to attach mpnpu work buffer, ret %d", ret);
		return ret;
	}

	return 0;
}

int aie4_detach_work_buffer(struct amdxdna_dev_hdl *ndev)
{
	DECLARE_AIE4_MSG(aie4_msg_release_dram_work_buffer, AIE4_MSG_OP_RELEASE_DRAM_WORK_BUFFER);
	struct amdxdna_dev *xdna = ndev->xdna;
	int ret;

	ret = aie4_send_msg_wait(ndev, &msg);
	if (ret) {
		XDNA_ERR(xdna, "Failed to detach mpnpu work buffer, ret %d", ret);
		return ret;
	}

	return ret;
}

int aie4_rw_aie_reg(struct amdxdna_dev_hdl *ndev, enum aie4_aie_debug_op op,
		    u32 ctx_id, u8 row, u8 col, u32 addr, u32 *value)
{
	DECLARE_AIE4_MSG(aie4_msg_aie4_debug_access, AIE4_MSG_OP_AIE_DEBUG_ACCESS);
	struct amdxdna_dev *xdna = ndev->xdna;
	int ret;

	req.opcode = op;
	req.hw_context_id = ctx_id;
	req.row = row;
	req.col = col;
	req.reg_access.reg_addr = addr;
	if (op == AIE4_AIE_DBG_OP_REG_WRITE)
		req.reg_access.reg_wval = *value;

	ret = aie4_send_msg_wait(ndev, &msg);
	if (ret) {
		XDNA_ERR(xdna, "AIE reg %s failed, ret %d",
			 op == AIE4_AIE_DBG_OP_REG_READ ? "read" : "write", ret);
		return ret;
	}

	if (op == AIE4_AIE_DBG_OP_REG_READ)
		*value = resp.reg_access.reg_rval;

	XDNA_DBG(xdna, "AIE reg %s ctx %u row %u col %u addr 0x%x value 0x%x",
		 op == AIE4_AIE_DBG_OP_REG_READ ? "read" : "write",
		 ctx_id, row, col, addr, *value);

	return 0;
}

int aie4_rw_aie_mem(struct amdxdna_dev_hdl *ndev, enum aie4_aie_debug_op op,
		    u32 ctx_id, u8 row, u8 col, u32 aie_addr, u64 dram_addr,
		    u32 size, u32 pasid)
{
	DECLARE_AIE4_MSG(aie4_msg_aie4_debug_access, AIE4_MSG_OP_AIE_DEBUG_ACCESS);
	struct amdxdna_dev *xdna = ndev->xdna;
	int ret;

	req.opcode = op;
	req.hw_context_id = ctx_id;
	req.row = row;
	req.col = col;
	req.mem_access.buffer_addr = dram_addr;
	req.mem_access.buffer_size = size;
	req.mem_access.mem_addr = aie_addr;
	req.mem_access.mem_size = size;
	req.mem_access.pasid.raw = 0;
	req.mem_access.pasid.f.pasid = pasid;
	req.mem_access.pasid.f.pasid_vld = 1;

	ret = aie4_send_msg_wait(ndev, &msg);
	if (ret) {
		XDNA_ERR(xdna, "AIE mem %s failed, ret %d",
			 op == AIE4_AIE_DBG_OP_BLOCK_READ ? "read" : "write", ret);
		return ret;
	}

	XDNA_DBG(xdna, "AIE mem %s ctx %u row %u col %u aie_addr 0x%x size %u",
		 op == AIE4_AIE_DBG_OP_BLOCK_READ ? "read" : "write",
		 ctx_id, row, col, aie_addr, size);

	return 0;
}

int aie4_get_aie_coredump(struct amdxdna_dev_hdl *ndev, struct amdxdna_mgmt_dma_hdl *dma_hdl,
			  u32 context_id, u32 pasid, u32 num_bufs)
{
	DECLARE_AIE4_MSG(aie4_msg_aie4_coredump, AIE4_MSG_OP_AIE_COREDUMP);
	struct amdxdna_dev *xdna = ndev->xdna;
	dma_addr_t addr;
	int ret;

	addr = amdxdna_mgmt_buff_get_dma_addr(dma_hdl);
	if (!addr) {
		XDNA_ERR(xdna, "Invalid DMA address: %lld", addr);
		return -EINVAL;
	}

	req.context_id = context_id;
	req.pasid.raw = 0;
	req.pasid.f.pasid = pasid;
	req.pasid.f.pasid_vld = 1;
	req.num_buffers = num_bufs;
	req.reserved = 0;
	req.buffer_list_addr = addr;

	ret = aie4_send_msg_wait(ndev, &msg);
	if (ret) {
		XDNA_ERR(xdna, "Get AIE coredump failed, status 0x%x", resp.status);
		return -EINVAL;
	}

	return 0;
}

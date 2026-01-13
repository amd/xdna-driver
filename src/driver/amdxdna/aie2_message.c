// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2023-2025, Advanced Micro Devices, Inc.
 */

#include <linux/kthread.h>
#include <drm/drm_cache.h>

#include "drm_local/amdxdna_accel.h"
#include "amdxdna_mailbox_helper.h"
#include "amdxdna_trace.h"
#include "amdxdna_ctx.h"
#include "amdxdna_pm.h"
#include "aie2_msg_priv.h"
#include "aie2_pci.h"

#define DECLARE_AIE2_MSG(name, op) \
	DECLARE_XDNA_MSG_COMMON(name, op, MAX_AIE2_STATUS_CODE)

#define EXEC_MSG_OPS(xdna)	((xdna)->dev_handle->exec_msg_ops)

static bool
is_supported_rt_cfg(struct amdxdna_dev_hdl *ndev, u32 type)
{
	const struct rt_cfg_ver *rt_cfg_tbl;
	int i;

	rt_cfg_tbl = ndev->priv->optional_cfg;
	if (!rt_cfg_tbl)
		return false;

	for (i = 0; rt_cfg_tbl[i].min_fw_version; i++) {
		if (rt_cfg_tbl[i].type != type)
			continue;

		if (ndev->mgmt_fw_version >= rt_cfg_tbl[i].min_fw_version)
			return true;

		XDNA_DBG(ndev->xdna, "Runtime cfg %d requires %d.%d, fw is %d.%d", type,
			 AIE2_FW_MAJOR(rt_cfg_tbl[i].min_fw_version),
			 AIE2_FW_MINOR(rt_cfg_tbl[i].min_fw_version),
			 AIE2_FW_MAJOR(ndev->mgmt_fw_version),
			 AIE2_FW_MINOR(ndev->mgmt_fw_version));
		return false;
	}

	return false;
}

static int aie2_send_mgmt_msg_wait(struct amdxdna_dev_hdl *ndev,
				   struct xdna_mailbox_msg *msg)
{
	struct amdxdna_dev *xdna = ndev->xdna;
	struct xdna_notify *hdl = msg->handle;
	int ret;

	if (!ndev->mgmt_chann)
		return -ENODEV;

	drm_WARN_ON(&xdna->ddev, !mutex_is_locked(&ndev->aie2_lock));
	ret = xdna_send_msg_wait(xdna, ndev->mgmt_chann, msg);
	if (ret == -ETIME) {
		xdna_mailbox_stop_channel(ndev->mgmt_chann);
		xdna_mailbox_destroy_channel(ndev->mgmt_chann);
		ndev->mgmt_chann = NULL;
	}

	if (!ret && *hdl->status != AIE2_STATUS_SUCCESS) {
		XDNA_ERR(xdna, "command opcode 0x%x failed, status 0x%x",
			 msg->opcode, *hdl->data);
		ret = -EINVAL;
	}

	return ret;
}

bool aie2_is_supported_msg(struct amdxdna_dev_hdl *ndev, enum aie2_msg_opcode opcode)
{
	const struct msg_op_ver *op_tbl;
	int i;

	op_tbl = ndev->priv->optional_msg;
	if (!op_tbl)
		return false;

	for (i = 0; op_tbl[i].min_fw_version; i++) {
		if (op_tbl[i].op != opcode)
			continue;

		if (ndev->mgmt_fw_version >= op_tbl[i].min_fw_version)
			return true;

		XDNA_DBG(ndev->xdna, "Opcode %d requires %d.%d, fw is %d.%d", opcode,
			 AIE2_FW_MAJOR(op_tbl[i].min_fw_version),
			 AIE2_FW_MINOR(op_tbl[i].min_fw_version),
			 AIE2_FW_MAJOR(ndev->mgmt_fw_version),
			 AIE2_FW_MINOR(ndev->mgmt_fw_version));
		return false;
	}

	return false;
}

int aie2_suspend_fw(struct amdxdna_dev_hdl *ndev)
{
	DECLARE_AIE2_MSG(suspend, MSG_OP_SUSPEND);
	int ret;

	ret = aie2_send_mgmt_msg_wait(ndev, &msg);
	if (ret) {
		XDNA_ERR(ndev->xdna, "Failed to suspend fw, ret %d", ret);
		return ret;
	}

	return aie2_psp_waitmode_poll(ndev->psp_hdl);
}

int aie2_resume_fw(struct amdxdna_dev_hdl *ndev)
{
	DECLARE_AIE2_MSG(suspend, MSG_OP_RESUME);

	return aie2_send_mgmt_msg_wait(ndev, &msg);
}

int aie2_set_runtime_cfg(struct amdxdna_dev_hdl *ndev, u32 type, u64 value)
{
	DECLARE_AIE2_MSG(set_runtime_cfg, MSG_OP_SET_RUNTIME_CONFIG);
	int ret;

	req.type = type;
	req.value = value;

	ret = aie2_send_mgmt_msg_wait(ndev, &msg);
	if (ret) {
		XDNA_ERR(ndev->xdna, "Failed to set runtime config, ret %d", ret);
		return ret;
	}

	return 0;
}

int aie2_get_runtime_cfg(struct amdxdna_dev_hdl *ndev, u32 type, u64 *value)
{
	DECLARE_AIE2_MSG(get_runtime_cfg, MSG_OP_GET_RUNTIME_CONFIG);
	int ret;

	req.type = type;
	ret = aie2_send_mgmt_msg_wait(ndev, &msg);
	if (ret) {
		XDNA_ERR(ndev->xdna, "Failed to get runtime config, ret %d", ret);
		return ret;
	}

	*value = resp.value;
	return 0;
}

int aie2_fine_preemption(struct amdxdna_dev_hdl *ndev, bool disable)
{
	u32 value = disable ? 0 : 1;
	u32 type = NPU4_RT_TYPE_FINE_PREEMPTION;

	if (!is_supported_rt_cfg(ndev, type)) {
		XDNA_DBG(ndev->xdna, "Skipped");
		return 0;
	}

	return aie2_set_runtime_cfg(ndev, type, value);
}

int aie2_force_preemption(struct amdxdna_dev_hdl *ndev, u32 hwctx_id)
{
	u32 type = NPU4_RT_TYPE_FORCE_PREEMPTION;

	if (!is_supported_rt_cfg(ndev, type)) {
		XDNA_DBG(ndev->xdna, "Skipped");
		return 0;
	}

	return aie2_set_runtime_cfg(ndev, type, hwctx_id);
}

int aie2_frame_boundary_preemption(struct amdxdna_dev_hdl *ndev, bool enable)
{
	/* Invert the values to map firmware interface */
	u32 value = enable ? 0 : 1;
	u32 type = NPU4_RT_TYPE_FRAME_BOUNDARY_PREEMPTION;
	int ret;

	if (!is_supported_rt_cfg(ndev, type)) {
		XDNA_DBG(ndev->xdna, "Skipped");
		return 0;
	}

	ret = aie2_set_runtime_cfg(ndev, type, value);
	if (ret)
		return ret;

	ndev->frame_boundary_preempt = enable;
	return 0;
}

int aie2_set_log_level(struct amdxdna_dev_hdl *ndev, enum fw_log_level level)
{
	u32 type = NPU4_RT_TYPE_LOG_LEVEL;

	if (!is_supported_rt_cfg(ndev, type)) {
		XDNA_DBG(ndev->xdna, "Skipped");
		return 0;
	}

	return aie2_set_runtime_cfg(ndev, type, level);
}

int aie2_set_log_format(struct amdxdna_dev_hdl *ndev, enum fw_log_format format)
{
	u32 type = NPU4_RT_TYPE_LOG_FORMAT;

	if (!is_supported_rt_cfg(ndev, type)) {
		XDNA_DBG(ndev->xdna, "Skipped");
		return 0;
	}

	return aie2_set_runtime_cfg(ndev, type, format);
}

int aie2_set_log_destination(struct amdxdna_dev_hdl *ndev, enum fw_log_destination destination)
{
	u32 type = NPU4_RT_TYPE_LOG_DESTINATION;

	if (!is_supported_rt_cfg(ndev, type)) {
		XDNA_DBG(ndev->xdna, "Skipped");
		return 0;
	}

	return aie2_set_runtime_cfg(ndev, type, destination);
}

static int
aie2_runtime_update_prop(struct amdxdna_dev_hdl *ndev,
			 struct amdxdna_ctx *ctx, u32 type, u32 value)
{
	DECLARE_AIE2_MSG(update_property, MSG_OP_UPDATE_PROPERTY);
	int ret;

	if (!aie2_is_supported_msg(ndev, MSG_OP_UPDATE_PROPERTY))
		return -EOPNOTSUPP;

	if (ctx)
		req.context_id = ctx->priv->id;
	else
		req.context_id = AIE2_UPDATE_PROPERTY_ALL_CTX;

	req.time_quota_us = value;
	req.type = type;

	ret = aie2_send_mgmt_msg_wait(ndev, &msg);
	if (ret) {
		XDNA_ERR(ndev->xdna, "%s update property failed, type %d ret %d",
			 ctx ? ctx->name : "All", type, ret);
		return ret;
	}

	return 0;
}

int aie2_update_prop_time_quota(struct amdxdna_dev_hdl *ndev,
				struct amdxdna_ctx *ctx, u32 us)
{
	int ret;

	ret = aie2_runtime_update_prop(ndev, ctx, UPDATE_PROPERTY_TIME_QUOTA, us);
	if (ret == -EOPNOTSUPP) {
		XDNA_DBG(ndev->xdna, "update time quota not support, skipped");
		return 0;
	}

	if (!ret) {
		XDNA_DBG(ndev->xdna, "%s execution time quantum updated to %d us",
			 ctx ? ctx->name : "All", us);
	}
	return ret;
}

int aie2_check_protocol_version(struct amdxdna_dev_hdl *ndev)
{
	DECLARE_AIE2_MSG(protocol_version, MSG_OP_GET_PROTOCOL_VERSION);
	struct amdxdna_dev *xdna = ndev->xdna;
	int ret;

	ret = aie2_send_mgmt_msg_wait(ndev, &msg);
	if (ret) {
		XDNA_ERR(xdna, "Failed to get protocol version, ret %d", ret);
		return ret;
	}

	ret = aie2_check_protocol(ndev, resp.major, resp.minor);
	if (ret) {
		XDNA_ERR(xdna, "Failed check protocol %d.%d", resp.major, resp.minor);
		return -EINVAL;
	}

	return 0;
}

int aie2_calibrate_time(struct amdxdna_dev_hdl *ndev)
{
	DECLARE_AIE2_MSG(calibrate_time, MSG_OP_CALIBRATE_TIME);
	int ret;

	if (!aie2_is_supported_msg(ndev, MSG_OP_CALIBRATE_TIME)) {
		XDNA_DBG(ndev->xdna, "Calibrate time not supported, skipped");
		return 0;
	}

	req.timestamp_ns = ktime_get_real_ns();

	ret = aie2_send_mgmt_msg_wait(ndev, &msg);
	if (ret) {
		XDNA_ERR(ndev->xdna, "Calibrate time failed, ret %d", ret);
		return ret;
	}

	XDNA_DBG(ndev->xdna, "System clock calibrated with firmware");
	return 0;
}

int aie2_query_aie_telemetry(struct amdxdna_dev_hdl *ndev, struct amdxdna_mgmt_dma_hdl *dma_hdl,
			     u32 type, u32 size, struct aie_version *version)
{
	DECLARE_AIE2_MSG(get_telemetry, MSG_OP_GET_TELEMETRY);
	struct amdxdna_dev *xdna = ndev->xdna;
	dma_addr_t addr;
	int ret;

	if (type >= MAX_TELEMETRY_TYPE) {
		XDNA_ERR(xdna, "Invalid telemetry type %d", type);
		return -EINVAL;
	}

	addr = amdxdna_mgmt_buff_get_dma_addr(dma_hdl);
	if (!addr) {
		XDNA_ERR(xdna, "Invalid DMA address: %lld", addr);
		return -EINVAL;
	}

	req.buf_addr = addr;
	req.buf_size = size;
	req.type = type;

	ret = aie2_send_mgmt_msg_wait(ndev, &msg);
	if (ret) {
		XDNA_ERR(xdna, "Failed to get telemetry, ret %d", ret);
		return ret;
	}

	XDNA_DBG(xdna, "Telemetry type %d major %d minor %d",
		 type, resp.major, resp.minor);

	if (version) {
		version->major = resp.major;
		version->minor = resp.minor;
	}

	return 0;
}

int aie2_assign_mgmt_pasid(struct amdxdna_dev_hdl *ndev, u16 pasid)
{
	DECLARE_AIE2_MSG(assign_mgmt_pasid, MSG_OP_ASSIGN_MGMT_PASID);

	req.pasid = pasid;

	return aie2_send_mgmt_msg_wait(ndev, &msg);
}

int aie2_query_aie_version(struct amdxdna_dev_hdl *ndev, struct aie_version *version)
{
	DECLARE_AIE2_MSG(aie_version_info, MSG_OP_QUERY_AIE_VERSION);
	struct amdxdna_dev *xdna = ndev->xdna;
	int ret;

	ret = aie2_send_mgmt_msg_wait(ndev, &msg);
	if (ret)
		return ret;

	XDNA_DBG(xdna, "Query AIE version - major: %u minor: %u completed",
		 resp.major, resp.minor);

	version->major = resp.major;
	version->minor = resp.minor;

	return 0;
}

int aie2_query_aie_metadata(struct amdxdna_dev_hdl *ndev, struct aie_metadata *metadata)
{
	DECLARE_AIE2_MSG(aie_tile_info, MSG_OP_QUERY_AIE_TILE_INFO);
	int ret;

	ret = aie2_send_mgmt_msg_wait(ndev, &msg);
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

int aie2_query_aie_firmware_version(struct amdxdna_dev_hdl *ndev,
				    struct amdxdna_fw_ver *fw_ver)
{
	DECLARE_AIE2_MSG(firmware_version, MSG_OP_GET_FIRMWARE_VERSION);
	int ret;

	ret = aie2_send_mgmt_msg_wait(ndev, &msg);
	if (ret)
		return ret;

	fw_ver->major = resp.major;
	fw_ver->minor = resp.minor;
	fw_ver->sub = resp.sub;
	fw_ver->build = resp.build;

	XDNA_DBG(ndev->xdna, "FW version %d.%d.%d.%d", fw_ver->major,
		 fw_ver->minor, fw_ver->sub, fw_ver->build);

	return 0;
}

int aie2_get_dev_revision(struct amdxdna_dev_hdl *ndev, enum aie2_dev_revision *rev)
{
	DECLARE_AIE2_MSG(get_dev_revision, MSG_OP_GET_DEV_REVISION);
	int ret;

	if (!aie2_is_supported_msg(ndev, MSG_OP_GET_DEV_REVISION))
		return -EOPNOTSUPP;

	ret = aie2_send_mgmt_msg_wait(ndev, &msg);
	if (ret)
		return ret;

	*rev = resp.rev;

	if (*rev >= AIE2_DEV_REVISION_UNKN) {
		XDNA_ERR(ndev->xdna, "Unknown device revision: %d (raw fuse: 0x%x)",
			 *rev, resp.raw_fuse_data);
		return -EINVAL;
	}

	XDNA_DBG(ndev->xdna, "Device revision: %d (raw fuse: 0x%x)", *rev, resp.raw_fuse_data);

	return 0;
}

int aie2_config_fw_log(struct amdxdna_dev_hdl *ndev, struct amdxdna_mgmt_dma_hdl *dma_hdl,
		       size_t size, u32 *msi_idx, u32 *msi_address)
{
	DECLARE_AIE2_MSG(config_fw_log, MSG_OP_CONFIG_FW_LOG);
	struct amdxdna_dev *xdna = ndev->xdna;
	dma_addr_t addr;
	int ret;

	if (!aie2_is_supported_msg(ndev, MSG_OP_CONFIG_FW_LOG))
		return -EOPNOTSUPP;

	addr = amdxdna_mgmt_buff_get_dma_addr(dma_hdl);
	if (!addr) {
		XDNA_ERR(xdna, "Invalid DMA address: %lld", addr);
		return -EINVAL;
	}

	/* Cmd with buffer size 0 detaches log buffer from FW */
	req.buf_size = size;
	req.buf_addr = addr;

	ret = aie2_send_mgmt_msg_wait(ndev, &msg);
	if (ret) {
		XDNA_ERR(xdna, "Config fw log failed, ret 0x%x", resp.status);
		return -EINVAL;
	}

	if (size && msi_idx && msi_address) {
		*msi_address = resp.msi_address;
		*msi_idx = resp.msi_idx;
	}

	return 0;
}

int aie2_set_trace_categories(struct amdxdna_dev_hdl *ndev, u32 categories)
{
	DECLARE_AIE2_MSG(set_fw_trace_categories, MSG_OP_SET_FW_TRACE_CATEGORIES);
	struct amdxdna_dev *xdna = ndev->xdna;
	int ret;

	if (!aie2_is_supported_msg(ndev, MSG_OP_SET_FW_TRACE_CATEGORIES))
		return -EOPNOTSUPP;

	req.fw_trace_categories = categories;

	ret = aie2_send_mgmt_msg_wait(ndev, &msg);
	if (ret) {
		XDNA_ERR(xdna, "Failed to set fw trace categories, ret 0x%x", resp.status);
		return -EINVAL;
	}

	return 0;
}

int aie2_start_fw_trace(struct amdxdna_dev_hdl *ndev, struct amdxdna_mgmt_dma_hdl *dma_hdl,
			size_t size, u32 categories, u32 *msi_idx, u32 *msi_address)
{
	DECLARE_AIE2_MSG(start_fw_trace, MSG_OP_START_FW_TRACE);
	struct amdxdna_dev *xdna = ndev->xdna;
	dma_addr_t addr;
	int ret;

	if (!aie2_is_supported_msg(ndev, MSG_OP_START_FW_TRACE))
		return -EOPNOTSUPP;

	addr = amdxdna_mgmt_buff_get_dma_addr(dma_hdl);
	if (!addr) {
		XDNA_ERR(xdna, "Invalid DMA address: %lld", addr);
		return -EINVAL;
	}

	req.destination = FW_TRACE_DESTINATION_DRAM;
	req.timestamp = FW_TRACE_TIMESTAMP_FW_CHRONO;
	req.categories = categories;
	req.buf_size = size;
	req.buf_addr = addr;

	ret = aie2_send_mgmt_msg_wait(ndev, &msg);
	if (ret) {
		XDNA_ERR(xdna, "start fw trace failed, ret 0x%x", resp.status);
		return -EINVAL;
	}

	*msi_address = resp.msi_address;
	*msi_idx = resp.msi_idx;
	return 0;
}

int aie2_stop_fw_trace(struct amdxdna_dev_hdl *ndev)
{
	DECLARE_AIE2_MSG(stop_fw_trace, MSG_OP_STOP_FW_TRACE);
	struct amdxdna_dev *xdna = ndev->xdna;
	int ret;

	if (!aie2_is_supported_msg(ndev, MSG_OP_STOP_FW_TRACE))
		return -EOPNOTSUPP;

	ret = aie2_send_mgmt_msg_wait(ndev, &msg);
	if (ret) {
		XDNA_ERR(xdna, "stop fw trace failed, ret 0x%x", resp.status);
		return -EINVAL;
	}

	return 0;
}

int aie2_create_context(struct amdxdna_dev_hdl *ndev, struct amdxdna_ctx *ctx,
			struct xdna_mailbox_chann_info *info)
{
	DECLARE_AIE2_MSG(create_ctx, MSG_OP_CREATE_CONTEXT);
	struct amdxdna_dev *xdna = ndev->xdna;
	struct cq_pair *cq_pair;
	int ret;

	req.aie_type = 1;
	req.start_col = ctx->start_col;
	req.num_col = ctx->num_col;
	req.num_unused_col = ctx->num_col - ctx->priv->orig_num_col;
	req.num_cq_pairs_requested = 1;
	req.pasid = ctx->client->pasid;
	req.context_priority = ctx->priv->priority + 1;

	ret = aie2_send_mgmt_msg_wait(ndev, &msg);
	if (ret)
		return ret;

	ctx->priv->id = resp.context_id;
	WARN_ONCE(ctx->priv->id == -1, "Unexpected context id");

	if (ndev->force_preempt_enabled) {
		ret = aie2_force_preemption(ndev, ctx->priv->id);
		WARN_ONCE(ret, "Failed to config force preemption");
	}

	info->msix_id = resp.msix_id;
	cq_pair = &resp.cq_pair[0];
	info->x2i.mb_head_ptr_reg = AIE2_MBOX_OFF(ndev, cq_pair->x2i_q.head_addr);
	info->x2i.mb_tail_ptr_reg = AIE2_MBOX_OFF(ndev, cq_pair->x2i_q.tail_addr);
	info->x2i.rb_start_addr   = AIE2_SRAM_OFF(ndev, cq_pair->x2i_q.buf_addr);
	info->x2i.rb_size	    = cq_pair->x2i_q.buf_size;

	info->i2x.mb_head_ptr_reg = AIE2_MBOX_OFF(ndev, cq_pair->i2x_q.head_addr);
	info->i2x.mb_tail_ptr_reg = AIE2_MBOX_OFF(ndev, cq_pair->i2x_q.tail_addr);
	info->i2x.rb_start_addr   = AIE2_SRAM_OFF(ndev, cq_pair->i2x_q.buf_addr);
	info->i2x.rb_size	  = cq_pair->i2x_q.buf_size;

	aie2_calc_intr_reg(info);
	XDNA_DBG(xdna,
		 "%s created hwctx %d pasid %d priority 0x%x start col %d num col %d unused col %d",
		 ctx->name, ctx->priv->id, ctx->client->pasid, ctx->qos.priority, ctx->start_col,
		 ctx->num_col, req.num_unused_col);

	return 0;
}

int aie2_destroy_context(struct amdxdna_dev_hdl *ndev, struct amdxdna_ctx *ctx)
{
	DECLARE_AIE2_MSG(destroy_ctx, MSG_OP_DESTROY_CONTEXT);
	struct amdxdna_dev *xdna = ndev->xdna;
	int ret;

	if (ctx->priv->id == -1)
		return 0;

	req.context_id = ctx->priv->id;
	ret = aie2_send_mgmt_msg_wait(ndev, &msg);
	if (ret)
		XDNA_WARN(xdna, "%s destroy context failed, ret %d", ctx->name, ret);

	trace_amdxdna_debug_point(ctx->name, 0, "channel destroyed");
	XDNA_DBG(xdna, "%s destroyed hwctx %d", ctx->name, ctx->priv->id);
	ctx->priv->id = -1;

	return ret;
}

int aie2_map_host_buf(struct amdxdna_dev_hdl *ndev, u32 context_id, u64 addr, u64 size)
{
	DECLARE_AIE2_MSG(host_buffer, MSG_OP_MAP_HOST_BUFFER);
	struct amdxdna_dev *xdna = ndev->xdna;
	size_t chunk_size;
	int ret;

	chunk_size = xdna->dev_info->dev_mem_size;
	WARN_ON(!is_power_of_2(chunk_size));
	WARN_ON(!IS_ALIGNED(size, chunk_size));
	do {
		req.context_id = context_id;
		req.buf_addr = addr;
		req.buf_size = chunk_size;
		ret = aie2_send_mgmt_msg_wait(ndev, &msg);
		if (ret) {
			XDNA_ERR(xdna, "hwctx %d addr 0x%llx size 0x%lx",
				 context_id, addr, chunk_size);
			return ret;
		}

		XDNA_DBG(xdna, "hwctx %d map host buf addr 0x%llx size 0x%lx",
			 context_id, addr, chunk_size);

		addr += chunk_size;
		size -= chunk_size;
		/* Change opcode if there are more than one chunk */
		msg.opcode = MSG_OP_ADD_HOST_BUFFER;
	} while (size);

	return 0;
}

#if defined(CONFIG_DEBUG_FS)
int aie2_self_test(struct amdxdna_dev_hdl *ndev)
{
	DECLARE_AIE2_MSG(check_self_test, MSG_OP_INVOKE_SELF_TEST);

	req.test_mask = 0x3F;
	return aie2_send_mgmt_msg_wait(ndev, &msg);
}
#else
int aie2_self_test(struct amdxdna_dev_hdl *ndev)
{
	return 0;
}
#endif

int aie2_query_aie_status(struct amdxdna_dev_hdl *ndev, char __user *buf,
			  u32 size, u32 *cols_filled)
{
	DECLARE_AIE2_MSG(aie_column_info, MSG_OP_QUERY_COL_STATUS);
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

	addr = amdxdna_mgmt_buff_get_dma_addr(dma_hdl);
	if (!addr) {
		XDNA_ERR(xdna, "Invalid DMA address: %lld", addr);
		return -EINVAL;
	}

	*cols_filled = 0;
	req.dump_buff_addr = addr;
	req.dump_buff_size = size;
	req.num_cols = hweight32(aie_bitmap);
	req.aie_bitmap = aie_bitmap;

	amdxdna_mgmt_buff_clflush(dma_hdl, 0, 0);
	ret = aie2_send_mgmt_msg_wait(ndev, &msg);
	if (ret) {
		XDNA_ERR(xdna, "Error during NPU query, status %d", ret);
		goto fail;
	}

	if (resp.status != AIE2_STATUS_SUCCESS) {
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

int aie2_register_asyn_event_msg(struct amdxdna_dev_hdl *ndev,
				 struct amdxdna_mgmt_dma_hdl *dma_hdl, void *handle,
				 int (*cb)(void*, void __iomem *, size_t))
{
	struct async_event_msg_req req = { 0 };
	struct xdna_mailbox_msg msg = {
		.send_data = (u8 *)&req,
		.send_size = sizeof(req),
		.handle = handle,
		.opcode = MSG_OP_REGISTER_ASYNC_EVENT_MSG,
		.notify_cb = cb,
	};
	dma_addr_t addr;

	addr = amdxdna_mgmt_buff_get_dma_addr(dma_hdl);
	if (!addr) {
		XDNA_ERR(ndev->xdna, "Invalid DMA address: %lld", addr);
		return -EINVAL;
	}

	req.buf_addr = addr;
	req.buf_size = ASYNC_BUF_SIZE;

	XDNA_DBG(ndev->xdna, "Register addr 0x%llx size 0x%x", req.buf_addr, req.buf_size);
	return xdna_mailbox_send_msg(ndev->mgmt_chann, &msg, TX_TIMEOUT);
}

void aie2_reset_app_health_report(struct app_health_report *r)
{
	if (!r)
		return;

	r->fatal_info.exception_type = AIE2_APP_HEALTH_RESET_FATAL_INFO;
	r->fatal_info.exception_pc = AIE2_APP_HEALTH_RESET_FATAL_INFO;
	r->fatal_info.app_module = AIE2_APP_HEALTH_RESET_FATAL_INFO;
	r->fatal_info.fatal_type = AIE2_APP_HEALTH_RESET_FATAL_INFO;
	r->txn_op_id = AIE2_APP_HEALTH_RESET_TXN_OP_ID;
	r->ctx_pc = AIE2_APP_HEALTH_RESET_CTX_PC;
}

int aie2_get_app_health(struct amdxdna_dev_hdl *ndev, struct amdxdna_mgmt_dma_hdl *dma_hdl,
			u32 context_id, u32 size)
{
	DECLARE_AIE2_MSG(get_app_health, MSG_OP_GET_APP_HEALTH);
	struct amdxdna_dev *xdna = ndev->xdna;
	dma_addr_t addr;
	int ret;

	if (!aie2_is_supported_msg(ndev, MSG_OP_GET_APP_HEALTH)) {
		XDNA_DBG(xdna, "Get app health unsupported for the device or firmware version");
		return -EOPNOTSUPP;
	}

	addr = amdxdna_mgmt_buff_get_dma_addr(dma_hdl);
	if (!addr) {
		XDNA_ERR(xdna, "Invalid DMA address: %lld", addr);
		return -EINVAL;
	}

	req.buf_addr = addr;
	req.context_id = context_id;
	req.buf_size = size;

	ret = aie2_send_mgmt_msg_wait(ndev, &msg);
	if (ret) {
		if (resp.status == AIE2_STATUS_MGMT_ERT_DRAM_BUFFER_SIZE_INVALID) {
			XDNA_ERR(xdna, "Invalid buffer size(required 0x%x) for get app health cmd",
				 resp.required_buffer_size);
		} else {
			XDNA_ERR(xdna, "Get app health got status 0x%x", resp.status);
		}
		ret = -EINVAL;
	}

	return ret;
}

static int aie2_notify_config_cu(void *handle, void __iomem *data, size_t size)
{
	struct amdxdna_dev *xdna = handle;
	int ret;

	ret = xdna_msg_noresp_cb(handle, data, size);
	amdxdna_pm_suspend_put(xdna);

	return ret;
}

/* Below messages are to hardware context mailbox channel */
int aie2_config_cu(struct amdxdna_ctx *ctx)
{
	struct mailbox_channel *chann = ctx->priv->mbox_chann;
	struct amdxdna_dev *xdna = ctx->client->xdna;
	u32 shift = xdna->dev_info->dev_mem_buf_shift;
	DECLARE_XDNA_MSG_NO_RESP(config_cu, MSG_OP_CONFIG_CU, xdna);
	struct drm_gem_object *gobj;
	struct amdxdna_gem_obj *abo;
	int ret, i;

	if (!ctx->cus)
		return 0;

	if (!chann)
		return -ENODEV;

	if (ctx->cus->num_cus > MAX_NUM_CUS) {
		XDNA_DBG(xdna, "Exceed maximum CU %d", MAX_NUM_CUS);
		return -EINVAL;
	}

	for (i = 0; i < ctx->cus->num_cus; i++) {
		struct amdxdna_cu_config *cu = &ctx->cus->cu_configs[i];

		gobj = drm_gem_object_lookup(ctx->client->filp, cu->cu_bo);
		if (!gobj) {
			XDNA_ERR(xdna, "Lookup GEM object failed");
			return -EINVAL;
		}
		abo = to_xdna_obj(gobj);

		if (abo->type != AMDXDNA_BO_DEV) {
			drm_gem_object_put(gobj);
			XDNA_ERR(xdna, "Invalid BO type");
			return -EINVAL;
		}

		req.cfgs[i] = FIELD_PREP(AIE2_MSG_CFG_CU_PDI_ADDR,
					 amdxdna_gem_dev_addr(abo) >> shift);
		req.cfgs[i] |= FIELD_PREP(AIE2_MSG_CFG_CU_FUNC, cu->cu_func);
		XDNA_DBG(xdna, "CU %d full addr 0x%llx, cfg 0x%x", i,
			 amdxdna_gem_dev_addr(abo), req.cfgs[i]);
		drm_gem_object_put(gobj);
	}
	req.num_cus = ctx->cus->num_cus;

	if (!pm_runtime_active(xdna->ddev.dev)) {
		XDNA_ERR(xdna, "Device inactive\n");
		return -EFAULT;
	}
	pm_runtime_get_noresume(xdna->ddev.dev);

	msg.notify_cb = aie2_notify_config_cu;
	ret = xdna_mailbox_send_msg(chann, &msg, TX_TIMEOUT);
	if (ret) {
		XDNA_ERR(xdna, "Send message failed, ret %d", ret);
		pm_runtime_put_noidle(xdna->ddev.dev);
	}

	return ret;
}

static int aie2_init_exec_cu_req(struct amdxdna_gem_obj *cmd_bo, void *req,
				 size_t *size, u32 *msg_op)
{
	struct execute_buffer_req *cu_req = req;
	u32 cmd_len;
	void *cmd;

	cmd = amdxdna_cmd_get_payload(cmd_bo, &cmd_len);
	if (!cmd)
		return -EINVAL;
	if (cmd_len > sizeof(cu_req->payload))
		return -EINVAL;

	cu_req->cu_idx = amdxdna_cmd_get_cu_idx(cmd_bo);
	if (cu_req->cu_idx == INVALID_CU_IDX)
		return -EINVAL;

	memcpy(cu_req->payload, cmd, cmd_len);

	*size = sizeof(*cu_req);
	*msg_op = MSG_OP_EXECUTE_BUFFER_CF;
	return 0;
}

static int aie2_init_exec_dpu_req(struct amdxdna_gem_obj *cmd_bo, void *req,
				  size_t *size, u32 *msg_op)
{
	struct exec_dpu_req *dpu_req = req;
	struct amdxdna_cmd_start_npu *sn;
	u32 cmd_len;

	sn = amdxdna_cmd_get_payload(cmd_bo, &cmd_len);
	if (!sn)
		return -EINVAL;
	if (cmd_len - sizeof(*sn) > sizeof(dpu_req->payload))
		return -EINVAL;

	dpu_req->cu_idx = amdxdna_cmd_get_cu_idx(cmd_bo);
	if (dpu_req->cu_idx == INVALID_CU_IDX)
		return -EINVAL;

	dpu_req->inst_buf_addr = sn->buffer;
	dpu_req->inst_size = sn->buffer_size;
	dpu_req->inst_prop_cnt = sn->prop_count;
	memcpy(dpu_req->payload, sn->prop_args, cmd_len - sizeof(*sn));

	*size = sizeof(*dpu_req);
	*msg_op = MSG_OP_EXEC_DPU;
	return 0;
}

static void aie2_init_exec_chain_req(void *req, u64 slot_addr, size_t size, u32 cmd_cnt)
{
	struct cmd_chain_req *chain_req = req;

	chain_req->buf_addr = slot_addr;
	chain_req->buf_size = size;
	chain_req->count = cmd_cnt;
}

static void aie2_init_npu_chain_req(void *req, u64 slot_addr, size_t size, u32 cmd_cnt)
{
	struct cmd_chain_npu_req *npu_chain_req = req;

	npu_chain_req->flags = 0;
	npu_chain_req->reserved = 0;
	npu_chain_req->buf_addr = slot_addr;
	npu_chain_req->buf_size = size;
	npu_chain_req->count = cmd_cnt;
}

static int
aie2_cmdlist_fill_cf(struct amdxdna_gem_obj *cmd_bo, void *slot, size_t *size)
{
	struct cmd_chain_slot_execbuf_cf *cf_slot = slot;
	u32 cmd_len;
	void *cmd;

	cmd = amdxdna_cmd_get_payload(cmd_bo, &cmd_len);
	if (!cmd)
		return -EINVAL;
	if (*size < sizeof(*cf_slot) + cmd_len)
		return -EINVAL;

	cf_slot->cu_idx = amdxdna_cmd_get_cu_idx(cmd_bo);
	if (cf_slot->cu_idx == INVALID_CU_IDX)
		return -EINVAL;

	cf_slot->arg_cnt = cmd_len / sizeof(u32);
	memcpy(cf_slot->args, cmd, cmd_len);
	/* Accurate slot size to hint firmware to do necessary copy */
	*size = sizeof(*cf_slot) + cmd_len;
	return 0;
}

static int
aie2_cmdlist_fill_dpu(struct amdxdna_gem_obj *cmd_bo, void *slot, size_t *size)
{
	struct cmd_chain_slot_dpu *dpu_slot = slot;
	struct amdxdna_cmd_start_npu *sn;
	u32 cmd_len;
	u32 arg_sz;

	sn = amdxdna_cmd_get_payload(cmd_bo, &cmd_len);
	if (!sn)
		return -EINVAL;
	arg_sz = cmd_len - sizeof(*sn);
	if (cmd_len < sizeof(*sn) || arg_sz > MAX_DPU_ARGS_SIZE)
		return -EINVAL;

	if (*size < sizeof(*dpu_slot) + arg_sz)
		return -EINVAL;

	dpu_slot->cu_idx = amdxdna_cmd_get_cu_idx(cmd_bo);
	if (dpu_slot->cu_idx == INVALID_CU_IDX)
		return -EINVAL;

	dpu_slot->inst_buf_addr = sn->buffer;
	dpu_slot->inst_size = sn->buffer_size;
	dpu_slot->inst_prop_cnt = sn->prop_count;
	dpu_slot->arg_cnt = arg_sz / sizeof(u32);
	memcpy(dpu_slot->args, sn->prop_args, arg_sz);

	/* Accurate slot size to hint firmware to do necessary copy */
	*size = sizeof(*dpu_slot) + arg_sz;
	return 0;
}

static int aie2_cmdlist_unsupp(struct amdxdna_gem_obj *cmd_bo, void *slot, size_t *size)
{
	return -EOPNOTSUPP;
}

static u32 aie2_get_chain_msg_op(u32 cmd_op)
{
	switch (cmd_op) {
	case ERT_START_CU:
		return MSG_OP_CHAIN_EXEC_BUFFER_CF;
	case ERT_START_NPU:
		return MSG_OP_CHAIN_EXEC_DPU;
	default:
		break;
	}

	return MSG_OP_MAX_OPCODE;
}

static struct aie2_exec_msg_ops legacy_exec_message_ops = {
	.init_cu_req = aie2_init_exec_cu_req,
	.init_dpu_req = aie2_init_exec_dpu_req,
	.init_chain_req = aie2_init_exec_chain_req,
	.fill_cf_slot = aie2_cmdlist_fill_cf,
	.fill_dpu_slot = aie2_cmdlist_fill_dpu,
	.fill_preempt_slot = aie2_cmdlist_unsupp,
	.fill_elf_slot = aie2_cmdlist_unsupp,
	.get_chain_msg_op = aie2_get_chain_msg_op,
};

static int
aie2_cmdlist_fill_npu_cf(struct amdxdna_gem_obj *cmd_bo, void *slot, size_t *size)
{
	struct cmd_chain_slot_npu *npu_slot = slot;
	u32 cmd_len;
	void *cmd;

	memset(npu_slot, 0, sizeof(*npu_slot));
	cmd = amdxdna_cmd_get_payload(cmd_bo, &cmd_len);
	if (!cmd)
		return -EINVAL;
	if (*size < sizeof(*npu_slot) + cmd_len)
		return -EINVAL;

	npu_slot->cu_idx = amdxdna_cmd_get_cu_idx(cmd_bo);
	if (npu_slot->cu_idx == INVALID_CU_IDX)
		return -EINVAL;

	npu_slot->type = EXEC_NPU_TYPE_NON_ELF;
	npu_slot->arg_cnt = cmd_len / sizeof(u32);
	memcpy(npu_slot->args, cmd, cmd_len);

	*size = sizeof(*npu_slot) + cmd_len;
	return 0;
}

static int
aie2_cmdlist_fill_npu_dpu(struct amdxdna_gem_obj *cmd_bo, void *slot, size_t *size)
{
	struct cmd_chain_slot_npu *npu_slot = slot;
	struct amdxdna_cmd_start_npu *sn;
	u32 cmd_len;
	u32 arg_sz;

	memset(npu_slot, 0, sizeof(*npu_slot));
	sn = amdxdna_cmd_get_payload(cmd_bo, &cmd_len);
	if (!sn)
		return -EINVAL;

	arg_sz = cmd_len - sizeof(*sn);
	if (cmd_len < sizeof(*sn) || arg_sz > MAX_NPU_ARGS_SIZE)
		return -EINVAL;

	if (*size < sizeof(*npu_slot) + arg_sz)
		return -EINVAL;

	npu_slot->cu_idx = amdxdna_cmd_get_cu_idx(cmd_bo);
	if (npu_slot->cu_idx == INVALID_CU_IDX)
		return -EINVAL;

	npu_slot->type = EXEC_NPU_TYPE_PARTIAL_ELF;
	npu_slot->inst_buf_addr = sn->buffer;
	npu_slot->inst_size = sn->buffer_size;
	npu_slot->inst_prop_cnt = sn->prop_count;
	npu_slot->arg_cnt = arg_sz / sizeof(u32);
	memcpy(npu_slot->args, sn->prop_args, arg_sz);

	*size = sizeof(*npu_slot) + arg_sz;
	return 0;
}

static int
aie2_cmdlist_fill_npu_preempt(struct amdxdna_gem_obj *cmd_bo, void *slot, size_t *size)
{
	struct cmd_chain_slot_npu *npu_slot = slot;
	struct amdxdna_cmd_preempt_data *pd;
	u32 cmd_len;
	u32 arg_sz;

	memset(npu_slot, 0, sizeof(*npu_slot));
	pd = amdxdna_cmd_get_payload(cmd_bo, &cmd_len);
	if (!pd)
		return -EINVAL;

	arg_sz = cmd_len - sizeof(*pd);
	if (cmd_len < sizeof(*pd) || arg_sz > MAX_NPU_ARGS_SIZE)
		return -EINVAL;

	if (*size < sizeof(*npu_slot) + arg_sz)
		return -EINVAL;

	npu_slot->cu_idx = amdxdna_cmd_get_cu_idx(cmd_bo);
	if (npu_slot->cu_idx == INVALID_CU_IDX)
		return -EINVAL;

	npu_slot->type = EXEC_NPU_TYPE_PREEMPT;
	npu_slot->inst_buf_addr = pd->inst_buf;
	npu_slot->save_buf_addr = pd->save_buf;
	npu_slot->restore_buf_addr = pd->restore_buf;
	npu_slot->inst_size = pd->inst_size;
	npu_slot->save_size = pd->save_size;
	npu_slot->restore_size = pd->restore_size;
	npu_slot->inst_prop_cnt = pd->inst_prop_cnt;
	npu_slot->arg_cnt = arg_sz / sizeof(u32);
	memcpy(npu_slot->args, pd->prop_args, arg_sz);

	*size = sizeof(*npu_slot) + arg_sz;
	return 0;
}

static int
aie2_cmdlist_fill_npu_elf(struct amdxdna_gem_obj *cmd_bo, void *slot, size_t *size)
{
	struct cmd_chain_slot_npu *npu_slot = slot;
	struct amdxdna_cmd_preempt_data *pd;
	u32 cmd_len;
	u32 arg_sz;

	memset(npu_slot, 0, sizeof(*npu_slot));
	pd = amdxdna_cmd_get_payload(cmd_bo, &cmd_len);
	if (!pd)
		return -EINVAL;

	arg_sz = cmd_len - sizeof(*pd);
	if (cmd_len < sizeof(*pd) || arg_sz > MAX_NPU_ARGS_SIZE)
		return -EINVAL;

	if (*size < sizeof(*npu_slot) + arg_sz)
		return -EINVAL;

	npu_slot->type = EXEC_NPU_TYPE_ELF;
	npu_slot->inst_buf_addr = pd->inst_buf;
	npu_slot->save_buf_addr = pd->save_buf;
	npu_slot->restore_buf_addr = pd->restore_buf;
	npu_slot->inst_size = pd->inst_size;
	npu_slot->save_size = pd->save_size;
	npu_slot->restore_size = pd->restore_size;
	npu_slot->inst_prop_cnt = pd->inst_prop_cnt;
	npu_slot->arg_cnt = 1;
	npu_slot->args[0] = AIE2_EXEC_BUFFER_KERNEL_OP_TXN;

	*size = struct_size(npu_slot, args, npu_slot->arg_cnt);
	return 0;
}

static u32 aie2_get_npu_chain_msg_op(u32 cmd_op)
{
	return MSG_OP_CHAIN_EXEC_NPU;
}

static struct aie2_exec_msg_ops npu_exec_message_ops = {
	.init_cu_req = aie2_init_exec_cu_req,
	.init_dpu_req = aie2_init_exec_dpu_req,
	.init_chain_req = aie2_init_npu_chain_req,
	.fill_cf_slot = aie2_cmdlist_fill_npu_cf,
	.fill_dpu_slot = aie2_cmdlist_fill_npu_dpu,
	.fill_preempt_slot = aie2_cmdlist_fill_npu_preempt,
	.fill_elf_slot = aie2_cmdlist_fill_npu_elf,
	.get_chain_msg_op = aie2_get_npu_chain_msg_op,
};

static int aie2_init_exec_req(void *req, struct amdxdna_gem_obj *cmd_abo,
			      size_t *size, u32 *msg_op)
{
	struct amdxdna_dev *xdna = cmd_abo->client->xdna;
	int ret;
	u32 op;

	op = amdxdna_cmd_get_op(cmd_abo);
	switch (op) {
	case ERT_START_CU:
		ret = EXEC_MSG_OPS(xdna)->init_cu_req(cmd_abo, req, size, msg_op);
		if (ret) {
			XDNA_DBG(xdna, "Init CU req failed ret %d", ret);
			return ret;
		}
		break;
	case ERT_START_NPU:
		ret = EXEC_MSG_OPS(xdna)->init_dpu_req(cmd_abo, req, size, msg_op);
		if (ret) {
			XDNA_DBG(xdna, "Init DPU req failed ret %d", ret);
			return ret;
		}

		break;
	default:
		XDNA_ERR(xdna, "Unsupported op %d", op);
		ret = -EOPNOTSUPP;
		break;
	}

	return ret;
}

static int
aie2_cmdlist_fill_slot(void *slot, struct amdxdna_gem_obj *cmd_abo,
		       size_t *size, u32 *cmd_op)
{
	struct amdxdna_dev *xdna = cmd_abo->client->xdna;
	int ret;
	u32 op;

	op = amdxdna_cmd_get_op(cmd_abo);
	if (*cmd_op == ERT_INVALID_CMD)
		*cmd_op = op;
	else if (op != *cmd_op)
		return -EINVAL;

	switch (op) {
	case ERT_START_CU:
		ret = EXEC_MSG_OPS(xdna)->fill_cf_slot(cmd_abo, slot, size);
		break;
	case ERT_START_NPU:
		ret = EXEC_MSG_OPS(xdna)->fill_dpu_slot(cmd_abo, slot, size);
		break;
	case ERT_START_NPU_PREEMPT:
		if (!AIE2_FEATURE_ON(xdna->dev_handle, AIE2_PREEMPT))
			return -EOPNOTSUPP;
		ret = EXEC_MSG_OPS(xdna)->fill_preempt_slot(cmd_abo, slot, size);
		break;
	case ERT_START_NPU_PREEMPT_ELF:
		if (!AIE2_FEATURE_ON(xdna->dev_handle, AIE2_PREEMPT))
			return -EOPNOTSUPP;
		ret = EXEC_MSG_OPS(xdna)->fill_elf_slot(cmd_abo, slot, size);
		break;
	default:
		XDNA_INFO(xdna, "Unsupported op %d", op);
		ret = -EOPNOTSUPP;
		break;
	}

	return ret;
}

void aie2_msg_init(struct amdxdna_dev_hdl *ndev)
{
	if (AIE2_FEATURE_ON(ndev, AIE2_NPU_COMMAND))
		ndev->exec_msg_ops = &npu_exec_message_ops;
	else
		ndev->exec_msg_ops = &legacy_exec_message_ops;
}

static inline struct amdxdna_gem_obj *
aie2_cmdlist_get_cmd_buf(struct amdxdna_sched_job *job)
{
	int idx = get_job_idx(job->seq);

	return job->ctx->priv->cmd_buf[idx];
}

int aie2_execbuf(struct amdxdna_ctx *ctx, struct amdxdna_sched_job *job,
		 int (*notify_cb)(void *, void __iomem *, size_t))
{
	struct mailbox_channel *chann = ctx->priv->mbox_chann;
	struct amdxdna_dev *xdna = ctx->client->xdna;
	struct amdxdna_gem_obj *cmd_abo = job->cmd_bo;
	struct xdna_mailbox_msg msg;
	union exec_req req;
	int ret;

	if (!chann)
		return -ENODEV;

	ret = aie2_init_exec_req(&req, cmd_abo, &msg.send_size, &msg.opcode);
	if (ret)
		return ret;

	msg.handle = job;
	msg.notify_cb = notify_cb;
	msg.send_data = (u8 *)&req;
#ifdef AMDXDNA_DEVEL
	print_hex_dump_debug("cmd: ", DUMP_PREFIX_OFFSET, 16, 4, &req,
			     msg.send_size, false);
#endif

	ret = xdna_mailbox_send_msg(chann, &msg, TX_TIMEOUT);
	if (ret) {
		XDNA_ERR(xdna, "Send message failed ret %d", ret);
		return ret;
	}
	job->msg_id = msg.id;

	return 0;
}

int aie2_cmdlist_multi_execbuf(struct amdxdna_ctx *ctx,
			       struct amdxdna_sched_job *job,
			       int (*notify_cb)(void *, void __iomem *, size_t))
{
	struct amdxdna_gem_obj *cmdbuf_abo = aie2_cmdlist_get_cmd_buf(job);
	struct mailbox_channel *chann = ctx->priv->mbox_chann;
	struct amdxdna_gem_obj *cmd_abo = job->cmd_bo;
	void *cmd_buf = amdxdna_gem_vmap(cmdbuf_abo);
	struct amdxdna_client *client = ctx->client;
	struct amdxdna_dev *xdna = client->xdna;
	struct amdxdna_cmd_chain *payload;
	struct xdna_mailbox_msg msg;
	union exec_chain_req req;
	u32 payload_len;
	u32 offset = 0;
	u64 dev_addr;
	size_t size;
	int ret;
	u32 op;
	u32 i;

	op = amdxdna_cmd_get_op(cmd_abo);
	payload = amdxdna_cmd_get_payload(cmd_abo, &payload_len);
	if (!payload)
		return -EINVAL;

	if (op != ERT_CMD_CHAIN || !payload->command_count ||
	    payload_len < struct_size(payload, data, payload->command_count))
		return -EINVAL;

	op = ERT_INVALID_CMD;
	for (i = 0; i < payload->command_count; i++) {
		u32 boh = (u32)(payload->data[i]);
		struct amdxdna_gem_obj *abo;

		abo = amdxdna_gem_get_obj(client, boh, AMDXDNA_BO_SHARE);
		if (!abo) {
			XDNA_ERR(xdna, "Failed to find cmd BO %d", boh);
			return -ENOENT;
		}

		size = cmdbuf_abo->mem.size - offset;
		ret = aie2_cmdlist_fill_slot(cmd_buf + offset, abo, &size, &op);
		amdxdna_gem_put_obj(abo);
		if (ret)
			return ret;

		offset += size;
	}
#ifdef AMDXDNA_DEVEL
	XDNA_DBG(client->xdna, "Total %d commands:", payload->command_count);
	print_hex_dump_debug("cmdbufs: ", DUMP_PREFIX_OFFSET, 16, 4,
			     amdxdna_gem_vmap(cmdbuf_abo), offset, false);
#endif

	msg.opcode = EXEC_MSG_OPS(xdna)->get_chain_msg_op(op);
	if (msg.opcode == MSG_OP_MAX_OPCODE)
		return -EOPNOTSUPP;

	/* The offset is the accumulated total size of the cmd buffer */
	dev_addr = amdxdna_gem_dev_addr(cmdbuf_abo);
	EXEC_MSG_OPS(xdna)->init_chain_req(&req, dev_addr, offset, payload->command_count);
	drm_clflush_virt_range(cmd_buf, offset);

	msg.handle = job;
	msg.notify_cb = notify_cb;
	msg.send_data = (u8 *)&req;
	msg.send_size = sizeof(req);
	ret = xdna_mailbox_send_msg(chann, &msg, TX_TIMEOUT);
	if (ret) {
		XDNA_ERR(xdna, "Send message failed");
		return ret;
	}
	job->msg_id = msg.id;
#ifdef AMDXDNA_DEVEL
	print_hex_dump_debug("cmdlist msg: ", DUMP_PREFIX_OFFSET, 16, 4,
			     &req, msg.send_size, false);
#endif

	return 0;
}

int aie2_cmdlist_single_execbuf(struct amdxdna_ctx *ctx,
				struct amdxdna_sched_job *job,
				int (*notify_cb)(void *, void __iomem *, size_t))
{
	struct amdxdna_gem_obj *cmdbuf_abo = aie2_cmdlist_get_cmd_buf(job);
	struct mailbox_channel *chann = ctx->priv->mbox_chann;
	struct amdxdna_dev *xdna = ctx->client->xdna;
	struct amdxdna_gem_obj *cmd_abo = job->cmd_bo;
	void *cmd_buf = amdxdna_gem_vmap(cmdbuf_abo);
	struct xdna_mailbox_msg msg;
	union exec_chain_req req;
	u32 op = ERT_INVALID_CMD;
	u64 dev_addr;
	size_t size;
	int ret;

	size = cmdbuf_abo->mem.size;
	ret = aie2_cmdlist_fill_slot(cmd_buf, cmd_abo, &size, &op);
	if (ret)
		return ret;
#ifdef AMDXDNA_DEVEL
	print_hex_dump_debug("cmdbuf: ", DUMP_PREFIX_OFFSET, 16, 4,
			     amdxdna_gem_vmap(cmdbuf_abo), size, false);
#endif

	msg.opcode = EXEC_MSG_OPS(xdna)->get_chain_msg_op(op);
	if (msg.opcode == MSG_OP_MAX_OPCODE)
		return -EOPNOTSUPP;

	dev_addr = amdxdna_gem_dev_addr(cmdbuf_abo);
	EXEC_MSG_OPS(xdna)->init_chain_req(&req, dev_addr, size, 1);
	drm_clflush_virt_range(cmd_buf, size);

	msg.handle = job;
	msg.notify_cb = notify_cb;
	msg.send_data = (u8 *)&req;
	msg.send_size = sizeof(req);
	ret = xdna_mailbox_send_msg(chann, &msg, TX_TIMEOUT);
	if (ret) {
		XDNA_ERR(xdna, "Send message failed");
		return ret;
	}
	job->msg_id = msg.id;
#ifdef AMDXDNA_DEVEL
	print_hex_dump_debug("cmdlist msg: ", DUMP_PREFIX_OFFSET, 16, 4,
			     &req, msg.send_size, false);
#endif

	return 0;
}

int aie2_sync_bo(struct amdxdna_ctx *ctx, struct amdxdna_sched_job *job,
		 int (*notify_cb)(void *, void __iomem *, size_t))
{
	struct mailbox_channel *chann = ctx->priv->mbox_chann;
	struct amdxdna_gem_obj *abo = to_xdna_obj(job->bos[0].obj);
	struct amdxdna_dev *xdna = ctx->client->xdna;
	struct xdna_mailbox_msg msg;
	struct sync_bo_req req;
	int ret;

	req.src_addr = 0;
	req.dst_addr = 0;
	req.size = abo->mem.size;

	/* Device to Host */
	req.type = FIELD_PREP(AIE2_MSG_SYNC_BO_SRC_TYPE, SYNC_BO_DEV_MEM) |
		FIELD_PREP(AIE2_MSG_SYNC_BO_DST_TYPE, SYNC_BO_HOST_MEM);

	XDNA_DBG(xdna, "sync %d bytes src(0x%llx) to dst(0x%llx) completed",
		 req.size, req.src_addr, req.dst_addr);

	msg.handle = job;
	msg.notify_cb = notify_cb;
	msg.send_data = (u8 *)&req;
	msg.send_size = sizeof(req);
	msg.opcode = MSG_OP_SYNC_BO;

	ret = xdna_mailbox_send_msg(chann, &msg, TX_TIMEOUT);
	if (ret) {
		XDNA_ERR(xdna, "Send message failed");
		return ret;
	}
	job->msg_id = msg.id;

	return 0;
}

int aie2_config_debug_bo(struct amdxdna_ctx *ctx, struct amdxdna_sched_job *job,
			 int (*notify_cb)(void *, void __iomem *, size_t))
{
	struct mailbox_channel *chann = ctx->priv->mbox_chann;
	struct amdxdna_gem_obj *abo = to_xdna_obj(job->bos[0].obj);
	struct amdxdna_dev *xdna = ctx->client->xdna;
	struct config_debug_bo_req req;
	struct xdna_mailbox_msg msg;
	int ret;

	req.config = (job->opcode == OP_REG_DEBUG_BO) ? REGISTER : UNREGISTER;
	req.offset = amdxdna_gem_dev_addr(abo) - amdxdna_gem_dev_addr(ctx->client->dev_heap);
	req.size = abo->mem.size;

	XDNA_DBG(xdna, "offset 0x%llx size 0x%llx config %d",
		 req.offset, req.size, req.config);

	msg.handle = job;
	msg.notify_cb = notify_cb;
	msg.send_data = (u8 *)&req;
	msg.send_size = sizeof(req);
	msg.opcode = MSG_OP_CONFIG_DEBUG_BO;

	ret = xdna_mailbox_send_msg(chann, &msg, TX_TIMEOUT);
	if (ret) {
		XDNA_ERR(xdna, "Send message failed");
		return ret;
	}
	job->msg_id = msg.id;

	return 0;
}

int aie2_get_aie_coredump(struct amdxdna_dev_hdl *ndev, struct amdxdna_mgmt_dma_hdl *dma_hdl,
			  u32 context_id, u32 num_bufs)
{
	DECLARE_AIE2_MSG(get_coredump, MSG_OP_GET_COREDUMP);
	struct amdxdna_dev *xdna = ndev->xdna;
	dma_addr_t addr;
	int ret;

	if (!aie2_is_supported_msg(ndev, MSG_OP_GET_COREDUMP)) {
		XDNA_DBG(xdna, "Get coredump unsupported for the device or firmware version");
		return -EOPNOTSUPP;
	}

	addr = amdxdna_mgmt_buff_get_dma_addr(dma_hdl);
	if (!addr) {
		XDNA_ERR(xdna, "Invalid DMA address: %lld", addr);
		return -EINVAL;
	}

	req.context_id = context_id;
	req.num_bufs = num_bufs;
	req.list_addr = addr;
	req.list_size = dma_hdl->size;

	ret = aie2_send_mgmt_msg_wait(ndev, &msg);
	if (ret) {
		if (resp.status == AIE2_STATUS_MGMT_ERT_DRAM_BUFFER_SIZE_INVALID) {
			XDNA_ERR(xdna, "Invalid buffer size(required 0x%x) for get coredump",
				 resp.required_buffer_size);
		} else {
			XDNA_ERR(xdna, "Get coredump got status 0x%x", resp.status);
		}
		ret = -EINVAL;
	}

	return ret;
}

#ifdef AMDXDNA_DEVEL
int aie2_register_pdis(struct amdxdna_ctx *ctx)
{
	DECLARE_AIE2_MSG(register_pdi, MSG_OP_REGISTER_PDI);
	struct amdxdna_dev *xdna = ctx->client->xdna;
	struct amdxdna_dev_hdl *ndev = xdna->dev_handle;
	int num_cus = ctx->cus->num_cus;
	struct drm_gem_object *gobj;
	struct amdxdna_gem_obj *abo;
	struct ctx_pdi *pdi;
	int i, ret;

	if (num_cus > MAX_NUM_CUS) {
		XDNA_DBG(xdna, "Exceed maximum CU %d", MAX_NUM_CUS);
		return -EINVAL;
	}

	ctx->priv->pdi_infos = kcalloc(num_cus, sizeof(*ctx->priv->pdi_infos), GFP_KERNEL);
	if (!ctx->priv->pdi_infos)
		return -ENOMEM;

	req.num_infos = 1;
	for (i = 0; i < num_cus; i++) {
		struct amdxdna_cu_config *cu = &ctx->cus->cu_configs[i];

		pdi = &ctx->priv->pdi_infos[i];
		gobj = drm_gem_object_lookup(ctx->client->filp, cu->cu_bo);
		if (!gobj) {
			XDNA_ERR(xdna, "Lookup GEM object failed");
			ret = -EINVAL;
			goto cleanup;
		}
		abo = to_xdna_obj(gobj);

		if (abo->type != AMDXDNA_BO_DEV) {
			drm_gem_object_put(gobj);
			XDNA_ERR(xdna, "Invalid BO type");
			ret = -EINVAL;
			goto cleanup;
		}

		pdi->id = -1; /* Set to negative value, so that cleanup can work */
		pdi->id = ida_alloc_range(&xdna->pdi_ida, 0, AIE2_MAX_PDI_ID, GFP_KERNEL);
		if (pdi->id < 0) {
			XDNA_ERR(xdna, "Cannot allocate PDI id");
			ret = pdi->id;
			goto cleanup;
		}
		pdi->size = gobj->size;
		pdi->addr = dma_alloc_noncoherent(xdna->ddev.dev, pdi->size, &pdi->dma_addr,
						  DMA_TO_DEVICE, GFP_KERNEL);
		if (!pdi->addr) {
			drm_gem_object_put(gobj);
			ret = -ENOMEM;
			goto cleanup;
		}

		if (copy_from_user(pdi->addr, u64_to_user_ptr(amdxdna_gem_uva(abo)), pdi->size)) {
			drm_gem_object_put(gobj);
			ret = -EFAULT;
			goto cleanup;
		}

		drm_gem_object_put(gobj);
		req.pdi_info.pdi_id = pdi->id;
		req.pdi_info.address = pdi->dma_addr;
		req.pdi_info.size = pdi->size;
		req.pdi_info.type = 3;
		resp.status = MAX_AIE2_STATUS_CODE;

		drm_clflush_virt_range(pdi->addr, pdi->size); /* device can access */
		ret = aie2_send_mgmt_msg_wait(ndev, &msg);
		if (ret) {
			XDNA_ERR(xdna, "PDI %d register failed, ret %d", pdi->id, ret);
			goto cleanup;
		}

		pdi->registered = 1;
		WARN_ONCE(pdi->id != resp.reg_index, "PDI ID and FW registered index mismatch");
		XDNA_DBG(xdna, "PDI %d register completed, index %d", pdi->id, resp.reg_index);
	}

	return 0;

cleanup:
	aie2_unregister_pdis(ctx);
	return ret;
}

int aie2_unregister_pdis(struct amdxdna_ctx *ctx)
{
	DECLARE_AIE2_MSG(unregister_pdi, MSG_OP_UNREGISTER_PDI);
	struct amdxdna_dev *xdna = ctx->client->xdna;
	struct amdxdna_dev_hdl *ndev = xdna->dev_handle;
	int num_cus = ctx->cus->num_cus;
	struct ctx_pdi *pdi;
	int ret, i;

	if (!ctx->priv->pdi_infos)
		return 0;

	req.num_pdi = 1;
	for (i = 0; i < num_cus; i++) {
		pdi = &ctx->priv->pdi_infos[i];

		if (pdi->registered) {
			req.pdi_id = pdi->id;
			resp.status = MAX_AIE2_STATUS_CODE;
			ret = aie2_send_mgmt_msg_wait(ndev, &msg);
			if (ret) {
				XDNA_ERR(xdna, "PDI %d unregister failed, ret %d",
					 pdi->id, ret);
				break;
			}

			pdi->registered = 0;
			XDNA_DBG(xdna, "PDI %d unregister completed", pdi->id);
		}

		if (pdi->addr)
			dma_free_noncoherent(xdna->ddev.dev, pdi->size, pdi->addr,
					     pdi->dma_addr, DMA_TO_DEVICE);

		if (pdi->id >= 0)
			ida_free(&xdna->pdi_ida, pdi->id);
	}

	kfree(ctx->priv->pdi_infos);
	return 0;
}

int aie2_legacy_config_cu(struct amdxdna_ctx *ctx)
{
	struct mailbox_channel *chann = ctx->priv->mbox_chann;
	DECLARE_AIE2_MSG(legacy_config_cu, MSG_OP_LEGACY_CONFIG_CU);
	struct amdxdna_dev *xdna = ctx->client->xdna;
	int ret, i;

	if (!chann)
		return -ENODEV;

	if (ctx->cus->num_cus > MAX_NUM_CUS) {
		XDNA_DBG(xdna, "Exceed maximum CU %d", MAX_NUM_CUS);
		return -EINVAL;
	}

	req.num_cus = ctx->cus->num_cus;
	for (i = 0; i < req.num_cus; i++) {
		struct amdxdna_cu_config *cu = &ctx->cus->cu_configs[i];

		req.configs[i].cu_idx = i;
		req.configs[i].cu_func = cu->cu_func;
		req.configs[i].cu_pdi_id = ctx->priv->pdi_infos[i].id;
	}

	ret = xdna_send_msg_wait(xdna, chann, &msg);
	if (ret == -ETIME) {
		xdna_mailbox_stop_channel(chann);
		xdna_mailbox_destroy_channel(chann);
		ctx->priv->mbox_chann = NULL;
	}

	XDNA_DBG(xdna, "Configure %d CUs, ret %d", req.num_cus, ret);

	return ret;
}
#endif

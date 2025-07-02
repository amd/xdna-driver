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
#include "aie2_msg_priv.h"
#include "aie2_pci.h"

#define DECLARE_AIE2_MSG(name, op) \
	DECLARE_XDNA_MSG_COMMON(name, op, MAX_AIE2_STATUS_CODE)

#define aie2_send_mgmt_msg_wait(ndev, msg) \
	aie2_send_mgmt_msg_wait_offset(ndev, msg, 0, false)

#define aie2_send_mgmt_msg_wait_silent(ndev, msg) \
	aie2_send_mgmt_msg_wait_offset(ndev, msg, 0, true)

static bool
is_supported_rt_cfg(struct amdxdna_dev_hdl *ndev, u32 type)
{
	int fw_minor = ndev->mgmt_prot_minor;
	const struct rt_cfg_ver *rt_cfg_tbl;
	int i;

	rt_cfg_tbl = ndev->priv->optional_cfg;
	if (!rt_cfg_tbl)
		return false;

	for (i = 0; rt_cfg_tbl[i].fw_minor; i++) {
		if (rt_cfg_tbl[i].type != type)
			continue;

		if (fw_minor >= rt_cfg_tbl[i].fw_minor)
			return true;

		XDNA_DBG(ndev->xdna, "Runtime cfg %d protocol %lld.%d, fw is %d.%d",
			 type, ndev->priv->protocol_major, rt_cfg_tbl[i].fw_minor,
			 ndev->mgmt_prot_major, ndev->mgmt_prot_minor);
		return false;
	}

	return false;
}

static int
aie2_send_mgmt_msg_wait_offset(struct amdxdna_dev_hdl *ndev,
			       struct xdna_mailbox_msg *msg,
			       u32 offset, bool silent)
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

	if (!ret && hdl->data[offset] != AIE2_STATUS_SUCCESS) {
		if (!silent) {
			XDNA_ERR(xdna, "command opcode 0x%x failed, status 0x%x",
				 msg->opcode, *hdl->data);
		}
		ret = -EINVAL;
	}

	return ret;
}

bool aie2_is_supported_msg(struct amdxdna_dev_hdl *ndev, enum aie2_msg_opcode opcode)
{
	int fw_minor = ndev->mgmt_prot_minor;
	const struct msg_op_ver *op_tbl;
	int i;

	op_tbl = ndev->priv->optional_msg;
	if (!op_tbl)
		return false;

	for (i = 0; op_tbl[i].fw_minor; i++) {
		if (op_tbl[i].op != opcode)
			continue;

		if (fw_minor >= op_tbl[i].fw_minor)
			return true;

		XDNA_DBG(ndev->xdna, "Opcode %d protocol %lld.%d, fw is %d.%d",
			 opcode, ndev->priv->protocol_major, op_tbl[i].fw_minor,
			 ndev->mgmt_prot_major, ndev->mgmt_prot_minor);
		return false;
	}

	return false;
}

int aie2_suspend_fw(struct amdxdna_dev_hdl *ndev)
{
	DECLARE_AIE2_MSG(suspend, MSG_OP_SUSPEND);

	return aie2_send_mgmt_msg_wait(ndev, &msg);
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

int aie2_query_aie_telemetry(struct amdxdna_dev_hdl *ndev, struct aie2_mgmt_dma_hdl *mgmt_hdl,
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

	addr = aie2_mgmt_buff_get_dma_addr(mgmt_hdl);
	if (!addr) {
		XDNA_ERR(xdna, "Invalid DMA address: %lld", addr);
		return -EINVAL;
	}

	req.buf_addr = addr;
	req.buf_size = size;
	req.type = type;

	ret = aie2_send_mgmt_msg_wait_offset(ndev, &msg, XDNA_STATUS_OFFSET(get_telemetry), false);
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

int aie2_start_event_trace(struct amdxdna_dev_hdl *ndev, dma_addr_t addr,
			   u32 size, u32 event_category)
{
	DECLARE_AIE2_MSG(start_event_trace, MSG_OP_START_EVENT_TRACE);
	int ret;

	req.dram_buffer_address = addr;
	req.dram_buffer_size = size;
	req.event_trace_dest = EVENT_TRACE_DEST_DRAM;
	req.event_trace_categories = event_category;
	req.event_trace_timestamp = EVENT_TRACE_TIMESTAMP_FW_CHRONO;

	XDNA_DBG(ndev->xdna, "send start event trace msg");
	ret = aie2_send_mgmt_msg_wait(ndev, &msg);
	if (ret)
		return ret;

	aie2_set_trace_timestamp(ndev, &resp);
	return 0;
}

int aie2_stop_event_trace(struct amdxdna_dev_hdl *ndev)
{
	DECLARE_AIE2_MSG(stop_event_trace, MSG_OP_STOP_EVENT_TRACE);
	int ret;

	XDNA_DBG(ndev->xdna, "send stop event trace msg");
	ret = aie2_send_mgmt_msg_wait(ndev, &msg);
	if (ret)
		return ret;

	aie2_unset_trace_timestamp(ndev);
	return 0;
}

int aie2_configure_dram_logging(struct amdxdna_dev_hdl *ndev, dma_addr_t addr, u32 size)
{
	DECLARE_AIE2_MSG(config_logging_dram_buf, MSG_OP_CONFIG_LOGGING_DRAM_BUF);
	int ret;

	req.dram_buffer_address = addr;
	req.dram_buffer_size = size;

	XDNA_DBG(ndev->xdna, "send configure dram logging msg");
	ret = aie2_send_mgmt_msg_wait(ndev, &msg);
	if (ret)
		return ret;

	/* Send same cmd with size 0, to detach logger from FW */
	if (!size)
		return 0;

	aie2_configure_log_buf_irq(ndev, &resp);
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
	struct aie2_mgmt_dma_hdl mgmt_hdl;
	struct amdxdna_client *client;
	struct amdxdna_ctx *ctx;
	unsigned long ctx_id;
	u32 aie_bitmap = 0;
	dma_addr_t addr;
	u8 *buff_addr;
	int ret, idx;

	if (!access_ok(buf, size)) {
		XDNA_ERR(xdna, "Failed to access status buffer size %d", size);
		return -EFAULT;
	}

	buff_addr = aie2_mgmt_buff_alloc(ndev, &mgmt_hdl, size, DMA_FROM_DEVICE);
	if (!buff_addr)
		return -ENOMEM;

	/* Go through each context and mark the AIE columns that are active */
	list_for_each_entry(client, &xdna->client_list, node) {
		idx = srcu_read_lock(&client->ctx_srcu);
		amdxdna_for_each_ctx(client, ctx_id, ctx)
			aie_bitmap |= amdxdna_ctx_col_map(ctx);
		srcu_read_unlock(&client->ctx_srcu, idx);
	}

	addr = aie2_mgmt_buff_get_dma_addr(&mgmt_hdl);
	if (!addr) {
		XDNA_ERR(xdna, "Invalid DMA address: %lld", addr);
		return -EINVAL;
	}

	*cols_filled = 0;
	req.dump_buff_addr = addr;
	req.dump_buff_size = size;
	req.num_cols = hweight32(aie_bitmap);
	req.aie_bitmap = aie_bitmap;

	aie2_mgmt_buff_clflush(&mgmt_hdl);
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

	if (copy_to_user(buf, buff_addr, resp.size)) {
		ret = -EFAULT;
		XDNA_ERR(xdna, "Failed to copy NPU status to user space");
		goto fail;
	}

	*cols_filled = aie_bitmap;

fail:
	aie2_mgmt_buff_free(&mgmt_hdl);
	return ret;
}

int aie2_register_asyn_event_msg(struct amdxdna_dev_hdl *ndev, struct aie2_mgmt_dma_hdl *mgmt_hdl,
				 void *handle, int (*cb)(void*, void __iomem *, size_t))
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

	addr = aie2_mgmt_buff_get_dma_addr(mgmt_hdl);
	if (!addr) {
		XDNA_ERR(ndev->xdna, "Invalid DMA address: %lld", addr);
		return -EINVAL;
	}

	req.buf_addr = addr;
	req.buf_size = ASYNC_BUF_SIZE;

	XDNA_DBG(ndev->xdna, "Register addr 0x%llx size 0x%x", req.buf_addr, req.buf_size);
	return xdna_mailbox_send_msg(ndev->mgmt_chann, &msg, TX_TIMEOUT);
}

int aie2_get_app_health(struct amdxdna_dev_hdl *ndev, struct aie2_mgmt_dma_hdl *mgmt_hdl,
			u32 context_id, u32 size)
{
	DECLARE_AIE2_MSG(get_app_health, MSG_OP_GET_APP_HEALTH);
	struct amdxdna_dev *xdna = ndev->xdna;
	dma_addr_t addr;
	int ret;

	addr = aie2_mgmt_buff_get_dma_addr(mgmt_hdl);
	if (!addr) {
		XDNA_ERR(xdna, "Invalid DMA address: %lld", addr);
		return -EINVAL;
	}

	req.buf_addr = addr;
	req.context_id = context_id;
	req.buf_size = size;

	ret = aie2_send_mgmt_msg_wait_silent(ndev, &msg);
	if (ret) {
		XDNA_DBG(xdna, "Get app health failed, ret 0x%x", ret);
		return ret;
	}

	if (resp.status != AIE2_STATUS_SUCCESS) {
		XDNA_DBG(xdna, "Get app health got status 0x%x", resp.status);
		ret = -EINVAL;
	}

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
					 abo->mem.dev_addr >> shift);
		req.cfgs[i] |= FIELD_PREP(AIE2_MSG_CFG_CU_FUNC, cu->cu_func);
		XDNA_DBG(xdna, "CU %d full addr 0x%llx, cfg 0x%x", i,
			 abo->mem.dev_addr, req.cfgs[i]);
		drm_gem_object_put(gobj);
	}
	req.num_cus = ctx->cus->num_cus;

	ret = xdna_mailbox_send_msg(chann, &msg, TX_TIMEOUT);
	if (ret)
		XDNA_ERR(xdna, "Send message failed, ret %d", ret);

	return ret;
}

int aie2_execbuf(struct amdxdna_ctx *ctx, struct amdxdna_sched_job *job, enum cmd_chain_class class,
		 int (*notify_cb)(void *, void __iomem *, size_t))
{
	struct mailbox_channel *chann = ctx->priv->mbox_chann;
	struct amdxdna_dev *xdna = ctx->client->xdna;
	struct amdxdna_gem_obj *cmd_abo = job->cmd_bo;
	union {
		struct exec_dpu_preempt_req dpu_pmpt;
		struct execute_buffer_req ebuf;
		struct exec_dpu_req dpu;
		struct exec_npu_req npu;
	} req;
	struct xdna_mailbox_msg msg;
	u32 payload_len;
	void *payload;
	int cu_idx;
	int ret;
	u32 op;

	op = amdxdna_cmd_get_op(cmd_abo);
	if (class == CMD_CHAIN_CLASS_NON_PREEMPT &&
	    (op == ERT_START_NPU_PREEMPT || op == ERT_START_NPU)) {
		XDNA_ERR(ctx->client->xdna, "Unsupported cmd chain for opcode %d", op);
		return -EOPNOTSUPP;
	}

	if (!chann)
		return -ENODEV;

	payload = amdxdna_cmd_get_payload(cmd_abo, &payload_len);
	if (!payload) {
		XDNA_ERR(xdna, "Invalid command, cannot get payload");
		return -EINVAL;
	}

	cu_idx = amdxdna_cmd_get_cu_idx(cmd_abo);
	if (cu_idx < 0) {
		XDNA_DBG(xdna, "Invalid cu idx");
		return -EINVAL;
	}

	switch (op) {
	case ERT_START_CU:
		if (unlikely(payload_len > sizeof(req.ebuf.payload))) {
			XDNA_ERR(xdna, "Invalid ebuf payload len: %d", payload_len);
			return -EINVAL;
		}

		req.ebuf.cu_idx = cu_idx;
		memcpy(req.ebuf.payload, payload, sizeof(req.ebuf.payload));
		msg.send_size = sizeof(req.ebuf);
		msg.opcode = MSG_OP_EXECUTE_BUFFER_CF;
		break;
	case ERT_START_NPU: {
		struct amdxdna_cmd_start_npu *sn = payload;

		if (unlikely(payload_len - sizeof(*sn) > sizeof(req.dpu.payload))) {
			XDNA_ERR(xdna, "Invalid dpu payload len: %d", payload_len);
			return -EINVAL;
		}

		req.dpu.inst_buf_addr = sn->buffer;
		req.dpu.inst_size = sn->buffer_size;
		req.dpu.inst_prop_cnt = sn->prop_count;
		req.dpu.cu_idx = cu_idx;
		memcpy(req.dpu.payload, sn->prop_args, sizeof(req.dpu.payload));
		msg.send_size = sizeof(req.dpu);
		msg.opcode = MSG_OP_EXEC_DPU;
		break;
	}
	case ERT_START_NPU_PREEMPT: {
		struct amdxdna_cmd_preempt_data *pd = payload;

		if (unlikely(payload_len - sizeof(*pd) > sizeof(req.dpu_pmpt.payload))) {
			XDNA_ERR(xdna, "Invalid dpu preempt payload len: %d", payload_len);
			return -EINVAL;
		}

		req.dpu_pmpt.inst_buf_addr = pd->inst_buf;
		req.dpu_pmpt.save_buf_addr = pd->save_buf;
		req.dpu_pmpt.restore_buf_addr = pd->restore_buf;
		req.dpu_pmpt.inst_size = pd->inst_size;
		req.dpu_pmpt.save_size = pd->save_size;
		req.dpu_pmpt.restore_size = pd->restore_size;
		req.dpu_pmpt.inst_prop_cnt = pd->inst_prop_cnt;
		req.dpu_pmpt.cu_idx = cu_idx;
		memcpy(req.dpu_pmpt.payload, pd->prop_args, sizeof(req.dpu_pmpt.payload));
		msg.send_size = sizeof(req.dpu_pmpt);
		msg.opcode = MSG_OP_EXEC_DPU_PREEMPT;
		break;
	}
	case ERT_START_NPU_PREEMPT_ELF: {
		struct amdxdna_cmd_preempt_data *nd = payload;

		if (unlikely(payload_len - sizeof(*nd) > sizeof(req.npu.payload))) {
			XDNA_ERR(xdna, "Invalid npu payload len: %d", payload_len);
			return -EINVAL;
		}

		req.npu.type = EXEC_NPU_TYPE_ELF;
		req.npu.inst_buf_addr = nd->inst_buf;
		req.npu.save_buf_addr = nd->save_buf;
		req.npu.restore_buf_addr = nd->restore_buf;
		req.npu.inst_size = nd->inst_size;
		req.npu.save_size = nd->save_size;
		req.npu.restore_size = nd->restore_size;
		req.npu.inst_prop_cnt = nd->inst_prop_cnt;

		/*
		 * Similar to the rest of the ERT opcodes, the kernel opcode must be embedded into
		 * the payload by XRT. Currently, this is missing hence hard coding the payload for
		 * now.
		 */
		req.npu.payload[0] = AIE2_EXEC_BUFFER_KERNEL_OP_TXN;

		msg.send_size = sizeof(req.npu);
		msg.opcode = MSG_OP_EXEC_NPU;
		break;
	}
	default:
		XDNA_DBG(xdna, "Invalid ERT cmd op code: %d", op);
		return -EINVAL;
	}
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

static inline int
aie2_cmdlist_fill_one_slot_cf(void *cmd_buf, u32 offset, enum cmd_chain_class class,
			      struct amdxdna_gem_obj *abo, u32 *size)
{
	int cu_idx = amdxdna_cmd_get_cu_idx(abo);
	u32 payload_len;
	void *payload;

	if (cu_idx < 0)
		return -EINVAL;

	payload = amdxdna_cmd_get_payload(abo, &payload_len);
	if (!payload)
		return -EINVAL;

	if (class == CMD_CHAIN_CLASS_PREEMPT) {
		struct cmd_chain_slot_npu *npu = cmd_buf + offset;

		if (!slot_has_space(*npu, offset, payload_len))
			return -ENOSPC;

		memset(npu, 0, sizeof(*npu));
		npu->type = EXEC_NPU_TYPE_NON_ELF;
		npu->arg_cnt = payload_len / sizeof(u32);
		npu->cu_idx = cu_idx;
		memcpy(npu->args, payload, payload_len);
		*size = struct_size(npu, args, npu->arg_cnt);
	} else {
		struct cmd_chain_slot_execbuf_cf *cf = cmd_buf + offset;

		if (!slot_has_space(*cf, offset, payload_len))
			return -ENOSPC;

		cf->arg_cnt = payload_len / sizeof(u32);
		cf->cu_idx = cu_idx;
		memcpy(cf->args, payload, payload_len);
		*size = struct_size(cf, args, cf->arg_cnt);
	}

	return 0;
}

static inline int
aie2_cmdlist_fill_one_slot_dpu(void *cmd_buf, u32 offset, enum cmd_chain_class class,
			       struct amdxdna_gem_obj *abo, u32 *size)
{
	int cu_idx = amdxdna_cmd_get_cu_idx(abo);
	struct amdxdna_cmd_start_npu *sn;
	u32 payload_len;
	void *payload;
	u32 arg_sz;

	if (cu_idx < 0)
		return -EINVAL;

	payload = amdxdna_cmd_get_payload(abo, &payload_len);
	if (!payload)
		return -EINVAL;
	sn = payload;
	arg_sz = payload_len - sizeof(*sn);
	if (payload_len < sizeof(*sn) || arg_sz > MAX_DPU_ARGS_SIZE)
		return -EINVAL;

	if (class == CMD_CHAIN_CLASS_PREEMPT) {
		struct cmd_chain_slot_npu *npu = cmd_buf + offset;

		if (!slot_has_space(*npu, offset, payload_len))
			return -ENOSPC;

		memset(npu, 0, sizeof(*npu));
		npu->type = EXEC_NPU_TYPE_PARTIAL_ELF;
		npu->inst_buf_addr = sn->buffer;
		npu->inst_size = sn->buffer_size;
		npu->inst_prop_cnt = sn->prop_count;
		npu->cu_idx = cu_idx;
		npu->arg_cnt = arg_sz / sizeof(u32);
		memcpy(npu->args, sn->prop_args, arg_sz);
		*size = struct_size(npu, args, npu->arg_cnt);
	} else {
		struct cmd_chain_slot_dpu *dpu = cmd_buf + offset;

		if (!slot_has_space(*dpu, offset, payload_len))
			return -ENOSPC;

		dpu->inst_buf_addr = sn->buffer;
		dpu->inst_size = sn->buffer_size;
		dpu->inst_prop_cnt = sn->prop_count;
		dpu->cu_idx = cu_idx;
		dpu->arg_cnt = arg_sz / sizeof(u32);
		memcpy(dpu->args, sn->prop_args, arg_sz);
		*size = struct_size(dpu, args, dpu->arg_cnt);
	}

	return 0;
}

static inline int
aie2_cmdlist_fill_one_slot_npu(void *cmd_buf, u32 offset,
			       struct amdxdna_gem_obj *abo, u32 *size)
{
	struct cmd_chain_slot_npu *npu = cmd_buf + offset;
	int cu_idx = amdxdna_cmd_get_cu_idx(abo);
	struct amdxdna_cmd_preempt_data *pd;
	u32 payload_len;
	void *payload;
	u32 arg_sz;

	if (cu_idx < 0)
		return -EINVAL;

	payload = amdxdna_cmd_get_payload(abo, &payload_len);
	if (!payload)
		return -EINVAL;
	pd = payload;
	arg_sz = payload_len - sizeof(*pd);
	if (payload_len < sizeof(*pd))
		return -EINVAL;

	if (!slot_has_space(*npu, offset, arg_sz))
		return -ENOSPC;

	npu->type = EXEC_NPU_TYPE_PREEMPT;
	npu->inst_buf_addr = pd->inst_buf;
	npu->save_buf_addr = pd->save_buf;
	npu->restore_buf_addr = pd->restore_buf;
	npu->inst_size = pd->inst_size;
	npu->save_size = pd->save_size;
	npu->restore_size = pd->restore_size;
	npu->inst_prop_cnt = pd->inst_prop_cnt;
	npu->cu_idx = cu_idx;
	npu->arg_cnt = arg_sz / sizeof(u32);
	memcpy(npu->args, pd->prop_args, arg_sz);
	*size = struct_size(npu, args, npu->arg_cnt);
	return 0;
}

static inline int
aie2_cmdlist_fill_one_slot_elf(void *cmd_buf, u32 offset,
			       struct amdxdna_gem_obj *abo, u32 *size)
{
	struct cmd_chain_slot_npu *npu = cmd_buf + offset;
	struct amdxdna_cmd_preempt_data *nd;
	u32 payload_len;
	void *payload;
	u32 arg_sz;

	payload = amdxdna_cmd_get_payload(abo, &payload_len);
	if (!payload)
		return -EINVAL;
	nd = payload;
	arg_sz = payload_len - sizeof(*nd);
	if (payload_len < sizeof(*nd))
		return -EINVAL;

	if (!slot_has_space(*npu, offset, arg_sz))
		return -ENOSPC;

	npu->type = EXEC_NPU_TYPE_ELF;
	npu->inst_buf_addr = nd->inst_buf;
	npu->save_buf_addr = nd->save_buf;
	npu->restore_buf_addr = nd->restore_buf;
	npu->inst_size = nd->inst_size;
	npu->save_size = nd->save_size;
	npu->restore_size = nd->restore_size;
	npu->inst_prop_cnt = nd->inst_prop_cnt;
	npu->arg_cnt = arg_sz / sizeof(u32);

	/*
	 * Similar to the rest of the ERT opcodes, the kernel opcode must be embedded into the
	 * payload by XRT. Currently, this is missing hence hard coding the payload for now.
	 */
	npu->args[0] = AIE2_EXEC_BUFFER_KERNEL_OP_TXN;

	*size = struct_size(npu, args, npu->arg_cnt);
	return 0;
}

static inline int
aie2_cmdlist_fill_one_slot(u32 op, struct amdxdna_gem_obj *cmdbuf_abo, u32 offset,
			   enum cmd_chain_class class, struct amdxdna_gem_obj *abo, u32 *size)
{
	u32 this_op = amdxdna_cmd_get_op(abo);
	void *cmd_buf = cmdbuf_abo->mem.kva;
	int ret;

	if (this_op != op) {
		ret = -EINVAL;
		goto done;
	}

	switch (op) {
	case ERT_START_CU:
		ret = aie2_cmdlist_fill_one_slot_cf(cmd_buf, offset, class, abo, size);
		break;
	case ERT_START_NPU:
		ret = aie2_cmdlist_fill_one_slot_dpu(cmd_buf, offset, class, abo, size);
		break;
	case ERT_START_NPU_PREEMPT:
		ret = aie2_cmdlist_fill_one_slot_npu(cmd_buf, offset, abo, size);
		break;
	case ERT_START_NPU_PREEMPT_ELF:
		ret = aie2_cmdlist_fill_one_slot_elf(cmd_buf, offset, abo, size);
		break;
	default:
		ret = -EOPNOTSUPP;
	}

done:
	if (ret) {
		XDNA_ERR(abo->client->xdna, "Can't fill slot for cmd op %d ret %d",
			 op, ret);
	}
	return ret;
}

static inline struct amdxdna_gem_obj *
aie2_cmdlist_get_cmd_buf(struct amdxdna_sched_job *job)
{
	int idx = get_job_idx(job->seq);

	return job->ctx->priv->cmd_buf[idx];
}

static inline void
aie2_cmdlist_prepare_request(void *req, struct amdxdna_gem_obj *cmdbuf_abo,
			     enum cmd_chain_class class, u32 size, u32 cnt)
{
	if (class == CMD_CHAIN_CLASS_PREEMPT) {
		struct cmd_chain_npu_req *npu = req;

		npu->buf_addr = cmdbuf_abo->mem.dev_addr;
		npu->buf_size = size;
		npu->count = cnt;
	} else {
		struct cmd_chain_req *dpu = req;

		dpu->buf_addr = cmdbuf_abo->mem.dev_addr;
		dpu->buf_size = size;
		dpu->count = cnt;
	}
	drm_clflush_virt_range(cmdbuf_abo->mem.kva, size);
	XDNA_DBG(cmdbuf_abo->client->xdna, "Command buf addr 0x%llx size 0x%x count %d",
		 cmdbuf_abo->mem.dev_addr, size, cnt);
}

static inline u32
aie2_cmd_op_to_msg_op(u32 op)
{
	switch (op) {
	case ERT_START_CU:
		return MSG_OP_CHAIN_EXEC_BUFFER_CF;
	case ERT_START_NPU:
		return MSG_OP_CHAIN_EXEC_DPU;
	default:
		return MSG_OP_MAX_OPCODE;
	}
}

int aie2_cmdlist_multi_execbuf(struct amdxdna_ctx *ctx,
			       struct amdxdna_sched_job *job, enum cmd_chain_class class,
			       int (*notify_cb)(void *, void __iomem *, size_t))
{
	struct amdxdna_gem_obj *cmdbuf_abo = aie2_cmdlist_get_cmd_buf(job);
	struct mailbox_channel *chann = ctx->priv->mbox_chann;
	struct amdxdna_gem_obj *cmd_abo = job->cmd_bo;
	struct amdxdna_client *client = ctx->client;
	union {
		struct cmd_chain_npu_req npu;
		struct cmd_chain_req dpu;
	} req;
	struct amdxdna_cmd_chain *payload;
	struct xdna_mailbox_msg msg;
	u32 payload_len;
	u32 offset = 0;
	u32 size;
	int ret;
	u32 op;
	u32 i;

	op = amdxdna_cmd_get_op(cmd_abo);
	payload = amdxdna_cmd_get_payload(cmd_abo, &payload_len);
	if (op != ERT_CMD_CHAIN || !payload || !payload->command_count ||
	    payload_len < struct_size(payload, data, payload->command_count))
		return -EINVAL;

	for (i = 0; i < payload->command_count; i++) {
		u32 boh = (u32)(payload->data[i]);
		struct amdxdna_gem_obj *abo;

		abo = amdxdna_gem_get_obj(client, boh, AMDXDNA_BO_CMD);
		if (!abo) {
			XDNA_ERR(client->xdna, "Failed to find cmd BO %d", boh);
			return -ENOENT;
		}

		/* All sub-cmd should have same op, use the first one. */
		if (i == 0) {
			op = amdxdna_cmd_get_op(abo);
			if (class == CMD_CHAIN_CLASS_NON_PREEMPT &&
			    (op == ERT_START_NPU || op == ERT_START_NPU_PREEMPT)) {
				amdxdna_gem_put_obj(abo);
				XDNA_ERR(client->xdna, "Unsupported cmd chain for opcode %d", op);
				return -EOPNOTSUPP;
			}
		}

		ret = aie2_cmdlist_fill_one_slot(op, cmdbuf_abo, offset, class, abo, &size);
		amdxdna_gem_put_obj(abo);
		if (ret)
			return -EINVAL;

		offset += size;
	}
#ifdef AMDXDNA_DEVEL
	XDNA_DBG(client->xdna, "Total %d commands:", payload->command_count);
	print_hex_dump_debug("cmdbufs: ", DUMP_PREFIX_OFFSET, 16, 4,
			     cmdbuf_abo->mem.kva, offset, false);
#endif

	/* The offset is the accumulated total size of the cmd buffer */
	aie2_cmdlist_prepare_request(&req, cmdbuf_abo, class, offset, payload->command_count);

	if (class == CMD_CHAIN_CLASS_PREEMPT) {
		msg.opcode = MSG_OP_CHAIN_EXEC_NPU;
		msg.send_size = sizeof(req.npu);
	} else {
		msg.opcode = aie2_cmd_op_to_msg_op(op);
		msg.send_size = sizeof(req.dpu);
	}

	if (msg.opcode == MSG_OP_MAX_OPCODE)
		return -EOPNOTSUPP;

	msg.handle = job;
	msg.notify_cb = notify_cb;
	msg.send_data = (u8 *)&req;
	ret = xdna_mailbox_send_msg(chann, &msg, TX_TIMEOUT);
	if (ret) {
		XDNA_ERR(client->xdna, "Send message failed");
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
				struct amdxdna_sched_job *job, enum cmd_chain_class class,
				int (*notify_cb)(void *, void __iomem *, size_t))
{
	struct amdxdna_gem_obj *cmdbuf_abo = aie2_cmdlist_get_cmd_buf(job);
	struct mailbox_channel *chann = ctx->priv->mbox_chann;
	struct amdxdna_gem_obj *cmd_abo = job->cmd_bo;
	union {
		struct cmd_chain_npu_req npu;
		struct cmd_chain_req dpu;
	} req;
	struct xdna_mailbox_msg msg;
	u32 size;
	int ret;
	u32 op;

	op = amdxdna_cmd_get_op(cmd_abo);
	if (class == CMD_CHAIN_CLASS_NON_PREEMPT &&
	    (op == ERT_START_NPU_PREEMPT || op == ERT_START_NPU)) {
		XDNA_ERR(ctx->client->xdna, "Unsupported cmd chain for opcode %d", op);
		return -EOPNOTSUPP;
	}

	ret = aie2_cmdlist_fill_one_slot(op, cmdbuf_abo, 0, class, cmd_abo, &size);
	if (ret)
		return ret;
#ifdef AMDXDNA_DEVEL
	print_hex_dump_debug("cmdbuf: ", DUMP_PREFIX_OFFSET, 16, 4,
			     cmdbuf_abo->mem.kva, size, false);
#endif

	aie2_cmdlist_prepare_request(&req, cmdbuf_abo, class, size, 1);

	if (class == CMD_CHAIN_CLASS_PREEMPT) {
		msg.opcode = MSG_OP_CHAIN_EXEC_NPU;
		msg.send_size = sizeof(req.npu);
	} else {
		msg.opcode = aie2_cmd_op_to_msg_op(op);
		msg.send_size = sizeof(req.dpu);
	}

	if (msg.opcode == MSG_OP_MAX_OPCODE)
		return -EOPNOTSUPP;

	msg.handle = job;
	msg.notify_cb = notify_cb;
	msg.send_data = (u8 *)&req;
	ret = xdna_mailbox_send_msg(chann, &msg, TX_TIMEOUT);
	if (ret) {
		XDNA_ERR(ctx->client->xdna, "Send message failed");
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
	req.offset = abo->mem.dev_addr - ctx->client->dev_heap->mem.dev_addr;
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

		if (copy_from_user(pdi->addr, u64_to_user_ptr(abo->mem.userptr), pdi->size)) {
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

// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2023-2024, Advanced Micro Devices, Inc.
 */

#include <linux/kthread.h>
#include <drm/drm_cache.h>

#include "drm_local/amdxdna_accel.h"
#include "amdxdna_ctx.h"
#include "npu1_msg_priv.h"
#include "npu1_pci.h"

#define TX_TIMEOUT 2000 /* miliseconds */
#define RX_TIMEOUT 5000 /* miliseconds */

struct npu_notify {
	struct completion       comp;
	u32			*data;
	size_t			size;
	int			error;
};

#define DECLARE_NPU_MSG(name, op)				\
	struct name##_req	req = { 0 };			\
	struct name##_resp	resp =				\
		{ NPU_STATUS_MAX_NPU_STATUS_CODE };		\
	struct npu_notify	hdl = {				\
		.error = 0,					\
		.data = (u32 *)&resp,				\
		.size = sizeof(resp),				\
		.comp = COMPLETION_INITIALIZER(hdl.comp),	\
	};							\
	struct xdna_mailbox_msg msg = {				\
		.send_data = (u8 *)&req,			\
		.send_size = sizeof(req),			\
		.handle = &hdl,					\
		.opcode = op,					\
		.notify_cb = npu_msg_cb,			\
	}

static void npu_msg_cb(void *handle, const u32 *data, size_t size)
{
	struct npu_notify *cb_arg = handle;

	if (!data) {
		cb_arg->error = 1;
		return;
	}

	print_hex_dump_debug("resp data: ", DUMP_PREFIX_OFFSET,
			     16, 4, data, size, true);
	memcpy(cb_arg->data, data, cb_arg->size);
	complete(&cb_arg->comp);
}

static int npu_send_msg_wait(struct npu_device *ndev,
			     struct mailbox_channel *chann,
			     struct xdna_mailbox_msg *msg)
{
	struct amdxdna_dev *xdna = ndev->xdna;
	struct npu_notify *hdl = msg->handle;
	int ret;

	ret = xdna_mailbox_send_msg(chann, msg, TX_TIMEOUT);
	if (ret) {
		XDNA_ERR(xdna, "Send message failed, ret %d", ret);
		return ret;
	}

	ret = wait_for_completion_timeout(&hdl->comp,
					  msecs_to_jiffies(RX_TIMEOUT));
	if (!ret) {
		XDNA_ERR(xdna, "wait for completion timeout");
		return -ETIME;
	}

	if (*hdl->data != NPU_STATUS_SUCCESS) {
		XDNA_ERR(xdna, "command opcode 0x%x failed, status 0x%x",
			 msg->opcode, *hdl->data);
		return -EINVAL;
	}

	return 0;
}

static int npu_send_mgmt_msg_wait(struct npu_device *ndev,
				  struct xdna_mailbox_msg *msg)
{
	struct amdxdna_dev *xdna = ndev->xdna;
	int ret;

	if (!ndev->mgmt_chann)
		return -ENODEV;

	drm_WARN_ON(&xdna->ddev, !mutex_is_locked(&xdna->dev_lock));
	ret = npu_send_msg_wait(ndev, ndev->mgmt_chann, msg);
	if (ret == -ETIME) {
		if (ndev->async_msgd)
			kthread_stop(ndev->async_msgd);
		xdna_mailbox_destroy_channel(ndev->mgmt_chann);
		ndev->async_msgd = NULL;
		ndev->mgmt_chann = NULL;
	}

	return ret;
}

int npu1_suspend_fw(struct npu_device *ndev)
{
	DECLARE_NPU_MSG(suspend, MSG_OP_SUSPEND);

	return npu_send_mgmt_msg_wait(ndev, &msg);
}

int npu1_resume_fw(struct npu_device *ndev)
{
	DECLARE_NPU_MSG(suspend, MSG_OP_RESUME);

	return npu_send_mgmt_msg_wait(ndev, &msg);
}

int npu1_set_runtime_cfg(struct npu_device *ndev, u32 type, u64 value)
{
	DECLARE_NPU_MSG(set_runtime_cfg, MSG_OP_SET_RUNTIME_CONFIG);

	req.type = type;
	req.value = value;

	return npu_send_mgmt_msg_wait(ndev, &msg);
}

int npu1_get_runtime_cfg(struct npu_device *ndev, u32 type, u64 *value)
{
	DECLARE_NPU_MSG(get_runtime_cfg, MSG_OP_GET_RUNTIME_CONFIG);
	int ret;

	req.type = type;
	ret = npu_send_mgmt_msg_wait(ndev, &msg);
	if (ret) {
		XDNA_ERR(ndev->xdna, "Failed to get runtime config, ret %d", ret);
		return ret;
	}

	*value = resp.value;
	return 0;
}

int npu1_check_protocol_version(struct npu_device *ndev)
{
	DECLARE_NPU_MSG(protocol_version, MSG_OP_GET_PROTOCOL_VERSION);
	struct amdxdna_dev *xdna = ndev->xdna;
	int ret;

	ret = npu_send_mgmt_msg_wait(ndev, &msg);
	if (ret) {
		XDNA_ERR(xdna, "Failed to get protocol version, ret %d", ret);
		return ret;
	}

	if (resp.major != ndev->priv->protocol_major) {
		ret = -EINVAL;
		XDNA_ERR(xdna, "Incompatible firmware protocol version major %d minor %d",
			 resp.major, resp.minor);
	}

	return ret;
}

int npu1_assign_mgmt_pasid(struct npu_device *ndev, u16 pasid)
{
	DECLARE_NPU_MSG(assign_mgmt_pasid, MSG_OP_ASSIGN_MGMT_PASID);

	req.pasid = pasid;

	return npu_send_mgmt_msg_wait(ndev, &msg);
}

int npu1_query_aie_version(struct npu_device *ndev, struct aie_version *version)
{
	DECLARE_NPU_MSG(aie_version_info, MSG_OP_QUERY_AIE_VERSION);
	struct amdxdna_dev *xdna = ndev->xdna;
	int ret;

	ret = npu_send_mgmt_msg_wait(ndev, &msg);
	if (ret)
		return ret;

	XDNA_DBG(xdna, "Query AIE version - major: %u minor: %u completed",
		 resp.major, resp.minor);

	version->major = resp.major;
	version->minor = resp.minor;

	return 0;
}

int npu1_query_aie_metadata(struct npu_device *ndev, struct aie_metadata *metadata)
{
	DECLARE_NPU_MSG(aie_tile_info, MSG_OP_QUERY_AIE_TILE_INFO);
	int ret;

	ret = npu_send_mgmt_msg_wait(ndev, &msg);
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

int npu1_query_firmware_version(struct npu_device *ndev,
				struct amdxdna_fw_ver *fw_ver)
{
	DECLARE_NPU_MSG(firmware_version, MSG_OP_GET_FIRMWARE_VERSION);
	int ret;

	ret = npu_send_mgmt_msg_wait(ndev, &msg);
	if (ret)
		return ret;

	fw_ver->major = resp.major;
	fw_ver->minor = resp.minor;
	fw_ver->sub = resp.sub;
	fw_ver->build = resp.build;

	return 0;
}

int npu1_create_context(struct npu_device *ndev, struct amdxdna_hwctx *hwctx)
{
	DECLARE_NPU_MSG(create_ctx, MSG_OP_CREATE_CONTEXT);
	struct amdxdna_dev *xdna = ndev->xdna;
	struct xdna_mailbox_chann_res x2i;
	struct xdna_mailbox_chann_res i2x;
	struct cq_pair *cq_pair;
	u32 intr_reg;
	int ret;

	req.aie_type = 1;
	req.start_col = hwctx->start_col;
	req.num_col = hwctx->num_col;
	req.num_cq_pairs_requested = 1;
	req.pasid = hwctx->client->pasid;
	req.context_priority = 2;

	ret = npu_send_mgmt_msg_wait(ndev, &msg);
	if (ret)
		return ret;

	hwctx->fw_ctx_id = resp.context_id;

	cq_pair = &resp.cq_pair[0];
	x2i.mb_head_ptr_reg = NPU_MBOX_OFF(ndev, cq_pair->x2i_q.head_addr);
	x2i.mb_tail_ptr_reg = NPU_MBOX_OFF(ndev, cq_pair->x2i_q.tail_addr);
	x2i.rb_start_addr   = NPU_SRAM_OFF(ndev, cq_pair->x2i_q.buf_addr);
	x2i.rb_size	    = cq_pair->x2i_q.buf_size;

	i2x.mb_head_ptr_reg = NPU_MBOX_OFF(ndev, cq_pair->i2x_q.head_addr);
	i2x.mb_tail_ptr_reg = NPU_MBOX_OFF(ndev, cq_pair->i2x_q.tail_addr);
	i2x.rb_start_addr   = NPU_SRAM_OFF(ndev, cq_pair->i2x_q.buf_addr);
	i2x.rb_size	    = cq_pair->i2x_q.buf_size;

	ret = pci_irq_vector(to_pci_dev(xdna->ddev.dev), resp.msix_id);
	if (ret == -EINVAL) {
		XDNA_ERR(xdna, "not able to create channel");
		goto out_destroy_context;
	}

	intr_reg = i2x.mb_head_ptr_reg + 4;
	hwctx->priv->mbox_chan = xdna_mailbox_create_channel(ndev->mbox, &x2i, &i2x,
							     intr_reg, ret);
	if (!hwctx->priv->mbox_chan) {
		XDNA_ERR(xdna, "not able to create channel");
		ret = -EINVAL;
		goto out_destroy_context;
	}

	XDNA_DBG(xdna, "%s.%d mailbox channel irq: %d, msix_id: %d",
		 hwctx->name, hwctx->id, ret, resp.msix_id);
	XDNA_DBG(xdna, "%s.%d created fw ctx %d pasid %d", hwctx->name,
		 hwctx->id, hwctx->fw_ctx_id, hwctx->client->pasid);

	return 0;

out_destroy_context:
	npu1_destroy_context(ndev, hwctx);
	return ret;
}

int npu1_destroy_context(struct npu_device *ndev, struct amdxdna_hwctx *hwctx)
{
	DECLARE_NPU_MSG(destroy_ctx, MSG_OP_DESTROY_CONTEXT);
	struct amdxdna_dev *xdna = ndev->xdna;
	int ret;

	if (!hwctx->priv->mbox_chan)
		return 0;

	req.context_id = hwctx->fw_ctx_id;
	ret = npu_send_mgmt_msg_wait(ndev, &msg);
	if (ret)
		XDNA_WARN(xdna, "%s.%d destroy context failed, ret %d",
			  hwctx->name, hwctx->id, ret);

	xdna_mailbox_destroy_channel(hwctx->priv->mbox_chan);
	hwctx->priv->mbox_chan = NULL;
	XDNA_DBG(xdna, "%s.%d destroyed fw ctx %d", hwctx->name,
		 hwctx->id, hwctx->fw_ctx_id);

	return ret;
}

int npu1_map_host_buf(struct npu_device *ndev, u32 context_id, u64 addr, u64 size)
{
	DECLARE_NPU_MSG(map_host_buffer, MSG_OP_MAP_HOST_BUFFER);
	struct amdxdna_dev *xdna = ndev->xdna;
	int ret;

	req.context_id = context_id;
	req.buf_addr = addr;
	req.buf_size = size;
	ret = npu_send_mgmt_msg_wait(ndev, &msg);
	if (ret)
		return ret;

	XDNA_DBG(xdna, "fw ctx %d map host buf addr 0x%llx size 0x%llx",
		 context_id, addr, size);

	return 0;
}

#if defined(CONFIG_DEBUG_FS)
int npu1_self_test(struct npu_device *ndev)
{
	DECLARE_NPU_MSG(check_self_test, MSG_OP_INVOKE_SELF_TEST);

	req.test_mask = 0x3F;
	return npu_send_mgmt_msg_wait(ndev, &msg);
}
#else
int npu1_self_test(struct npu_device *ndev)
{
}
#endif

int npu1_query_status(struct npu_device *ndev, char __user *buf, u32 size, u32 *cols_filled)
{
	DECLARE_NPU_MSG(aie_column_info, MSG_OP_QUERY_COL_STATUS);
	struct amdxdna_client *client, *tmp_client;
	struct amdxdna_dev *xdna = ndev->xdna;
	struct amdxdna_hwctx *hwctx;
	dma_addr_t xdna_dev_addr;
	u32 aie_bitmap_copy;
	u32 aie_bitmap = 0;
	u32 num_col = 0;
	u8 *buff_addr;
	int next = 0;
	int ret, idx;
	u32 i;

	buff_addr = dma_alloc_noncoherent(xdna->ddev.dev, size, &xdna_dev_addr,
					  DMA_TO_DEVICE, GFP_KERNEL);
	if (!buff_addr)
		return -ENOMEM;

	/* Go through each hardware context and mark the AIE columns that are active */
	mutex_lock(&xdna->dev_lock);
	list_for_each_entry_safe(client, tmp_client, &xdna->client_list, node) {
		idx = srcu_read_lock(&client->hwctx_srcu);
		idr_for_each_entry_continue(&client->hwctx_idr, hwctx, next) {
			for (i = hwctx->start_col; i < hwctx->num_col; i++)
				aie_bitmap = aie_bitmap | (1 << (i));
		}
		srcu_read_unlock(&client->hwctx_srcu, idx);
	}
	mutex_unlock(&xdna->dev_lock);

	/* Hardware contexts may share AIE columns. Count columns after creating the bitmap */
	aie_bitmap_copy = aie_bitmap;
	while (aie_bitmap_copy != 0) {
		aie_bitmap_copy = aie_bitmap_copy >> 1;
		num_col++;
	}

	*cols_filled = 0;
	req.dump_buff_addr = (u64)buff_addr;
	req.dump_buff_size = size;
	req.num_cols = num_col;
	req.aie_bitmap = aie_bitmap;

	ret = npu_send_mgmt_msg_wait(ndev, &msg);
	if (ret) {
		XDNA_ERR(xdna, "Error during NPU query, status %d", ret);
		goto fail;
	}

	if (resp.status != NPU_STATUS_SUCCESS) {
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
	dma_free_noncoherent(xdna->ddev.dev, size, buff_addr,
			     xdna_dev_addr, DMA_TO_DEVICE);
	return ret;
}

int npu1_register_asyn_event_msg(struct npu_device *ndev, dma_addr_t addr, u32 size,
				 void *handle, void (*cb)(void*, const u32 *, size_t))
{
	struct async_event_msg_req req = { 0 };
	struct xdna_mailbox_msg msg = {
		.send_data = (u8 *)&req,
		.send_size = sizeof(req),
		.handle = handle,
		.opcode = MSG_OP_REGISTER_ASYNC_EVENT_MSG,
		.notify_cb = cb,
	};

	req.buf_addr = addr;
	req.buf_size = size;

	XDNA_DBG(ndev->xdna, "Register addr 0x%llx size 0x%x", addr, size);
	return xdna_mailbox_send_msg(ndev->mgmt_chann, &msg, TX_TIMEOUT);
}

/* Below messages are to hardware context mailbox channel */
int npu1_config_cu(struct amdxdna_hwctx *hwctx)
{
	struct mailbox_channel *chann = hwctx->priv->mbox_chan;
	struct amdxdna_dev *xdna = hwctx->client->xdna;
	u32 shift = xdna->dev_info->dev_mem_buf_shift;
	DECLARE_NPU_MSG(config_cu, MSG_OP_CONFIG_CU);
	int ret, i;

	if (!chann)
		return -ENODEV;

	if (!hwctx->cus) {
		XDNA_DBG(xdna, "No CU config in hwctx");
		return -EINVAL;
	}

	if (hwctx->cus->num_cus > MAX_NUM_CUS) {
		XDNA_DBG(xdna, "Exceed maximum CU %d", MAX_NUM_CUS);
		return -EINVAL;
	}

	req.num_cus = hwctx->cus->num_cus;
	for (i = 0; i < req.num_cus; i++) {
		struct amdxdna_cu_config *cu = &hwctx->cus->cu_configs[i];

		req.configs[i].pdi_addr = cu->xdna_addr >> shift;
		req.configs[i].cu_func = cu->cu_func;
		XDNA_DBG(xdna, "CU %d full addr 0x%llx, short addr 0x%x, cu func %d", i,
			 cu->xdna_addr, req.configs[i].pdi_addr, req.configs[i].cu_func);
	}

	ret = npu_send_msg_wait(xdna->dev_handle, chann, &msg);
	if (ret)
		return ret;

	XDNA_DBG(xdna, "configure %d CUs completed", hwctx->cus->num_cus);

	return 0;
}

int npu1_execbuf(struct amdxdna_hwctx *hwctx, u32 cu_idx,
		 u32 *payload, u32 payload_len, void *handle,
		 void (*notify_cb)(void *, const u32 *, size_t))
{
	struct mailbox_channel *chann = hwctx->priv->mbox_chan;
	struct amdxdna_dev *xdna = hwctx->client->xdna;
	struct execute_buffer_req req;
	struct xdna_mailbox_msg msg;
	int ret;

	if (!chann)
		return -ENODEV;

	if (payload_len < sizeof(req.payload)) {
		XDNA_DBG(xdna, "Invalid payload len");
		return -EINVAL;
	}

	req.cu_idx = cu_idx;
	memcpy(req.payload, payload, sizeof(req.payload));
	msg.send_data = (u8 *)&req;
	msg.send_size = sizeof(req);
	msg.handle = handle;
	msg.opcode = MSG_OP_EXECUTE_BUFFER_CF;
	msg.notify_cb = notify_cb;

	ret = xdna_mailbox_send_msg(chann, &msg, TX_TIMEOUT);
	if (ret) {
		XDNA_ERR(xdna, "Send message failed");
		return ret;
	}

	return 0;
}


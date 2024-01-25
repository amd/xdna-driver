// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2023-2024, Advanced Micro Devices, Inc.
 *
 * Authors:
 *	Min Ma <min.ma@amd.com>
 */

#include <linux/kthread.h>
#include <drm/drm_cache.h>

#include "drm_local/amdxdna_accel.h"
#include "ipu_msg_priv.h"
#include "ipu_pci.h"

#define TX_TIMEOUT 2000 /* miliseconds */
#define RX_TIMEOUT 5000 /* miliseconds */

struct ipu_notify {
	struct completion       comp;
	u32			*data;
	size_t			size;
	int			error;
};

#define DECLARE_IPU_MSG(name, op)		\
	struct name##_req	req = { 0 };	\
	struct name##_resp	resp =		\
{ IPU_STATUS_MAX_IPU_STATUS_CODE };	\
struct ipu_notify	hdl = {			\
	.error = 0,				\
	.data = (u32 *)&resp,			\
	.size = sizeof(resp),			\
	.comp = COMPLETION_INITIALIZER(hdl.comp),	\
};						\
struct xdna_mailbox_msg msg = {			\
	.send_data = (u8 *)&req,		\
	.send_size = sizeof(req),		\
	.handle = &hdl,				\
	.opcode = op,				\
	.notify_cb = ipu_msg_cb,		\
}

static void ipu_msg_cb(void *handle, const u8 *data, size_t size)
{
	struct ipu_notify *cb_arg = handle;

	if (!data) {
		cb_arg->error = 1;
		return;
	}

	print_hex_dump_debug("resp data: ", DUMP_PREFIX_OFFSET,
			     16, 4, data, size, true);
	memcpy(cb_arg->data, data, cb_arg->size);
	complete(&cb_arg->comp);
}

static int ipu_send_msg_wait(struct amdxdna_dev *xdna,
			     struct mailbox_channel *chann,
			     struct xdna_mailbox_msg *msg)
{
	struct ipu_notify *hdl = msg->handle;
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

	if (*hdl->data != IPU_STATUS_SUCCESS) {
		XDNA_ERR(xdna, "command opcode 0x%x failed, status 0x%x",
			 msg->opcode, *hdl->data);
		return -EINVAL;
	}

	return 0;
}

static int ipu_send_mgmt_msg_wait(struct amdxdna_dev *xdna,
				  struct xdna_mailbox_msg *msg)
{
	int ret;

	if (!xdna->mgmt_chann)
		return -ENODEV;

	ret = ipu_send_msg_wait(xdna, xdna->mgmt_chann, msg);
	if (ret == -ETIME) {
		if (xdna->async_msgd)
			kthread_stop(xdna->async_msgd);
		xdna_mailbox_destroy_channel(xdna->mgmt_chann);
		xdna->async_msgd = NULL;
		xdna->mgmt_chann = NULL;
	}

	return ret;
}

int ipu_suspend_fw(struct ipu_device *idev)
{
	DECLARE_IPU_MSG(suspend, MSG_OP_SUSPEND);
	struct amdxdna_dev *xdna = idev->xdna;

	return ipu_send_mgmt_msg_wait(xdna, &msg);
}

int ipu_resume_fw(struct ipu_device *idev)
{
	DECLARE_IPU_MSG(suspend, MSG_OP_RESUME);
	struct amdxdna_dev *xdna = idev->xdna;

	return ipu_send_mgmt_msg_wait(xdna, &msg);
}

int ipu_check_header_hash(struct ipu_device *idev)
{
	DECLARE_IPU_MSG(check_header_hash, MSG_OP_CHECK_HEADER_HASH);
	struct amdxdna_dev *xdna = idev->xdna;
	int ret;

	req.hash_high = idev->priv->fw_hash_high;
	req.hash_low = idev->priv->fw_hash_low;

	ret = ipu_send_mgmt_msg_wait(xdna, &msg);
	if (ret) {
		XDNA_ERR(xdna, "check header hash 0x%llx%llx failed, ret %d",
			 req.hash_high, req.hash_low, ret);
	}

	return ret;
}

int ipu_assign_mgmt_pasid(struct ipu_device *idev, u16 pasid)
{
	DECLARE_IPU_MSG(assign_mgmt_pasid, MSG_OP_ASSIGN_MGMT_PASID);
	struct amdxdna_dev *xdna = idev->xdna;

	req.pasid = pasid;

	return ipu_send_mgmt_msg_wait(xdna, &msg);
}

int ipu_register_pdis(struct ipu_device *idev, struct amdxdna_xclbin *xclbin)
{
	DECLARE_IPU_MSG(register_pdi, MSG_OP_REGISTER_PDI);
	struct amdxdna_dev *xdna = idev->xdna;
	struct amdxdna_partition *part;
	int ret, i;

	part = &xclbin->partition;
	req.num_infos = 1;
	for (i = 0; i < part->num_pdis; i++) {
		struct amdxdna_pdi *pdi = &part->pdis[i];

		if (pdi->id > IPU_MAX_PDI_ID) {
			XDNA_ERR(xdna, "PDI ID out of range, XCLBIN not supported");
			ret = -EOPNOTSUPP;
			goto cleanup;
		}

		req.pdi_info.pdi_id = pdi->id;
		req.pdi_info.address = pdi->addr;
		req.pdi_info.size = pdi->size;
		req.pdi_info.type = pdi->type;
		resp.status = IPU_STATUS_MAX_IPU_STATUS_CODE;
		drm_clflush_virt_range(pdi->image, pdi->size);

		ret = ipu_send_mgmt_msg_wait(xdna, &msg);
		if (ret) {
			XDNA_ERR(xdna, "PDI %d register failed, ret %d", pdi->id, ret);
			if (ret == -ETIME || ret == -ENODEV)
				return ret;

			goto cleanup;
		}

		pdi->registered = 1;
		WARN_ONCE(pdi->id != resp.reg_index, "PDI ID and FW registered index mismatch");
		XDNA_DBG(xdna, "PDI %d register completed, index %d",
			 pdi->id, resp.reg_index);
	}

	XDNA_DBG(xdna, "XCLBIN %pUb PDIs register completed", &xclbin->uuid);

	return 0;

cleanup:
	ret = ipu_unregister_pdis(idev, xclbin);
	if (ret)
		XDNA_ERR(xdna, "Clean up PDIs failed, ret %d", ret);
	return ret;
}

int ipu_unregister_pdis(struct ipu_device *idev, struct amdxdna_xclbin *xclbin)
{
	DECLARE_IPU_MSG(unregister_pdi, MSG_OP_UNREGISTER_PDI);
	struct amdxdna_dev *xdna = idev->xdna;
	struct amdxdna_partition *part;
	int ret, i;

	req.num_pdi = 1;
	part = &xclbin->partition;
	for (i = 0; i < part->num_pdis; i++) {
		struct amdxdna_pdi *pdi = &part->pdis[i];

		if (!pdi->registered)
			continue;

		req.pdi_id = pdi->id;
		req.registered = 1;
		resp.status = IPU_STATUS_MAX_IPU_STATUS_CODE;
		ret = ipu_send_mgmt_msg_wait(xdna, &msg);
		if (ret) {
			XDNA_ERR(xdna, "PDI %d unregister failed, ret %d",
				 pdi->id, ret);
			return ret;
		}

		pdi->registered = 0;
		XDNA_DBG(xdna, "PDI %d unregister completed", pdi->id);
	}
	XDNA_DBG(xdna, "XCLBIN %pUb unregister completed", &xclbin->uuid);

	return 0;
}

int ipu_create_context(struct ipu_device *idev, struct amdxdna_hwctx *hwctx)
{
	DECLARE_IPU_MSG(create_ctx, MSG_OP_CREATE_CONTEXT);
	struct amdxdna_dev *xdna = idev->xdna;
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

	ret = ipu_send_mgmt_msg_wait(xdna, &msg);
	if (ret)
		return ret;

	hwctx->fw_ctx_id = resp.context_id;

	cq_pair = &resp.cq_pair[0];
	x2i.mb_head_ptr_reg = IPU_MBOX_OFF(idev, cq_pair->x2i_q.head_addr);
	x2i.mb_tail_ptr_reg = IPU_MBOX_OFF(idev, cq_pair->x2i_q.tail_addr);
	x2i.rb_start_addr   = IPU_SRAM_OFF(idev, cq_pair->x2i_q.buf_addr);
	x2i.rb_size	    = cq_pair->x2i_q.buf_size;

	i2x.mb_head_ptr_reg = IPU_MBOX_OFF(idev, cq_pair->i2x_q.head_addr);
	i2x.mb_tail_ptr_reg = IPU_MBOX_OFF(idev, cq_pair->i2x_q.tail_addr);
	i2x.rb_start_addr   = IPU_SRAM_OFF(idev, cq_pair->i2x_q.buf_addr);
	i2x.rb_size	    = cq_pair->i2x_q.buf_size;

	ret = pci_irq_vector(xdna->pdev, resp.msix_id);
	if (ret == -EINVAL) {
		XDNA_ERR(xdna, "not able to create channel");
		goto out_destroy_context;
	}

	intr_reg = i2x.mb_head_ptr_reg + 4;
	hwctx->mbox_chan = xdna_mailbox_create_channel(xdna->mbox, &x2i, &i2x,
						       intr_reg, ret);
	if (!hwctx->mbox_chan) {
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
	ipu_destroy_context(idev, hwctx);
	return ret;
}

int ipu_destroy_context(struct ipu_device *idev, struct amdxdna_hwctx *hwctx)
{
	DECLARE_IPU_MSG(destroy_ctx, MSG_OP_DESTROY_CONTEXT);
	struct amdxdna_dev *xdna = idev->xdna;
	int ret;

	if (!hwctx->mbox_chan)
		return 0;

	req.context_id = hwctx->fw_ctx_id;
	ret = ipu_send_mgmt_msg_wait(xdna, &msg);
	if (ret)
		XDNA_WARN(xdna, "%s.%d destroy context failed, ret %d",
			  hwctx->name, hwctx->id, ret);

	xdna_mailbox_destroy_channel(hwctx->mbox_chan);
	hwctx->mbox_chan = NULL;
	XDNA_DBG(xdna, "%s.%d destroyed fw ctx %d", hwctx->name,
		 hwctx->id, hwctx->fw_ctx_id);

	return ret;
}

int ipu_map_host_buf(struct ipu_device *idev, u32 context_id, u64 addr, u64 size)
{
	DECLARE_IPU_MSG(map_host_buffer, MSG_OP_MAP_HOST_BUFFER);
	struct amdxdna_dev *xdna = idev->xdna;
	int ret;

	req.context_id = context_id;
	req.buf_addr = addr;
	req.buf_size = size;
	ret = ipu_send_mgmt_msg_wait(xdna, &msg);
	if (ret)
		return ret;

	XDNA_DBG(xdna, "fw ctx %d map host buf addr 0x%llx size 0x%llx",
		 context_id, addr, size);

	return 0;
}

int ipu_query_error(struct ipu_device *idev, u64 addr, u32 size, u32 *row,
		    u32 *col, u32 *mod, u32 *count, bool *next)
{
	DECLARE_IPU_MSG(query_error, MSG_OP_QUERY_ERROR_INFO);
	struct amdxdna_dev *xdna = idev->xdna;
	int ret;

	req.buf_addr = addr;
	req.buf_size = size;
	req.next_row = *row;
	req.next_column = *col;
	req.next_module = *mod;

	ret = ipu_send_mgmt_msg_wait(xdna, &msg);
	if (ret)
		return ret;

	*row = resp.next_row;
	*col = resp.next_column;
	*mod = resp.next_module;
	*next = resp.has_next_err;
	*count = resp.num_err;

	return 0;
}

int ipu_config_cu(struct ipu_device *idev, struct mailbox_channel *chann,
		  struct amdxdna_xclbin *xclbin)
{
	DECLARE_IPU_MSG(config_cu, MSG_OP_CONFIG_CU);
	struct amdxdna_dev *xdna = idev->xdna;
	int ret, i;

	req.num_cus = xclbin->num_cus;
	for (i = 0; i < req.num_cus; i++) {
		struct amdxdna_cu *cu = &xclbin->cu[i];

		req.configs[i].cu_idx = cu->index;
		req.configs[i].cu_func = cu->func;
		req.configs[i].cu_pdi_id = cu->pdi_id;
	}

	ret = ipu_send_msg_wait(xdna, chann, &msg);
	if (ret)
		return ret;

	XDNA_DBG(xdna, "configure %d CUs completed", xclbin->num_cus);

	return 0;
}

int ipu_execbuf(struct ipu_device *idev, struct mailbox_channel *chann,
		u32 cu_idx, u32 *payload, void *handle,
		void (*notify_cb)(void *, const u8 *, size_t))
{
	struct amdxdna_dev *xdna = idev->xdna;
	struct execute_buffer_req req;
	struct xdna_mailbox_msg msg;
	int ret;

	if (!chann)
		return -ENODEV;

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

#if defined(CONFIG_DEBUG_FS)
int ipu_self_test(struct ipu_device *idev)
{
	DECLARE_IPU_MSG(check_self_test, MSG_OP_INVOKE_SELF_TEST);
	struct amdxdna_dev *xdna = idev->xdna;

	req.test_mask = 0x3F;
	return ipu_send_mgmt_msg_wait(xdna, &msg);
}
#endif

int ipu_query_version(struct ipu_device *idev, struct aie_version *version)
{
	DECLARE_IPU_MSG(aie_version_info, MSG_OP_QUERY_AIE_VERSION);
	struct amdxdna_dev *xdna = idev->xdna;
	int ret;

	ret = ipu_send_mgmt_msg_wait(xdna, &msg);
	if (ret)
		return ret;

	XDNA_DBG(xdna, "Query AIE version - major: %u minor: %u completed",
		 resp.major, resp.minor);

	version->major = resp.major;
	version->minor = resp.minor;

	return 0;
}

int ipu_query_metadata(struct ipu_device *idev, struct aie_metadata *metadata)
{
	DECLARE_IPU_MSG(aie_tile_info, MSG_OP_QUERY_AIE_TILE_INFO);
	struct amdxdna_dev *xdna = idev->xdna;
	int ret;

	ret = ipu_send_mgmt_msg_wait(xdna, &msg);
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

int ipu_query_status(struct ipu_device *idev, u32 start_col, u32 num_col, char __user *buf,
		     u32 size, u32 *cols_filled)
{
	DECLARE_IPU_MSG(aie_column_info, MSG_OP_QUERY_COL_STATUS);
	struct amdxdna_dev *xdna = idev->xdna;
	dma_addr_t xdna_dev_addr;
	u32 aie_bitmap = 0;
	u8 *buff_addr;
	int ret;
	u32 i;

	buff_addr = dma_alloc_noncoherent(&xdna->pdev->dev, size, &xdna_dev_addr,
					  DMA_TO_DEVICE, GFP_KERNEL);
	if (!buff_addr)
		return -ENOMEM;

	WARN_ON(idev->metadata.cols > 32);
	for (i = start_col; i < start_col + num_col; i++)
		aie_bitmap |= (1 << i);

	*cols_filled = 0;
	req.dump_buff_addr = (u64)buff_addr;
	req.dump_buff_size = size;
	req.num_cols = num_col;
	req.aie_bitmap = aie_bitmap;

	ret = ipu_send_mgmt_msg_wait(xdna, &msg);
	if (ret) {
		XDNA_ERR(xdna, "Error during IPU query, status %d", ret);
		goto fail;
	}

	if (resp.status != IPU_STATUS_SUCCESS) {
		XDNA_ERR(xdna, "Query IPU status failed, status 0x%x", resp.status);
		ret = -EINVAL;
		goto fail;
	}
	XDNA_DBG(xdna, "Query IPU status completed");

	if (size < resp.size) {
		ret = -EINVAL;
		XDNA_ERR(xdna, "Bad buffer size. Available: %u. Needs: %u", size, resp.size);
		goto fail;
	}

	if (copy_to_user(buf, buff_addr, resp.size)) {
		ret = -EFAULT;
		XDNA_ERR(xdna, "Failed to copy IPU status to user space");
		goto fail;
	}

	*cols_filled = aie_bitmap;

fail:
	dma_free_noncoherent(&xdna->pdev->dev, size, buff_addr, xdna_dev_addr, DMA_TO_DEVICE);
	return ret;
}

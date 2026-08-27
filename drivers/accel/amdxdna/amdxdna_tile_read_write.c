// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2026, Advanced Micro Devices, Inc.
 */

#include "drm/amdxdna_accel.h"
#include <drm/drm_cache.h>
#include <drm/drm_print.h>
#include <linux/errno.h>
#include <linux/uaccess.h>

#include "aie.h"
#include "amdxdna_ctx.h"
#include "amdxdna_mailbox_helper.h"
#include "amdxdna_pci_drv.h"
#include "amdxdna_tile_read_write.h"

struct amdxdna_tile_rw_walk_arg {
	struct amdxdna_hwctx_key			key;

	struct aie_device				*aie;
	const struct amdxdna_drm_aie_tile_access	*access;
	u8 __user					*buf;
};

/* amdxdna_hwctx_match() casts the walk arg to struct amdxdna_hwctx_key. */
static_assert(offsetof(struct amdxdna_tile_rw_walk_arg, key) == 0,
	      "key must be the first member for amdxdna_hwctx_match()");

static int amdxdna_aie_tile_read_reg(struct amdxdna_hwctx *hwctx,
				     struct amdxdna_tile_rw_walk_arg *wa)
{
	struct amdxdna_dev *xdna = hwctx->client->xdna;
	u32 reg_val = 0;
	int ret;

	if (wa->access->size != sizeof(u32)) {
		XDNA_ERR(xdna, "REG access requires size == 4 (got %u)",
			 wa->access->size);
		return -EINVAL;
	}

	ret = wa->aie->msg_ops.rw_reg(hwctx, true, wa->access->row,
				      wa->access->col, wa->access->addr,
				      &reg_val);
	if (ret) {
		XDNA_ERR(xdna, "AIE register read failed, ret %d", ret);
		return ret;
	}

	if (copy_to_user(wa->buf, &reg_val, sizeof(reg_val))) {
		XDNA_ERR(xdna, "Failed to copy register data to user");
		return -EFAULT;
	}

	return 0;
}

static int amdxdna_aie_tile_read_mem(struct amdxdna_hwctx *hwctx,
				     struct amdxdna_tile_rw_walk_arg *wa)
{
	struct amdxdna_dev *xdna = hwctx->client->xdna;
	struct amdxdna_msg_buf_hdl *dma_hdl;
	int ret;

	dma_hdl = amdxdna_alloc_msg_buff(xdna, wa->access->size);
	if (IS_ERR(dma_hdl)) {
		XDNA_ERR(xdna, "Failed to allocate DMA buffer, ret %ld",
			 PTR_ERR(dma_hdl));
		return PTR_ERR(dma_hdl);
	}

	memset(to_cpu_addr(dma_hdl, 0), 0, to_buf_size(dma_hdl));
	drm_clflush_virt_range(to_cpu_addr(dma_hdl, 0), to_buf_size(dma_hdl));

	ret = wa->aie->msg_ops.rw_mem(hwctx, true, wa->access->row,
				      wa->access->col, wa->access->addr,
				      to_dma_addr(dma_hdl, 0),
				      wa->access->size);
	if (ret) {
		XDNA_ERR(xdna, "AIE memory read failed, ret %d", ret);
		goto free_dma;
	}

	drm_clflush_virt_range(to_cpu_addr(dma_hdl, 0), to_buf_size(dma_hdl));

	if (copy_to_user(wa->buf, to_cpu_addr(dma_hdl, 0), wa->access->size)) {
		XDNA_ERR(xdna, "Failed to copy data to user");
		ret = -EFAULT;
	}

free_dma:
	amdxdna_free_msg_buff(dma_hdl);
	return ret;
}

static int amdxdna_aie_tile_read_cb(struct amdxdna_hwctx *hwctx, void *arg)
{
	struct amdxdna_dev *xdna = hwctx->client->xdna;
	struct amdxdna_tile_rw_walk_arg *wa = arg;

	if (!amdxdna_client_visible(hwctx->client)) {
		XDNA_ERR(xdna, "Permission denied for context %u", wa->access->context_id);
		return -EPERM;
	}

	if (wa->access->col >= hwctx->num_col) {
		XDNA_ERR(xdna, "Column %u is outside partition range [0, %u)",
			 wa->access->col, hwctx->num_col);
		return -EINVAL;
	}

	switch (wa->access->type) {
	case AMDXDNA_AIE_TILE_ACCESS_REG:
		return amdxdna_aie_tile_read_reg(hwctx, wa);
	case AMDXDNA_AIE_TILE_ACCESS_MEM:
		return amdxdna_aie_tile_read_mem(hwctx, wa);
	default:
		XDNA_ERR(xdna, "Invalid access type %u", wa->access->type);
		return -EINVAL;
	}
}

int amdxdna_aie_tile_read(struct aie_device *aie,
			  struct amdxdna_client *client,
			  struct amdxdna_drm_get_array *args)
{
	struct amdxdna_drm_aie_tile_access access = {};
	struct amdxdna_dev *xdna = client->xdna;
	struct amdxdna_tile_rw_walk_arg wa;
	struct amdxdna_client *tmp_client;
	int ret = -ENOENT;
	size_t buf_size;
	u8 __user *buf;

	drm_WARN_ON(&xdna->ddev, !mutex_is_locked(&xdna->dev_lock));

	if (!aie->msg_ops.rw_reg || !aie->msg_ops.rw_mem)
		return -EOPNOTSUPP;

	if (args->num_element != 1) {
		XDNA_ERR(xdna, "Invalid num_element %u, expected 1",
			 args->num_element);
		return -EINVAL;
	}

	buf_size = (size_t)args->num_element * args->element_size;
	buf = u64_to_user_ptr(args->buffer);
	if (!access_ok(buf, buf_size)) {
		XDNA_ERR(xdna, "Failed to access buffer");
		return -EFAULT;
	}

	if (buf_size < sizeof(access)) {
		XDNA_ERR(xdna, "Insufficient buffer size: 0x%zx", buf_size);
		args->element_size = sizeof(access);
		return -ENOSPC;
	}

	if (copy_from_user(&access, buf, sizeof(access))) {
		XDNA_ERR(xdna, "Failed to copy tile access from user");
		return -EFAULT;
	}

	if (access.type > AMDXDNA_AIE_TILE_ACCESS_MEM) {
		XDNA_ERR(xdna, "Invalid access type %u", access.type);
		return -EINVAL;
	}

	if (XDNA_MBZ_DBG(xdna, &access.pad, sizeof(access.pad)))
		return -EINVAL;

	XDNA_DBG(xdna, "AIE tile read: ctx %u pid %llu col %u row %u addr 0x%x size %u",
		 access.context_id, access.pid, access.col, access.row,
		 access.addr, access.size);

	if (!access.size) {
		XDNA_ERR(xdna, "Zero access size");
		return -EINVAL;
	}

	if (buf_size < access.size) {
		XDNA_ERR(xdna, "Insufficient buffer size: 0x%zx, need 0x%x",
			 buf_size, access.size);
		args->element_size = access.size;
		return -ENOSPC;
	}

	if (access.row >= aie->metadata.rows) {
		XDNA_ERR(xdna, "Row %u is outside range [0, %u)",
			 access.row, aie->metadata.rows);
		return -EINVAL;
	}

	wa.key.ctx_id = access.context_id;
	wa.key.pid = access.pid;
	wa.access = &access;
	wa.aie = aie;
	wa.buf = buf;

	amdxdna_for_each_client(xdna, tmp_client) {
		ret = amdxdna_hwctx_walk(tmp_client, &wa,
					 amdxdna_hwctx_match,
					 amdxdna_aie_tile_read_cb);
		if (ret != -ENOENT)
			break;
	}
	if (ret == -ENOENT)
		XDNA_ERR(xdna, "Context %u for pid %llu not found",
			 access.context_id, access.pid);
	return ret;
}

static int amdxdna_aie_tile_write_reg(struct amdxdna_hwctx *hwctx,
				      struct amdxdna_tile_rw_walk_arg *wa)
{
	struct amdxdna_dev *xdna = hwctx->client->xdna;
	u32 reg_val;
	int ret;

	if (wa->access->size != sizeof(u32)) {
		XDNA_ERR(xdna, "REG access requires size == 4 (got %u)",
			 wa->access->size);
		return -EINVAL;
	}

	if (copy_from_user(&reg_val, wa->buf + sizeof(*wa->access),
			   sizeof(reg_val))) {
		XDNA_ERR(xdna, "Failed to copy register data from user");
		return -EFAULT;
	}

	ret = wa->aie->msg_ops.rw_reg(hwctx, false, wa->access->row,
				      wa->access->col, wa->access->addr,
				      &reg_val);
	if (ret)
		XDNA_ERR(xdna, "AIE register write failed, ret %d", ret);

	return ret;
}

static int amdxdna_aie_tile_write_mem(struct amdxdna_hwctx *hwctx,
				      struct amdxdna_tile_rw_walk_arg *wa)
{
	struct amdxdna_dev *xdna = hwctx->client->xdna;
	struct amdxdna_msg_buf_hdl *dma_hdl;
	int ret;

	dma_hdl = amdxdna_alloc_msg_buff(xdna, wa->access->size);
	if (IS_ERR(dma_hdl)) {
		XDNA_ERR(xdna, "Failed to allocate DMA buffer, ret %ld",
			 PTR_ERR(dma_hdl));
		return PTR_ERR(dma_hdl);
	}

	if (copy_from_user(to_cpu_addr(dma_hdl, 0),
			   wa->buf + sizeof(*wa->access), wa->access->size)) {
		XDNA_ERR(xdna, "Failed to copy data from user");
		ret = -EFAULT;
		goto free_dma;
	}

	drm_clflush_virt_range(to_cpu_addr(dma_hdl, 0), to_buf_size(dma_hdl));

	ret = wa->aie->msg_ops.rw_mem(hwctx, false, wa->access->row,
				      wa->access->col, wa->access->addr,
				      to_dma_addr(dma_hdl, 0),
				      wa->access->size);
	if (ret)
		XDNA_ERR(xdna, "AIE memory write failed, ret %d", ret);

free_dma:
	amdxdna_free_msg_buff(dma_hdl);
	return ret;
}

static int amdxdna_aie_tile_write_cb(struct amdxdna_hwctx *hwctx, void *arg)
{
	struct amdxdna_dev *xdna = hwctx->client->xdna;
	struct amdxdna_tile_rw_walk_arg *wa = arg;

	if (!amdxdna_client_visible(hwctx->client)) {
		XDNA_ERR(xdna, "Permission denied for context %u", wa->access->context_id);
		return -EPERM;
	}

	if (wa->access->col >= hwctx->num_col) {
		XDNA_ERR(xdna, "Column %u is outside partition range [0, %u)",
			 wa->access->col, hwctx->num_col);
		return -EINVAL;
	}

	switch (wa->access->type) {
	case AMDXDNA_AIE_TILE_ACCESS_REG:
		return amdxdna_aie_tile_write_reg(hwctx, wa);
	case AMDXDNA_AIE_TILE_ACCESS_MEM:
		return amdxdna_aie_tile_write_mem(hwctx, wa);
	default:
		XDNA_ERR(xdna, "Invalid access type %u", wa->access->type);
		return -EINVAL;
	}
}

int amdxdna_aie_tile_write(struct aie_device *aie,
			   struct amdxdna_client *client,
			   struct amdxdna_drm_set_state *args)
{
	struct amdxdna_drm_aie_tile_access access = {};
	struct amdxdna_dev *xdna = client->xdna;
	struct amdxdna_tile_rw_walk_arg wa;
	struct amdxdna_client *tmp_client;
	int ret = -ENOENT;
	u8 __user *buf;

	drm_WARN_ON(&xdna->ddev, !mutex_is_locked(&xdna->dev_lock));

	if (!aie->msg_ops.rw_reg || !aie->msg_ops.rw_mem)
		return -EOPNOTSUPP;

	buf = u64_to_user_ptr(args->buffer);
	if (!access_ok(buf, args->buffer_size)) {
		XDNA_ERR(xdna, "Failed to access buffer");
		return -EFAULT;
	}

	if (args->buffer_size < sizeof(access)) {
		XDNA_ERR(xdna, "Insufficient buffer size: 0x%x",
			 args->buffer_size);
		args->buffer_size = sizeof(access);
		return -ENOSPC;
	}

	if (copy_from_user(&access, buf, sizeof(access))) {
		XDNA_ERR(xdna, "Failed to copy tile access from user");
		return -EFAULT;
	}

	if (access.type > AMDXDNA_AIE_TILE_ACCESS_MEM) {
		XDNA_ERR(xdna, "Invalid access type %u", access.type);
		return -EINVAL;
	}

	if (XDNA_MBZ_DBG(xdna, &access.pad, sizeof(access.pad)))
		return -EINVAL;

	XDNA_DBG(xdna, "AIE tile write: ctx %u pid %llu col %u row %u addr 0x%x size %u",
		 access.context_id, access.pid, access.col, access.row,
		 access.addr, access.size);

	if (!access.size) {
		XDNA_ERR(xdna, "Zero access size");
		return -EINVAL;
	}

	if (access.size > args->buffer_size - sizeof(access)) {
		XDNA_ERR(xdna, "Insufficient buffer size: 0x%x, need 0x%zx",
			 args->buffer_size,
			 sizeof(access) + (size_t)access.size);
		args->buffer_size = sizeof(access) + access.size;
		return -ENOSPC;
	}

	if (access.row >= aie->metadata.rows) {
		XDNA_ERR(xdna, "Row %u is outside range [0, %u)",
			 access.row, aie->metadata.rows);
		return -EINVAL;
	}

	wa.key.ctx_id = access.context_id;
	wa.key.pid = access.pid;
	wa.access = &access;
	wa.aie = aie;
	wa.buf = buf;

	amdxdna_for_each_client(xdna, tmp_client) {
		ret = amdxdna_hwctx_walk(tmp_client, &wa,
					 amdxdna_hwctx_match,
					 amdxdna_aie_tile_write_cb);
		if (ret != -ENOENT)
			break;
	}
	if (ret == -ENOENT)
		XDNA_ERR(xdna, "Context %u for pid %llu not found",
			 access.context_id, access.pid);
	return ret;
}

// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2025, Advanced Micro Devices, Inc.
 */
#include <linux/device.h>
#include <linux/version.h>
#include <linux/vmalloc.h>

#include "ve2_fw.h"
#include "ve2_of.h"
#include "ve2_mgmt.h"
#include "ve2_res_solver.h"

static int ve2_query_ctx_status_array(struct amdxdna_client *client,
				      struct amdxdna_drm_hwctx_entry *tmp,
				      pid_t pid, u32 ctx_id)
{
	struct amdxdna_dev *xdna = client->xdna;
	struct amdxdna_client *tmp_client;
	struct amdxdna_ctx *ctx;
	unsigned long id;
	int ret = 0, idx;
	u32 hw_i = 0;

	list_for_each_entry(tmp_client, &xdna->client_list, node) {
		size_t total_bo_usage;
		u32 pid, pasid;

		if (pid && pid != tmp_client->pid)
			continue;

		mutex_lock(&tmp_client->mm_lock);
		total_bo_usage = tmp_client->total_bo_usage;
		pid = tmp_client->pid;
		pasid = tmp_client->pasid;
		mutex_unlock(&tmp_client->mm_lock);

		idx = srcu_read_lock(&tmp_client->ctx_srcu);
		amdxdna_for_each_ctx(tmp_client, id, ctx) {
			if (!ctx->priv)
				continue;

			if (ctx_id && ctx_id != ctx->id)
				continue;

			tmp[hw_i].pid = pid;
			tmp[hw_i].context_id = ctx->id;
			tmp[hw_i].hwctx_id = ctx->id;
			tmp[hw_i].start_col = ctx->start_col;
			tmp[hw_i].num_col = ctx->num_col;
			tmp[hw_i].command_submissions = ctx->submitted;
			tmp[hw_i].command_completions = ctx->completed;
			tmp[hw_i].migrations = 0;
			tmp[hw_i].preemptions = 0;
			tmp[hw_i].errors = 0;
			tmp[hw_i].pasid = pasid;
			tmp[hw_i].priority = ctx->qos.priority;
			tmp[hw_i].gops = ctx->qos.gops;
			tmp[hw_i].fps = ctx->qos.fps;
			tmp[hw_i].dma_bandwidth = ctx->qos.dma_bandwidth;
			tmp[hw_i].latency = ctx->qos.latency;
			tmp[hw_i].frame_exec_time = ctx->qos.frame_exec_time;
			/* Using heap_usage for total_bo_usage for VE2 */
			tmp[hw_i].heap_usage = total_bo_usage;
			tmp[hw_i].suspensions = 0;
			tmp[hw_i].state = ctx->priv->state;

			hw_i++;
		}
		srcu_read_unlock(&tmp_client->ctx_srcu, idx);
	}

	if (pid && ctx_id && !hw_i) {
		XDNA_ERR(xdna, "Invalid context ID %d for PID %d", ctx_id, pid);
		ret = -EINVAL;
	}

	return ret;
}

static int ve2_get_array_hwctx(struct amdxdna_client *client,
			       struct amdxdna_drm_get_array *args)
{
	struct amdxdna_drm_hwctx_entry __user *buf;
	struct amdxdna_dev *xdna = client->xdna;
	struct amdxdna_drm_hwctx_entry *tmp;
	int ctx_limit, ctx_cnt, ret, i;

	buf = u64_to_user_ptr(args->buffer);
	tmp = kcalloc(args->num_element, sizeof(*tmp), GFP_KERNEL);
	if (!tmp) {
		XDNA_ERR(xdna, "Failed to allocate memory for hwctx array");
		return -ENOMEM;
	}

	switch (args->param) {
	case DRM_AMDXDNA_HW_CONTEXT_ALL:
		ctx_limit = ve2_hwctx_limit;
		WARN_ON(ctx_limit > AMDXDNA_MAX_NUM_ELEMENT);
		ctx_cnt = 0;
		struct amdxdna_client *tmp_client;

		list_for_each_entry(tmp_client, &xdna->client_list, node) {
			unsigned long id;
			struct amdxdna_ctx *ctx;

			xa_for_each(&tmp_client->ctx_xa, id, ctx)
				if (ctx->priv)
					ctx_cnt++;
		}

		if (args->num_element < ctx_cnt) {
			XDNA_ERR(xdna, "Not enough space. Total ctx %d, got %d",
				 ctx_cnt, args->num_element);
			args->num_element = ctx_cnt;
			ret = -ENOSPC;
			goto exit;
		}

		ret = ve2_query_ctx_status_array(client, tmp, 0, 0);
		if (ret)
			goto exit;

		break;

	default:
		XDNA_ERR(xdna, "Not supported request parameter %u",
			 args->param);
		ret = -EOPNOTSUPP;
		goto exit;
	}

	for (i = 0; i < ctx_cnt; i++) {
		if (copy_to_user(&buf[i], &tmp[i], sizeof(*tmp))) {
			ret = -EFAULT;
			goto exit;
		}
	}
	args->num_element = ctx_cnt;

exit:
	kfree(tmp);
	return ret;
}

static int ve2_aie_write(struct amdxdna_client *client,
			 struct amdxdna_drm_set_state *args)
{
	struct amdxdna_dev *xdna = client->xdna;
	struct amdxdna_drm_aie_tile_access footer = {};
	struct amdxdna_client *tmp_client;
	struct amdxdna_ctx *hwctx = NULL;
	struct device *aie_dev;
	unsigned long hwctx_id;
	void *local_buf = NULL;
	int ret = 0, idx;
	u32 offset;

	/* Extract footer from the end of the buffer */
	offset = args->buffer_size - sizeof(footer);
	if (copy_from_user(&footer, u64_to_user_ptr(args->buffer) + offset, sizeof(footer))) {
		XDNA_ERR(xdna, "Failed to copy request footer from user");
		return -EFAULT;
	}

	XDNA_DBG(xdna, "Write request for ctx_id: %u, col: %u, row: %u, addr: 0x%x, size: %u\n",
		 footer.context_id, footer.col, footer.row, footer.addr, footer.size);

	/* Find the hardware context */
	list_for_each_entry(tmp_client, &xdna->client_list, node) {
		idx = srcu_read_lock(&tmp_client->ctx_srcu);
		struct amdxdna_ctx *hw_ctx;

		amdxdna_for_each_ctx(tmp_client, hwctx_id, hw_ctx) {
			if (footer.context_id == hwctx_id && footer.pid == hw_ctx->client->pid)
				hwctx = hw_ctx;
		}
		srcu_read_unlock(&tmp_client->ctx_srcu, idx);
	}

	if (!hwctx) {
		XDNA_ERR(xdna, "hw context :%u pid:%llu not found\n", footer.context_id,
			 footer.pid);
		return -EINVAL;
	}

	XDNA_DBG(xdna, "Found hwctx: cl_pid: %u, hwctx_id: %u, start_col %u, ncol %u\n",
		 hwctx->client->pid, hwctx->id, hwctx->start_col, hwctx->num_col);

	/* Validate column is within partition */
	if (footer.col >= hwctx->num_col) {
		XDNA_ERR(xdna, "Column %u is outside partition range [0, %u)\n",
			 footer.col, hwctx->num_col);
		return -EINVAL;
	}

	/* Validate row */
	if (footer.row >= xdna->dev_handle->aie_dev_info.rows) {
		XDNA_ERR(xdna, "Row %u is outside range [0, %u)\n",
			 footer.row, xdna->dev_handle->aie_dev_info.rows);
		return -EINVAL;
	}

	/* Get AIE device handle */
	aie_dev = hwctx->priv->aie_dev;
	if (!aie_dev) {
		XDNA_ERR(xdna, "AIE device handle not found\n");
		return -EINVAL;
	}

	/* Allocate local buffer for write data */
	local_buf = kzalloc(footer.size, GFP_KERNEL);
	if (!local_buf)
		return -ENOMEM;

	/* Copy data from user space (data is at the beginning of buffer) */
	if (copy_from_user(local_buf, u64_to_user_ptr(args->buffer), footer.size)) {
		XDNA_ERR(xdna, "Error: unable to copy data from userptr\n");
		kfree(local_buf);
		return -EFAULT;
	}

	/* Write to AIE memory */
	ret = ve2_partition_write(aie_dev, footer.col, footer.row, footer.addr,
				  footer.size, local_buf);
	if (ret < 0) {
		XDNA_ERR(xdna, "Error in AIE memory write operation, err: %d\n", ret);
		kfree(local_buf);
		return ret;
	}

	kfree(local_buf);
	return 0;
}

static int ve2_aie_read(struct amdxdna_client *client, struct amdxdna_drm_get_array *args)
{
	struct amdxdna_dev *xdna = client->xdna;
	struct amdxdna_drm_aie_tile_access footer = {};
	struct amdxdna_client *tmp_client;
	struct amdxdna_ctx *hwctx = NULL;
	struct device *aie_dev;
	unsigned long hwctx_id;
	void *local_buf = NULL;
	int ret = 0, idx;
	u32 buf_size;
	u32 offset;

	buf_size = args->num_element * args->element_size;
	offset = buf_size - sizeof(footer);
	if (copy_from_user(&footer, u64_to_user_ptr(args->buffer) + offset, sizeof(footer))) {
		XDNA_ERR(xdna, "Failed to copy request from user");
		return -EFAULT;
	}

	XDNA_DBG(xdna, "Read request for ctx_id: %u, col: %u, row: %u, addr: 0x%x, size: %u\n",
		 footer.context_id, footer.col, footer.row, footer.addr, footer.size);

	/* Find the hardware context */
	list_for_each_entry(tmp_client, &xdna->client_list, node) {
		idx = srcu_read_lock(&tmp_client->ctx_srcu);
		struct amdxdna_ctx *hw_ctx;

		amdxdna_for_each_ctx(tmp_client, hwctx_id, hw_ctx) {
			if (footer.context_id == hwctx_id && footer.pid == hw_ctx->client->pid)
				hwctx = hw_ctx;
		}
		srcu_read_unlock(&tmp_client->ctx_srcu, idx);
	}

	if (!hwctx) {
		XDNA_ERR(xdna, "hw context :%u pid:%llu not found\n", footer.context_id,
			 footer.pid);
		return -EINVAL;
	}

	XDNA_DBG(xdna, "Found hwctx: cl_pid: %u, hwctx_id: %u, start_col %u, ncol %u\n",
		 hwctx->client->pid, hwctx->id, hwctx->start_col, hwctx->num_col);

	/* Validate column is within partition */
	if (footer.col >= hwctx->num_col) {
		XDNA_ERR(xdna, "Column %u is outside partition range [0, %u)\n",
			 footer.col, hwctx->num_col);
		return -EINVAL;
	}

	/* Validate row */
	if (footer.row >= xdna->dev_handle->aie_dev_info.rows) {
		XDNA_ERR(xdna, "Row %u is outside range [0, %u)\n",
			 footer.row, xdna->dev_handle->aie_dev_info.rows);
		return -EINVAL;
	}

	/* Get AIE device handle and relative column */
	aie_dev = hwctx->priv->aie_dev;
	if (!aie_dev) {
		XDNA_ERR(xdna, "AIE device handle not found\n");
		return -EINVAL;
	}

	/* Allocate local buffer for read */
	local_buf = kzalloc(footer.size, GFP_KERNEL);
	if (!local_buf)
		return -ENOMEM;

	/* Read from AIE memory */
	ret = ve2_partition_read(aie_dev, footer.col, footer.row, footer.addr,
				 footer.size, local_buf);
	if (ret < 0) {
		XDNA_ERR(xdna, "Error in AIE memory read operation, err: %d\n", ret);
		kfree(local_buf);
		return ret;
	}

	/* Copy data to user space */
	if (copy_to_user(u64_to_user_ptr(args->buffer), local_buf, footer.size)) {
		XDNA_ERR(xdna, "Error: unable to copy memory to userptr\n");
		kfree(local_buf);
		return -EFAULT;
	}

	kfree(local_buf);
	return 0;
}

static int ve2_coredump_read(struct amdxdna_client *client, struct amdxdna_drm_get_array *args)
{
	struct amdxdna_dev *xdna = client->xdna;
	struct amdxdna_drm_aie_coredump footer = {};
	struct amdxdna_client *tmp_client;
	struct amdxdna_ctx *hwctx = NULL;
	unsigned long hwctx_id;
	void *local_buf = NULL;
	int ret = 0, idx;
	u32 rel_size = 0;
	u32 buf_size;
	u32 offset;

	buf_size = args->num_element * args->element_size;
	offset = buf_size - sizeof(footer);
	if (copy_from_user(&footer, u64_to_user_ptr(args->buffer) + offset, sizeof(footer))) {
		XDNA_ERR(xdna, "Failed to copy request from user");
		return -EFAULT;
	}

	XDNA_DBG(xdna, "AIE Coredump request received for context_id = %u buffer size %u\n",
		 footer.context_id, buf_size);

	list_for_each_entry(tmp_client, &xdna->client_list, node) {
		idx = srcu_read_lock(&tmp_client->ctx_srcu);
		struct amdxdna_ctx *hw_ctx;

		amdxdna_for_each_ctx(tmp_client, hwctx_id, hw_ctx) {
			if (footer.context_id == hwctx_id && footer.pid == hw_ctx->client->pid)
				hwctx = hw_ctx;
		}
		srcu_read_unlock(&tmp_client->ctx_srcu, idx);
	}

	if (!hwctx) {
		XDNA_ERR(xdna, "hw context :%u pid:%llu not found\n", footer.context_id,
			 footer.pid);
		return -EINVAL;
	}

	XDNA_DBG(xdna, "cl_pid: %u, hwctx_id: %u, start_col %u, ncol %u\n",
		 hwctx->client->pid, hwctx->id, hwctx->start_col,
		 hwctx->num_col);

	rel_size = hwctx->priv->num_col * xdna->dev_handle->aie_dev_info.rows * TILE_ADDRESS_SPACE;
	if (rel_size > buf_size) {
		XDNA_DBG(xdna, "Invalid buffer size:%d (rel_size:%d)\n", buf_size, rel_size);
		args->element_size = rel_size;
		return -ENOBUFS;
	}

	local_buf = vmalloc(rel_size);
	if (!local_buf)
		return -ENOMEM;

	ret = ve2_create_coredump(xdna, hwctx, local_buf, rel_size);
	XDNA_DBG(xdna, "created dump of size:%d\n", ret);

	if (ret < 0) {
		XDNA_ERR(xdna, "Error in AIE Data mem read operation, err: %d\n", ret);
		vfree(local_buf);
		return ret;
	}

	if (copy_to_user(u64_to_user_ptr(args->buffer), local_buf, ret)) {
		XDNA_ERR(xdna, "Error: unable to copy memory to userptr\n");
		vfree(local_buf);
		return -EFAULT;
	}
	vfree(local_buf);
	return 0;
}

static int ve2_get_firmware_version(struct amdxdna_client *client,
				    struct amdxdna_drm_get_info *args)
{
	struct amdxdna_dev_hdl *hdl = client->xdna->dev_handle;
	struct ve2_firmware_version *fver = &hdl->fw_version;
	struct amdxdna_drm_query_ve2_firmware_version version;

	if (!fver)
		return -EINVAL;

	memset(&version, 0, sizeof(version));

	version.major = fver->major;
	version.minor = fver->minor;

	memcpy(version.date, fver->date, VE2_FW_DATE_STRING_LENGTH);
	memcpy(version.git_hash, fver->git_hash, VE2_FW_HASH_STRING_LENGTH);

	if (args->buffer_size < sizeof(version))
		return -EINVAL;

	if (copy_to_user((u64_to_user_ptr(args->buffer)), &version, sizeof(version)))
		return -EFAULT;

	return 0;
}

static int ve2_get_total_col(struct amdxdna_client *client, struct amdxdna_drm_get_info *args)
{
	struct amdxdna_dev *xdna = client->xdna;
	struct amdxdna_drm_query_aie_metadata *meta;
	int ret = 0;

	meta = kmalloc(sizeof(*meta), GFP_KERNEL);
	if (!meta)
		return -ENOMEM;

	meta->cols = xrs_get_total_cols(xdna->dev_handle->xrs_hdl);
	if (copy_to_user(u64_to_user_ptr(args->buffer), meta, args->buffer_size))
		ret = -EFAULT;

	kfree(meta);
	return ret;
}

int ve2_get_aie_info(struct amdxdna_client *client, struct amdxdna_drm_get_info *args)
{
	struct amdxdna_dev *xdna = client->xdna;
	int ret, idx;

	if (!drm_dev_enter(&xdna->ddev, &idx))
		return -ENODEV;

	XDNA_DBG(xdna, "Received get air info request param %d", args->param);

	mutex_lock(&xdna->dev_lock);
	switch (args->param) {
	case DRM_AMDXDNA_QUERY_VE2_FIRMWARE_VERSION:
		ret = ve2_get_firmware_version(client, args);
		break;
	case DRM_AMDXDNA_QUERY_AIE_METADATA:
		ret = ve2_get_total_col(client, args);
		break;
	default:
		XDNA_ERR(xdna, "Not supported request parameter %u", args->param);
		ret = -EOPNOTSUPP;
	}

	mutex_unlock(&xdna->dev_lock);
	drm_dev_exit(idx);

	return ret;
}

int ve2_get_array(struct amdxdna_client *client, struct amdxdna_drm_get_array *args)
{
	struct amdxdna_dev *xdna = client->xdna;
	int ret, idx;

	if (!drm_dev_enter(&xdna->ddev, &idx))
		return -ENODEV;

	XDNA_DBG(xdna, "Received get air info request param %d", args->param);

	mutex_lock(&xdna->dev_lock);
	switch (args->param) {
	case DRM_AMDXDNA_AIE_COREDUMP:
		ret = ve2_coredump_read(client, args);
		break;
	case DRM_AMDXDNA_HW_CONTEXT_ALL:
		ret = ve2_get_array_hwctx(client, args);
		break;
	case DRM_AMDXDNA_AIE_TILE_READ:
		ret = ve2_aie_read(client, args);
		break;
	default:
		XDNA_ERR(xdna, "Not supported request parameter %u", args->param);
		ret = -EOPNOTSUPP;
	}

	mutex_unlock(&xdna->dev_lock);
	drm_dev_exit(idx);

	return ret;
}

int ve2_set_aie_state(struct amdxdna_client *client, struct amdxdna_drm_set_state *args)
{
	struct amdxdna_dev *xdna = client->xdna;
	int ret, idx;

	if (!drm_dev_enter(&xdna->ddev, &idx))
		return -ENODEV;

	XDNA_DBG(xdna, "Received set aie status request param %d", args->param);

	mutex_lock(&xdna->dev_lock);
	switch (args->param) {
	case DRM_AMDXDNA_AIE_TILE_WRITE:
		ret = ve2_aie_write(client, args);
		break;
	default:
		XDNA_ERR(xdna, "Not supported request parameter %u", args->param);
		ret = -EOPNOTSUPP;
	}

	mutex_unlock(&xdna->dev_lock);
	drm_dev_exit(idx);

	return ret;
}

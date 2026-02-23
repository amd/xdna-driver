// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2025, Advanced Micro Devices, Inc.
 */
#include <linux/device.h>
#include <linux/version.h>
#include <linux/vmalloc.h>
#include <linux/completion.h>
#include <linux/jiffies.h>
#include <linux/sched.h>
#include <linux/fdtable.h>

#include "ve2_fw.h"
#include "ve2_of.h"
#include "ve2_mgmt.h"
#include "ve2_res_solver.h"
#include "amdxdna_error.h"
#include "amdxdna_drm.h"

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

	XDNA_DBG(xdna, "Query context status: pid=%d, ctx_id=%u", pid, ctx_id);

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

	XDNA_DBG(xdna, "Coredump read: ctx_id=%u, pid=%llu, buf_size=%u",
		 footer.context_id, footer.pid, buf_size);

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

	if (args->buffer_size < sizeof(*meta)) {
		XDNA_ERR(xdna, "Buffer too small. Given: %u, required: %zu",
			 args->buffer_size, sizeof(*meta));
		args->buffer_size = sizeof(*meta);
		return -ENOBUFS;
	}

	meta = kzalloc(sizeof(*meta), GFP_KERNEL);
	if (!meta)
		return -ENOMEM;

	meta->cols = xdna->dev_handle->aie_dev_info.cols;
	meta->rows = xdna->dev_handle->aie_dev_info.rows;
	meta->core.row_count = xdna->dev_handle->aie_dev_info.core_rows;
	meta->mem.row_count = xdna->dev_handle->aie_dev_info.mem_rows;
	meta->shim.row_count = xdna->dev_handle->aie_dev_info.shim_rows;

	if (copy_to_user(u64_to_user_ptr(args->buffer), meta, sizeof(*meta)))
		ret = -EFAULT;

	kfree(meta);
	return ret;
}

static int ve2_get_clock_metadata(struct amdxdna_client *client, struct amdxdna_drm_get_info *args)
{
	struct amdxdna_drm_query_clock_metadata clock_metadata = {};
	struct aie_partition_req part_req = { 0 };
	struct xrs_action_load action = {};
	struct alloc_requests req = {};
	struct amdxdna_dev *xdna = client->xdna;
	struct amdxdna_client *tmp_client;
	struct amdxdna_ctx *hwctx = NULL;
	struct device *aie_dev = NULL;
	struct solver_state *xrs = NULL;
	unsigned long ctx_id;
	u32 partition_id;
	u32 num_cols = MIN_COL_SUPPORT;
	u64 aie_freq = 0;
	int ret, idx;

	if (args->buffer_size != sizeof(clock_metadata)) {
		XDNA_ERR(xdna, "Invalid buffer size. Given: %u, Expected: %lu",
			 args->buffer_size, sizeof(clock_metadata));
		return -EINVAL;
	}

	/* Search for existing context with AIE partition across all clients */
	list_for_each_entry(tmp_client, &xdna->client_list, node) {
		idx = srcu_read_lock(&tmp_client->ctx_srcu);
		amdxdna_for_each_ctx(tmp_client, ctx_id, hwctx) {
			if (hwctx && hwctx->priv && hwctx->priv->aie_dev) {
				aie_dev = hwctx->priv->aie_dev;
				srcu_read_unlock(&tmp_client->ctx_srcu, idx);
				ret = aie_partition_get_freq(aie_dev, &aie_freq);
				if (ret) {
					XDNA_ERR(xdna, "Failed to read AIE frequency: %d", ret);
					return ret;
				}
				goto fill_metadata;
			}
		}
		srcu_read_unlock(&tmp_client->ctx_srcu, idx);
	}
	/* No existing context - allocate temporary partition using resolver */
	req.cdo.ncols = num_cols;
	ret = ve2_xrs_col_list(xdna, &req, num_cols);
	if (ret) {
		XDNA_ERR(xdna, "Failed to build column list: %d", ret);
		return ret;
	}
	req.rid = (u64)client;
	req.rqos.user_start_col = USER_START_COL_NOT_REQUESTED;

	xrs = (struct solver_state *)xdna->dev_handle->xrs_hdl;
	mutex_lock(&xrs->xrs_lock);
	ret = xrs_allocate_resource(xdna->dev_handle->xrs_hdl, &req, &action);
	mutex_unlock(&xrs->xrs_lock);

	if (ret) {
		XDNA_ERR(xdna, "Failed to allocate temporary partition: %d", ret);
		kfree(req.cdo.start_cols);
		return ret;
	}
	partition_id = aie_calc_part_id(action.part.start_col, action.part.ncols);
	part_req.partition_id = partition_id;
	aie_dev = aie_partition_request(&part_req);
	if (IS_ERR(aie_dev)) {
		ret = PTR_ERR(aie_dev);

		mutex_lock(&xrs->xrs_lock);
		xrs_release_resource(xdna->dev_handle->xrs_hdl, req.rid, &action);
		mutex_unlock(&xrs->xrs_lock);

		kfree(req.cdo.start_cols);
		XDNA_ERR(xdna, "Failed to request AIE partition %u: %d", partition_id, ret);
		return ret;
	}
	ret = aie_partition_get_freq(aie_dev, &aie_freq);
	aie_partition_release(aie_dev);

	mutex_lock(&xrs->xrs_lock);
	xrs_release_resource(xdna->dev_handle->xrs_hdl, req.rid, &action);
	mutex_unlock(&xrs->xrs_lock);

	kfree(req.cdo.start_cols);

	if (ret) {
		XDNA_ERR(xdna, "Failed to read AIE frequency: %d", ret);
		return ret;
	}

fill_metadata:
	strscpy(clock_metadata.mp_npu_clock.name, "AIE Clock");
	clock_metadata.mp_npu_clock.freq_mhz = (u16)(aie_freq / 1000000);

	if (copy_to_user(u64_to_user_ptr(args->buffer), &clock_metadata, sizeof(clock_metadata))) {
		XDNA_ERR(xdna, "Failed to copy clock metadata to user");
		return -EFAULT;
	}

	return 0;
}

static int ve2_get_hwctx_mem_bitmap(struct amdxdna_client *client,
				    struct amdxdna_drm_get_array *args)
{
	struct amdxdna_dev *xdna = client->xdna;
	struct amdxdna_ctx *hwctx;
	u32 context_id;
	u32 mem_bitmap;
	int idx;

	/* Context ID is passed via element_size */
	context_id = args->element_size;

	XDNA_DBG(xdna, "Query mem_bitmap for context_id=%u", context_id);

	idx = srcu_read_lock(&client->ctx_srcu);
	hwctx = xa_load(&client->ctx_xa, context_id);
	if (!hwctx) {
		XDNA_ERR(xdna, "Context %u not found", context_id);
		srcu_read_unlock(&client->ctx_srcu, idx);
		return -EINVAL;
	}

	if (!hwctx->priv) {
		XDNA_ERR(xdna, "Context %u has no private data", context_id);
		srcu_read_unlock(&client->ctx_srcu, idx);
		return -EINVAL;
	}

	mem_bitmap = hwctx->priv->mem_bitmap;
	srcu_read_unlock(&client->ctx_srcu, idx);

	XDNA_DBG(xdna, "Returning mem_bitmap=0x%x for context_id=%u", mem_bitmap, context_id);

	if (copy_to_user(u64_to_user_ptr(args->buffer), &mem_bitmap, sizeof(mem_bitmap))) {
		XDNA_ERR(xdna, "Failed to copy mem_bitmap to user");
		return -EFAULT;
	}

	args->num_element = 1;
	return 0;
}

int ve2_get_aie_info(struct amdxdna_client *client, struct amdxdna_drm_get_info *args)
{
	struct amdxdna_dev *xdna = client->xdna;
	int ret, idx;

	if (!drm_dev_enter(&xdna->ddev, &idx))
		return -ENODEV;

	XDNA_DBG(xdna, "Get AIE info: param=%u, buffer_size=%u", args->param, args->buffer_size);

	mutex_lock(&xdna->dev_lock);
	switch (args->param) {
	case DRM_AMDXDNA_QUERY_VE2_FIRMWARE_VERSION:
		XDNA_DBG(xdna, "Querying firmware version");
		ret = ve2_get_firmware_version(client, args);
		break;
	case DRM_AMDXDNA_QUERY_AIE_METADATA:
		XDNA_DBG(xdna, "Querying AIE metadata");
		ret = ve2_get_total_col(client, args);
		break;
	case DRM_AMDXDNA_QUERY_CLOCK_METADATA:
		ret = ve2_get_clock_metadata(client, args);
		break;
	default:
		XDNA_ERR(xdna, "Not supported request parameter %u", args->param);
		ret = -EOPNOTSUPP;
		break;
	}

	XDNA_DBG(xdna, "Get AIE info result: ret=%d", ret);
	mutex_unlock(&xdna->dev_lock);
	drm_dev_exit(idx);

	return ret;
}

static int ve2_get_array_async_error(struct amdxdna_dev *xdna, struct amdxdna_drm_get_array *args)
{
	struct amdxdna_async_error tmp;
	struct amdxdna_mgmtctx *mgmtctx;
	struct amdxdna_dev_hdl *hdl = xdna->dev_handle;
	int ret = 0;
	u32 i, max_idx;
	/* 50ms to wait for callback to start */
	unsigned long poll_timeout = msecs_to_jiffies(50);
	/* 100ms timeout for callback completion */
	unsigned long wait_timeout = msecs_to_jiffies(100);

	/* Set num_element to 0 to indicate no errors */
	args->num_element = 0;

	/* Check if dev_handle and ve2_mgmtctx are valid */
	if (!hdl || !hdl->ve2_mgmtctx)
		return 0;

	/* Wait for any pending error callbacks to complete before reading cached errors.
	 * This ensures async errors are cached before we query for them.
	 * The error callback may start after command completion, so we poll briefly
	 * to catch cases where it starts shortly after the query.
	 */
	max_idx = min_t(u32, hdl->hwctx_limit, hdl->aie_dev_info.cols);
	for (i = 0; i < max_idx; i++) {
		mgmtctx = &hdl->ve2_mgmtctx[i];
		/* Check if mgmtctx is initialized */
		if (!mgmtctx->xdna)
			continue;

		/* Check if mgmt_aiedev is valid before checking callback status */
		mutex_lock(&mgmtctx->ctx_lock);
		if (!mgmtctx->mgmt_aiedev) {
			mutex_unlock(&mgmtctx->ctx_lock);
			continue;
		}
		mutex_unlock(&mgmtctx->ctx_lock);

		/* Poll briefly to see if error callback starts */
		unsigned long poll_start = jiffies;
		bool callback_started = false;

		while (time_before(jiffies, poll_start + poll_timeout)) {
			if (atomic_read(&mgmtctx->error_cb_in_progress)) {
				callback_started = true;
				break;
			}
			/* Small delay to avoid busy waiting */
			schedule_timeout_uninterruptible(msecs_to_jiffies(1));
		}

		/* If callback started (or was already in progress), wait for it to complete */
		if (callback_started || atomic_read(&mgmtctx->error_cb_in_progress)) {
			XDNA_DBG(xdna, "Waiting for error callback to complete on mgmtctx[%u]", i);
			if (wait_for_completion_timeout(&mgmtctx->error_cb_completion,
							wait_timeout) == 0) {
				XDNA_WARN(xdna, "Timeout waiting for err callback completion\n");
			}
		}
	}

	/* Find the first mgmtctx with a cached error */
	/* Use min of hwctx_limit and cols to prevent out-of-bounds access */
	max_idx = min_t(u32, hdl->hwctx_limit, hdl->aie_dev_info.cols);
	for (i = 0; i < max_idx; i++) {
		mgmtctx = &hdl->ve2_mgmtctx[i];
		/* Check if mgmtctx is initialized */
		if (!mgmtctx->xdna)
			continue;

		/* Lock ctx_lock first to ensure mgmtctx structure is stable */
		mutex_lock(&mgmtctx->ctx_lock);
		/* Re-check mgmt_aiedev after acquiring lock to ensure it's still valid */
		if (!mgmtctx->mgmt_aiedev) {
			mutex_unlock(&mgmtctx->ctx_lock);
			continue;
		}

		/* Now lock async_errs_cache to access error data */
		mutex_lock(&mgmtctx->async_errs_cache.lock);
		if (mgmtctx->async_errs_cache.err.err_code) {
			args->num_element++;
			memcpy(&tmp, &mgmtctx->async_errs_cache.err, sizeof(tmp));
			mutex_unlock(&mgmtctx->async_errs_cache.lock);
			mutex_unlock(&mgmtctx->ctx_lock);
			ret = amdxdna_drm_copy_array_to_user(args, &tmp, sizeof(tmp), 1);
			return ret;
		}
		mutex_unlock(&mgmtctx->async_errs_cache.lock);
		mutex_unlock(&mgmtctx->ctx_lock);
	}

	return 0;
}

static int ve2_get_aie_part_fd(struct amdxdna_client *client,
			       struct amdxdna_drm_get_array *args)
{
	struct amdxdna_dev *xdna = client->xdna;
	struct amdxdna_ctx_priv *nhwctx;
	struct amdxdna_ctx *ctx;
	u32 hwctx_handle;
	int srcu_idx;
	int ret = 0;
	int aie_fd;

	hwctx_handle = args->num_element;
	srcu_idx = srcu_read_lock(&client->ctx_srcu);
	ctx = xa_load(&client->ctx_xa, hwctx_handle);
	if (!ctx) {
		XDNA_ERR(xdna, "Failed to get ctx %u", hwctx_handle);
		ret = -EINVAL;
		goto unlock;
	}

	nhwctx = ctx->priv;
	if (!nhwctx || !nhwctx->aie_dev) {
		XDNA_ERR(xdna, "AIE partition not available for hwctx %p", ctx);
		ret = -ENODEV;
		goto unlock;
	}

	aie_fd = aie_partition_get_fd(nhwctx->aie_dev);
	if (aie_fd < 0) {
		XDNA_ERR(xdna, "Failed to get AIE partition FD: %d", aie_fd);
		ret = aie_fd;
		goto unlock;
	}

	if (copy_to_user(u64_to_user_ptr(args->buffer), &aie_fd, sizeof(aie_fd))) {
		XDNA_ERR(xdna, "Failed to copy AIE partition FD to user");
		close_fd(aie_fd);
		ret = -EFAULT;
		goto unlock;
	}

unlock:
	srcu_read_unlock(&client->ctx_srcu, srcu_idx);
	return ret;
}

int ve2_get_array(struct amdxdna_client *client, struct amdxdna_drm_get_array *args)
{
	struct amdxdna_dev *xdna = client->xdna;
	int ret, idx;

	if (!drm_dev_enter(&xdna->ddev, &idx))
		return -ENODEV;

	XDNA_DBG(xdna, "Get array: param=%u, num_element=%u, element_size=%u",
		 args->param, args->num_element, args->element_size);

	mutex_lock(&xdna->dev_lock);
	switch (args->param) {
	case DRM_AMDXDNA_AIE_COREDUMP:
		XDNA_DBG(xdna, "Reading AIE coredump");
		ret = ve2_coredump_read(client, args);
		break;
	case DRM_AMDXDNA_HW_CONTEXT_ALL:
		XDNA_DBG(xdna, "Getting all hardware contexts");
		ret = ve2_get_array_hwctx(client, args);
		break;
	case DRM_AMDXDNA_AIE_TILE_READ:
		XDNA_DBG(xdna, "Reading AIE tile");
		ret = ve2_aie_read(client, args);
		break;
	case DRM_AMDXDNA_HW_LAST_ASYNC_ERR:
		XDNA_DBG(xdna, "Getting last async error");
		ret = ve2_get_array_async_error(xdna, args);
		break;
	case DRM_AMDXDNA_HWCTX_AIE_PART_FD:
		ret = ve2_get_aie_part_fd(client, args);
		break;
	case DRM_AMDXDNA_HWCTX_MEM_BITMAP:
		XDNA_DBG(xdna, "Getting hardware context mem_bitmap");
		ret = ve2_get_hwctx_mem_bitmap(client, args);
		break;
	default:
		XDNA_ERR(xdna, "Not supported request parameter %u", args->param);
		ret = -EOPNOTSUPP;
		break;
	}

	XDNA_DBG(xdna, "Get array result: ret=%d", ret);
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

	XDNA_DBG(xdna, "Set AIE state: param=%u, buffer_size=%u", args->param, args->buffer_size);

	mutex_lock(&xdna->dev_lock);
	switch (args->param) {
	case DRM_AMDXDNA_AIE_TILE_WRITE:
		XDNA_DBG(xdna, "Writing AIE tile");
		ret = ve2_aie_write(client, args);
		break;
	default:
		XDNA_ERR(xdna, "Not supported request parameter %u", args->param);
		ret = -EOPNOTSUPP;
		break;
	}

	XDNA_DBG(xdna, "Set AIE state result: ret=%d", ret);
	mutex_unlock(&xdna->dev_lock);
	drm_dev_exit(idx);

	return ret;
}

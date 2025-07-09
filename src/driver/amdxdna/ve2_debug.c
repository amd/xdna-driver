// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2025, Advanced Micro Devices, Inc.
 */
#include <linux/device.h>
#include <linux/version.h>

#include "ve2_fw.h"
#include "ve2_mgmt.h"
#include "ve2_of.h"

static int ve2_get_hwctx_status(struct amdxdna_client *client, struct amdxdna_drm_get_info *args)
{
	size_t hwctx_data_sz = sizeof(struct amdxdna_drm_query_ctx);
	struct amdxdna_drm_query_ctx *hwctx_data;
	struct amdxdna_drm_query_ctx __user *buf;
	struct amdxdna_dev *xdna = client->xdna;
	struct amdxdna_client *tmp_client;
	u32 req_bytes = 0, hw_i = 0;
	struct amdxdna_ctx *hwctx;
	unsigned long hwctx_id;
	int ret, idx;

	hwctx_data = kzalloc(hwctx_data_sz, GFP_KERNEL);
	if (!hwctx_data)
		return -ENOMEM;

	buf = u64_to_user_ptr(args->buffer);

	mutex_lock(&xdna->dev_lock);
	list_for_each_entry(tmp_client, &xdna->client_list, node) {
		idx = srcu_read_lock(&tmp_client->ctx_srcu);
		amdxdna_for_each_ctx(tmp_client, hwctx_id, hwctx) {
			req_bytes += hwctx_data_sz;
			if (args->buffer_size < req_bytes) {
				XDNA_ERR(xdna, "Invalid buffer size. Given: %u Required: %u bytes",
					 args->buffer_size, req_bytes);
				ret = -EINVAL;
				srcu_read_unlock(&tmp_client->ctx_srcu, idx);
				mutex_unlock(&xdna->dev_lock);
				goto out;
			}

			hwctx_data->pid = hwctx->client->pid;
			hwctx_data->context_id = hwctx->id;
			hwctx_data->start_col = hwctx->start_col;
			hwctx_data->num_col = hwctx->num_col;
			XDNA_DBG(xdna, "cl_pid: %llu, hwctx_id: %u, start_col %u, ncol %u\n",
				 hwctx_data->pid, hwctx_data->context_id, hwctx_data->start_col,
				 hwctx_data->num_col);

			if (copy_to_user(&buf[hw_i], hwctx_data, hwctx_data_sz)) {
				ret = -EFAULT;
				srcu_read_unlock(&tmp_client->ctx_srcu, idx);
				mutex_unlock(&xdna->dev_lock);
				goto out;
			}
			hw_i++;
		}
		srcu_read_unlock(&tmp_client->ctx_srcu, idx);
	}
	mutex_unlock(&xdna->dev_lock);
out:
	kfree(hwctx_data);
	args->buffer_size = req_bytes;

	return ret;
}

static struct device *get_aie_part(struct amdxdna_dev *xdna, u32 col, struct aie_location *loc)
{
	struct amdxdna_ctx *hwctx;

	hwctx = ve2_get_hwctx(xdna, col);
	if (!hwctx || !hwctx->priv)
		return NULL;

	loc->col = col - hwctx->start_col;

	return hwctx->priv->aie_part;
}

static int ve2_tile_data_reg_write(struct amdxdna_client *client,
				   struct amdxdna_drm_set_state *args)
{
	struct amdxdna_dev *xdev = client->xdna;
	struct amdxdna_drm_aie_reg info;
	struct device *aie_dev = NULL;
	struct aie_location loc;
	int ret;

	if (!access_ok(u64_to_user_ptr(args->buffer), args->buffer_size)) {
		XDNA_ERR(xdev, "Failed to access buffer size %d", args->buffer_size);
		return -EFAULT;
	}

	if (copy_from_user(&info, u64_to_user_ptr(args->buffer), sizeof(info))) {
		XDNA_ERR(xdev, "Failed to copy aie_reg info request from user");
		return -EFAULT;
	}

	XDNA_DBG(xdev, "AIE Data Reg write req received for col %u, row %u, addr %u\n", info.row,
		 info.col, info.addr);

	aie_dev = get_aie_part(xdev, info.col, &loc);
	if (!aie_dev) {
		XDNA_ERR(xdev, "AIE device handle not found for given col %u\n", info.col);
		return -EINVAL;
	}

	loc.row = info.row;
	ret = aie_partition_write(aie_dev, loc, info.addr, sizeof(u32), (void *)&info.val, 0);
	if (ret < 0) {
		XDNA_ERR(xdev, "Error in AIE Data Reg write operation, err: %d\n", ret);
		return ret;
	}

	return 0;
}

static int ve2_tile_data_mem_write(struct amdxdna_client *client,
				   struct amdxdna_drm_set_state *args)
{
	struct amdxdna_dev *xdev = client->xdna;
	struct amdxdna_drm_aie_mem info;
	struct aie_location loc;
	struct device *aie_dev;
	void *local_buf;
	int ret;

	if (!access_ok(u64_to_user_ptr(args->buffer), args->buffer_size)) {
		XDNA_ERR(xdev, "Failed to access buffer size %d", args->buffer_size);
		return -EFAULT;
	}

	if (copy_from_user(&info, u64_to_user_ptr(args->buffer), sizeof(info))) {
		XDNA_ERR(xdev, "Failed to copy aie_mem info request from user");
		return -EFAULT;
	}

	XDNA_DBG(xdev, "AIE Data mem write req received for col %u, row %u, addr %u\n", info.row,
		 info.col, info.addr);

	aie_dev = get_aie_part(xdev, info.col, &loc);
	if (!aie_dev) {
		XDNA_ERR(xdev, "AIE device handle not found for given col %u\n", info.col);
		return -EINVAL;
	}

	local_buf = kzalloc(info.size, GFP_KERNEL);
	if (!local_buf) {
		XDNA_ERR(xdev, "Error: not enough memory to store %d\n", info.size);
		return -ENOMEM;
	}

	if (copy_from_user(local_buf, u64_to_user_ptr(info.buf_p), info.size)) {
		XDNA_ERR(xdev, "Error: unable to copy memory to userptr\n");
		kfree(local_buf);
		return -EFAULT;
	}

	loc.row = info.row;
	ret = aie_partition_write(aie_dev, loc, info.addr, info.size, local_buf, 0);
	if (ret < 0) {
		XDNA_ERR(xdev, "Error in AIE Data mem write operation, err: %d\n", ret);
		return ret;
	}

	kfree(local_buf);

	return 0;
}

static int ve2_tile_data_reg_read(struct amdxdna_client *client, struct amdxdna_drm_get_info *args)
{
	struct amdxdna_dev *xdev = client->xdna;
	struct amdxdna_drm_aie_reg info;
	struct aie_location loc;
	struct device *aie_dev;
	int ret;

	if (!access_ok(u64_to_user_ptr(args->buffer), args->buffer_size)) {
		XDNA_ERR(xdev, "Failed to access buffer size %d", args->buffer_size);
		return -EFAULT;
	}

	if (copy_from_user(&info, u64_to_user_ptr(args->buffer), sizeof(info))) {
		XDNA_ERR(xdev, "Failed to copy request from user");
		return -EFAULT;
	}

	XDNA_DBG(xdev, "AIE Data Reg read req received for col %u, row %u, addr %u\n", info.row,
		 info.col, info.addr);

	aie_dev = get_aie_part(xdev, info.col, &loc);
	if (!aie_dev) {
		XDNA_ERR(xdev, "AIE device handle not found for given input args\n");
		return -EINVAL;
	}

	loc.row = info.row;
	ret = aie_partition_read(aie_dev, loc, info.addr, sizeof(u32), (void *)&info.val);
	if (ret < 0) {
		XDNA_ERR(xdev, "Error in AIE Data Reg read operation, err: %d\n", ret);
		return ret;

	} else if (copy_to_user(u64_to_user_ptr(args->buffer), &info, sizeof(info))) {
		XDNA_ERR(xdev, "Error: unable to copy memory to userptr\n");
		return -EFAULT;
	}

	return 0;
}

static int ve2_tile_data_mem_read(struct amdxdna_client *client, struct amdxdna_drm_get_info *args)
{
	struct amdxdna_dev *xdev = client->xdna;
	struct amdxdna_drm_aie_mem info;
	struct aie_location loc;
	struct device *aie_dev;
	void *local_buf = NULL;
	int ret;

	if (!access_ok(u64_to_user_ptr(args->buffer), args->buffer_size)) {
		XDNA_ERR(xdev, "Failed to access buffer size %d", args->buffer_size);
		return -EFAULT;
	}

	if (copy_from_user(&info, u64_to_user_ptr(args->buffer), sizeof(info))) {
		XDNA_ERR(xdev, "Failed to copy request from user");
		return -EFAULT;
	}

	XDNA_DBG(xdev, "AIE Data Mem read req received for col %u, row %u, addr %u\n",
		 info.row, info.col, info.addr);

	aie_dev = get_aie_part(xdev, info.col, &loc);
	if (!aie_dev) {
		XDNA_ERR(xdev, "AIE device handle not found for given input args\n");
		return -EINVAL;
	}

	local_buf = kzalloc(info.size, GFP_KERNEL);
	if (!local_buf)
		return -ENOMEM;

	loc.row = info.row;
	ret = aie_partition_read(aie_dev, loc, info.addr, info.size, local_buf);

	if (copy_to_user(u64_to_user_ptr(info.buf_p), local_buf, info.size)) {
		XDNA_ERR(xdev, "Error: unable to copy memory to userptr\n");
		kfree(local_buf);
		return -EFAULT;
	}

	kfree(local_buf);

	if (ret < 0) {
		XDNA_ERR(xdev, "Error in AIE Data mem read operation, err: %d\n", ret);
		return ret;
	}

	return 0;
}

static int ve2_get_firmware_version(struct amdxdna_client *client,
				    struct amdxdna_drm_get_info *args)
{
	struct amdxdna_drm_query_ve2_firmware_version version;
	struct amdxdna_dev *xdev = client->xdna;
	struct ve2_firmware_version *cver = &xdev->dev_handle->fw_version;

	if (!access_ok(u64_to_user_ptr(args->buffer), args->buffer_size)) {
		XDNA_ERR(xdev, "Failed to access buffer size %d", args->buffer_size);
		return -EFAULT;
	}

	if (args->buffer_size < sizeof(version))
		return -EINVAL;

	memset(&version, 0, sizeof(version));
	version.major = cver->major;
	version.minor = cver->minor;
	memcpy(version.date, cver->date, VE2_FW_DATE_STRING_LENGTH);
	memcpy(version.git_hash, cver->git_hash, VE2_FW_HASH_STRING_LENGTH);

	if (copy_to_user((u64_to_user_ptr(args->buffer)), &version, sizeof(version)))
		return -EFAULT;

	return 0;
}

int ve2_get_aie_info(struct amdxdna_client *client, struct amdxdna_drm_get_info *args)
{
	struct amdxdna_dev *xdna = client->xdna;
	int ret, idx;

	if (!drm_dev_enter(&xdna->ddev, &idx))
		return -ENODEV;

	XDNA_DBG(xdna, "Received get air info request param %d", args->param);

	switch (args->param) {
	case DRM_AMDXDNA_QUERY_HW_CONTEXTS:
		ret = ve2_get_hwctx_status(client, args);
		break;
	case DRM_AMDXDNA_READ_AIE_MEM:
		ret = ve2_tile_data_mem_read(client, args);
		break;
	case DRM_AMDXDNA_READ_AIE_REG:
		ret = ve2_tile_data_reg_read(client, args);
		break;
	case DRM_AMDXDNA_QUERY_VE2_FIRMWARE_VERSION:
		ret = ve2_get_firmware_version(client, args);
		break;
	default:
		XDNA_ERR(xdna, "Not supported request parameter %u", args->param);
		ret = -EOPNOTSUPP;
	}

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

	switch (args->param) {
	case DRM_AMDXDNA_WRITE_AIE_MEM:
		ret = ve2_tile_data_mem_write(client, args);
		break;
	case DRM_AMDXDNA_WRITE_AIE_REG:
		ret = ve2_tile_data_reg_write(client, args);
		break;
	default:
		XDNA_ERR(xdna, "Not supported request parameter %u", args->param);
		ret = -EOPNOTSUPP;
	}

	drm_dev_exit(idx);

	return ret;
}

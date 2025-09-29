// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2025, Advanced Micro Devices, Inc.
 */
#include <linux/device.h>
#include <linux/version.h>

#include "ve2_fw.h"
#include "ve2_of.h"
#include "ve2_mgmt.h"
#include "ve2_res_solver.h"

static int ve2_get_hwctx_status(struct amdxdna_client *client, struct amdxdna_drm_get_info *args)
{
	size_t hwctx_data_sz = sizeof(struct amdxdna_drm_query_hwctx);
	struct amdxdna_drm_query_hwctx *hwctx_data;
	struct amdxdna_drm_query_hwctx __user *buf;
	struct amdxdna_dev *xdna = client->xdna;
	struct amdxdna_client *tmp_client;
	u32 req_bytes = 0, hw_i = 0;
	struct amdxdna_ctx *hwctx;
	unsigned long hwctx_id;
	bool overflow = false;
	int ret = 0, idx;

	hwctx_data = kzalloc(hwctx_data_sz, GFP_KERNEL);
	if (!hwctx_data)
		return -ENOMEM;

	buf = u64_to_user_ptr(args->buffer);

	list_for_each_entry(tmp_client, &xdna->client_list, node) {
		idx = srcu_read_lock(&tmp_client->ctx_srcu);
		amdxdna_for_each_ctx(tmp_client, hwctx_id, hwctx) {
			req_bytes += hwctx_data_sz;
			if (args->buffer_size < req_bytes) {
				/* Continue iterating to get the required size */
				overflow = true;
				continue;
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
				goto out;
			}
			hw_i++;
		}
		srcu_read_unlock(&tmp_client->ctx_srcu, idx);
	}

	if (overflow) {
		XDNA_ERR(xdna, "Invalid buffer size. Given: %u Need: %u.",
			 args->buffer_size, req_bytes);
		ret = -EINVAL;
		goto out;
	}

	if (hw_i == 0) {
		XDNA_ERR(xdna, "pid %d failed to get hwctx\n", client->pid);
		ret = -EINVAL;
	}

out:
	kfree(hwctx_data);
	args->buffer_size = req_bytes;
	return ret;
}

static struct device *get_aie_device_handle(struct amdxdna_dev *xdna, u32 col, u32 *rel_col)
{
	struct amdxdna_ctx *hwctx;

	hwctx = ve2_get_hwctx(xdna, col);
	if (!hwctx || !hwctx->priv)
		return NULL;

	*rel_col = col - hwctx->start_col;
	return hwctx->priv->aie_dev;
}

static int ve2_tile_data_reg_write(struct amdxdna_client *client,
				   struct amdxdna_drm_set_state *args)
{
	struct amdxdna_dev *xdev = client->xdna;
	struct amdxdna_drm_aie_reg info;
	struct device *aie_dev = NULL;
	u32 rel_col;
	int ret = 0;

	if (copy_from_user(&info, u64_to_user_ptr(args->buffer), sizeof(info))) {
		XDNA_ERR(xdev, "Failed to copy request from user");
		return -EFAULT;
	}

	XDNA_DBG(xdev, "AIE Data Reg write req received for col %u, row %u, addr %u\n", info.row,
		 info.col, info.addr);

	aie_dev = get_aie_device_handle(xdev, info.col, &rel_col);
	if (!aie_dev) {
		XDNA_ERR(xdev, "AIE device handle not found for given col %u\n", info.col);
		return -EINVAL;
	}

	ret = ve2_partition_write(aie_dev, rel_col, info.row, info.addr,
				  sizeof(uint32_t), (void *)&info.val);
	if (ret < 0)
		XDNA_ERR(xdev, "Error in AIE Data Reg write operation, err: %d\n", ret);

	return ret > 0 ? 0 : ret;
}

static int ve2_tile_data_mem_write(struct amdxdna_client *client,
				   struct amdxdna_drm_set_state *args)
{
	struct amdxdna_dev *xdev = client->xdna;
	struct amdxdna_drm_aie_mem info;
	struct device *aie_dev;
	void *local_buf = NULL;
	u32 rel_col;
	int ret = 0;

	if (copy_from_user(&info, u64_to_user_ptr(args->buffer), sizeof(info))) {
		XDNA_ERR(xdev, "Failed to copy aie_mem info request from user");
		return -EFAULT;
	}

	XDNA_DBG(xdev, "AIE Data mem write req received for col %u, row %u, addr %u\n", info.row,
		 info.col, info.addr);

	aie_dev = get_aie_device_handle(xdev, info.col, &rel_col);
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

	ret = ve2_partition_write(aie_dev, rel_col, info.row, info.addr,
				  info.size, local_buf);

	if (ret < 0)
		XDNA_ERR(xdev, "Error in AIE Data mem write operation, err: %d\n", ret);

	kfree(local_buf);
	return ret > 0 ? 0 : ret;
}

static int ve2_tile_data_reg_read(struct amdxdna_client *client, struct amdxdna_drm_get_info *args)
{
	struct amdxdna_dev *xdev = client->xdna;
	struct amdxdna_drm_aie_reg info;
	struct device *aie_dev;
	u32 rel_col;
	int ret;

	if (copy_from_user(&info, u64_to_user_ptr(args->buffer), sizeof(info))) {
		XDNA_ERR(xdev, "Failed to copy request from user");
		return -EFAULT;
	}

	XDNA_DBG(xdev, "AIE Data Reg read req received for col %u, row %u, addr %u\n", info.row,
		 info.col, info.addr);

	aie_dev = get_aie_device_handle(xdev, info.col, &rel_col);
	if (!aie_dev) {
		XDNA_ERR(xdev, "AIE device handle not found for given input args\n");
		return -EINVAL;
	}

	ret = ve2_partition_read(aie_dev, rel_col, info.row, info.addr,
				 sizeof(uint32_t),
				 (void *)&info.val);
	/* aie_partition_read(write)_register() API return values
	 *   Number of bytes it reads/writes: on success
	 *   Error code: on failure
	 */
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
	struct device *aie_dev;
	void *local_buf = NULL;
	u32 rel_col;
	int ret;

	if (copy_from_user(&info, u64_to_user_ptr(args->buffer), sizeof(info))) {
		XDNA_ERR(xdev, "Failed to copy request from user");
		return -EFAULT;
	}

	XDNA_DBG(xdev, "AIE Data Mem read req received for col %u, row %u, addr %u\n",
		 info.row, info.col, info.addr);

	aie_dev = get_aie_device_handle(xdev, info.col, &rel_col);
	if (!aie_dev) {
		XDNA_ERR(xdev, "AIE device handle not found for given input args\n");
		return -EINVAL;
	}

	local_buf = kzalloc(info.size, GFP_KERNEL);
	if (!local_buf)
		return -ENOMEM;

	ret = ve2_partition_read(aie_dev, rel_col, info.row, info.addr,
				 info.size, local_buf);
	if (ret < 0) {
		XDNA_ERR(xdev, "Error in AIE Data mem read operation, err: %d\n", ret);
		return ret;
	}

	if (copy_to_user(u64_to_user_ptr(info.buf_p), local_buf, info.size)) {
		XDNA_ERR(xdev, "Error: unable to copy memory to userptr\n");
		kfree(local_buf);
		return -EFAULT;
	}

	kfree(local_buf);

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

int ve2_set_aie_state(struct amdxdna_client *client, struct amdxdna_drm_set_state *args)
{
	struct amdxdna_dev *xdna = client->xdna;
	int ret, idx;

	if (!drm_dev_enter(&xdna->ddev, &idx))
		return -ENODEV;

	XDNA_DBG(xdna, "Received set aie status request param %d", args->param);

	mutex_lock(&xdna->dev_lock);
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

	mutex_unlock(&xdna->dev_lock);
	drm_dev_exit(idx);

	return ret;
}

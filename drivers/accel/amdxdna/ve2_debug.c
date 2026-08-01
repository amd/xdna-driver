// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2026, Advanced Micro Devices, Inc.
 *
 * VE2 debug / info ioctls: hwctx array for XRT aie_partition_info query.
 */

#include <drm/drm_device.h>
#include <drm/drm_drv.h>
#include <linux/cleanup.h>
#include <linux/completion.h>
#include <linux/errno.h>
#include <linux/fdtable.h>
#include <linux/jiffies.h>
#include <linux/minmax.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/vmalloc.h>
#include <linux/xlnx-ai-engine.h>

#include "drm/amdxdna_accel.h"

#include "amdxdna_ctx.h"
#include "amdxdna_pci_drv.h"
#include "ve2_aux.h"
#include "ve2_debug.h"
#include "ve2_hwctx.h"
#include "ve2_mgmt.h"

static int ve2_hwctx_status_cb(struct amdxdna_hwctx *hwctx, void *arg)
{
	struct amdxdna_drm_hwctx_entry *tmp __free(kfree) = NULL;
	struct amdxdna_drm_get_array *array_args = arg;
	struct amdxdna_drm_hwctx_entry __user *buf;
	struct amdxdna_ctx_priv *vp;
	u32 size;

	if (!array_args->num_element)
		return 0;

	tmp = kzalloc_obj(*tmp);
	if (!tmp)
		return -ENOMEM;

	vp = ve2_hw_priv(hwctx);
	tmp->pid = hwctx->client->pid;
	tmp->context_id = hwctx->id;
	tmp->hwctx_id = hwctx->id;
	tmp->start_col = hwctx->start_col;
	tmp->num_col = hwctx->num_col ? hwctx->num_col : hwctx->num_tiles;
	tmp->migrations = 0;
	tmp->preemptions = 0;
	tmp->errors = 0;
	tmp->suspensions = 0;
	if (vp) {
		tmp->command_submissions = vp->submitted;
		tmp->command_completions = vp->completed;
		tmp->state = vp->state;
	} else {
		tmp->state = AMDXDNA_HWCTX_STATE_ACTIVE;
	}
	tmp->pasid = hwctx->client->pasid;
	tmp->heap_usage = hwctx->client->total_bo_usage;
	tmp->priority = hwctx->qos.priority;
	tmp->gops = hwctx->qos.gops;
	tmp->fps = hwctx->qos.fps;
	tmp->dma_bandwidth = hwctx->qos.dma_bandwidth;
	tmp->latency = hwctx->qos.latency;
	tmp->frame_exec_time = hwctx->qos.frame_exec_time;
	buf = u64_to_user_ptr(array_args->buffer);
	size = min(sizeof(*tmp), array_args->element_size);
	if (copy_to_user(buf, tmp, size))
		return -EFAULT;

	array_args->buffer += size;
	array_args->num_element--;

	return 0;
}

static int ve2_query_ctx_status_array(struct amdxdna_client *client,
				      struct amdxdna_drm_get_array *args)
{
	struct amdxdna_drm_get_array array_args;
	struct amdxdna_dev *xdna = client->xdna;
	struct amdxdna_client *tmp_client;
	int ret;

	drm_WARN_ON(&xdna->ddev, !mutex_is_locked(&xdna->dev_lock));

	if (args->element_size > SZ_4K || args->num_element > SZ_1K)
		return -EINVAL;

	array_args.element_size = min(args->element_size,
				      sizeof(struct amdxdna_drm_hwctx_entry));
	array_args.buffer = args->buffer;
	array_args.num_element = args->num_element * args->element_size /
				 array_args.element_size;

	list_for_each_entry(tmp_client, &xdna->client_list, node) {
		ret = amdxdna_hwctx_walk(tmp_client, &array_args, NULL, ve2_hwctx_status_cb);
		if (ret)
			break;
	}

	args->element_size = array_args.element_size;
	args->num_element = (u32)((array_args.buffer - args->buffer) /
				  args->element_size);
	return ret;
}

static int ve2_get_hwctx_mem_bitmap(struct amdxdna_client *client,
				    struct amdxdna_drm_get_array *args)
{
	struct amdxdna_hwctx *hwctx;
	struct amdxdna_ctx_priv *vp;
	u32 context_id = args->element_size;
	u32 mem_bitmap = 0;
	int idx;

	idx = srcu_read_lock(&client->hwctx_srcu);
	hwctx = xa_load(&client->hwctx_xa, context_id);
	if (!hwctx) {
		srcu_read_unlock(&client->hwctx_srcu, idx);
		return -EINVAL;
	}

	vp = ve2_hw_priv(hwctx);
	if (vp)
		mem_bitmap = vp->mem_bitmap;
	srcu_read_unlock(&client->hwctx_srcu, idx);
	if (copy_to_user(u64_to_user_ptr(args->buffer), &mem_bitmap, sizeof(mem_bitmap)))
		return -EFAULT;

	args->num_element = 1;
	return 0;
}

static int ve2_aie_tile_read(struct amdxdna_client *client, struct amdxdna_drm_get_array *args)
{
	struct amdxdna_drm_aie_tile_access footer = {};
	struct amdxdna_dev *xdna = client->xdna;
	struct amdxdna_hwctx *hwctx = NULL;
	struct amdxdna_mgmtctx *mgmtctx;
	struct amdxdna_ctx_priv *vp;
	struct amdxdna_client *tmp;
	struct aie_location loc;
	void *local_buf = NULL;
	u32 buf_size, offset;
	unsigned long hx_id;
	int ret;

	buf_size = (u32)args->num_element * args->element_size;
	if (buf_size < sizeof(footer) + 1) {
		XDNA_ERR(xdna, "buffer_size %u too small", buf_size);
		return -EINVAL;
	}

	/* Footer is at the tail of the buffer; data area precedes it */
	offset = buf_size - sizeof(footer);
	if (copy_from_user(&footer, u64_to_user_ptr(args->buffer) + offset, sizeof(footer))) {
		XDNA_ERR(xdna, "Failed to copy tile_access footer from user");
		return -EFAULT;
	}

	drm_WARN_ON(&xdna->ddev, !mutex_is_locked(&xdna->dev_lock));

	/* Find the hwctx matching context_id + pid */

	list_for_each_entry(tmp, &xdna->client_list, node) {
		struct amdxdna_hwctx *hx;
		int sidx;

		sidx = srcu_read_lock(&tmp->hwctx_srcu);
		xa_for_each(&tmp->hwctx_xa, hx_id, hx) {
			if (hx->id == footer.context_id &&
			    (u64)hx->client->pid == footer.pid) {
				hwctx = hx;
				break;
			}
		}
		srcu_read_unlock(&tmp->hwctx_srcu, sidx);
		if (hwctx)
			break;
	}

	if (!hwctx) {
		XDNA_ERR(xdna, "hwctx %u pid %llu not found",
			 footer.context_id, footer.pid);
		return -EINVAL;
	}

	if (footer.col >= hwctx->num_col) {
		XDNA_ERR(xdna, "col %u out of partition range [0, %u)",
			 footer.col, hwctx->num_col);
		return -EINVAL;
	}

	if (footer.row >= xdna->dev_handle->aie_dev_info.rows) {
		XDNA_ERR(xdna, "row %u out of range [0, %u)",
			 footer.row, xdna->dev_handle->aie_dev_info.rows);
		return -EINVAL;
	}

	vp = ve2_hw_priv(hwctx);
	if (!vp || !vp->mgmtctx) {
		XDNA_ERR(xdna, "hwctx %u has no AIE partition", hwctx->id);
		return -EINVAL;
	}
	mgmtctx = vp->mgmtctx;

	local_buf = kzalloc(footer.size, GFP_KERNEL);
	if (!local_buf)
		return -ENOMEM;

	/* Drop dev_lock — aie_partition_read can block on hardware I/O */
	mutex_unlock(&xdna->dev_lock);
	mutex_lock(&mgmtctx->ctx_lock);

	if (mgmtctx->active_ctx != hwctx) {
		XDNA_ERR(xdna, "hwctx %u is not the active context", hwctx->id);
		mutex_unlock(&mgmtctx->ctx_lock);
		mutex_lock(&xdna->dev_lock);
		kfree(local_buf);
		return -EPERM;
	}

	loc.col = footer.col;
	loc.row = footer.row;
	ret = aie_partition_read(mgmtctx->aie_dev, loc, footer.addr, footer.size, local_buf);
	mutex_unlock(&mgmtctx->ctx_lock);
	mutex_lock(&xdna->dev_lock);

	if (ret < 0) {
		XDNA_ERR(xdna, "aie_partition_read failed: %d", ret);
		kfree(local_buf);
		return ret;
	}

	if (copy_to_user(u64_to_user_ptr(args->buffer), local_buf, footer.size)) {
		XDNA_ERR(xdna, "Failed to copy read data to user");
		kfree(local_buf);
		return -EFAULT;
	}

	kfree(local_buf);

	return 0;
}

static int ve2_coredump_read(struct amdxdna_client *client, struct amdxdna_drm_get_array *args)
{
	struct amdxdna_drm_aie_coredump footer = {};
	struct amdxdna_dev *xdna = client->xdna;
	struct amdxdna_hwctx *hwctx = NULL;
	struct amdxdna_client *tmp_client;
	struct amdxdna_mgmtctx *mgmtctx;
	struct amdxdna_ctx_priv *vp;
	u32 buf_size, rel_size;
	void *local_buf;
	u32 offset;
	int ret;

	buf_size = (u32)args->num_element * args->element_size;
	if (buf_size < sizeof(footer))
		return -EINVAL;

	/* Footer is at the tail of the user buffer — contains context_id + pid. */
	offset = buf_size - sizeof(footer);
	if (copy_from_user(&footer, u64_to_user_ptr(args->buffer) + offset, sizeof(footer))) {
		XDNA_ERR(xdna, "Failed to copy coredump request from user");
		return -EFAULT;
	}

	XDNA_DBG(xdna, "Coredump read: ctx_id=%u, pid=%llu, buf_size=%u", footer.context_id,
		 footer.pid, buf_size);

	/* Find the hwctx matching the requested context_id and pid. */
	drm_WARN_ON(&xdna->ddev, !mutex_is_locked(&xdna->dev_lock));
	list_for_each_entry(tmp_client, &xdna->client_list, node) {
		struct amdxdna_hwctx *hx;
		unsigned long hx_id;
		int srcu_idx;

		srcu_idx = srcu_read_lock(&tmp_client->hwctx_srcu);
		xa_for_each(&tmp_client->hwctx_xa, hx_id, hx) {
			if (hx->id == footer.context_id && (u64)hx->client->pid == footer.pid) {
				hwctx = hx;
				break;
			}
		}
		srcu_read_unlock(&tmp_client->hwctx_srcu, srcu_idx);
		if (hwctx)
			break;
	}

	if (!hwctx) {
		XDNA_ERR(xdna, "Cannot get coredump: Hardware context %u with pid %llu not found",
			 footer.context_id, footer.pid);
		return -EINVAL;
	}

	XDNA_DBG(xdna, "cl_pid: %u, hwctx_id: %u, start_col %u, ncol %u\n", hwctx->client->pid,
		 hwctx->id, hwctx->start_col, hwctx->num_col);

	vp = ve2_hw_priv(hwctx);
	if (!vp || !vp->mgmtctx) {
		XDNA_ERR(xdna, "Coredump: hwctx %u has no management partition", hwctx->id);
		return -EINVAL;
	}

	mgmtctx = vp->mgmtctx;

	if (mgmtctx->active_ctx != hwctx) {
		XDNA_ERR(xdna, "Coredump: hwctx %u is not the active context", hwctx->id);
		return -EPERM;
	}

	/* Required buffer: num_col * num_rows * tile_size */
	rel_size = hwctx->num_col * mgmtctx->num_rows * TILE_ADDRESS_SPACE;
	if (rel_size > buf_size) {
		XDNA_DBG(xdna, "Coredump buffer too small: need %u got %u", rel_size, buf_size);
		args->element_size = rel_size;
		return -ENOBUFS;
	}

	local_buf = vmalloc(rel_size);
	if (!local_buf)
		return -ENOMEM;

	ret = aie_partition_coredump(mgmtctx->aie_dev, rel_size, local_buf);
	if (ret < 0) {
		XDNA_ERR(xdna, "aie_partition_coredump failed: %d", ret);
		vfree(local_buf);
		return ret;
	}

	if (copy_to_user(u64_to_user_ptr(args->buffer), local_buf, ret)) {
		XDNA_ERR(xdna, "Coredump copy_to_user failed");
		vfree(local_buf);
		return -EFAULT;
	}

	XDNA_DBG(xdna, "Coredump: copied %d bytes for hwctx %u", ret, hwctx->id);
	vfree(local_buf);
	return 0;
}

static int ve2_get_firmware_version(struct amdxdna_client *client,
				    struct amdxdna_drm_get_info *args)
{
	struct amdxdna_dev *xdna = client->xdna;
	struct ve2_firmware_version *fver = &ve2_dev_hdl(xdna)->fw_version;
	struct amdxdna_drm_query_firmware_version version = {};

	if (args->buffer_size < sizeof(version)) {
		XDNA_ERR(xdna, "Buffer too small. Given: %u, required: %zu",
			 args->buffer_size, sizeof(version));
		args->buffer_size = sizeof(version);
		return -ENOBUFS;
	}

	XDNA_DBG(xdna, "CERT firmware: git_hash=%s, date=%s", fver->git_hash, fver->date);

	version.major = fver->major;
	version.minor = fver->minor;
	version.patch = fver->hotfix;
	version.build = fver->build;

	if (copy_to_user(u64_to_user_ptr(args->buffer), &version, sizeof(version)))
		return -EFAULT;

	return 0;
}

static int ve2_get_aie_metadata(struct amdxdna_client *client, struct amdxdna_drm_get_info *args)
{
	struct amdxdna_dev *xdna = client->xdna;
	struct aie_device_info *info = &ve2_dev_hdl(xdna)->aie_dev_info;
	struct amdxdna_drm_query_aie_metadata *meta;
	int ret = 0;

	if (args->buffer_size < sizeof(*meta)) {
		XDNA_ERR(xdna, "Buffer too small. Given: %u, required: %zu",
			 args->buffer_size, sizeof(*meta));
		args->buffer_size = sizeof(*meta);
		return -ENOBUFS;
	}

	meta = kzalloc_obj(*meta);
	if (!meta)
		return -ENOMEM;

	meta->cols = info->cols;
	meta->rows = info->rows;
	meta->core.row_count = info->core_rows;
	meta->mem.row_count = info->mem_rows;
	meta->shim.row_count = info->shim_rows;

	if (copy_to_user(u64_to_user_ptr(args->buffer), meta, sizeof(*meta)))
		ret = -EFAULT;

	kfree(meta);
	return ret;
}

/*
 * Resolve an AIE partition device for clock get/set. If a context is active,
 * reuse its partition; otherwise request a temporary partition at column 0.
 * Caller holds xdna->dev_lock, which serializes this against context creation,
 * so a lack of active partition guarantees the columns are free to request.
 *
 * On success returns a valid aie_dev and sets *temp to true when a temporary
 * partition was allocated (caller must release it via ve2_put_clock_aie_dev()).
 * On failure returns an ERR_PTR.
 */
static struct device *ve2_get_clock_aie_dev(struct amdxdna_dev *xdna, bool *temp)
{
	struct amdxdna_dev_hdl *hdl = ve2_dev_hdl(xdna);
	struct aie_partition_req req = { };
	struct device *aie_dev;
	u32 i;

	*temp = false;

	for (i = 0; hdl->ve2_mgmtctx && i < hdl->aie_dev_info.cols; i++) {
		if (hdl->ve2_mgmtctx[i].aie_dev)
			return hdl->ve2_mgmtctx[i].aie_dev;
	}

	req.partition_id = (0 << AIE_PART_ID_START_COL_SHIFT) |
			   (VE2_MIN_COL_SUPPORT << AIE_PART_ID_NUM_COLS_SHIFT);
	aie_dev = aie_partition_request(&req);
	if (IS_ERR(aie_dev)) {
		XDNA_ERR(xdna, "Failed to request temporary AIE partition: %ld",
			 PTR_ERR(aie_dev));
		return aie_dev;
	}

	*temp = true;
	return aie_dev;
}

static void ve2_put_clock_aie_dev(struct device *aie_dev, bool temp)
{
	if (temp && !IS_ERR_OR_NULL(aie_dev))
		aie_partition_release(aie_dev);
}

static int ve2_get_clock_metadata(struct amdxdna_client *client, struct amdxdna_drm_get_info *args)
{
	struct amdxdna_drm_query_clock_metadata clock_metadata = {};
	struct amdxdna_dev *xdna = client->xdna;
	struct device *aie_dev;
	u64 aie_freq = 0;
	bool temp;
	int ret;

	if (args->buffer_size != sizeof(clock_metadata)) {
		XDNA_ERR(xdna, "Invalid buffer size. Given: %u, Expected: %zu",
			 args->buffer_size, sizeof(clock_metadata));
		return -EINVAL;
	}

	aie_dev = ve2_get_clock_aie_dev(xdna, &temp);
	if (IS_ERR(aie_dev))
		return PTR_ERR(aie_dev);

	ret = aie_partition_get_freq(aie_dev, &aie_freq);
	ve2_put_clock_aie_dev(aie_dev, temp);
	if (ret) {
		XDNA_ERR(xdna, "Failed to read AIE frequency: %d", ret);
		return ret;
	}

	strscpy(clock_metadata.mp_npu_clock.name, "AIE Clock",
		sizeof(clock_metadata.mp_npu_clock.name));
	clock_metadata.mp_npu_clock.freq_mhz = (u16)(aie_freq / 1000000);

	if (copy_to_user(u64_to_user_ptr(args->buffer), &clock_metadata, sizeof(clock_metadata))) {
		XDNA_ERR(xdna, "Failed to copy clock metadata to user");
		return -EFAULT;
	}

	return 0;
}

int ve2_get_aie_info(struct amdxdna_client *client, struct amdxdna_drm_get_info *args)
{
	struct amdxdna_dev *xdna = client->xdna;

	/*
	 * dev_lock is already held by amdxdna_drm_get_info_ioctl().
	 * Do not lock again (non-recursive mutex -> deadlock).
	 */
	drm_WARN_ON(&xdna->ddev, !mutex_is_locked(&xdna->dev_lock));

	XDNA_DBG(xdna, "Get AIE info: param=%u buffer_size=%u", args->param, args->buffer_size);

	switch (args->param) {
	case DRM_AMDXDNA_QUERY_CERT_FIRMWARE_VERSION:
		return ve2_get_firmware_version(client, args);
	case DRM_AMDXDNA_QUERY_AIE_METADATA:
		return ve2_get_aie_metadata(client, args);
	case DRM_AMDXDNA_QUERY_CLOCK_METADATA:
		return ve2_get_clock_metadata(client, args);
	default:
		XDNA_ERR(xdna, "Not supported GET_INFO param %u", args->param);
		return -EOPNOTSUPP;
	}
}

/*
 * Return the most recent cached AIE asynchronous error across all active
 * contexts. The error is captured by ve2_aie_error_cb() and cached per
 * partition (mgmtctx). num_element is set to 0 when no error is cached.
 *
 * Caller holds xdna->dev_lock (protects client_list).
 */
static int ve2_get_array_async_error(struct amdxdna_client *client,
				     struct amdxdna_drm_get_array *args)
{
	/* 50ms to observe the callback starting; 100ms cap once it has. */
	unsigned long poll_timeout = msecs_to_jiffies(50);
	unsigned long wait_timeout = msecs_to_jiffies(100);
	struct amdxdna_dev *xdna = client->xdna;
	struct amdxdna_async_error tmp = {};
	struct amdxdna_client *tmp_client;
	bool found = false;

	args->num_element = 0;

	/* Wait for any pending error callbacks to complete before reading cached errors.
	 * This ensures async errors are cached before we query for them.
	 * The error callback may start after command completion, so we poll briefly
	 * to catch cases where it starts shortly after the query.
	 */
	list_for_each_entry(tmp_client, &xdna->client_list, node) {
		struct amdxdna_hwctx *hwctx;
		unsigned long hx_id;
		int idx;

		idx = srcu_read_lock(&tmp_client->hwctx_srcu);
		xa_for_each(&tmp_client->hwctx_xa, hx_id, hwctx) {
			struct amdxdna_ctx_priv *vp = ve2_hw_priv(hwctx);
			struct amdxdna_mgmtctx *mgmtctx;
			unsigned long poll_start = jiffies;
			bool callback_started = false;

			if (!vp || !vp->mgmtctx)
				continue;

			mgmtctx = vp->mgmtctx;
			while (time_before(jiffies, poll_start + poll_timeout)) {
				if (atomic_read(&mgmtctx->error_cb_in_progress)) {
					callback_started = true;
					break;
				}
				schedule_timeout_uninterruptible(msecs_to_jiffies(1));
			}

			if (callback_started ||
			    atomic_read(&mgmtctx->error_cb_in_progress)) {
				if (wait_for_completion_timeout(&mgmtctx->error_cb_completion,
								wait_timeout) == 0)
					XDNA_WARN(xdna,
						  "Timeout waiting for error callback completion");
			}
		}
		srcu_read_unlock(&tmp_client->hwctx_srcu, idx);
	}

	/* Find the first mgmtctx with a cached error */
	list_for_each_entry(tmp_client, &xdna->client_list, node) {
		struct amdxdna_hwctx *hwctx;
		unsigned long hx_id;
		int idx;

		idx = srcu_read_lock(&tmp_client->hwctx_srcu);
		xa_for_each(&tmp_client->hwctx_xa, hx_id, hwctx) {
			struct amdxdna_ctx_priv *vp = ve2_hw_priv(hwctx);
			struct amdxdna_async_err_cache *cache;

			if (!vp || !vp->mgmtctx)
				continue;

			cache = &vp->mgmtctx->async_errs_cache;
			mutex_lock(&cache->lock);
			if (cache->err.err_code) {
				memcpy(&tmp, &cache->err, sizeof(tmp));
				found = true;
			}
			mutex_unlock(&cache->lock);

			if (found)
				break;
		}
		srcu_read_unlock(&tmp_client->hwctx_srcu, idx);

		if (found)
			break;
	}

	if (!found)
		return 0;

	if (copy_to_user(u64_to_user_ptr(args->buffer), &tmp, sizeof(tmp)))
		return -EFAULT;

	args->num_element = 1;
	return 0;
}

/*
 * Export a file descriptor for the AIE partition backing a hardware context.
 *
 * The hwctx handle is passed in @num_element. The returned fd lets userspace
 * (e.g. the XRT shim) operate directly on the underlying AIE partition.
 *
 * Caller holds xdna->dev_lock.
 */
static int ve2_get_aie_part_fd(struct amdxdna_client *client,
			       struct amdxdna_drm_get_array *args)
{
	struct amdxdna_dev *xdna = client->xdna;
	struct amdxdna_mgmtctx *mgmtctx;
	struct amdxdna_hwctx *hwctx;
	struct amdxdna_ctx_priv *vp;
	u32 hwctx_handle;
	int srcu_idx;
	int ret = 0;
	int aie_fd;

	hwctx_handle = args->num_element;
	srcu_idx = srcu_read_lock(&client->hwctx_srcu);
	hwctx = xa_load(&client->hwctx_xa, hwctx_handle);
	if (!hwctx) {
		XDNA_ERR(xdna, "Failed to get hwctx %u", hwctx_handle);
		ret = -EINVAL;
		goto unlock;
	}

	vp = ve2_hw_priv(hwctx);
	mgmtctx = vp ? vp->mgmtctx : NULL;
	if (!mgmtctx || !mgmtctx->aie_dev) {
		XDNA_ERR(xdna, "AIE partition not available for hwctx_id=%u (pid=%d)",
			 hwctx->id, client->pid);
		ret = -ENODEV;
		goto unlock;
	}

	aie_fd = aie_partition_get_fd(mgmtctx->aie_dev);
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
	srcu_read_unlock(&client->hwctx_srcu, srcu_idx);
	return ret;
}

int ve2_debug_get_array(struct amdxdna_client *client, struct amdxdna_drm_get_array *args)
{
	struct amdxdna_dev *xdna = client->xdna;
	int ret, idx;

	if (!drm_dev_enter(&xdna->ddev, &idx))
		return -ENODEV;

	/*
	 * Unlike get_info/set_state, the shared amdxdna_drm_get_array_ioctl()
	 * does NOT hold dev_lock. The VE2 handlers below walk client_list/hwctx
	 * and some (coredump, tile read) temporarily drop and re-acquire
	 * dev_lock around blocking hardware I/O, so acquire it here.
	 */
	mutex_lock(&xdna->dev_lock);

	switch (args->param) {
	case DRM_AMDXDNA_HW_CONTEXT_ALL:
		ret = ve2_query_ctx_status_array(client, args);
		break;
	case DRM_AMDXDNA_HWCTX_MEM_BITMAP:
		ret = ve2_get_hwctx_mem_bitmap(client, args);
		break;
	case DRM_AMDXDNA_AIE_COREDUMP:
		ret = ve2_coredump_read(client, args);
		break;
	case DRM_AMDXDNA_AIE_TILE_READ:
		ret = ve2_aie_tile_read(client, args);
		break;
	case DRM_AMDXDNA_HW_LAST_ASYNC_ERR:
		ret = ve2_get_array_async_error(client, args);
		break;
	case DRM_AMDXDNA_HWCTX_AIE_PART_FD:
		ret = ve2_get_aie_part_fd(client, args);
		break;
	default:
		XDNA_ERR(xdna, "Not supported GET_ARRAY param %u", args->param);
		ret = -EOPNOTSUPP;
	}

	mutex_unlock(&xdna->dev_lock);
	drm_dev_exit(idx);
	return ret;
}

static int ve2_aie_tile_write(struct amdxdna_client *client, struct amdxdna_drm_set_state *args)
{
	struct amdxdna_drm_aie_tile_access footer = {};
	struct amdxdna_dev *xdna = client->xdna;
	struct amdxdna_hwctx *hwctx = NULL;
	struct amdxdna_mgmtctx *mgmtctx;
	struct amdxdna_ctx_priv *vp;
	struct amdxdna_client *tmp;
	struct aie_location loc;
	void *local_buf = NULL;
	unsigned long hx_id;
	u32 offset;
	int ret;

	if (args->buffer_size < sizeof(footer)) {
		XDNA_ERR(xdna, "buffer_size %u too small (need %zu)",
			 args->buffer_size, sizeof(footer));
		return -EINVAL;
	}

	/* Footer is at the tail of the buffer */
	offset = args->buffer_size - sizeof(footer);
	if (copy_from_user(&footer, u64_to_user_ptr(args->buffer) + offset, sizeof(footer))) {
		XDNA_ERR(xdna, "Failed to copy tile_access footer from user");
		return -EFAULT;
	}

	/* Find the hwctx matching context_id + pid */
	drm_WARN_ON(&xdna->ddev, !mutex_is_locked(&xdna->dev_lock));

	list_for_each_entry(tmp, &xdna->client_list, node) {
		struct amdxdna_hwctx *hx;
		int sidx;

		sidx = srcu_read_lock(&tmp->hwctx_srcu);
		xa_for_each(&tmp->hwctx_xa, hx_id, hx) {
			if (hx->id == footer.context_id &&
			    (u64)hx->client->pid == footer.pid) {
				hwctx = hx;
				break;
			}
		}
		srcu_read_unlock(&tmp->hwctx_srcu, sidx);
		if (hwctx)
			break;
	}

	if (!hwctx) {
		XDNA_ERR(xdna, "hwctx %u pid %llu not found", footer.context_id, footer.pid);
		return -EINVAL;
	}

	if (footer.col >= hwctx->num_col) {
		XDNA_ERR(xdna, "col %u out of partition range [0, %u)",
			 footer.col, hwctx->num_col);
		return -EINVAL;
	}

	if (footer.row >= xdna->dev_handle->aie_dev_info.rows) {
		XDNA_ERR(xdna, "row %u out of range [0, %u)",
			 footer.row, xdna->dev_handle->aie_dev_info.rows);
		return -EINVAL;
	}

	vp = ve2_hw_priv(hwctx);
	if (!vp || !vp->mgmtctx) {
		XDNA_ERR(xdna, "hwctx %u has no AIE partition", hwctx->id);
		return -EINVAL;
	}
	mgmtctx = vp->mgmtctx;

	local_buf = kzalloc(footer.size, GFP_KERNEL);
	if (!local_buf)
		return -ENOMEM;

	if (copy_from_user(local_buf, u64_to_user_ptr(args->buffer), footer.size)) {
		XDNA_ERR(xdna, "Failed to copy write data from user");
		kfree(local_buf);
		return -EFAULT;
	}

	/*
	 * aie_partition_write can block on hardware I/O. Release dev_lock
	 * before calling it to avoid stalling all other IOCTLs. Use
	 * mgmtctx->ctx_lock to serialize against context switches.
	 */
	mutex_unlock(&xdna->dev_lock);
	mutex_lock(&mgmtctx->ctx_lock);

	if (mgmtctx->active_ctx != hwctx) {
		XDNA_ERR(xdna, "hwctx %u is not the active context", hwctx->id);
		mutex_unlock(&mgmtctx->ctx_lock);
		mutex_lock(&xdna->dev_lock);
		kfree(local_buf);
		return -EPERM;
	}

	loc.col = footer.col;
	loc.row = footer.row;
	ret = aie_partition_write(mgmtctx->aie_dev, loc, footer.addr, footer.size, local_buf, 0);
	mutex_unlock(&mgmtctx->ctx_lock);
	mutex_lock(&xdna->dev_lock);

	if (ret < 0)
		XDNA_ERR(xdna, "aie_partition_write failed: %d", ret);
	else
		ret = 0;

	kfree(local_buf);
	return ret;
}

static int ve2_set_clock_freq(struct amdxdna_client *client, struct amdxdna_drm_set_state *args)
{
	struct amdxdna_drm_query_clock set_freq;
	struct amdxdna_dev *xdna = client->xdna;
	struct device *aie_dev;
	u64 freq_hz;
	bool temp;
	int ret;

	if (args->buffer_size != sizeof(set_freq)) {
		XDNA_ERR(xdna, "Invalid buffer size. Given: %u, Expected: %zu",
			 args->buffer_size, sizeof(set_freq));
		return -EINVAL;
	}

	if (copy_from_user(&set_freq, u64_to_user_ptr(args->buffer), sizeof(set_freq))) {
		XDNA_ERR(xdna, "Failed to copy set_clock_freq from user");
		return -EFAULT;
	}

	freq_hz = (u64)set_freq.freq_mhz * 1000000;
	XDNA_DBG(xdna, "Set AIE clock freq: %llu Hz (%u MHz)", freq_hz, set_freq.freq_mhz);

	aie_dev = ve2_get_clock_aie_dev(xdna, &temp);
	if (IS_ERR(aie_dev))
		return PTR_ERR(aie_dev);

	ret = aie_partition_set_freq_req(aie_dev, freq_hz);
	ve2_put_clock_aie_dev(aie_dev, temp);
	if (ret)
		XDNA_ERR(xdna, "Failed to set AIE frequency to %llu Hz: %d", freq_hz, ret);
	else
		XDNA_DBG(xdna, "Set AIE frequency to %llu Hz (%u MHz)", freq_hz, set_freq.freq_mhz);

	return ret;
}

int ve2_set_aie_state(struct amdxdna_client *client, struct amdxdna_drm_set_state *args,
		      u32 *settle_ms)
{
	struct amdxdna_dev *xdna = client->xdna;

	/*
	 * dev_lock is already held by amdxdna_drm_set_state_ioctl().
	 * Taking it again here would deadlock (non-recursive mutex).
	 */
	drm_WARN_ON(&xdna->ddev, !mutex_is_locked(&xdna->dev_lock));

	XDNA_DBG(xdna, "Set AIE state: param=%u buffer_size=%u",
		 args->param, args->buffer_size);

	switch (args->param) {
	case DRM_AMDXDNA_AIE_TILE_WRITE:
		return ve2_aie_tile_write(client, args);
	case DRM_AMDXDNA_SET_CLOCK_FREQ:
		return ve2_set_clock_freq(client, args);
	default:
		XDNA_ERR(xdna, "Unsupported set_state param %u", args->param);
		return -EOPNOTSUPP;
	}
}

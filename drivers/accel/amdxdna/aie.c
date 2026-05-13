// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2026, Advanced Micro Devices, Inc.
 */

#include "drm/amdxdna_accel.h"
#include <drm/drm_cache.h>
#include <drm/drm_drv.h>
#include <drm/drm_print.h>
#include <drm/gpu_scheduler.h>
#include <linux/errno.h>
#include <linux/limits.h>
#include <linux/sched.h>
#include <linux/sizes.h>
#include <linux/slab.h>
#include <linux/uaccess.h>

#include "aie.h"
#include "amdxdna_ctx.h"
#include "amdxdna_gem.h"
#include "amdxdna_mailbox_helper.h"
#include "amdxdna_mailbox.h"
#include "amdxdna_pci_drv.h"
#include "amdxdna_pm.h"

void aie_dump_mgmt_chann_debug(struct aie_device *aie)
{
	struct amdxdna_dev *xdna = aie->xdna;

	XDNA_DBG(xdna, "i2x tail    0x%x", aie->mgmt_i2x.mb_tail_ptr_reg);
	XDNA_DBG(xdna, "i2x head    0x%x", aie->mgmt_i2x.mb_head_ptr_reg);
	XDNA_DBG(xdna, "i2x ringbuf 0x%x", aie->mgmt_i2x.rb_start_addr);
	XDNA_DBG(xdna, "i2x rsize   0x%x", aie->mgmt_i2x.rb_size);
	XDNA_DBG(xdna, "x2i tail    0x%x", aie->mgmt_x2i.mb_tail_ptr_reg);
	XDNA_DBG(xdna, "x2i head    0x%x", aie->mgmt_x2i.mb_head_ptr_reg);
	XDNA_DBG(xdna, "x2i ringbuf 0x%x", aie->mgmt_x2i.rb_start_addr);
	XDNA_DBG(xdna, "x2i rsize   0x%x", aie->mgmt_x2i.rb_size);
	XDNA_DBG(xdna, "x2i chann index 0x%x", aie->mgmt_chan_idx);
	XDNA_DBG(xdna, "mailbox protocol major 0x%x", aie->mgmt_prot_major);
	XDNA_DBG(xdna, "mailbox protocol minor 0x%x", aie->mgmt_prot_minor);
}

void aie_destroy_chann(struct aie_device *aie, struct mailbox_channel **chann)
{
	struct amdxdna_dev *xdna = aie->xdna;

	drm_WARN_ON(&xdna->ddev, !mutex_is_locked(&xdna->dev_lock));

	if (!*chann)
		return;

	xdna_mailbox_stop_channel(*chann);
	xdna_mailbox_free_channel(*chann);
	*chann = NULL;
}

int aie_send_mgmt_msg_wait(struct aie_device *aie, struct xdna_mailbox_msg *msg)
{
	struct amdxdna_dev *xdna = aie->xdna;
	struct xdna_notify *hdl = msg->handle;
	int ret;

	drm_WARN_ON(&xdna->ddev, !mutex_is_locked(&xdna->dev_lock));

	if (!aie->mgmt_chann)
		return -ENODEV;

	ret = xdna_send_msg_wait(xdna, aie->mgmt_chann, msg);
	if (ret == -ETIME)
		aie_destroy_chann(aie, &aie->mgmt_chann);

	if (!ret && *hdl->status) {
		XDNA_ERR(xdna, "command opcode 0x%x failed, status 0x%x",
			 msg->opcode, *hdl->data);
		ret = -EINVAL;
	}

	return ret;
}

int aie_check_protocol(struct aie_device *aie, u32 fw_major, u32 fw_minor)
{
	const struct amdxdna_fw_feature_tbl *feature;
	bool found = false;

	for (feature = aie->xdna->dev_info->fw_feature_tbl;
	     feature->major; feature++) {
		if (feature->major != fw_major)
			continue;
		if (fw_minor < feature->min_minor)
			continue;
		if (feature->max_minor > 0 && fw_minor > feature->max_minor)
			continue;

		aie->feature_mask |= feature->features;

		/* firmware version matches one of the driver support entry */
		found = true;
	}

	return found ? 0 : -EOPNOTSUPP;
}

static void amdxdna_update_vbnv(struct amdxdna_dev *xdna,
				const struct amdxdna_rev_vbnv *tbl,
				u32 rev)
{
	int i;

	for (i = 0; tbl[i].vbnv; i++) {
		if (tbl[i].revision == rev) {
			xdna->vbnv = tbl[i].vbnv;
			break;
		}
	}
}

void amdxdna_vbnv_init(struct amdxdna_dev *xdna)
{
	const struct amdxdna_dev_info *info = xdna->dev_info;
	u32 rev;

	xdna->vbnv = info->default_vbnv;

	if (!info->ops->get_dev_revision || !info->rev_vbnv_tbl)
		return;

	if (info->ops->get_dev_revision(xdna, &rev))
		return;

	amdxdna_update_vbnv(xdna, info->rev_vbnv_tbl, rev);
}

void amdxdna_io_stats_job_start(struct amdxdna_client *client)
{
	int depth;

	guard(spinlock)(&client->io_stats.lock);

	depth = client->io_stats.job_depth++;
	if (!depth)
		client->io_stats.start_time = ktime_get_ns();
}

void amdxdna_io_stats_job_done(struct amdxdna_client *client)
{
	u64 busy_ns;
	int depth;

	guard(spinlock)(&client->io_stats.lock);

	depth = --client->io_stats.job_depth;
	if (!depth) {
		busy_ns = ktime_get_ns() - client->io_stats.start_time;
		client->io_stats.start_time = 0;
		client->io_stats.busy_time += busy_ns;
	}
}

u64 amdxdna_io_stats_busy_time_ns(struct amdxdna_client *client)
{
	u64 busy_ns;

	guard(spinlock)(&client->io_stats.lock);

	busy_ns = client->io_stats.busy_time;
	if (client->io_stats.job_depth)
		busy_ns += ktime_get_ns() - client->io_stats.start_time;

	return busy_ns;
}

int amdxdna_get_metadata(struct aie_device *aie,
			 struct amdxdna_client *client,
			 struct amdxdna_drm_get_info *args)
{
	int ret = 0;
	u32 buf_sz;

	buf_sz = min(args->buffer_size, sizeof(aie->metadata));
	if (copy_to_user(u64_to_user_ptr(args->buffer), &aie->metadata, buf_sz))
		ret = -EFAULT;

	return ret;
}

int amdxdna_query_sensors(struct amdxdna_client *client,
			  struct amdxdna_drm_get_info *args, u32 total_col)
{
#if IS_ENABLED(CONFIG_AMD_PMF) && defined(HAVE_7_0_amd_pmf_get_npu_data)
	struct amdxdna_drm_query_sensor sensor = {};
	struct amd_pmf_npu_metrics npu_metrics = {};
	u32 sensors_count = 0, i;
	int ret;

#ifdef HAVE_7_2_amd_pmf_npu_metrics_npu_temp
	npu_metrics.npu_temp = U16_MAX;
#endif

	ret = AIE_GET_PMF_NPU_METRICS(&npu_metrics);
	if (ret)
		return ret;

	sensor.type = AMDXDNA_SENSOR_TYPE_POWER;
	sensor.input = npu_metrics.npu_power;
	sensor.unitm = -3;
	scnprintf(sensor.label, sizeof(sensor.label), "Total Power");
	scnprintf(sensor.units, sizeof(sensor.units), "mW");

	if (args->buffer_size < sizeof(sensor))
		goto out;

	if (copy_to_user(u64_to_user_ptr(args->buffer), &sensor, sizeof(sensor)))
		return -EFAULT;

	args->buffer_size -= sizeof(sensor);
	sensors_count++;

#ifdef HAVE_7_2_amd_pmf_npu_metrics_npu_temp
	if (npu_metrics.npu_temp != U16_MAX) {
		memset(&sensor, 0, sizeof(sensor));
		sensor.type = AMDXDNA_SENSOR_TYPE_TEMPERATURE;
		sensor.input = npu_metrics.npu_temp;
		sensor.unitm = 0;
		scnprintf(sensor.label, sizeof(sensor.label), "Temperature");
		scnprintf(sensor.units, sizeof(sensor.units), "C");

		if (args->buffer_size < sizeof(sensor))
			goto out;

		if (copy_to_user(u64_to_user_ptr(args->buffer) + sensors_count * sizeof(sensor),
				 &sensor, sizeof(sensor)))
			return -EFAULT;

		args->buffer_size -= sizeof(sensor);
		sensors_count++;
	}
#endif

	for (i = 0; i < min_t(u32, total_col, 8); i++) {
		memset(&sensor, 0, sizeof(sensor));
		sensor.input = npu_metrics.npu_busy[i];
		sensor.type = AMDXDNA_SENSOR_TYPE_COLUMN_UTILIZATION;
		sensor.unitm = 0;
		scnprintf(sensor.label, sizeof(sensor.label), "Column %d Utilization", i);
		scnprintf(sensor.units, sizeof(sensor.units), "%%");

		if (args->buffer_size < sizeof(sensor))
			goto out;

		if (copy_to_user(u64_to_user_ptr(args->buffer) + sensors_count * sizeof(sensor),
				 &sensor, sizeof(sensor)))
			return -EFAULT;

		args->buffer_size -= sizeof(sensor);
		sensors_count++;
	}

out:
	args->buffer_size = sensors_count * sizeof(sensor);

	return 0;
#else
	return -EOPNOTSUPP;
#endif
}

void amdxdna_hmm_invalidate(struct amdxdna_gem_obj *abo,
			    unsigned long cur_seq)
{
	struct amdxdna_dev *xdna = to_xdna_dev(to_gobj(abo)->dev);
	struct drm_gem_object *gobj = to_gobj(abo);
	long ret;

	ret = dma_resv_wait_timeout(gobj->resv, DMA_RESV_USAGE_BOOKKEEP,
				    true, MAX_SCHEDULE_TIMEOUT);
	if (!ret)
		XDNA_ERR(xdna, "Failed to wait for bo, ret %ld", ret);
	else if (ret == -ERESTARTSYS)
		XDNA_DBG(xdna, "Wait for bo interrupted by signal");
}

struct amdxdna_msg_buf_hdl *amdxdna_alloc_msg_buff(struct amdxdna_dev *xdna, u32 size)
{
	struct amdxdna_msg_buf_hdl *hdl;
	int order;

	hdl = kzalloc_obj(*hdl);
	if (!hdl)
		return ERR_PTR(-ENOMEM);

	hdl->xdna = xdna;
	hdl->size = max_t(u32, size, SZ_8K);
	order = get_order(hdl->size);
	if (order > MAX_PAGE_ORDER)
		goto free_hdl;
	hdl->size = PAGE_SIZE << order;

	if (amdxdna_iova_on(xdna)) {
		hdl->vaddr = amdxdna_iommu_alloc(xdna, hdl->size, &hdl->dma_addr);
		if (IS_ERR(hdl->vaddr))
			goto free_hdl;
	} else {
		hdl->vaddr = dma_alloc_noncoherent(xdna->ddev.dev, hdl->size,
						   &hdl->dma_addr,
						   DMA_FROM_DEVICE, GFP_KERNEL);
		if (!hdl->vaddr)
			goto free_hdl;
	}

	return hdl;

free_hdl:
	kfree(hdl);
	return ERR_PTR(-ENOMEM);
}

void amdxdna_free_msg_buff(struct amdxdna_msg_buf_hdl *hdl)
{
	if (!hdl)
		return;

	if (amdxdna_iova_on(hdl->xdna)) {
		amdxdna_iommu_free(hdl->xdna, hdl->size, hdl->vaddr,
				   hdl->dma_addr);
	} else {
		dma_free_noncoherent(hdl->xdna->ddev.dev, hdl->size,
				     hdl->vaddr, hdl->dma_addr,
				     DMA_FROM_DEVICE);
	}

	kfree(hdl);
}

struct amdxdna_coredump_walk_arg {
	u64				pid;
	u32				ctx_id;

	struct aie_device		*aie;
	struct amdxdna_drm_get_array	*args;
	u8 __user			*buf;
	size_t				buf_size;
};

struct amdxdna_tile_rw_walk_arg {
	struct aie_device				*aie;
	const struct amdxdna_drm_aie_tile_access	*access;
	u8 __user					*buf;
};

static bool amdxdna_get_coredump_filter(struct amdxdna_hwctx *hwctx, void *arg)
{
	struct amdxdna_coredump_walk_arg *wa = arg;

	return hwctx->client->pid == wa->pid && hwctx->id == wa->ctx_id;
}

static int amdxdna_get_coredump_cb(struct amdxdna_hwctx *hwctx, void *arg)
{
	struct amdxdna_dev *xdna = hwctx->client->xdna;
	struct amdxdna_msg_buf_hdl **data_hdls = NULL;
	struct amdxdna_msg_buf_hdl *list_hdl = NULL;
	struct amdxdna_coredump_buf_entry *buf_list;
	struct amdxdna_coredump_walk_arg *wa = arg;
	size_t data_buf_size = SZ_1M;
	size_t offset = 0;
	size_t total_size;
	int ret = 0, i;
	u32 num_bufs;
	u32 orig_col;

	if (!amdxdna_client_visible(hwctx->client)) {
		XDNA_ERR(xdna, "Permission denied for context %u", wa->ctx_id);
		return -EPERM;
	}

	orig_col = hwctx->num_col - hwctx->num_unused_col;
	num_bufs = wa->aie->metadata.rows * orig_col;
	total_size = (size_t)num_bufs * data_buf_size;

	if (wa->buf_size < total_size) {
		XDNA_DBG(xdna, "Insufficient buffer size %zu, need %zu",
			 wa->buf_size, total_size);
		wa->args->element_size = total_size;
		ret = -ENOSPC;
		goto out;
	}

	list_hdl = amdxdna_alloc_msg_buff(xdna, num_bufs * sizeof(*buf_list));
	if (IS_ERR(list_hdl)) {
		XDNA_ERR(xdna, "Failed to allocate buffer list");
		ret = PTR_ERR(list_hdl);
		list_hdl = NULL;
		goto out;
	}

	buf_list = to_cpu_addr(list_hdl, 0);
	memset(buf_list, 0, to_buf_size(list_hdl));

	data_hdls = kzalloc_objs(*data_hdls, num_bufs);
	if (!data_hdls) {
		ret = -ENOMEM;
		goto free_list_hdl;
	}

	for (i = 0; i < num_bufs; i++) {
		data_hdls[i] = amdxdna_alloc_msg_buff(xdna, data_buf_size);
		if (IS_ERR(data_hdls[i])) {
			XDNA_ERR(xdna, "Failed to allocate data buffer %d", i);
			ret = PTR_ERR(data_hdls[i]);
			data_hdls[i] = NULL;
			goto free_data_hdls;
		}

		memset(to_cpu_addr(data_hdls[i], 0), 0, to_buf_size(data_hdls[i]));
		drm_clflush_virt_range(to_cpu_addr(data_hdls[i], 0), to_buf_size(data_hdls[i]));

		buf_list[i].buf_addr = to_dma_addr(data_hdls[i], 0);
		buf_list[i].buf_size = data_buf_size;
	}

	drm_clflush_virt_range(buf_list, to_buf_size(list_hdl));

	ret = wa->aie->msg_ops.get_coredump(hwctx, list_hdl, num_bufs);
	if (ret) {
		XDNA_ERR(xdna, "Failed to get coredump from firmware, ret=%d",
			 ret);
		goto free_data_hdls;
	}

	for (i = 0; i < num_bufs; i++) {
		if (copy_to_user(wa->buf + offset, to_cpu_addr(data_hdls[i], 0),
				 data_buf_size)) {
			ret = -EFAULT;
			goto free_data_hdls;
		}
		offset += data_buf_size;
	}

free_data_hdls:
	for (i = 0; i < num_bufs; i++)
		amdxdna_free_msg_buff(data_hdls[i]);
	kfree(data_hdls);
free_list_hdl:
	amdxdna_free_msg_buff(list_hdl);
out:
	return ret;
}

int amdxdna_get_coredump(struct aie_device *aie,
			 struct amdxdna_client *client,
			 struct amdxdna_drm_get_array *args)
{
	struct amdxdna_drm_aie_coredump config = {};
	struct amdxdna_dev *xdna = client->xdna;
	struct amdxdna_coredump_walk_arg wa;
	struct amdxdna_client *tmp_client;
	size_t buf_size;
	u8 __user *buf;
	int ret;

	drm_WARN_ON(&xdna->ddev, !mutex_is_locked(&xdna->dev_lock));

	if (!aie->msg_ops.get_coredump)
		return -EOPNOTSUPP;

	if (args->num_element != 1) {
		XDNA_ERR(xdna, "Invalid num_element %u, expected 1",
			 args->num_element);
		return -EINVAL;
	}

	buf_size = (size_t)args->num_element * args->element_size;
	buf = u64_to_user_ptr(args->buffer);
	if (!access_ok(buf, buf_size)) {
		XDNA_ERR(xdna, "Failed to access buffer, element num %d size 0x%x",
			 args->num_element, args->element_size);
		return -EFAULT;
	}

	if (buf_size < sizeof(config)) {
		XDNA_ERR(xdna, "Insufficient buffer size: 0x%zx", buf_size);
		args->element_size = sizeof(config);
		return -ENOSPC;
	}

	if (copy_from_user(&config, buf, sizeof(config))) {
		XDNA_ERR(xdna, "Failed to copy coredump config from user");
		return -EFAULT;
	}

	if (XDNA_MBZ_DBG(xdna, &config.pad, sizeof(config.pad)))
		return -EINVAL;

	XDNA_DBG(xdna, "AIE Coredump request for context_id=%u pid=%llu",
		 config.context_id, config.pid);

	wa.ctx_id = config.context_id;
	wa.buf_size = buf_size;
	wa.pid = config.pid;
	wa.args = args;
	wa.aie = aie;
	wa.buf = buf;

	amdxdna_for_each_client(xdna, tmp_client) {
		ret = amdxdna_hwctx_walk(tmp_client, &wa,
					 amdxdna_get_coredump_filter,
					 amdxdna_get_coredump_cb);
		if (ret != -ENOENT)
			break;
	}
	if (ret == -ENOENT)
		XDNA_ERR(xdna, "Context %u for pid %llu not found",
			 config.context_id, config.pid);
	return ret;
}

static bool amdxdna_tile_rw_filter(struct amdxdna_hwctx *hwctx, void *arg)
{
	struct amdxdna_tile_rw_walk_arg *wa = arg;

	return hwctx->client->pid == wa->access->pid && hwctx->id == wa->access->context_id;
}

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
	size_t buf_size;
	u8 __user *buf;
	int ret;

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

	wa.access = &access;
	wa.aie = aie;
	wa.buf = buf;

	amdxdna_for_each_client(xdna, tmp_client) {
		ret = amdxdna_hwctx_walk(tmp_client, &wa,
					 amdxdna_tile_rw_filter,
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

	if (copy_from_user(&reg_val, wa->buf + sizeof(wa->access),
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
	u8 __user *buf;
	int ret;

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

	wa.access = &access;
	wa.aie = aie;
	wa.buf = buf;

	amdxdna_for_each_client(xdna, tmp_client) {
		ret = amdxdna_hwctx_walk(tmp_client, &wa,
					 amdxdna_tile_rw_filter,
					 amdxdna_aie_tile_write_cb);
		if (ret != -ENOENT)
			break;
	}
	if (ret == -ENOENT)
		XDNA_ERR(xdna, "Context %u for pid %llu not found",
			 access.context_id, access.pid);
	return ret;
}

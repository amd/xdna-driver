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
	struct amdxdna_drm_query_aie_metadata *meta;
	int ret = 0;
	u32 buf_sz;

	meta = kzalloc_obj(*meta);
	if (!meta)
		return -ENOMEM;

	meta->col_size = aie->metadata.size;
	meta->cols = aie->metadata.cols;
	meta->rows = aie->metadata.rows;

	meta->version.major = aie->metadata.version.major;
	meta->version.minor = aie->metadata.version.minor;

	meta->core.row_count = aie->metadata.core.row_count;
	meta->core.row_start = aie->metadata.core.row_start;
	meta->core.dma_channel_count = aie->metadata.core.dma_channel_count;
	meta->core.lock_count = aie->metadata.core.lock_count;
	meta->core.event_reg_count = aie->metadata.core.event_reg_count;

	meta->mem.row_count = aie->metadata.mem.row_count;
	meta->mem.row_start = aie->metadata.mem.row_start;
	meta->mem.dma_channel_count = aie->metadata.mem.dma_channel_count;
	meta->mem.lock_count = aie->metadata.mem.lock_count;
	meta->mem.event_reg_count = aie->metadata.mem.event_reg_count;

	meta->shim.row_count = aie->metadata.shim.row_count;
	meta->shim.row_start = aie->metadata.shim.row_start;
	meta->shim.dma_channel_count = aie->metadata.shim.dma_channel_count;
	meta->shim.lock_count = aie->metadata.shim.lock_count;
	meta->shim.event_reg_count = aie->metadata.shim.event_reg_count;

	buf_sz = min(args->buffer_size, sizeof(*meta));
	if (copy_to_user(u64_to_user_ptr(args->buffer), meta, buf_sz))
		ret = -EFAULT;

	kfree(meta);
	return ret;
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

bool amdxdna_hwctx_access_allowed(struct amdxdna_hwctx *hwctx, bool root_only)
{
	if (amdxdna_is_admin())
		return true;

	if (root_only)
		return false;

	return task_tgid_nr(current) == hwctx->client->pid;
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
	if (order > MAX_PAGE_ORDER) {
		kfree(hdl);
		return ERR_PTR(-EINVAL);
	}
	hdl->size = PAGE_SIZE << order;

	if (amdxdna_iova_on(xdna)) {
		hdl->vaddr = amdxdna_iommu_alloc(xdna, hdl->size, &hdl->dma_addr);
	} else {
		hdl->vaddr = dma_alloc_noncoherent(xdna->ddev.dev, hdl->size,
						   &hdl->dma_addr,
						   DMA_FROM_DEVICE, GFP_KERNEL);
		if (!hdl->vaddr)
			hdl->vaddr = ERR_PTR(-ENOMEM);
	}

	if (IS_ERR(hdl->vaddr)) {
		int ret = PTR_ERR(hdl->vaddr);

		kfree(hdl);
		return ERR_PTR(ret);
	}

	return hdl;
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

void amdxdna_clflush_msg_buff(struct amdxdna_msg_buf_hdl *hdl, u32 offset, u32 size)
{
	if (!hdl || offset > hdl->size)
		return;
	if (!size)
		size = hdl->size - offset;
	else if (size > hdl->size - offset)
		return;

	drm_clflush_virt_range(to_cpu_addr(hdl, offset), size);
}

int amdxdna_get_coredump(struct aie_device *aie,
			 struct amdxdna_client *client,
			 struct amdxdna_drm_get_array *args)
{
	struct amdxdna_msg_buf_hdl **data_hdls = NULL;
	struct amdxdna_drm_aie_coredump config = {};
	struct amdxdna_coredump_buf_entry *buf_list;
	struct amdxdna_msg_buf_hdl *list_hdl = NULL;
	struct amdxdna_client *ctx_client = NULL;
	struct amdxdna_dev *xdna = client->xdna;
	struct amdxdna_hwctx *hwctx = NULL;
	struct amdxdna_client *tmp_client;
	u32 data_buf_size = SZ_1M;
	int ret = 0, idx = 0, i;
	unsigned long hwctx_id;
	size_t offset = 0;
	size_t total_size;
	size_t buf_size;
	u8 __user *buf;
	u32 num_bufs;
	u32 orig_col;

	if (!xdna->dev_info->ops->get_coredump)
		return -EOPNOTSUPP;

	drm_WARN_ON(&xdna->ddev, !mutex_is_locked(&xdna->dev_lock));

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

	amdxdna_for_each_client(xdna, tmp_client) {
		struct amdxdna_hwctx *hw_ctx;

		idx = srcu_read_lock(&tmp_client->hwctx_srcu);
		amdxdna_for_each_hwctx(tmp_client, hwctx_id, hw_ctx) {
			if (config.context_id == hwctx_id &&
			    config.pid == hw_ctx->client->pid) {
				hwctx = hw_ctx;
				ctx_client = tmp_client;
				break;
			}
		}
		if (hwctx)
			break;
		srcu_read_unlock(&tmp_client->hwctx_srcu, idx);
	}

	if (!hwctx) {
		XDNA_ERR(xdna, "Context %u for pid %llu not found",
			 config.context_id, config.pid);
		return -EINVAL;
	}

	if (!amdxdna_hwctx_access_allowed(hwctx, false)) {
		XDNA_ERR(xdna, "Permission denied for context %u",
			 config.context_id);
		ret = -EPERM;
		goto unlock_srcu;
	}

	orig_col = hwctx->num_col - hwctx->num_unused_col;
	num_bufs = aie->metadata.rows * orig_col;
	total_size = (size_t)num_bufs * data_buf_size;

	if (buf_size < total_size) {
		XDNA_DBG(xdna, "Insufficient buffer size %zu, need %zu",
			 buf_size, total_size);
		args->element_size = total_size;
		ret = -ENOSPC;
		goto unlock_srcu;
	}

	list_hdl = amdxdna_alloc_msg_buff(xdna,
					  max_t(u32, num_bufs * sizeof(*buf_list), SZ_8K));
	if (IS_ERR(list_hdl)) {
		XDNA_ERR(xdna, "Failed to allocate buffer list");
		ret = PTR_ERR(list_hdl);
		goto unlock_srcu;
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

		memset(to_cpu_addr(data_hdls[i], 0), 0, data_buf_size);
		amdxdna_clflush_msg_buff(data_hdls[i], 0, 0);

		buf_list[i].buf_addr = to_dma_addr(data_hdls[i], 0);
		buf_list[i].buf_size = data_buf_size;
	}

	amdxdna_clflush_msg_buff(list_hdl, 0, 0);

	ret = xdna->dev_info->ops->get_coredump(xdna, list_hdl,
					       hwctx, num_bufs);
	if (ret) {
		XDNA_ERR(xdna, "Failed to get coredump from firmware, ret=%d",
			 ret);
		goto free_data_hdls;
	}

	for (i = 0; i < num_bufs; i++) {
		if (copy_to_user(buf + offset, to_cpu_addr(data_hdls[i], 0),
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
unlock_srcu:
	srcu_read_unlock(&ctx_client->hwctx_srcu, idx);
	return ret;
}

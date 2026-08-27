// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2026, Advanced Micro Devices, Inc.
 */

#include "drm/amdxdna_accel.h"
#include <drm/drm_cache.h>
#include <drm/drm_drv.h>
#include <drm/drm_print.h>
#include <linux/errno.h>
#include <linux/limits.h>
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

static int aie_check_protocol_impl(struct aie_device *aie, u32 fw_major, u32 fw_minor,
				   const struct amdxdna_fw_feature_tbl *feature)
{
	bool found = false;

	for (; feature && feature->major; feature++) {
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

int aie_check_protocol(struct aie_device *aie, u32 fw_major, u32 fw_minor)
{
	return aie_check_protocol_impl(aie, fw_major, fw_minor,
				       aie->xdna->dev_info->fw_feature_tbl);
}

int aie_check_cert_protocol(struct aie_device *aie, u32 cert_major, u32 cert_minor)
{
	return aie_check_protocol_impl(aie, cert_major, cert_minor,
				       aie->xdna->dev_info->cert_feature_tbl);
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

int amdxdna_get_aie_version(struct amdxdna_client *client,
			    struct amdxdna_drm_get_info *args,
			    struct amdxdna_drm_query_aie_version *version)
{
	int ret = 0;
	u32 buf_sz;

	buf_sz = min(args->buffer_size, sizeof(*version));
	if (copy_to_user(u64_to_user_ptr(args->buffer), version, buf_sz))
		ret = -EFAULT;

	return ret;
}

int amdxdna_get_firmware_version(struct amdxdna_client *client,
				 struct amdxdna_drm_get_info *args,
				 struct amdxdna_drm_query_firmware_version *version)
{
	int ret = 0;
	u32 buf_sz;

	buf_sz = min(args->buffer_size, sizeof(*version));
	if (copy_to_user(u64_to_user_ptr(args->buffer), version, buf_sz))
		ret = -EFAULT;

	return ret;
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

int amdxdna_get_aie_status(struct aie_device *aie,
			   struct amdxdna_client *client,
			   struct amdxdna_drm_get_info *args)
{
	struct amdxdna_drm_query_aie_status status = {};
	struct amdxdna_dev *xdna = client->xdna;
	struct amdxdna_msg_buf_hdl *buf_hdl;
	u32 cols_filled = 0;
	u32 resp_size = 0;
	u32 alloc_sz;
	u32 buf_sz;
	int ret;

	if (!aie->msg_ops.query_status)
		return -EOPNOTSUPP;

	buf_sz = min(args->buffer_size, sizeof(status));
	if (copy_from_user(&status, u64_to_user_ptr(args->buffer), buf_sz)) {
		XDNA_ERR(xdna, "Failed to copy AIE request into kernel");
		return -EFAULT;
	}

	alloc_sz = aie->metadata.cols * aie->metadata.col_size;
	if (!alloc_sz)
		return -EINVAL;

	buf_hdl = amdxdna_alloc_msg_buff(xdna, alloc_sz);
	if (IS_ERR(buf_hdl))
		return PTR_ERR(buf_hdl);

	memset(to_cpu_addr(buf_hdl, 0), 0, to_buf_size(buf_hdl));
	drm_clflush_virt_range(to_cpu_addr(buf_hdl, 0), to_buf_size(buf_hdl));

	ret = aie->msg_ops.query_status(aie, buf_hdl, &cols_filled, &resp_size);
	if (ret) {
		XDNA_ERR(xdna, "Failed to get AIE status info, ret %d", ret);
		goto out_free;
	}

	if (to_buf_size(buf_hdl) < resp_size) {
		XDNA_ERR(xdna, "Bad buffer size. Available: %u. Needs: %u",
			 to_buf_size(buf_hdl), resp_size);
		ret = -EINVAL;
		goto out_free;
	}

	/* Invalidate stale cache lines before reading FW-written data. */
	drm_clflush_virt_range(to_cpu_addr(buf_hdl, 0), to_buf_size(buf_hdl));

	resp_size = min(status.buffer_size, resp_size);
	if (copy_to_user(u64_to_user_ptr(status.buffer),
			 to_cpu_addr(buf_hdl, 0), resp_size)) {
		XDNA_ERR(xdna, "Failed to copy AIE status to user space");
		ret = -EFAULT;
		goto out_free;
	}

	status.cols_filled = cols_filled;
	if (copy_to_user(u64_to_user_ptr(args->buffer), &status, buf_sz))
		ret = -EFAULT;

out_free:
	amdxdna_free_msg_buff(buf_hdl);
	return ret;
}

/*
 * The telemetry map is indexed by firmware context id and sized by
 * aie->hwctx_limit, so the walk has to carry both the map and that bound:
 * the per-generation struct amdxdna_dev_hdl that holds the limit is not
 * visible from here.
 */
struct amdxdna_hwctx_map_ctx {
	u32	*map;
	u32	limit;
};

static int amdxdna_fill_hwctx_map_cb(struct amdxdna_hwctx *hwctx, void *arg)
{
	struct amdxdna_dev *xdna = hwctx->client->xdna;
	struct amdxdna_hwctx_map_ctx *ctx = arg;

	if (hwctx->fw_ctx_id >= ctx->limit) {
		XDNA_ERR(xdna, "Invalid fw ctx id %d/%d", hwctx->fw_ctx_id,
			 ctx->limit);
		return -EINVAL;
	}

	/* Map firmware allocated context id (key) to driver context id (value). */
	ctx->map[hwctx->fw_ctx_id] = hwctx->id;
	return 0;
}

/*
 * Fill the firmware-context-id to driver-context-id translation for every
 * context the caller may see. amdxdna_get_telemetry() places the result at
 * the head of the telemetry buffer, so a consumer can resolve the firmware
 * context id (the key the firmware indexes its per-context telemetry by) to
 * the driver context id.
 */
static int amdxdna_fill_hwctx_map(struct aie_device *aie, u32 *map)
{
	struct amdxdna_hwctx_map_ctx ctx = { .map = map, .limit = aie->hwctx_limit };
	struct amdxdna_dev *xdna = aie->xdna;
	struct amdxdna_client *tmp_client;
	int ret;

	amdxdna_for_each_client(xdna, tmp_client) {
		if (!amdxdna_client_visible(tmp_client))
			continue;
		ret = amdxdna_hwctx_walk(tmp_client, &ctx, NULL,
					 amdxdna_fill_hwctx_map_cb);
		if (ret)
			return ret;
	}

	return 0;
}

int amdxdna_get_telemetry(struct aie_device *aie,
			  struct amdxdna_client *client,
			  struct amdxdna_drm_get_info *args)
{
	struct amdxdna_drm_query_telemetry_header *header __free(kfree) = NULL;
	u32 telemetry_data_sz, header_sz, elem_num;
	struct amdxdna_dev *xdna = client->xdna;
	u64 payload;
	int ret;

	if (!aie->msg_ops.query_telemetry)
		return -EOPNOTSUPP;

	/* Device-wide telemetry: admin or matching EUID only (see uAPI). */
	if (!amdxdna_client_visible(client))
		return -EPERM;

	drm_WARN_ON(&xdna->ddev, !mutex_is_locked(&xdna->dev_lock));

	elem_num = aie->hwctx_limit;
	header_sz = struct_size(header, map, elem_num);
	if (args->buffer_size <= header_sz) {
		XDNA_DBG(xdna, "Invalid buffer size");
		return -EINVAL;
	}
	telemetry_data_sz = args->buffer_size - header_sz;

	header = kzalloc(header_sz, GFP_KERNEL);
	if (!header)
		return -ENOMEM;

	if (copy_from_user(header, u64_to_user_ptr(args->buffer), sizeof(*header))) {
		XDNA_ERR(xdna, "Failed to copy telemetry header from user");
		return -EFAULT;
	}

	header->map_num_elements = elem_num;
	if (elem_num) {
		ret = amdxdna_fill_hwctx_map(aie, header->map);
		if (ret)
			return ret;
	}

	if (check_add_overflow(args->buffer, (u64)header_sz, &payload))
		return -EINVAL;

	ret = aie->msg_ops.query_telemetry(aie, u64_to_user_ptr(payload),
					   telemetry_data_sz, header);
	if (ret) {
		XDNA_ERR(xdna, "Query telemetry failed ret %d", ret);
		return ret;
	}

	if (copy_to_user(u64_to_user_ptr(args->buffer), header, header_sz)) {
		XDNA_ERR(xdna, "Copy telemetry header to user failed");
		return -EFAULT;
	}

	return 0;
}

int amdxdna_get_force_preempt_state(struct aie_device *aie, struct amdxdna_drm_get_info *args)
{
	struct amdxdna_drm_attribute_state state = {};
	u32 buf_sz;

	state.state = aie->force_preempt_enabled;

	buf_sz = min(args->buffer_size, sizeof(state));
	if (copy_to_user(u64_to_user_ptr(args->buffer), &state, buf_sz))
		return -EFAULT;

	return 0;
}

int amdxdna_get_frame_boundary_preempt_state(struct aie_device *aie,
					     struct amdxdna_drm_get_info *args)
{
	struct amdxdna_drm_attribute_state state = {};
	u32 buf_sz;

	state.state = aie->frame_boundary_preempt_enabled;

	buf_sz = min(args->buffer_size, sizeof(state));
	if (copy_to_user(u64_to_user_ptr(args->buffer), &state, buf_sz))
		return -EFAULT;

	return 0;
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


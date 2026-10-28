// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2026, Advanced Micro Devices, Inc.
 *
 * VE2 management transport.
 *
 * VE2 aie2ps has no mailbox IP. This file still provides the
 * amdxdna_mailbox.h API so the shared aie4 probe path can send the same
 * opcodes it sends on npu12. A handler calls the Xilinx AIE driver and
 * completes the message locally. An opcode that is not implemented returns
 * -EOPNOTSUPP.
 *
 * Implemented here: firmware identity, CERT version, and AIE geometry, which
 * xrt-smi examine uses; and the partition and hardware-context opcodes the
 * shared aie4 context path sends.
 *
 * CREATE_PARTITION takes an AIE column-range partition, and CREATE_HW_CONTEXT
 * starts CERT on it. CERT runs the host queue at the aie4 request's
 * hsa_addr. The AIE partition id is returned as the partition, hw context and
 * completion index, because each partition carries exactly one context.
 * The aie4 doorbell and completion hooks reach that partition through
 * ve2_mbox_ring_doorbell() and ve2_mbox_attach_notify().
 */

#include <drm/drm_device.h>
#include <drm/drm_managed.h>
#include <linux/bitfield.h>
#include <linux/bitmap.h>
#include <linux/firmware.h>
#include <linux/ktime.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <linux/xarray.h>

#include "aie4_msg_priv.h"
#include "ve2.h"
#include "amdxdna_drv.h"
#include "amdxdna_mailbox.h"
#include "ve2_aie.h"

#define VE2_CERT_FW			"amdnpu/release_cert_ve2.elf"
#define VE2_PROG_DATA_MEMORY_OFF	0x80000
#define VE2_CERT_VERSION_OFF		0x50
#define VE2_CERT_VERSION_SIZE		0x40
#define VE2_FW_HASH_LEN			41
#define VE2_FW_DATE_LEN			11

/* Reported to aie4 so the shared feature check accepts this CERT. */
#define VE2_HOST_QUEUE_MAJOR		1
#define VE2_HOST_QUEUE_MINOR		0

#define VE2_MAX_COLS			256

/* Partitions start and size on 4-column boundaries. */
#define VE2_PART_COL_ALIGN		4
/* AIE4_PART_AUTO_COL: no start column requested, the transport places it. */
#define VE2_PART_AUTO_COL		0xFF

/* Column field of an AIE array tile address; gives CERT its partition base. */
#define VE2_COL_SHIFT			25
/* Shim tile (col 0, row 0) event generate register and the CERT doorbell event. */
#define VE2_EVENT_GENERATE_REG		0x00034008
#define VE2_USER_EVENT_ID		0xB6

#define VE2_CERT_ALIVE_MAGIC		0x404C5645
#define VE2_HS_PARTITION_SIZE		GENMASK(6, 0)
#define VE2_HS_ADDR_INVALID		0xFFFFFFFF

/*
 * CERT handshake image, one per column, at the start of the uC private data
 * memory. Named fields are the only ones this driver programs. reserved0 and
 * reserved1 are not used; they keep host_time and the debug-queue address at
 * the offsets CERT reads. The image is allocated zeroed, so those gaps start
 * clear. The copy ends at dbg_hsa_addr_low.
 */
struct ve2_cert_handshake {
	u32 mpaie_alive;
	u32 partition_base_address;
	u32 aie_info;
	u32 hsa_addr_high;
	u32 hsa_addr_low;
	u32 reserved0[7];
	u32 host_time_high;
	u32 host_time_low;
	u32 reserved1[7];
	u32 dbg_hsa_addr_high;
	u32 dbg_hsa_addr_low;
};

static_assert(sizeof(struct ve2_cert_handshake) == 0x5c);
static_assert(offsetof(struct ve2_cert_handshake, host_time_high) == 0x30);
static_assert(offsetof(struct ve2_cert_handshake, dbg_hsa_addr_high) == 0x54);

struct ve2_part {
	struct device			*aie_dev;
	u32				id;
	u32				start_col;
	u32				num_col;
	bool				has_ctx;
	spinlock_t			notify_lock; /* protects notify_cb, notify_data */
	void				(*notify_cb)(void *data);
	void				*notify_data;
};

struct mailbox {
	struct amdxdna_dev		*xdna;
	struct mutex			lock; /* serializes VE2 mailbox opcodes */
	bool				dropped;
	bool				cert_ready;
	bool				dev_info_ready;
	struct ve2_aie_device_info	dev_info;
	u8				cert_major;
	u8				cert_minor;
	u8				cert_hotfix;
	u8				cert_build;
	char				cert_git[VE2_FW_HASH_LEN];
	char				cert_date[VE2_FW_DATE_LEN];
	struct xarray			parts; /* struct ve2_part, by AIE partition id */
	DECLARE_BITMAP(used_cols, VE2_MAX_COLS);
};

struct mailbox_channel {
	struct mailbox			*mb;
	bool				started;
	void				*async_handle;
	xdna_mailbox_async_cb_t	async_cb;
};

static int ve2_reply(const struct xdna_mailbox_msg *msg, const void *resp, size_t len)
{
	if (!msg->notify_cb || !msg->handle)
		return -EINVAL;

	return msg->notify_cb(msg->handle, (void __iomem *)resp, len);
}

/* AIE user_event1 callback: CERT raised its completion interrupt. */
static void ve2_part_event(u32 partition_id, void *priv)
{
	struct ve2_part *part = priv;
	unsigned long flags;

	spin_lock_irqsave(&part->notify_lock, flags);
	if (part->notify_cb)
		part->notify_cb(part->notify_data);
	spin_unlock_irqrestore(&part->notify_lock, flags);
}

static void ve2_part_free(struct mailbox *mb, struct ve2_part *part)
{
	xa_erase(&mb->parts, part->id);
	ve2_aie_partition_teardown(part->aie_dev);
	ve2_aie_partition_release(part->aie_dev);
	bitmap_clear(mb->used_cols, part->start_col, part->num_col);
	kfree(part);
}

static void ve2_mbox_drop(struct mailbox *mb)
{
	struct ve2_part *part;
	unsigned long id;

	if (!mb || mb->dropped)
		return;

	mb->dropped = true;
	xa_for_each(&mb->parts, id, part)
		ve2_part_free(mb, part);
	xa_destroy(&mb->parts);
	mutex_destroy(&mb->lock);
}

static void ve2_mbox_drop_action(struct drm_device *ddev, void *arg)
{
	ve2_mbox_drop(arg);
}

void ve2_mbox_release(struct mailbox *mb)
{
	ve2_mbox_drop(mb);
}

static int ve2_ensure_dev_info(struct mailbox *mb)
{
	int ret;

	if (mb->dev_info_ready)
		return 0;

	ret = ve2_aie_get_device_info(&mb->dev_info);
	if (ret) {
		XDNA_ERR(mb->xdna, "AIE device info failed, ret %d", ret);
		return ret;
	}

	if (!mb->dev_info.cols || mb->dev_info.cols > VE2_MAX_COLS ||
	    !mb->dev_info.core_rows) {
		XDNA_ERR(mb->xdna, "unexpected AIE geometry cols %u core rows %u",
			 mb->dev_info.cols, mb->dev_info.core_rows);
		return -EINVAL;
	}

	mb->dev_info_ready = true;
	return 0;
}

static int ve2_load_cert(struct mailbox *mb)
{
	struct amdxdna_dev *xdna = mb->xdna;
	u8 raw[VE2_CERT_VERSION_SIZE];
	const struct firmware *fw;
	struct device *aie_dev;
	char *image;
	int ret;

	ret = request_firmware(&fw, VE2_CERT_FW, xdna->ddev.dev);
	if (ret) {
		XDNA_ERR(xdna, "request fw %s failed %d", VE2_CERT_FW, ret);
		return -ENODEV;
	}

	image = kmemdup(fw->data, fw->size, GFP_KERNEL);
	release_firmware(fw);
	if (!image)
		return -ENOMEM;

	aie_dev = ve2_aie_partition_request(0, 0, NULL, NULL, NULL);
	if (IS_ERR(aie_dev)) {
		ret = PTR_ERR(aie_dev);
		XDNA_ERR(xdna, "CERT partition request failed: %d", ret);
		goto out_image;
	}

	ret = ve2_aie_partition_initialize(aie_dev, VE2_AIE_INIT_FIRMWARE, NULL, 0);
	if (ret) {
		XDNA_ERR(xdna, "CERT partition init failed: %d", ret);
		goto out_release;
	}

	ret = ve2_aie_load_cert(aie_dev, image);
	if (ret) {
		XDNA_ERR(xdna, "CERT load failed: %d", ret);
		goto out_teardown;
	}

	ret = ve2_aie_read(aie_dev, 0, 0,
			   VE2_PROG_DATA_MEMORY_OFF + VE2_CERT_VERSION_OFF,
			   sizeof(raw), raw);
	if (ret < 0) {
		XDNA_ERR(xdna, "CERT version read failed: %d", ret);
		goto out_teardown;
	}

	mb->cert_major = raw[0];
	mb->cert_minor = raw[1];
	memcpy(mb->cert_git, raw + 2, VE2_FW_HASH_LEN);
	mb->cert_git[VE2_FW_HASH_LEN - 1] = '\0';
	memcpy(mb->cert_date, raw + 2 + VE2_FW_HASH_LEN, VE2_FW_DATE_LEN);
	mb->cert_date[VE2_FW_DATE_LEN - 1] = '\0';
	mb->cert_hotfix = raw[2 + VE2_FW_HASH_LEN + VE2_FW_DATE_LEN];
	mb->cert_build = raw[2 + VE2_FW_HASH_LEN + VE2_FW_DATE_LEN + 1];
	mb->cert_ready = true;

	XDNA_INFO(xdna, "CERT %u.%u hotfix %u build %u",
		  mb->cert_major, mb->cert_minor, mb->cert_hotfix, mb->cert_build);
	ret = 0;

out_teardown:
	ve2_aie_partition_teardown(aie_dev);
out_release:
	ve2_aie_partition_release(aie_dev);
out_image:
	kfree(image);
	return ret;
}

static int ve2_ensure_cert(struct mailbox *mb)
{
	if (mb->cert_ready)
		return 0;

	return ve2_load_cert(mb);
}

/*
 * Probe-time load, in the product driver's order: AIE geometry first, then
 * CERT. Runs before the mailbox has users, so mb->lock is not taken across the
 * CERT broadcast wait. The IDENTIFY and CERT version opcodes then answer from
 * the cached results.
 */
int ve2_mbox_load_fw(struct mailbox *mb)
{
	int ret;

	ret = ve2_ensure_dev_info(mb);
	if (ret == -ENODEV)
		return -EPROBE_DEFER;
	if (ret)
		return ret;

	return ve2_ensure_cert(mb);
}

static int ve2_op_identify(struct mailbox *mb, const struct xdna_mailbox_msg *msg)
{
	struct aie4_msg_identify_resp resp = { };
	int ret;

	ret = ve2_ensure_cert(mb);
	if (ret)
		return ret;

	resp.status = AIE4_MSG_STATUS_SUCCESS;
	resp.fw_major = mb->cert_major;
	resp.fw_minor = mb->cert_minor;
	resp.fw_patch = mb->cert_hotfix;
	resp.fw_build = mb->cert_build;
	return ve2_reply(msg, &resp, sizeof(resp));
}

static int ve2_op_cert_version(struct mailbox *mb, const struct xdna_mailbox_msg *msg)
{
	struct aie4_msg_query_cert_firmware_version_resp resp = { };
	int ret;

	ret = ve2_ensure_cert(mb);
	if (ret)
		return ret;

	resp.status = AIE4_MSG_STATUS_SUCCESS;
	resp.major_version = mb->cert_major;
	resp.minor_version = mb->cert_minor;
	memcpy(resp.git_hash, mb->cert_git, sizeof(resp.git_hash));
	memcpy(resp.date, mb->cert_date, sizeof(resp.date));
	resp.hotfix = mb->cert_hotfix;
	resp.build = mb->cert_build;
	resp.host_queue_major = VE2_HOST_QUEUE_MAJOR;
	resp.host_queue_minor = VE2_HOST_QUEUE_MINOR;
	return ve2_reply(msg, &resp, sizeof(resp));
}

static int ve2_op_version(struct mailbox *mb, const struct xdna_mailbox_msg *msg)
{
	struct aie4_msg_aie4_version_info_resp resp = { };
	int ret;

	ret = ve2_ensure_dev_info(mb);
	if (ret)
		return ret;

	/*
	 * aie_get_device_info() has no generation field. Report success so
	 * aie4_setup_aie() can continue; column and row counts come from
	 * AIE_TILE_INFO.
	 */
	resp.status = AIE4_MSG_STATUS_SUCCESS;
	return ve2_reply(msg, &resp, sizeof(resp));
}

static int ve2_op_tile_info(struct mailbox *mb, const struct xdna_mailbox_msg *msg)
{
	struct aie4_msg_aie4_tile_info_resp resp = { };
	struct ve2_aie_device_info *info;
	int ret;

	ret = ve2_ensure_dev_info(mb);
	if (ret)
		return ret;

	info = &mb->dev_info;
	resp.status = AIE4_MSG_STATUS_SUCCESS;
	resp.info.size = 0x100000;
	resp.info.cols = info->cols;
	resp.info.rows = info->rows;
	resp.info.core_rows = info->core_rows;
	resp.info.mem_rows = info->mem_rows;
	resp.info.shim_rows = info->shim_rows;
	resp.info.shim_row_start = 0;
	resp.info.mem_row_start = info->shim_rows;
	resp.info.core_row_start = info->shim_rows + info->mem_rows;
	return ve2_reply(msg, &resp, sizeof(resp));
}

static bool ve2_cols_free(struct mailbox *mb, u32 start, u32 count)
{
	return find_next_bit(mb->used_cols, start + count, start) >= start + count;
}

static int ve2_op_create_partition(struct mailbox *mb, const struct xdna_mailbox_msg *msg)
{
	const struct aie4_msg_create_partition_req *req = (const void *)msg->send_data;
	struct aie4_msg_create_partition_resp resp = { };
	struct ve2_part *part;
	u32 start, count, cols;
	int ret;

	if (msg->send_size < sizeof(*req))
		return -EINVAL;

	ret = ve2_ensure_dev_info(mb);
	if (ret)
		return ret;

	cols = mb->dev_info.cols;
	count = req->partition_col_count;
	if (!count || !IS_ALIGNED(count, VE2_PART_COL_ALIGN) || count > cols)
		return -EINVAL;

	if (req->partition_col_start == VE2_PART_AUTO_COL) {
		for (start = 0; start + count <= cols; start += VE2_PART_COL_ALIGN) {
			if (ve2_cols_free(mb, start, count))
				break;
		}
		if (start + count > cols)
			return -EBUSY;
	} else {
		start = req->partition_col_start;
		if (!IS_ALIGNED(start, VE2_PART_COL_ALIGN) || start >= cols ||
		    count > cols - start)
			return -ERANGE;
		if (!ve2_cols_free(mb, start, count))
			return -EBUSY;
	}

	part = kzalloc_obj(*part);
	if (!part)
		return -ENOMEM;

	spin_lock_init(&part->notify_lock);
	part->start_col = start;
	part->num_col = count;
	part->aie_dev = ve2_aie_partition_request(start, count, ve2_part_event, part,
						  &part->id);
	if (IS_ERR(part->aie_dev)) {
		ret = PTR_ERR(part->aie_dev);
		XDNA_ERR(mb->xdna, "AIE partition request col %u+%u failed: %d",
			 start, count, ret);
		kfree(part);
		return ret;
	}

	ret = xa_insert(&mb->parts, part->id, part, GFP_KERNEL);
	if (ret) {
		ve2_aie_partition_release(part->aie_dev);
		kfree(part);
		return ret;
	}
	bitmap_set(mb->used_cols, start, count);

	resp.status = AIE4_MSG_STATUS_SUCCESS;
	resp.partition_id = part->id;
	ret = ve2_reply(msg, &resp, sizeof(resp));
	if (ret)
		ve2_part_free(mb, part);
	return ret;
}

static int ve2_op_destroy_partition(struct mailbox *mb, const struct xdna_mailbox_msg *msg)
{
	const struct aie4_msg_destroy_partition_req *req = (const void *)msg->send_data;
	struct aie4_msg_destroy_partition_resp resp = { };
	struct ve2_part *part;

	if (msg->send_size < sizeof(*req))
		return -EINVAL;

	part = xa_load(&mb->parts, req->partition_id);
	if (!part)
		return -ENOENT;
	if (part->has_ctx)
		return -EBUSY;

	ve2_part_free(mb, part);
	resp.status = AIE4_MSG_STATUS_SUCCESS;
	return ve2_reply(msg, &resp, sizeof(resp));
}

/*
 * Write the CERT handshake into every column of @part, then wake the lead uC.
 * Only the lead column runs the host queue at @hsa_addr.
 */
static int ve2_part_start_cert(struct mailbox *mb, struct ve2_part *part, u64 hsa_addr)
{
	struct ve2_aie_handshake *hs_data;
	struct ve2_cert_handshake *hs;
	u64 host_time = ktime_get_ns();
	u32 col;
	int ret;

	hs = kcalloc(part->num_col, sizeof(*hs), GFP_KERNEL);
	hs_data = kcalloc(part->num_col, sizeof(*hs_data), GFP_KERNEL);
	if (!hs || !hs_data) {
		ret = -ENOMEM;
		goto out;
	}

	for (col = 0; col < part->num_col; col++) {
		hs[col].mpaie_alive = VE2_CERT_ALIVE_MAGIC;
		hs[col].partition_base_address = part->start_col << VE2_COL_SHIFT;
		hs[col].aie_info = FIELD_PREP(VE2_HS_PARTITION_SIZE, part->num_col);
		if (!col) {
			hs[col].hsa_addr_high = upper_32_bits(hsa_addr);
			hs[col].hsa_addr_low = lower_32_bits(hsa_addr);
		} else {
			hs[col].hsa_addr_high = VE2_HS_ADDR_INVALID;
			hs[col].hsa_addr_low = VE2_HS_ADDR_INVALID;
		}
		hs[col].dbg_hsa_addr_high = VE2_HS_ADDR_INVALID;
		hs[col].dbg_hsa_addr_low = VE2_HS_ADDR_INVALID;
		hs[col].host_time_high = upper_32_bits(host_time);
		hs[col].host_time_low = lower_32_bits(host_time);

		hs_data[col].addr = &hs[col];
		hs_data[col].size = sizeof(*hs);
		hs_data[col].col = col;
	}

	ret = ve2_aie_partition_initialize(part->aie_dev, VE2_AIE_INIT_RUNTIME,
					   hs_data, part->num_col);
	if (ret) {
		XDNA_ERR(mb->xdna, "partition 0x%x runtime init failed: %d", part->id, ret);
		goto out;
	}

	ret = ve2_aie_partition_wake_lead_uc(part->aie_dev);
	if (ret)
		XDNA_ERR(mb->xdna, "partition 0x%x lead uC wake-up failed: %d", part->id, ret);
out:
	kfree(hs_data);
	kfree(hs);
	return ret;
}

static int ve2_op_create_hw_context(struct mailbox *mb, const struct xdna_mailbox_msg *msg)
{
	const struct aie4_msg_create_hw_context_req *req = (const void *)msg->send_data;
	struct aie4_msg_create_hw_context_resp resp = { };
	struct ve2_part *part;
	u64 hsa_addr;
	int ret;

	if (msg->send_size < sizeof(*req))
		return -EINVAL;

	part = xa_load(&mb->parts, req->partition_id);
	if (!part)
		return -ENOENT;
	if (part->has_ctx)
		return -EBUSY;

	hsa_addr = ((u64)req->hsa_addr_high << 32) | req->hsa_addr_low;
	if (!hsa_addr)
		return -EINVAL;

	ret = ve2_part_start_cert(mb, part, hsa_addr);
	if (ret)
		return ret;
	part->has_ctx = true;

	resp.status = AIE4_MSG_STATUS_SUCCESS;
	resp.hw_context_id = part->id;
	resp.job_complete_msix_idx = part->id;
	ret = ve2_reply(msg, &resp, sizeof(resp));
	if (ret)
		part->has_ctx = false;
	return ret;
}

/* CERT keeps running until DESTROY_PARTITION tears the partition down. */
static int ve2_op_destroy_hw_context(struct mailbox *mb, const struct xdna_mailbox_msg *msg)
{
	const struct aie4_msg_destroy_hw_context_req *req = (const void *)msg->send_data;
	struct aie4_msg_destroy_hw_context_resp resp = { };
	struct ve2_part *part;

	if (msg->send_size < sizeof(*req))
		return -EINVAL;

	part = xa_load(&mb->parts, req->hw_context_id);
	if (!part || !part->has_ctx)
		return -ENOENT;

	part->has_ctx = false;
	resp.status = AIE4_MSG_STATUS_SUCCESS;
	return ve2_reply(msg, &resp, sizeof(resp));
}

/* aie4 completion hook: route @index's CERT interrupt to @cb. */
int ve2_mbox_attach_notify(struct mailbox *mb, u32 index, void (*cb)(void *data),
			   void *data)
{
	struct ve2_part *part;
	int ret = 0;

	mutex_lock(&mb->lock);
	part = xa_load(&mb->parts, index);
	if (part) {
		spin_lock_irq(&part->notify_lock);
		part->notify_cb = cb;
		part->notify_data = data;
		spin_unlock_irq(&part->notify_lock);
	} else {
		ret = -ENOENT;
	}
	mutex_unlock(&mb->lock);
	return ret;
}

/* On return, @index's callback is no longer running and will not run again. */
void ve2_mbox_detach_notify(struct mailbox *mb, u32 index)
{
	struct ve2_part *part;

	mutex_lock(&mb->lock);
	part = xa_load(&mb->parts, index);
	if (part) {
		spin_lock_irq(&part->notify_lock);
		part->notify_cb = NULL;
		part->notify_data = NULL;
		spin_unlock_irq(&part->notify_lock);
	}
	mutex_unlock(&mb->lock);
}

/* aie4 doorbell hook: tell CERT on @hw_ctx_id's partition the queue moved. */
int ve2_mbox_ring_doorbell(struct mailbox *mb, u32 hw_ctx_id)
{
	u32 event = VE2_USER_EVENT_ID;
	struct ve2_part *part;
	int ret;

	mutex_lock(&mb->lock);
	part = xa_load(&mb->parts, hw_ctx_id);
	if (part && part->has_ctx)
		ret = ve2_aie_write(part->aie_dev, 0, 0, VE2_EVENT_GENERATE_REG,
				    sizeof(event), &event);
	else
		ret = -ENOENT;
	mutex_unlock(&mb->lock);
	return ret < 0 ? ret : 0;
}

struct mailbox *xdnam_mailbox_create(struct drm_device *ddev,
				     const struct xdna_mailbox_res *res)
{
	struct mailbox *mb;
	int ret;

	mb = drmm_kzalloc(ddev, sizeof(*mb), GFP_KERNEL);
	if (!mb)
		return ERR_PTR(-ENOMEM);

	mb->xdna = to_xdna_dev(ddev);
	mutex_init(&mb->lock);
	xa_init(&mb->parts);

	ret = drmm_add_action_or_reset(ddev, ve2_mbox_drop_action, mb);
	if (ret)
		return ERR_PTR(ret);

	return mb;
}

struct mailbox_channel *xdna_mailbox_alloc_channel(struct mailbox *mb)
{
	struct mailbox_channel *chann;

	chann = kzalloc_obj(*chann);
	if (!chann)
		return NULL;

	chann->mb = mb;
	return chann;
}

int xdna_mailbox_start_channel(struct mailbox_channel *mb_chann,
			       const struct xdna_mailbox_chann_res *x2i,
			       const struct xdna_mailbox_chann_res *i2x,
			       u32 xdna_mailbox_intr_reg, int mb_irq, u32 n_msg)
{
	if (!mb_chann)
		return -EINVAL;

	mb_chann->started = true;
	return 0;
}

void xdna_mailbox_set_async_cb(struct mailbox_channel *mailbox_chann,
			       void *async_handle, xdna_mailbox_async_cb_t async_cb)
{
	if (!mailbox_chann)
		return;

	mailbox_chann->async_handle = async_handle;
	mailbox_chann->async_cb = async_cb;
}

void xdna_mailbox_free_channel(struct mailbox_channel *mailbox_chann)
{
	kfree(mailbox_chann);
}

void xdna_mailbox_stop_channel(struct mailbox_channel *mailbox_chann)
{
	if (mailbox_chann)
		mailbox_chann->started = false;
}

void xdna_mailbox_drain_channel(struct mailbox_channel *mailbox_chann)
{
}

int xdna_mailbox_send_msg(struct mailbox_channel *mailbox_chann,
			  const struct xdna_mailbox_msg *msg)
{
	struct mailbox *mb;
	int ret;

	if (!mailbox_chann || !mailbox_chann->started || !msg)
		return -EINVAL;

	mb = mailbox_chann->mb;
	mutex_lock(&mb->lock);
	switch (msg->opcode) {
	case AIE4_MSG_OP_IDENTIFY:
		ret = ve2_op_identify(mb, msg);
		break;
	case AIE4_MSG_OP_QUERY_CERT_FIRMWARE_VERSION:
		ret = ve2_op_cert_version(mb, msg);
		break;
	case AIE4_MSG_OP_AIE_VERSION_INFO:
		ret = ve2_op_version(mb, msg);
		break;
	case AIE4_MSG_OP_AIE_TILE_INFO:
		ret = ve2_op_tile_info(mb, msg);
		break;
	case AIE4_MSG_OP_CREATE_PARTITION:
		ret = ve2_op_create_partition(mb, msg);
		break;
	case AIE4_MSG_OP_DESTROY_PARTITION:
		ret = ve2_op_destroy_partition(mb, msg);
		break;
	case AIE4_MSG_OP_CREATE_HW_CONTEXT:
		ret = ve2_op_create_hw_context(mb, msg);
		break;
	case AIE4_MSG_OP_DESTROY_HW_CONTEXT:
		ret = ve2_op_destroy_hw_context(mb, msg);
		break;
	default:
		XDNA_DBG(mb->xdna, "VE2 opcode 0x%x is not implemented", msg->opcode);
		ret = -EOPNOTSUPP;
		break;
	}
	mutex_unlock(&mb->lock);
	return ret;
}

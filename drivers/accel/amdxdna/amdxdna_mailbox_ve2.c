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
 * CREATE_PARTITION takes or shares an AIE column-range partition, while
 * CREATE_HW_CONTEXT creates a logical context with its own HSA queue. CERT
 * runs one such queue at a time; the per-partition scheduler switches the
 * handshake when a waiting context needs the partition. The physical AIE
 * partition id remains the shared completion index, while logical context IDs
 * route doorbells. The aie4 hooks reach this layer through
 * ve2_mbox_ring_doorbell() and ve2_mbox_attach_notify().
 */

#include <drm/drm_device.h>
#include <drm/drm_managed.h>
#include <linux/bitfield.h>
#include <linux/bitmap.h>
#include <linux/firmware.h>
#include <linux/ktime.h>
#include <linux/list.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <linux/workqueue.h>
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
/* CERT's handshake location in the lead shim tile's privileged memory. */
#define VE2_CERT_HANDSHAKE_OFF		0x88000
#define VE2_CERT_HSA_NOT_EMPTY		BIT(0)
#define VE2_CERT_IDLE			BIT(2)
#define VE2_CERT_CTX_SWITCH_SHARE	BIT(0)

/*
 * CERT handshake image, one per column, at the start of the uC private data
 * memory. Named fields are the only ones this driver programs or reads.
 * reserved0..reserved2 keep ctx_switch_req, cert_idle_status, host_time and
 * the debug-queue address at the offsets CERT uses. reserved3 is the rest of
 * the 0x104-byte firmware image (context save, counters, and similar state
 * this driver does not interpret). The image is allocated zeroed and copied
 * in full on every CERT restart, so a context switch clears that tail.
 */
struct ve2_cert_handshake {
	u32 mpaie_alive;
	u32 partition_base_address;
	u32 aie_info;
	u32 hsa_addr_high;
	u32 hsa_addr_low;
	u32 ctx_switch_req;
	u32 reserved0;
	u32 cert_idle_status;
	u32 reserved1[4];
	u32 host_time_high;
	u32 host_time_low;
	u32 reserved2[7];
	u32 dbg_hsa_addr_high;
	u32 dbg_hsa_addr_low;
	u32 reserved3[42];
};

static_assert(sizeof(struct ve2_cert_handshake) == 0x104);
static_assert(offsetof(struct ve2_cert_handshake, ctx_switch_req) == 0x14);
static_assert(offsetof(struct ve2_cert_handshake, cert_idle_status) == 0x1c);
static_assert(offsetof(struct ve2_cert_handshake, host_time_high) == 0x30);
static_assert(offsetof(struct ve2_cert_handshake, dbg_hsa_addr_high) == 0x54);

struct ve2_ctx;

struct ve2_part {
	struct device			*aie_dev;
	struct amdxdna_dev		*xdna;
	struct ve2_ctx			*active;
	struct mutex			sched_lock; /* protects contexts and scheduler state */
	struct list_head		contexts;
	struct list_head		runq;
	struct delayed_work		sched_work;
	void				(*notify_cb)(void *data);
	void				*notify_data;
	spinlock_t			notify_lock; /* protects notify_cb and notify_data */
	u32				id;
	u32				start_col;
	u32				num_col;
	u32				users;
	bool				dead;
	bool				switch_requested;
};

/*
 * Logical hardware context sharing a physical AIE partition. The HSA queue
 * remains owned by aie4; the pointers registered at doorbell setup are used
 * only to verify the active queue is drained during teardown.
 */
struct ve2_ctx {
	struct ve2_part		*part;
	struct list_head	part_node;
	struct list_head	run_node;
	u64			hsa_addr;
	u64			*read_index;
	u64			*write_index;
	u32			id;
	bool			bound;
	bool			queued;
};

struct mailbox {
	struct amdxdna_dev		*xdna;
	struct mutex			lock; /* serializes VE2 mailbox opcodes */
	bool				dropped;
	bool				cert_ready;
	bool				dev_info_ready;
	u16				max_cols;
	struct ve2_aie_device_info	dev_info;
	u8				cert_major;
	u8				cert_minor;
	u8				cert_hotfix;
	u8				cert_build;
	char				cert_git[VE2_FW_HASH_LEN];
	char				cert_date[VE2_FW_DATE_LEN];
	struct xarray			parts; /* struct ve2_part, by AIE partition id */
	struct xarray			ctxs; /* struct ve2_ctx, by hardware context id */
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

static void ve2_part_schedule(struct ve2_part *part);

/* AIE user_event1 callback: CERT raised its completion interrupt. */
static void ve2_part_event(u32 partition_id, void *priv)
{
	struct ve2_part *part = priv;
	unsigned long flags;

	spin_lock_irqsave(&part->notify_lock, flags);
	if (part->notify_cb)
		part->notify_cb(part->notify_data);
	if (!part->dead)
		ve2_part_schedule(part);
	spin_unlock_irqrestore(&part->notify_lock, flags);
}

static void ve2_part_free(struct mailbox *mb, struct ve2_part *part)
{
	unsigned long flags;

	spin_lock_irqsave(&part->notify_lock, flags);
	part->dead = true;
	part->notify_cb = NULL;
	part->notify_data = NULL;
	spin_unlock_irqrestore(&part->notify_lock, flags);
	cancel_delayed_work_sync(&part->sched_work);
	xa_erase(&mb->parts, part->id);
	ve2_aie_partition_teardown(part->aie_dev);
	ve2_aie_partition_release(part->aie_dev);
	bitmap_clear(mb->used_cols, part->start_col, part->num_col);
	mutex_destroy(&part->sched_lock);
	kfree(part);
}

static void ve2_mbox_drop(struct mailbox *mb)
{
	struct ve2_ctx *ctx;
	struct ve2_part *part;
	unsigned long id;

	if (!mb || mb->dropped)
		return;

	mb->dropped = true;
	/*
	 * Stop every scheduler before freeing the logical contexts it may still
	 * reference through part->active or part->runq.
	 */
	xa_for_each(&mb->parts, id, part)
		ve2_part_free(mb, part);
	xa_for_each(&mb->ctxs, id, ctx) {
		xa_erase(&mb->ctxs, id);
		kfree(ctx);
	}
	xa_destroy(&mb->ctxs);
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

int ve2_mbox_set_max_cols(struct mailbox *mb, u32 max_cols)
{
	int ret;

	ret = ve2_ensure_dev_info(mb);
	if (ret)
		return ret;
	if (max_cols && max_cols > mb->dev_info.cols)
		return -ERANGE;

	mb->max_cols = max_cols;
	return 0;
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

static struct ve2_part *
ve2_find_shared_part(struct mailbox *mb, u32 start, u32 count, bool pinned)
{
	struct ve2_part *part, *best = NULL;
	unsigned long id;

	xa_for_each(&mb->parts, id, part) {
		if (part->num_col != count || (pinned && part->start_col != start))
			continue;
		if (!best || part->users < best->users)
			best = part;
	}

	return best;
}

static void ve2_part_scheduler(struct work_struct *work);

static int ve2_part_alloc(struct mailbox *mb, u32 start, u32 count,
			  struct ve2_part **out)
{
	struct ve2_part *part;
	int ret;

	part = kzalloc_obj(*part);
	if (!part)
		return -ENOMEM;

	mutex_init(&part->sched_lock);
	INIT_LIST_HEAD(&part->contexts);
	INIT_LIST_HEAD(&part->runq);
	INIT_DELAYED_WORK(&part->sched_work, ve2_part_scheduler);
	spin_lock_init(&part->notify_lock);
	part->start_col = start;
	part->num_col = count;
	part->users = 1;
	part->xdna = mb->xdna;
	part->aie_dev = ve2_aie_partition_request(start, count, ve2_part_event, part,
						  &part->id);
	if (IS_ERR(part->aie_dev)) {
		ret = PTR_ERR(part->aie_dev);
		XDNA_ERR(mb->xdna, "AIE partition request col %u+%u failed: %d",
			 start, count, ret);
		mutex_destroy(&part->sched_lock);
		kfree(part);
		return ret;
	}

	ret = xa_insert(&mb->parts, part->id, part, GFP_KERNEL);
	if (ret) {
		ve2_aie_partition_release(part->aie_dev);
		mutex_destroy(&part->sched_lock);
		kfree(part);
		return ret;
	}

	bitmap_set(mb->used_cols, start, count);
	*out = part;
	return 0;
}

static int ve2_op_create_partition(struct mailbox *mb, const struct xdna_mailbox_msg *msg)
{
	const struct aie4_msg_create_partition_req *req = (const void *)msg->send_data;
	struct aie4_msg_create_partition_resp resp = { };
	struct ve2_part *part;
	bool pinned;
	u32 start = 0, count, cols;
	int ret;

	if (msg->send_size < sizeof(*req))
		return -EINVAL;

	ret = ve2_ensure_dev_info(mb);
	if (ret)
		return ret;

	cols = mb->max_cols ? mb->max_cols : mb->dev_info.cols;
	count = req->partition_col_count;
	if (!count || !IS_ALIGNED(count, VE2_PART_COL_ALIGN) || count > cols)
		return -EINVAL;

	pinned = req->partition_col_start != VE2_PART_AUTO_COL;
	if (!pinned) {
		for (start = 0; start + count <= cols; start += VE2_PART_COL_ALIGN) {
			if (ve2_cols_free(mb, start, count))
				break;
		}
	} else {
		start = req->partition_col_start;
		if (!IS_ALIGNED(start, VE2_PART_COL_ALIGN) || start >= cols ||
		    count > cols - start)
			return -ERANGE;
	}

	/*
	 * A pinned request shares an existing matching physical range, or creates
	 * that exact range when it is free. An automatic request takes a free
	 * range first, then shares the least-used matching partition once the
	 * array has no suitable free range.
	 */
	if (pinned) {
		part = ve2_find_shared_part(mb, start, count, pinned);
		if (part) {
			part->users++;
		} else if (ve2_cols_free(mb, start, count)) {
			ret = ve2_part_alloc(mb, start, count, &part);
			if (ret)
				return ret;
		} else {
			return -EBUSY;
		}
	} else if (start + count > cols) {
		part = ve2_find_shared_part(mb, start, count, false);
		if (!part)
			return -EBUSY;
		part->users++;
	} else {
		ret = ve2_part_alloc(mb, start, count, &part);
		if (ret)
			return ret;
	}

	resp.status = AIE4_MSG_STATUS_SUCCESS;
	resp.partition_id = part->id;
	ret = ve2_reply(msg, &resp, sizeof(resp));
	if (ret && !--part->users)
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

	if (!part->users)
		return -EINVAL;
	/*
	 * Each aie4 context releases its partition lease after destroying its
	 * own hardware context. Other sharers can still be live, so dropping a
	 * non-final lease must succeed rather than returning -EBUSY; aie4 does
	 * not retry a partition destroy that it regards as complete.
	 */
	if (part->users == 1 && !list_empty(&part->contexts))
		return -EBUSY;
	if (!--part->users)
		ve2_part_free(mb, part);
	resp.status = AIE4_MSG_STATUS_SUCCESS;
	return ve2_reply(msg, &resp, sizeof(resp));
}

/*
 * Write the CERT handshake into every column of @part, then wake the lead uC.
 * Only the lead column runs the host queue of @ctx.
 */
static int ve2_part_start_cert(struct ve2_part *part, struct ve2_ctx *ctx)
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
			hs[col].hsa_addr_high = upper_32_bits(ctx->hsa_addr);
			hs[col].hsa_addr_low = lower_32_bits(ctx->hsa_addr);
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
		XDNA_ERR(part->xdna, "partition 0x%x runtime init failed: %d", part->id, ret);
		goto out;
	}

	ret = ve2_aie_partition_wake_lead_uc(part->aie_dev);
	if (ret)
		XDNA_ERR(part->xdna, "partition 0x%x lead uC wake-up failed: %d", part->id, ret);
out:
	kfree(hs_data);
	kfree(hs);
	return ret;
}

static int ve2_part_ring_locked(struct ve2_part *part)
{
	u32 event = VE2_USER_EVENT_ID;

	return ve2_aie_write(part->aie_dev, 0, 0, VE2_EVENT_GENERATE_REG,
			     sizeof(event), &event);
}

static int ve2_part_request_switch_locked(struct ve2_part *part)
{
	u32 req = 0;
	int ret;

	if (part->switch_requested)
		return 0;

	ret = ve2_aie_priv_read(part->aie_dev,
				VE2_CERT_HANDSHAKE_OFF +
				offsetof(struct ve2_cert_handshake, ctx_switch_req),
				sizeof(req), &req);
	if (ret)
		return ret;

	req |= VE2_CERT_CTX_SWITCH_SHARE;
	ret = ve2_aie_priv_write(part->aie_dev,
				 VE2_CERT_HANDSHAKE_OFF +
				 offsetof(struct ve2_cert_handshake, ctx_switch_req),
				 sizeof(req), &req);
	if (!ret)
		part->switch_requested = true;
	return ret;
}

static int ve2_part_activate_locked(struct ve2_part *part, struct ve2_ctx *ctx)
{
	int ret;

	ret = ve2_part_start_cert(part, ctx);
	if (ret)
		return ret;

	if (ctx->queued) {
		list_del_init(&ctx->run_node);
		ctx->queued = false;
	}
	part->active = ctx;
	part->switch_requested = false;
	return 0;
}

static void ve2_part_schedule(struct ve2_part *part)
{
	/*
	 * CERT can complete a short command while the previous scheduler pass
	 * is still reprogramming the partition. A plain work item drops that
	 * completion because it is already running. Delayed work with no delay
	 * is explicitly requeueable from this IRQ callback.
	 */
	mod_delayed_work(system_wq, &part->sched_work, 0);
}

/* CERT has consumed every command published for this context. */
static bool ve2_ctx_queue_drained(struct ve2_ctx *ctx)
{
	u64 ri, wi;

	if (!ctx->read_index || !ctx->write_index)
		return false;

	ri = READ_ONCE(*ctx->read_index);
	/* Order the CERT-owned read index before the driver-owned write index. */
	smp_rmb();
	wi = READ_ONCE(*ctx->write_index);
	return ri >= wi;
}

/* CERT has acknowledged a switch request or has gone idle on its own. */
static bool ve2_part_cert_yielded(struct ve2_part *part)
{
	u32 status = 0;
	int ret;

	ret = ve2_aie_priv_read(part->aie_dev,
				VE2_CERT_HANDSHAKE_OFF +
				offsetof(struct ve2_cert_handshake, cert_idle_status),
				sizeof(status), &status);
	return !ret && (status & (VE2_CERT_HSA_NOT_EMPTY | VE2_CERT_IDLE));
}

/*
 * Install @ctx's HSA queue and ring CERT. The command was published before
 * the context was queued, so reinitialization alone does not start it.
 */
static int ve2_part_dispatch_locked(struct ve2_part *part, struct ve2_ctx *ctx)
{
	int ret;

	ret = ve2_part_activate_locked(part, ctx);
	if (ret)
		return ret;

	return ve2_part_ring_locked(part);
}

static void ve2_part_scheduler(struct work_struct *work)
{
	struct delayed_work *dwork = to_delayed_work(work);
	struct ve2_part *part = container_of(dwork, struct ve2_part, sched_work);
	struct ve2_ctx *next;
	int ret;

	mutex_lock(&part->sched_lock);
	if (part->dead || list_empty(&part->runq))
		goto out;

	next = list_first_entry(&part->runq, struct ve2_ctx, run_node);
	/*
	 * Switch immediately only when the active context has no published
	 * command left. CERT's HSA-not-empty bit is set while a command is
	 * running, so it is a yield acknowledgment only after this scheduler
	 * has asked CERT to yield. Restarting the partition earlier aborts the
	 * running command and the host observes a zero output.
	 */
	if (!part->active || ve2_ctx_queue_drained(part->active) ||
	    (part->switch_requested && ve2_part_cert_yielded(part))) {
		XDNA_INFO(part->xdna, "dispatch VE2 context %u on partition 0x%x",
			  next->id, part->id);
		ret = ve2_part_dispatch_locked(part, next);
		if (ret)
			XDNA_ERR(part->xdna, "dispatch VE2 context %u failed: %d",
				 next->id, ret);
		goto out;
	}

	if (!part->switch_requested) {
		ret = ve2_part_request_switch_locked(part);
		if (ret) {
			XDNA_ERR(part->xdna, "request VE2 context switch failed: %d", ret);
			goto out;
		}
		ret = ve2_part_ring_locked(part);
		if (ret)
			XDNA_ERR(part->xdna, "ring VE2 context switch failed: %d", ret);
	}
out:
	mutex_unlock(&part->sched_lock);
}

static int ve2_op_create_hw_context(struct mailbox *mb, const struct xdna_mailbox_msg *msg)
{
	const struct aie4_msg_create_hw_context_req *req = (const void *)msg->send_data;
	struct aie4_msg_create_hw_context_resp resp = { };
	struct ve2_part *part;
	struct ve2_ctx *ctx;
	u32 id;
	u64 hsa_addr;
	int ret;

	if (msg->send_size < sizeof(*req))
		return -EINVAL;

	part = xa_load(&mb->parts, req->partition_id);
	if (!part)
		return -ENOENT;

	hsa_addr = ((u64)req->hsa_addr_high << 32) | req->hsa_addr_low;
	if (!hsa_addr)
		return -EINVAL;

	ctx = kzalloc_obj(*ctx);
	if (!ctx)
		return -ENOMEM;
	INIT_LIST_HEAD(&ctx->part_node);
	INIT_LIST_HEAD(&ctx->run_node);
	ctx->part = part;
	ctx->hsa_addr = hsa_addr;
	ret = xa_alloc(&mb->ctxs, &id, ctx, XA_LIMIT(1, U32_MAX), GFP_KERNEL);
	if (ret) {
		kfree(ctx);
		return ret;
	}
	ctx->id = id;

	mutex_lock(&part->sched_lock);
	list_add_tail(&ctx->part_node, &part->contexts);
	if (!part->active)
		ret = ve2_part_activate_locked(part, ctx);
	if (ret)
		list_del_init(&ctx->part_node);
	mutex_unlock(&part->sched_lock);
	if (ret) {
		xa_erase(&mb->ctxs, ctx->id);
		kfree(ctx);
		return ret;
	}

	resp.status = AIE4_MSG_STATUS_SUCCESS;
	resp.hw_context_id = ctx->id;
	resp.job_complete_msix_idx = part->id;
	ret = ve2_reply(msg, &resp, sizeof(resp));
	if (ret) {
		mutex_lock(&part->sched_lock);
		if (part->active == ctx)
			part->active = NULL;
		list_del(&ctx->part_node);
		mutex_unlock(&part->sched_lock);
		xa_erase(&mb->ctxs, ctx->id);
		kfree(ctx);
	}
	return ret;
}

static int ve2_op_destroy_hw_context(struct mailbox *mb, const struct xdna_mailbox_msg *msg)
{
	const struct aie4_msg_destroy_hw_context_req *req = (const void *)msg->send_data;
	struct aie4_msg_destroy_hw_context_resp resp = { };
	struct ve2_ctx *ctx, *next = NULL;
	struct ve2_part *part;
	int ret = 0;

	if (msg->send_size < sizeof(*req))
		return -EINVAL;

	ctx = xa_load(&mb->ctxs, req->hw_context_id);
	if (!ctx)
		return -ENOENT;
	part = ctx->part;

	mutex_lock(&part->sched_lock);
	if (ctx->queued) {
		list_del_init(&ctx->run_node);
		ctx->queued = false;
	}
	if (part->active == ctx) {
		part->active = NULL;
		if (!list_empty(&part->runq))
			next = list_first_entry(&part->runq, struct ve2_ctx, run_node);
		if (next)
			ret = ve2_part_dispatch_locked(part, next);
	}
	list_del(&ctx->part_node);
	mutex_unlock(&part->sched_lock);
	if (ret)
		return ret;

	xa_erase(&mb->ctxs, ctx->id);
	kfree(ctx);
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

int ve2_mbox_bind_ctx(struct mailbox *mb, u32 hw_ctx_id, u64 *read_index,
		      u64 *write_index)
{
	struct ve2_ctx *ctx;
	struct ve2_part *part;
	int ret = 0;

	if (!read_index || !write_index)
		return -EINVAL;

	mutex_lock(&mb->lock);
	ctx = xa_load(&mb->ctxs, hw_ctx_id);
	if (!ctx) {
		ret = -ENOENT;
		goto out_mbox;
	}

	part = ctx->part;
	mutex_lock(&part->sched_lock);
	if (part->dead) {
		ret = -ENODEV;
	} else {
		ctx->read_index = read_index;
		ctx->write_index = write_index;
		ctx->bound = true;
	}
	mutex_unlock(&part->sched_lock);
out_mbox:
	mutex_unlock(&mb->lock);
	return ret;
}

/*
 * aie4 doorbell hook: an active context can ring CERT directly. A context
 * sharing the partition is queued, asks CERT to yield, and is started by the
 * per-partition worker after CERT reports idle.
 */
int ve2_mbox_ring_doorbell(struct mailbox *mb, u32 hw_ctx_id)
{
	struct ve2_ctx *ctx;
	struct ve2_part *part;
	int ret;

	mutex_lock(&mb->lock);
	ctx = xa_load(&mb->ctxs, hw_ctx_id);
	if (!ctx) {
		ret = -ENOENT;
		goto out_mbox;
	}

	part = ctx->part;
	mutex_lock(&part->sched_lock);
	if (part->dead || !ctx->bound) {
		ret = -ENODEV;
	} else if (part->active == ctx) {
		ret = ve2_part_ring_locked(part);
	} else {
		if (!ctx->queued) {
			list_add_tail(&ctx->run_node, &part->runq);
			ctx->queued = true;
		}
		ve2_part_schedule(part);
		ret = 0;
	}
	mutex_unlock(&part->sched_lock);
out_mbox:
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
	xa_init_flags(&mb->ctxs, XA_FLAGS_ALLOC);

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

// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2026, Advanced Micro Devices, Inc.
 *
 * VE2 management transport.
 *
 * VE2 aie2ps has no mailbox IP. This file still provides the
 * amdxdna_mailbox.h API so the shared aie4 probe path can send the same
 * opcodes it sends on npu12. A handler calls the Xilinx AIE driver and
 * completes the message locally. An opcode this commit does not implement
 * returns -EOPNOTSUPP.
 *
 * Implemented here: firmware identity, CERT version, and AIE geometry.
 * Those are the queries xrt-smi examine uses. Partition, hardware-context,
 * and command opcodes are intentionally left for the next change.
 */

#include <drm/drm_device.h>
#include <drm/drm_managed.h>
#include <linux/firmware.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#include <linux/string.h>

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

struct mailbox {
	struct amdxdna_dev		*xdna;
	struct mutex			lock;
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

static void ve2_mbox_drop(struct mailbox *mb)
{
	if (!mb || mb->dropped)
		return;

	mb->dropped = true;
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

	aie_dev = ve2_aie_partition_request();
	if (IS_ERR(aie_dev)) {
		ret = PTR_ERR(aie_dev);
		XDNA_ERR(xdna, "CERT partition request failed: %d", ret);
		goto out_image;
	}

	ret = ve2_aie_partition_initialize(aie_dev, VE2_AIE_INIT_FIRMWARE);
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

	ret = drmm_add_action_or_reset(ddev, ve2_mbox_drop_action, mb);
	if (ret)
		return ERR_PTR(ret);

	return mb;
}

struct mailbox_channel *xdna_mailbox_alloc_channel(struct mailbox *mb)
{
	struct mailbox_channel *chann;

	chann = kzalloc(sizeof(*chann), GFP_KERNEL);
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
			  const struct xdna_mailbox_msg *msg, u64 tx_timeout_ms)
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
	default:
		XDNA_DBG(mb->xdna, "VE2 opcode 0x%x is not implemented", msg->opcode);
		ret = -EOPNOTSUPP;
		break;
	}
	mutex_unlock(&mb->lock);
	return ret;
}

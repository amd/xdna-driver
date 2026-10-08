// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2026, Advanced Micro Devices, Inc.
 *
 * VE2 mailbox transport.
 *
 * VE2 aie2ps has no mailbox IP. There are no management/doorbell rings and no
 * IPI channel. CERT firmware is reached through the Xilinx AIE driver
 * (aie_partition_*). This file still provides the amdxdna_mailbox.h API so the
 * shared aie4 code can send the same opcodes it sends on npu12 and npu9.
 *
 * An opcode is carried out here by calling the AIE driver and completing the
 * message the same way those parts do. An opcode this part cannot handle
 * returns -EOPNOTSUPP, the same error aie4_send_mgmt_msg_wait() returns when
 * the device role does not allow the opcode.
 *
 * Column placement for AIE4_PART_AUTO_COL is a first-fit scan. The product
 * driver uses the XRS solver for that; this slice does not.
 *
 * CERT still consumes the product host-queue ABI: one struct hsa_queue, a
 * completion u64 per slot just after it, and completion_signal aimed at that
 * slot. The shared aie4 queue is not that object. CREATE_HW_CONTEXT hands
 * CERT the product queue, and the doorbell copies each published aie4 packet
 * into it before the user-event kick.
 */

#include <drm/drm_device.h>
#include <drm/drm_managed.h>
#include <linux/bitmap.h>
#include <linux/bitops.h>
#include <linux/dma-mapping.h>
#include <linux/firmware.h>
#include <linux/idr.h>
#include <linux/ktime.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/xarray.h>

#include "aie4.h"
#include "aie4_ve2.h"
#include "aie4_host_queue.h"
#include "aie4_msg_priv.h"
#include "amdxdna_ctx.h"
#include "amdxdna_drv.h"
#include "amdxdna_mailbox.h"
#include "ve2_aie.h"

#define VE2_QUEUE_SLOTS		32
#define VE2_INDIRECT_UC		36

#define VE2_CERT_FW			"amdnpu/release_cert_ve2.elf"
#define VE2_PROG_DATA_MEMORY_OFF	0x80000
#define VE2_CERT_VERSION_OFF		0x50
#define VE2_CERT_VERSION_SIZE		0x40
#define VE2_FW_HASH_LEN			41
#define VE2_FW_DATE_LEN			11

#define VE2_COL_SHIFT			25
#define VE2_ROW_SHIFT			20
#define VE2_ADDR(col, row, off) \
	(((col) << VE2_COL_SHIFT) + ((row) << VE2_ROW_SHIFT) + (off))
#define VE2_EVENT_GENERATE_REG		0x00034008
#define VE2_USER_EVENT_ID		0xB6
#define VE2_ALIVE_MAGIC			0x404C5645

/* Matches the product host-queue ABI that AIE4_HSA_COMMAND is negotiated on. */
#define VE2_HOST_QUEUE_MAJOR		1
#define VE2_HOST_QUEUE_MINOR		0

#define VE2_MAX_COLS			256

/*
 * CERT handshake ABI. Field layout matches the product driver's struct
 * handshake so aie_partition_initialize() programs the same offsets.
 */
struct ve2_cert_handshake {
	u32 mpaie_alive;
	u32 partition_base_address;
	struct {
		u32 partition_size:7;
		u32 reserved:23;
		u32 mode:1;
		u32 uc_b:1;
	} aie_info;
	u32 hsa_addr_high;
	u32 hsa_addr_low;
	u32 ctx_switch_req;
	u32 hsa_location;
	u32 cert_idle_status;
	u32 misc_status;
	u32 log_addr_high;
	u32 log_addr_low;
	u32 log_buf_size;
	u32 host_time_high;
	u32 host_time_low;
	struct {
		u32 dtrace_addr_high;
		u32 dtrace_addr_low;
	} trace;
	union {
		struct {
			struct {
				u16 page_index:15;
				u16 cmd_chain_failure:1;
				u16 page_offset;
			} restore_page;
			struct {
				u32 id;
				u16 page_index;
				u16 page_offset:15;
				u16 core_elf_type:1;
			} pdi[2];
		} contents;
		u32 raw[5];
	} ctx_save;
	struct {
		u32 hsa_addr_high;
		u32 hsa_addr_low;
	} dbg;
	struct {
		u32 dbg_buf_addr_high;
		u32 dbg_buf_addr_low;
		u32 size;
	} dbg_buf;
	union {
		struct {
			u16 page_index;
			u16 fired_count;
		} info;
		u32 raw;
	} trace_save;
	u32 doorbell_pending;
	u32 runlist_read_idx;
	u32 completion_status;
	u32 last_preemption_id;
	u32 save_dbg_buf_offset;
	u32 npi_interrupt_status;
	struct {
		u16 pdi;
		u16 core_elf;
	} last_loaded;
	u32 reserved1[2];
	u32 last_ddr_dm2mm_addr_high;
	u32 last_ddr_dm2mm_addr_low;
	u32 last_ddr_mm2dm_addr_high;
	u32 last_ddr_mm2dm_addr_low;
	struct {
		u32 fw_state;
		u32 abs_page_index;
		u32 ppc;
	} vm;
	struct {
		u32 ear;
		u32 esr;
		u32 pc;
	} exception;
	struct {
		u32 c_job_readiness_checked;
		u32 c_opcode;
		u32 c_job_launched;
		u32 c_job_finished;
		u32 c_hsa_pkt;
		u32 c_page;
		u32 c_doorbell;
		u32 c_uc_scrub;
		u32 c_tct_requested;
		u32 c_tct_received;
		u16 c_preemption_ucdma;
		u16 c_preemption_ucdma_sync;
		u16 c_preemption_poll;
		u16 c_preemption_mask_poll;
		u16 c_preemption_remote_barrier;
		u16 c_preemption_wait_tct;
		u16 c_block_ucdma;
		u16 c_block_ucdma_sync;
		u16 c_block_local_barrier;
		u16 c_block_remote_barrier;
		u16 c_block_wait_tct;
		u16 c_actor_hash_conflict;
	} counter;
	u32 opcode_timeout_config;
	struct {
		u32 host_addr_offset_high_bits:25;
		u32 reserved:6;
		u32 valid:1;
	} host_addr_offset_high;
	u32 host_addr_offset_low;
};

/* CERT packet header. Same bytes as the product common_header. */
struct ve2_pkt_hdr {
	union {
		struct {
			u16 type:8;
			u16 barrier:1;
			u16 acquire_fence_scope:2;
			u16 release_fence_scope:2;
		};
		u16 header;
	};
	u8 opcode;
	u8 chain_flag;
	u16 count;
	u8 distribute;
	u8 indirect;
};

struct ve2_hipe {
	u32 host_addr_low;
	u32 host_addr_high:25;
	u32 uc_index:7;
};

struct ve2_indirect_hdr {
	struct ve2_pkt_hdr header;
	u32 data[VE2_INDIRECT_UC * sizeof(struct ve2_hipe)];
};

struct ve2_indirect_pkt {
	struct ve2_pkt_hdr header;
	struct exec_buf payload;
};

/*
 * Product struct hsa_queue. CERT finds direct packets at data_address and
 * indirect packets at fixed offsets from that base.
 */
struct ve2_cert_queue {
	struct host_queue_header	hq_header;
	struct host_queue_packet	hq_entry[VE2_QUEUE_SLOTS];
	struct ve2_indirect_hdr		hq_indirect_hdr[VE2_QUEUE_SLOTS];
	struct ve2_indirect_pkt		hq_indirect_pkt[VE2_INDIRECT_UC][VE2_QUEUE_SLOTS];
};

static_assert(CTX_MAX_CMDS == VE2_QUEUE_SLOTS);
static_assert(sizeof(struct ve2_hipe) == sizeof(struct host_indirect_packet_entry));

struct ve2_part {
	struct device			*aie_dev;
	u32				partition_id;
	u32				start_col;
	u32				num_col;
	u32				hw_ctx_id;
	bool				have_ctx;
	bool				inited;
	struct ve2_cert_queue		*cert_q;
	dma_addr_t			cert_dma;
	size_t				cert_bytes;
	u64				*hqc;
	dma_addr_t			hqc_dma;
	u64				cert_wi;
	struct amdxdna_hwctx		*hwctx;
	struct device			*queue_dev;
};

struct mailbox {
	struct amdxdna_dev		*xdna;
	struct mutex			lock;
	struct xarray			parts;
	struct ida			ctx_ids;
	unsigned long			col_used[BITS_TO_LONGS(VE2_MAX_COLS)];
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

static int ve2_copy_req(const struct xdna_mailbox_msg *msg, void *req, size_t len)
{
	if (!msg->send_data || msg->send_size < len)
		return -EINVAL;

	memcpy(req, msg->send_data, len);
	return 0;
}

static void ve2_user_event(u32 partition_id, void *priv)
{
	struct amdxdna_dev *xdna = priv;
	struct amdxdna_dev_hdl *ndev;
	struct ve2_part *part;
	struct cert_comp *comp;
	unsigned long idx;

	if (!xdna)
		return;

	ndev = xdna->dev_handle;
	if (!ndev || !ndev->mbox || ndev->mbox->dropped)
		return;

	/*
	 * CERT advanced its own queue. The shared waiter samples the aie4
	 * read_index, so publish CERT's value there before waking it.
	 * Do not take the mailbox lock: the kick that raised this event may
	 * already hold it.
	 */
	xa_for_each(&ndev->mbox->parts, idx, part) {
		struct amdxdna_hwctx *hwctx = READ_ONCE(part->hwctx);
		u64 ri;

		if (!part->cert_q || !hwctx || !hwctx->priv || !hwctx->priv->umq_read_index)
			continue;
		ri = READ_ONCE(part->cert_q->hq_header.read_index);
		WRITE_ONCE(*hwctx->priv->umq_read_index, ri);
	}

	xa_for_each(&ndev->cert_comp_xa, idx, comp)
		wake_up_all(&comp->waitq);
}

static void ve2_part_unmark(struct mailbox *mb, struct ve2_part *part)
{
	if (part->num_col && part->start_col < VE2_MAX_COLS)
		bitmap_clear(mb->col_used, part->start_col, part->num_col);
}

static void ve2_queue_free(struct ve2_part *part)
{
	if (!part->cert_q)
		return;

	dma_free_coherent(part->queue_dev, part->cert_bytes, part->cert_q, part->cert_dma);
	part->cert_q = NULL;
	part->hqc = NULL;
	part->queue_dev = NULL;
}

static void ve2_queue_reset(struct ve2_part *part)
{
	struct ve2_cert_queue *q = part->cert_q;
	u32 slot, uc;

	memset(q, 0, sizeof(*q));
	memset(part->hqc, 0, VE2_QUEUE_SLOTS * sizeof(u64));
	q->hq_header.data_address = part->cert_dma + sizeof(q->hq_header);
	q->hq_header.capacity = VE2_QUEUE_SLOTS;
	q->hq_header.version.major = VE2_HOST_QUEUE_MAJOR;
	q->hq_header.version.minor = VE2_HOST_QUEUE_MINOR;
	part->cert_wi = 0;

	for (slot = 0; slot < VE2_QUEUE_SLOTS; slot++) {
		struct ve2_indirect_hdr *ihdr = &q->hq_indirect_hdr[slot];

		/* INVALID until the slot is published, matching the product queue. */
		q->hq_entry[slot].pkt_header.common_header.reserved = 1;

		ihdr->header.type = 0;
		ihdr->header.opcode = OPCODE_EXEC_BUF;
		ihdr->header.distribute = 1;
		ihdr->header.indirect = 1;

		for (uc = 0; uc < VE2_INDIRECT_UC; uc++) {
			struct ve2_indirect_pkt *ipkt = &q->hq_indirect_pkt[uc][slot];

			ipkt->header.type = 0;
			ipkt->header.opcode = OPCODE_EXEC_BUF;
			ipkt->header.count = sizeof(struct exec_buf);
			ipkt->header.distribute = 1;
		}
	}
}

static int ve2_queue_alloc(struct mailbox *mb, struct ve2_part *part)
{
	size_t bytes = sizeof(struct ve2_cert_queue) + VE2_QUEUE_SLOTS * sizeof(u64);
	struct device *dev = mb->xdna->ddev.dev;
	void *cpu;
	dma_addr_t dma;

	if (part->cert_q) {
		ve2_queue_reset(part);
		return 0;
	}

	cpu = dma_alloc_coherent(dev, bytes, &dma, GFP_KERNEL);
	if (!cpu)
		return -ENOMEM;

	part->cert_q = cpu;
	part->cert_dma = dma;
	part->cert_bytes = bytes;
	part->hqc = (u64 *)((u8 *)cpu + sizeof(struct ve2_cert_queue));
	part->hqc_dma = dma + sizeof(struct ve2_cert_queue);
	part->queue_dev = dev;
	ve2_queue_reset(part);
	return 0;
}

static u64 ve2_queue_off(struct ve2_part *part, const void *ptr)
{
	return part->cert_q->hq_header.data_address +
		((u64)(uintptr_t)ptr - (u64)(uintptr_t)&part->cert_q->hq_entry);
}

static void ve2_hipe_set(struct ve2_hipe *hp, u64 addr, u32 uc)
{
	hp->host_addr_low = lower_32_bits(addr);
	hp->host_addr_high = upper_32_bits(addr);
	hp->uc_index = uc;
}

static int ve2_copy_slot(struct ve2_part *part, struct amdxdna_hwctx_priv *priv, u64 seq)
{
	u32 slot = seq & (VE2_QUEUE_SLOTS - 1);
	struct host_queue_packet *src = &priv->umq_pkts[slot];
	struct host_queue_packet *dst = &part->cert_q->hq_entry[slot];
	struct common_header *sh = &src->pkt_header.common_header;
	struct common_header *dh = &dst->pkt_header.common_header;

	memset(dst, 0, sizeof(*dst));
	dh->opcode = OPCODE_EXEC_BUF;
	dh->chain_flag = sh->chain_flag;
	dst->pkt_header.completion_signal = part->hqc_dma + slot * sizeof(u64);

	if (!sh->indirect) {
		dh->count = sizeof(struct exec_buf);
		memcpy(dst->data, src->data, sizeof(struct exec_buf));
		return 0;
	}

	{
		struct ve2_indirect_hdr *ihdr = &part->cert_q->hq_indirect_hdr[slot];
		struct host_indirect_packet_entry *sent =
			(struct host_indirect_packet_entry *)src->data;
		struct ve2_hipe *dent = (struct ve2_hipe *)ihdr->data;
		u32 nentry = sh->count / sizeof(*sent);
		u32 i;

		if (!nentry || nentry > HSA_MAX_LEVEL1_INDIRECT_ENTRIES)
			return -EINVAL;

		dh->count = sizeof(struct ve2_hipe);
		dh->distribute = 1;
		dh->indirect = 1;
		ve2_hipe_set((struct ve2_hipe *)dst->data,
			     ve2_queue_off(part, ihdr), 0);

		ihdr->header.type = 0;
		ihdr->header.opcode = OPCODE_EXEC_BUF;
		ihdr->header.count = nentry * sizeof(struct ve2_hipe);
		ihdr->header.distribute = 1;
		ihdr->header.indirect = 1;

		for (i = 0; i < nentry; i++) {
			u32 uc = FIELD_GET(HIPE_UC_INDEX_MASK,
					   sent[i].host_addr_high_uc_index);
			struct ve2_indirect_pkt *ipkt;
			u32 idx = uc * CTX_MAX_CMDS + slot;

			if (uc >= HSA_MAX_LEVEL1_INDIRECT_ENTRIES)
				return -EINVAL;

			ipkt = &part->cert_q->hq_indirect_pkt[uc][slot];
			ipkt->header.type = 0;
			ipkt->header.opcode = OPCODE_EXEC_BUF;
			ipkt->header.count = sizeof(struct exec_buf);
			ipkt->header.distribute = 1;
			ipkt->header.indirect = 0;
			ipkt->payload = priv->umq_indirect_pkts[idx].payload;
			ve2_hipe_set(&dent[i], ve2_queue_off(part, ipkt), uc);
		}
	}
	return 0;
}

static int ve2_publish_queue(struct ve2_part *part, struct amdxdna_hwctx *hwctx)
{
	struct amdxdna_hwctx_priv *priv = hwctx->priv;
	u64 wi = READ_ONCE(priv->write_index);
	int ret = 0;

	if (!part->cert_q || !priv->umq_pkts)
		return -ENODEV;

	while (part->cert_wi < wi) {
		ret = ve2_copy_slot(part, priv, part->cert_wi);
		if (ret)
			break;
		part->cert_wi++;
	}

	wmb();
	WRITE_ONCE(part->cert_q->hq_header.write_index, part->cert_wi);
	return ret;
}

static void ve2_part_free(struct mailbox *mb, struct ve2_part *part)
{
	if (!part)
		return;

	if (part->aie_dev) {
		if (part->inited)
			ve2_aie_partition_teardown(part->aie_dev);
		ve2_aie_partition_release(part->aie_dev);
	}
	ve2_part_unmark(mb, part);
	if (part->have_ctx)
		ida_free(&mb->ctx_ids, part->hw_ctx_id);
	WRITE_ONCE(part->hwctx, NULL);
	ve2_queue_free(part);
	kfree(part);
}

static void ve2_mbox_drop_parts(struct mailbox *mb)
{
	struct ve2_part *part;
	unsigned long idx;

	if (!mb || mb->dropped)
		return;

	mb->dropped = true;
	mutex_lock(&mb->lock);
	idx = 0;
	for (;;) {
		part = xa_find(&mb->parts, &idx, ULONG_MAX, XA_PRESENT);
		if (!part)
			break;
		xa_erase(&mb->parts, idx);
		ve2_part_free(mb, part);
		idx++;
	}
	mutex_unlock(&mb->lock);
	xa_destroy(&mb->parts);
	ida_destroy(&mb->ctx_ids);
	mutex_destroy(&mb->lock);
}

static void ve2_mbox_drop_action(struct drm_device *ddev, void *arg)
{
	ve2_mbox_drop_parts(arg);
}

void ve2_mbox_release(struct mailbox *mb)
{
	ve2_mbox_drop_parts(mb);
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
	 * aie4_setup_aie() can store a version; the geometry comes from
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

static bool ve2_range_free(struct mailbox *mb, u32 start, u32 count)
{
	u32 i;

	if (!count || start >= mb->dev_info.cols ||
	    count > mb->dev_info.cols - start)
		return false;

	for (i = start; i < start + count; i++) {
		if (test_bit(i, mb->col_used))
			return false;
	}
	return true;
}

static int ve2_claim_cols(struct mailbox *mb, u32 start, u32 count, u32 *out_start)
{
	u32 i, col;
	int ret;

	ret = ve2_ensure_dev_info(mb);
	if (ret)
		return ret;

	if (!count || count > 0xff)
		return -EINVAL;

	if (start == AIE4_PART_AUTO_COL) {
		for (i = 0; i + count <= mb->dev_info.cols; i += AIE4_PART_COL_ALIGN) {
			if (ve2_range_free(mb, i, count)) {
				start = i;
				goto mark;
			}
		}
		return -ENOSPC;
	}

	if (start > 0xff || !ve2_range_free(mb, start, count))
		return -EINVAL;

mark:
	for (col = start; col < start + count; col++)
		set_bit(col, mb->col_used);
	*out_start = start;
	return 0;
}

static int ve2_op_create_partition(struct mailbox *mb, const struct xdna_mailbox_msg *msg)
{
	struct aie4_msg_create_partition_resp resp = { };
	struct aie4_msg_create_partition_req req;
	struct ve2_part *part;
	u32 start_col;
	int ret;

	ret = ve2_copy_req(msg, &req, sizeof(req));
	if (ret)
		return ret;

	ret = ve2_claim_cols(mb, req.partition_col_start, req.partition_col_count,
			     &start_col);
	if (ret)
		return ret;

	part = kzalloc(sizeof(*part), GFP_KERNEL);
	if (!part) {
		bitmap_clear(mb->col_used, start_col, req.partition_col_count);
		return -ENOMEM;
	}

	part->start_col = start_col;
	part->num_col = req.partition_col_count;
	part->aie_dev = ve2_aie_partition_request(start_col, req.partition_col_count,
						  ve2_user_event, mb->xdna,
						  &part->partition_id);
	if (IS_ERR(part->aie_dev)) {
		ret = PTR_ERR(part->aie_dev);
		part->aie_dev = NULL;
		XDNA_ERR(mb->xdna, "AIE partition request %u+%u failed: %d",
			 start_col, req.partition_col_count, ret);
		goto free_part;
	}

	if (!part->partition_id) {
		XDNA_ERR(mb->xdna, "AIE partition id is 0");
		ret = -EINVAL;
		goto free_part;
	}

	ret = xa_insert(&mb->parts, part->partition_id, part, GFP_KERNEL);
	if (ret) {
		XDNA_ERR(mb->xdna, "store partition 0x%x failed: %d",
			 part->partition_id, ret);
		goto free_part;
	}

	resp.status = AIE4_MSG_STATUS_SUCCESS;
	resp.partition_id = part->partition_id;
	XDNA_DBG(mb->xdna, "partition 0x%x cols %u-%u",
		 part->partition_id, start_col, start_col + part->num_col - 1);
	return ve2_reply(msg, &resp, sizeof(resp));

free_part:
	ve2_part_free(mb, part);
	return ret;
}

static struct ve2_part *ve2_part_by_ctx(struct mailbox *mb, u32 hw_ctx_id)
{
	struct ve2_part *part;
	unsigned long idx;

	xa_for_each(&mb->parts, idx, part) {
		if (part->have_ctx && part->hw_ctx_id == hw_ctx_id)
			return part;
	}
	return NULL;
}

static int ve2_op_destroy_partition(struct mailbox *mb, const struct xdna_mailbox_msg *msg)
{
	struct aie4_msg_destroy_partition_resp resp = { };
	struct aie4_msg_destroy_partition_req req;
	struct ve2_part *part;
	int ret;

	ret = ve2_copy_req(msg, &req, sizeof(req));
	if (ret)
		return ret;

	part = xa_erase(&mb->parts, req.partition_id);
	if (!part)
		return -ENOENT;

	ve2_part_free(mb, part);
	resp.status = AIE4_MSG_STATUS_SUCCESS;
	return ve2_reply(msg, &resp, sizeof(resp));
}

static void ve2_fill_handshake(struct ve2_cert_handshake *hs, u32 num_col,
			       u32 start_col, u32 hsa_high, u32 hsa_low)
{
	u64 now = ktime_get_ns();
	u32 col;

	for (col = 0; col < num_col; col++) {
		u64 hsa = (col == 0) ? ((u64)hsa_high << 32) | hsa_low : ~0ULL;

		hs[col].mpaie_alive = VE2_ALIVE_MAGIC;
		hs[col].partition_base_address = VE2_ADDR(start_col, 0, 0);
		hs[col].aie_info.partition_size = num_col;
		hs[col].hsa_addr_high = upper_32_bits(hsa);
		hs[col].hsa_addr_low = lower_32_bits(hsa);
		hs[col].dbg.hsa_addr_high = ~0U;
		hs[col].dbg.hsa_addr_low = ~0U;
		hs[col].host_time_high = upper_32_bits(now);
		hs[col].host_time_low = lower_32_bits(now);
	}
}

static int ve2_program_handshake(struct ve2_part *part, u32 hsa_high, u32 hsa_low)
{
	struct ve2_aie_handshake *desc;
	struct ve2_cert_handshake *hs;
	u32 col, num_col = part->num_col;
	int ret;

	desc = kcalloc(num_col, sizeof(*desc), GFP_KERNEL);
	hs = kcalloc(num_col, sizeof(*hs), GFP_KERNEL);
	if (!desc || !hs) {
		ret = -ENOMEM;
		goto out;
	}

	ve2_fill_handshake(hs, num_col, part->start_col, hsa_high, hsa_low);
	for (col = 0; col < num_col; col++) {
		desc[col].addr = &hs[col];
		desc[col].size = sizeof(hs[col]);
		desc[col].col = col;
		desc[col].row = 0;
	}

	ret = ve2_aie_partition_initialize(part->aie_dev, VE2_AIE_INIT_RUNTIME,
					   desc, num_col);
	if (ret)
		goto out;

	part->inited = true;
	ve2_fill_handshake(hs, num_col, part->start_col, hsa_high, hsa_low);
	ret = ve2_aie_partition_handshake_update(part->aie_dev, desc, num_col);
	if (ret)
		goto out;

	ret = ve2_aie_partition_wake_lead_uc(part->aie_dev);
out:
	kfree(desc);
	kfree(hs);
	return ret;
}

static int ve2_op_create_context(struct mailbox *mb, const struct xdna_mailbox_msg *msg)
{
	struct aie4_msg_create_hw_context_resp resp = { };
	struct aie4_msg_create_hw_context_req req;
	struct ve2_part *part;
	int ctx_id;
	int ret;

	ret = ve2_copy_req(msg, &req, sizeof(req));
	if (ret)
		return ret;

	part = xa_load(&mb->parts, req.partition_id);
	if (!part)
		return -ENOENT;
	if (part->have_ctx)
		return -EBUSY;

	ctx_id = ida_alloc_range(&mb->ctx_ids, 1, INT_MAX, GFP_KERNEL);
	if (ctx_id < 0)
		return ctx_id;

	/*
	 * CERT reads the product host queue, not the aie4 umq named in the
	 * request. The doorbell copies published umq packets into this queue.
	 */
	ret = ve2_queue_alloc(mb, part);
	if (ret) {
		ida_free(&mb->ctx_ids, ctx_id);
		return ret;
	}

	ret = ve2_program_handshake(part, upper_32_bits(part->cert_dma),
				    lower_32_bits(part->cert_dma));
	if (ret) {
		XDNA_ERR(mb->xdna, "partition 0x%x context init failed: %d",
			 part->partition_id, ret);
		ve2_queue_free(part);
		ida_free(&mb->ctx_ids, ctx_id);
		return ret;
	}

	part->hw_ctx_id = ctx_id;
	part->have_ctx = true;

	resp.status = AIE4_MSG_STATUS_SUCCESS;
	resp.hw_context_id = ctx_id;
	resp.doorbell_offset = 0;
	resp.job_complete_msix_idx = 0;
	return ve2_reply(msg, &resp, sizeof(resp));
}

static int ve2_op_destroy_context(struct mailbox *mb, const struct xdna_mailbox_msg *msg)
{
	struct aie4_msg_destroy_hw_context_resp resp = { };
	struct aie4_msg_destroy_hw_context_req req;
	struct ve2_part *part;
	int ret;

	ret = ve2_copy_req(msg, &req, sizeof(req));
	if (ret)
		return ret;

	part = ve2_part_by_ctx(mb, req.hw_context_id);
	if (!part)
		return -ENOENT;

	ida_free(&mb->ctx_ids, part->hw_ctx_id);
	part->have_ctx = false;
	part->hw_ctx_id = 0;
	WRITE_ONCE(part->hwctx, NULL);

	/*
	 * The partition teardown belongs to DESTROY_PARTITION. A graceful
	 * destroy does not save CERT state, so report NO_RESTORE the same way
	 * firmware does when there is nothing to restore.
	 */
	if (FIELD_GET(AIE4_MSG_GRACEFUL_FLAG, req.graceful_flag))
		resp.status = AIE4_MSG_STATUS_NO_RESTORE;
	else
		resp.status = AIE4_MSG_STATUS_SUCCESS;

	return ve2_reply(msg, &resp, sizeof(resp));
}

int ve2_cert_bind(struct amdxdna_hwctx *hwctx)
{
	struct amdxdna_dev *xdna = hwctx->client->xdna;
	struct mailbox *mb = xdna->dev_handle ? xdna->dev_handle->mbox : NULL;
	struct ve2_part *part;

	if (!mb || !hwctx->priv)
		return -ENODEV;

	mutex_lock(&mb->lock);
	part = xa_load(&mb->parts, hwctx->priv->partition_id);
	if (!part || !part->cert_q) {
		mutex_unlock(&mb->lock);
		return -ENOENT;
	}
	WRITE_ONCE(part->hwctx, hwctx);
	mutex_unlock(&mb->lock);
	return 0;
}

int ve2_cert_kick(struct amdxdna_hwctx *hwctx)
{
	struct amdxdna_dev *xdna = hwctx->client->xdna;
	struct mailbox *mb = xdna->dev_handle ? xdna->dev_handle->mbox : NULL;
	u32 event = VE2_USER_EVENT_ID;
	struct ve2_part *part;
	int ret;

	if (!mb || !hwctx->priv)
		return -ENODEV;

	mutex_lock(&mb->lock);
	part = xa_load(&mb->parts, hwctx->priv->partition_id);
	if (!part || !part->aie_dev || !part->cert_q) {
		mutex_unlock(&mb->lock);
		return -ENOENT;
	}

	ret = ve2_publish_queue(part, hwctx);
	if (!ret || part->cert_wi) {
		int kick;

		kick = ve2_aie_write(part->aie_dev, 0, 0, VE2_EVENT_GENERATE_REG,
				     sizeof(event), &event);
		if (kick < 0)
			ret = kick;
	}
	mutex_unlock(&mb->lock);
	if (ret < 0)
		return ret;

	return 0;
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
	ida_init(&mb->ctx_ids);

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
	case AIE4_MSG_OP_CREATE_PARTITION:
		ret = ve2_op_create_partition(mb, msg);
		break;
	case AIE4_MSG_OP_DESTROY_PARTITION:
		ret = ve2_op_destroy_partition(mb, msg);
		break;
	case AIE4_MSG_OP_CREATE_HW_CONTEXT:
		ret = ve2_op_create_context(mb, msg);
		break;
	case AIE4_MSG_OP_DESTROY_HW_CONTEXT:
		ret = ve2_op_destroy_context(mb, msg);
		break;
	default:
		XDNA_DBG(mb->xdna, "VE2 opcode 0x%x is not implemented", msg->opcode);
		ret = -EOPNOTSUPP;
		break;
	}
	mutex_unlock(&mb->lock);
	return ret;
}

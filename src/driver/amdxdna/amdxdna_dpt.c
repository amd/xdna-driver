// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2025, Advanced Micro Devices, Inc.
 */

#include <drm/drm_cache.h>
#include <linux/interrupt.h>
#include <linux/jiffies.h>
#include <linux/moduleparam.h>
#include <linux/pci.h>
#include <linux/sizes.h>
#include <linux/slab.h>
#include <linux/timer.h>
#include <linux/version.h>
#include <linux/workqueue.h>

#include "amdxdna_dpt.h"
#include "aie2_msg_priv.h"

u8 fw_log_level = 1;
module_param(fw_log_level, byte, 0444);
MODULE_PARM_DESC(fw_log_level,
		 " Firmware log verbosity: 0: DISABLE 1: ERROR (Default) 2: WARN 3: INFO 4: DEBUG");

u64 fw_log_size = SZ_4M;
module_param(fw_log_size, ullong, 0444);
MODULE_PARM_DESC(fw_log_size, " Size of firmware log (Default 4MB). Min 8KB, Max 4MB");

bool poll_fw_log;
module_param(poll_fw_log, bool, 0444);
MODULE_PARM_DESC(poll_fw_log, " Enable firmware log polling (Default false)");

#define AMDXDNA_MGMT_APP_ID		0xFF

static bool fw_log_dump_to_dmesg;

static bool amdxdna_update_tail(struct amdxdna_dpt *dpt)
{
	struct amdxdna_dpt_footer *footer;
	u32 offset;
	u64 tail;

	offset = dpt->dma_hdl->size - AMDXDNA_DPT_FOOTER_SIZE;
	footer = dpt->dma_hdl->vaddr + offset;

	amdxdna_mgmt_buff_clflush(dpt->dma_hdl, offset, sizeof(*footer));

	/* Extend 32-bit firmware pointer to a 64-bit value */
	tail = (dpt->tail & ~GENMASK_ULL(31, 0)) | footer->tail;
	if (tail < dpt->tail)
		tail += BIT_ULL(32);

	drm_WARN_ONCE(&dpt->xdna->ddev, tail - dpt->tail > BIT_ULL(31),
		      "Unexpceted jump in tail pointer. Missed IRQ or bug");

	if (dpt->tail != tail) {
		WRITE_ONCE(dpt->tail, tail);
		wake_up(&dpt->wait);
		return true;
	}
	return false;
}

static const char * const fw_log_level_str[] = {
	"OFF",
	"ERR",
	"WRN",
	"INF",
	"DBG",
	"MAX"
};

static void amdxdna_fw_log_print(struct amdxdna_dpt *log, u8 *buffer, size_t size)
{
	u8 *end = buffer + size;

	if (!size)
		return;

	while (buffer < end) {
		struct fw_log_header {
			u64 timestamp;
			u32 format      : 1;
			u32 reserved_1  : 7;
			u32 level       : 3;
			u32 reserved_11 : 5;
			u32 appn        : 8;
			u32 argc        : 8;
			u32 line        : 16;
			u32 module      : 16;
		} *header;
		const u32 header_size = sizeof(struct fw_log_header);
		char appid[20];
		u32 msg_size;

		header = (struct fw_log_header *)buffer;

		if (header->format != FW_LOG_FORMAT_FULL || !header->argc || header->level > 4) {
			XDNA_ERR(log->xdna, "Potential buffer overflow or corruption!\n");
			buffer += AMDXDNA_DPT_FW_LOG_MSG_ALIGN;
			continue;
		}

		msg_size = (header->argc) * sizeof(u32);
		if (msg_size + header_size > size) {
			XDNA_ERR(log->xdna, "Log entry size exceeds available buffer size");
			return;
		}

		if (header->appn == AMDXDNA_MGMT_APP_ID)
			scnprintf(appid, sizeof(appid), "MGMNT");
		else
			scnprintf(appid, sizeof(appid), "APP%2d", header->appn);

		XDNA_INFO(log->xdna, "[%lld] [%s] [%s]: %s", header->timestamp,
			  fw_log_level_str[header->level], appid, (char *)(buffer + header_size));

		buffer += ALIGN(header_size + msg_size, AMDXDNA_DPT_FW_LOG_MSG_ALIGN);
	}
}

static int amdxdna_dpt_fetch_payload(struct amdxdna_dpt *dpt, u8 *buffer, size_t *size)
{
	struct amdxdna_dev *xdna = dpt->xdna;
	struct amdxdna_mgmt_dma_hdl *dma_hdl;
	size_t req_size, log_size;
	u32 start, aligned, end;
	u64 tail;

	dma_hdl = dpt->dma_hdl;
	log_size = dma_hdl->size;

	tail = READ_ONCE(dpt->tail);
	start = dpt->head % log_size;
	end = tail % log_size;

	if (start == end)
		return 0;

	if (!IS_ALIGNED(start, AMDXDNA_DPT_FW_LOG_MSG_ALIGN)) {
		XDNA_WARN(xdna, "Unaligned start offset");
		aligned = ALIGN(start, AMDXDNA_DPT_FW_LOG_MSG_ALIGN);
		start = aligned > log_size ? 0 : aligned;
	}

	req_size = (end > start) ? (end - start) : (log_size - start + end);

	if (req_size > *size) {
		XDNA_ERR(xdna, "Insufficient driver log buffer size: 0x%lx", req_size);
		return -ENOSPC;
	}

	if (start > end) {
		/* First chuck: Copy from start point until the end of log buffer */
		amdxdna_mgmt_buff_clflush(dma_hdl, start, log_size - start);
		memcpy(buffer, amdxdna_mgmt_buff_get_cpu_addr(dma_hdl, start), log_size - start);
		/* Last chuck: Wrap around and copy from the start of log buffer to end */
		amdxdna_mgmt_buff_clflush(dma_hdl, 0, end);
		memcpy(buffer + (log_size - start),
		       amdxdna_mgmt_buff_get_cpu_addr(dma_hdl, 0), end);
	} else {
		amdxdna_mgmt_buff_clflush(dma_hdl, start, end - start);
		memcpy(buffer, amdxdna_mgmt_buff_get_cpu_addr(dma_hdl, start), end - start);
	}

	*size = req_size;
	dpt->head = tail;
	return 0;
}

static void amdxdna_dpt_read_metadata(struct amdxdna_dpt *dpt)
{
	struct amdxdna_dpt_footer *footer;
	u32 offset;

	offset = dpt->dma_hdl->size - AMDXDNA_DPT_FOOTER_SIZE;
	footer = dpt->dma_hdl->vaddr + offset;

	amdxdna_mgmt_buff_clflush(dpt->dma_hdl, offset, sizeof(*footer));

	dpt->payload_version = footer->payload_version;
	dpt->minor = footer->minor;
	dpt->major = footer->major;

	XDNA_DBG(dpt->xdna, "%s: version: %d.%d",
		 dpt->name, dpt->major, dpt->minor);
	XDNA_DBG(dpt->xdna, "%s: payload version: %d",
		 dpt->name, dpt->payload_version);
}

static irqreturn_t dpt_irq_handler(int irq, void *data)
{
	struct amdxdna_dpt *dpt = (struct amdxdna_dpt *)data;

	/* Clear the interrupt */
	writel(0, dpt->io_base + dpt->msi_address);

#if KERNEL_VERSION(6, 17, 0) > LINUX_VERSION_CODE
	queue_work(system_wq, &dpt->work);
#else
	queue_work(system_percpu_wq, &dpt->work);
#endif
	return IRQ_HANDLED;
}

static int amdxdna_dpt_irq_init(struct amdxdna_dpt *dpt)
{
	struct amdxdna_dev *xdna = dpt->xdna;
	int ret;

	if (!dpt->msi_idx || !dpt->msi_address) {
		XDNA_ERR(xdna, "MSI ID or address undefined");
		return -EINVAL;
	}

	ret = pci_irq_vector(to_pci_dev(xdna->ddev.dev), dpt->msi_idx);
	if (ret < 0) {
		XDNA_ERR(xdna, "Failed to get IRQ number, %d", ret);
		return ret;
	}
	dpt->irq = ret;

	ret = request_irq(dpt->irq, dpt_irq_handler, 0, dpt->name, dpt);
	if (ret) {
		XDNA_ERR(xdna, "Failed to register irq %d ret %d", dpt->irq, ret);
		return ret;
	}

	return 0;
}

static void amdxdna_dpt_irq_fini(struct amdxdna_dpt *dpt)
{
	if (dpt->irq)
		free_irq(dpt->irq, dpt);

	dpt->msi_address = 0;
	dpt->msi_idx = 0;
}

int amdxdna_fw_log_resume(struct amdxdna_dev *xdna)
{
	int ret;

	ret = amdxdna_fw_log_init(xdna);
	if (ret) {
		XDNA_WARN(xdna, "Failed to enable firmware logging: %d", ret);
		return ret;
	}

	if (fw_log_dump_to_dmesg)
		amdxdna_dpt_dump_to_dmesg(xdna->fw_log, true);

	return 0;
}

int amdxdna_fw_log_suspend(struct amdxdna_dev *xdna)
{
	return amdxdna_fw_log_fini(xdna);
}

static void amdxdna_dpt_worker(struct work_struct *w)
{
	struct amdxdna_dpt *dpt = container_of(w, struct amdxdna_dpt, work);
	size_t size = fw_log_size;
	int ret;

	ret = amdxdna_update_tail(dpt);
	if (!ret)
		return;

	/* Skip fetch and print to dmesg if dump_fw_log is not enabled */
	if (!dpt->dump_to_dmesg)
		return;

	ret = amdxdna_dpt_fetch_payload(dpt, dpt->local_buffer, &size);
	if (ret) {
		XDNA_ERR(dpt->xdna, "Failed to fetch fw buffer: %d", ret);
		return;
	}

	amdxdna_fw_log_print(dpt, dpt->local_buffer, size);
}

static void amdxdna_dpt_timer(struct timer_list *t)
{
	struct amdxdna_dpt *dpt = container_of(t, struct amdxdna_dpt, timer);

#if KERNEL_VERSION(6, 17, 0) > LINUX_VERSION_CODE
	queue_work(system_wq, &dpt->work);
#else
	queue_work(system_percpu_wq, &dpt->work);
#endif
	mod_timer(&dpt->timer, jiffies + msecs_to_jiffies(AMDXDNA_DPT_POLL_INTERVAL_MS));
}

static void amdxdna_dpt_enable_polling(struct amdxdna_dpt *dpt, bool enable)
{
	if (dpt->polling == enable)
		return;

	if (enable) {
		timer_setup(&dpt->timer, amdxdna_dpt_timer, 0);
		mod_timer(&dpt->timer, jiffies + msecs_to_jiffies(AMDXDNA_DPT_POLL_INTERVAL_MS));
	} else {
		timer_delete_sync(&dpt->timer);
		cancel_work_sync(&dpt->work);
	}
	dpt->polling = enable;
}

int amdxdna_dpt_dump_to_dmesg(struct amdxdna_dpt *dpt, bool dump)
{
	if (dpt->dump_to_dmesg == dump)
		return 0;

	if (dump) {
		dpt->local_buffer = kzalloc(fw_log_size, GFP_KERNEL);
		if (!dpt->local_buffer) {
			XDNA_ERR(dpt->xdna, "Failed to allocate fw fetch buffer");
			return -ENOMEM;
		}
		amdxdna_dpt_enable_polling(dpt, true);
	} else {
		if (!poll_fw_log)
			amdxdna_dpt_enable_polling(dpt, false);
		kfree(dpt->local_buffer);
	}

	dpt->dump_to_dmesg = dump;
	return 0;
}

int amdxdna_fw_log_init(struct amdxdna_dev *xdna)
{
	struct amdxdna_mgmt_dma_hdl *dma_hdl;
	struct amdxdna_dpt *log_hdl;
	int ret;

	if (!xdna->dev_info->ops->fw_log_init)
		return -EOPNOTSUPP;

	if (!fw_log_level) {
		XDNA_WARN(xdna, "FW logging disabled. Default level: %d", fw_log_level);
		return 0;
	}

	if (fw_log_size < SZ_8K || fw_log_size > SZ_4M) {
		XDNA_ERR(xdna, "Invalid fw log buffer size: 0x%llx", fw_log_size);
		return -EINVAL;
	}

	log_hdl = kzalloc(sizeof(*log_hdl), GFP_KERNEL);
	if (!log_hdl)
		return -ENOMEM;

	dma_hdl = amdxdna_mgmt_buff_alloc(xdna, fw_log_size, DMA_FROM_DEVICE);
	if (IS_ERR(dma_hdl)) {
		XDNA_ERR(xdna, "Failed to allocate fw log buffer of size: 0x%llx", fw_log_size);
		ret = PTR_ERR(dma_hdl);
		goto kfree;
	}

	amdxdna_mgmt_buff_clflush(dma_hdl, 0, 0);

	strscpy(log_hdl->name, AMDXDNA_DPT_FW_LOG_NAME, sizeof(log_hdl->name));
	log_hdl->dma_hdl = dma_hdl;
	log_hdl->xdna = xdna;
	log_hdl->tail = 0;
	log_hdl->head = 0;
	init_waitqueue_head(&log_hdl->wait);
	INIT_WORK(&log_hdl->work, amdxdna_dpt_worker);
	xdna->fw_log = log_hdl;

	ret = xdna->dev_info->ops->fw_log_init(xdna, fw_log_size, fw_log_level);
	if (ret) {
		/* Sliently fail for device generation that don't support FW logging */
		if (ret != -EOPNOTSUPP)
			XDNA_ERR(xdna, "Failed to configure fw logging: %d", ret);
		else
			ret = 0;
		goto mfree;
	}

	ret = amdxdna_dpt_irq_init(log_hdl);
	if (ret)
		XDNA_ERR(xdna, "Failed to init fw logging IRQ: %d", ret);

	/* Enable polling, if IRQ initialization fails or enabled by default */
	if (ret || poll_fw_log)
		amdxdna_dpt_enable_polling(log_hdl, true);

	amdxdna_dpt_read_metadata(log_hdl);

	log_hdl->enabled = true;
	return 0;
mfree:
	amdxdna_mgmt_buff_free(dma_hdl);
kfree:
	kfree(log_hdl);
	xdna->fw_log = NULL;
	return ret;
}

int amdxdna_fw_log_fini(struct amdxdna_dev *xdna)
{
	struct amdxdna_dpt *log_hdl = xdna->fw_log;
	int ret;

	if (!log_hdl || !log_hdl->enabled)
		return 0;

	if (!xdna->dev_info->ops->fw_log_fini)
		return -EOPNOTSUPP;

	/* Retain the state of dump_to_dmesg across suspend/resume */
	fw_log_dump_to_dmesg = xdna->fw_log->dump_to_dmesg;

	ret = xdna->dev_info->ops->fw_log_fini(xdna);
	if (ret)
		XDNA_ERR(xdna, "Failed to disable fw logging: %d", ret);

	amdxdna_dpt_irq_fini(log_hdl);
	amdxdna_dpt_enable_polling(log_hdl, false);
	amdxdna_dpt_dump_to_dmesg(log_hdl, false);
	amdxdna_mgmt_buff_free(log_hdl->dma_hdl);
	kfree(log_hdl);
	xdna->fw_log = NULL;
	return 0;
}

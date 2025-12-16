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
#include <linux/string_helpers.h>
#include <linux/timer.h>
#include <linux/version.h>
#include <linux/workqueue.h>

#include "amdxdna_dpt.h"
#include "aie2_msg_priv.h"

#define AMDXDNA_DPT_FW_LOG_MAX_DEFAULT		1
#define AMDXDNA_DPT_FW_TRACE_MAX_DEFAULT	(~0)

static u8 fw_log_level = 1;
module_param(fw_log_level, byte, 0444);
MODULE_PARM_DESC(fw_log_level,
		 " Firmware log verbosity: 0: DISABLE 1: ERROR (Default) 2: WARN 3: INFO 4: DEBUG");

static u64 fw_log_size = SZ_4M;
module_param(fw_log_size, ullong, 0444);
MODULE_PARM_DESC(fw_log_size, " Size of firmware log (Default 4MB). Min 8KB, Max 4MB");

static bool poll_fw_log;
module_param(poll_fw_log, bool, 0444);
MODULE_PARM_DESC(poll_fw_log, " Enable firmware log polling (Default false)");

static u32 fw_trace_categories;
module_param(fw_trace_categories, uint, 0444);
MODULE_PARM_DESC(fw_trace_uint, " Bitmask to enable firmware trace event categories (Default 0)");

static u64 fw_trace_size = SZ_4M;
module_param(fw_trace_size, ullong, 0444);
MODULE_PARM_DESC(fw_trace_size, " Size of firmware trace (Default 4MB). Min 8KB, Max 4MB");

static bool poll_fw_trace;
module_param(poll_fw_trace, bool, 0444);
MODULE_PARM_DESC(poll_fw_trace, " Enable firmware trace polling (Default false)");

static bool fw_log_dump_to_dmesg;
static bool fw_trace_dump_to_dmesg;

static inline int amdxnda_dpt_cpy(void *to, void *from, size_t size, bool user)
{
	if (user) {
		if (copy_to_user(to, from, size))
			return -EFAULT;
	} else {
		memcpy(to, from, size);
	}
	return 0;
}

static int amdxdna_dpt_fetch_payload(struct amdxdna_dpt *dpt, u8 *buffer, u64 *offset, u32 *size,
				     bool user)
{
	struct amdxdna_dev *xdna = dpt->xdna;
	struct amdxdna_mgmt_dma_hdl *dma_hdl;
	size_t req_size, log_size;
	u32 start, end;
	u64 tail;

	dma_hdl = dpt->dma_hdl;
	log_size = dma_hdl->size - SZ_4K; /* 4K size is reserved for the footer */

	tail = READ_ONCE(dpt->tail);

	if (tail < *offset) {
		XDNA_ERR(xdna, "%s: invalid fetch offset: 0x%llx", dpt->name, *offset);
		return -EINVAL;
	}

	if (tail == *offset) {
		req_size = 0;
		goto exit;
	}

	start = *offset % log_size;
	end = tail % log_size;

	/*
	 * Start at 0 if the writer (tail) has advanced past one full buffer plus our current slot
	 * (offset % log_size), meaning our position was overwritten
	 */
	if (tail - *offset >= log_size + start)
		start = 0;

	if (end > start) {
		req_size = end - start;
		if (req_size > *size) {
			/* Return as much data as it can fit */
			XDNA_DBG(xdna, "%s: insufficient buffer size: 0x%lx", dpt->name, req_size);
			end = start + req_size;
		}
	} else {
		req_size = log_size - start + end;
		if (req_size > *size) {
			/* Return as much data as it can fit */
			XDNA_DBG(xdna, "%s: insufficient buffer size: 0x%lx", dpt->name, req_size);
			if (start + req_size <= log_size)
				end = start + req_size;
			else
				end = req_size - (log_size - start);
		}
	}

	if (start > end) {
		/* First chuck: Copy from start point until the end of log buffer */
		amdxdna_mgmt_buff_clflush(dma_hdl, start, log_size - start);
		if (amdxnda_dpt_cpy(buffer, amdxdna_mgmt_buff_get_cpu_addr(dma_hdl, start),
				    log_size - start, user))
			return -EFAULT;

		/* Last chuck: Wrap around and copy from the start of log buffer to end */
		amdxdna_mgmt_buff_clflush(dma_hdl, 0, end);
		if (amdxnda_dpt_cpy(buffer + (log_size - start),
				    amdxdna_mgmt_buff_get_cpu_addr(dma_hdl, 0), end, user))
			return -EFAULT;
	} else {
		amdxdna_mgmt_buff_clflush(dma_hdl, start, end - start);
		if (amdxnda_dpt_cpy(buffer, amdxdna_mgmt_buff_get_cpu_addr(dma_hdl, start),
				    end - start, user))
			return -EFAULT;
	}
exit:
	*size = req_size;
	*offset = tail;
	return 0;
}

static bool amdxdna_update_tail(struct amdxdna_dpt *dpt)
{
	struct amdxdna_dpt_footer *footer;
	u32 offset;
	u64 tail;

	offset = dpt->dma_hdl->size - AMDXDNA_DPT_FOOTER_SIZE;
	footer = amdxdna_mgmt_buff_get_cpu_addr(dpt->dma_hdl, offset);

	amdxdna_mgmt_buff_clflush(dpt->dma_hdl, offset, sizeof(*footer));

	/* Extend 32-bit firmware pointer to a 64-bit value */
	tail = (dpt->tail & ~GENMASK_ULL(31, 0)) | footer->tail;
	if (tail < dpt->tail)
		tail += BIT_ULL(32);

	drm_WARN_ONCE(&dpt->xdna->ddev, tail - dpt->tail > BIT_ULL(31),
		      "Unexpected jump in tail pointer. Missed IRQ or bug");

	if (dpt->tail != tail) {
		WRITE_ONCE(dpt->tail, tail);
		XDNA_DBG(dpt->xdna, "%s: Tail updated: 0x%llx", dpt->name, tail);
		wake_up(&dpt->wait);
		return true;
	}
	return false;
}

static void amdxdna_dpt_read_metadata(struct amdxdna_dpt *dpt)
{
	struct amdxdna_dpt_footer *footer;
	u32 offset;

	offset = dpt->dma_hdl->size - AMDXDNA_DPT_FOOTER_SIZE;
	footer = amdxdna_mgmt_buff_get_cpu_addr(dpt->dma_hdl, offset);

	amdxdna_mgmt_buff_clflush(dpt->dma_hdl, offset, sizeof(*footer));

	dpt->payload_version = footer->payload_version;
	dpt->minor = footer->minor;
	dpt->major = footer->major;

	XDNA_DBG(dpt->xdna, "%s: version: %d.%d", dpt->name, dpt->major, dpt->minor);
	XDNA_DBG(dpt->xdna, "%s: payload version: 0x%x", dpt->name, dpt->payload_version);
}

static irqreturn_t dpt_irq_handler(int irq, void *data)
{
	struct amdxdna_dpt *dpt = (struct amdxdna_dpt *)data;

	/* Clear the interrupt */
	writel(0, dpt->io_base + dpt->msi_address);

#ifdef HAVE_system_percpu_wq
	queue_work(system_percpu_wq, &dpt->work);
#else
	queue_work(system_wq, &dpt->work);
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

static void amdxdna_dpt_fetch_and_dump_to_dmesg(struct amdxdna_dpt *dpt)
{
	u32 size = dpt->size;
	int ret;

	ret = amdxdna_dpt_fetch_payload(dpt, dpt->local_buffer, &dpt->head, &size, false);
	if (ret) {
		XDNA_ERR(dpt->xdna, "Failed to fetch FW buffer: %d", ret);
		return;
	}

	dpt->parse(dpt->xdna, dpt->local_buffer, size);
}

static void amdxdna_dpt_drain_pending_data(struct amdxdna_dpt *dpt)
{
	if (dpt->head != dpt->tail)
		amdxdna_dpt_fetch_and_dump_to_dmesg(dpt);
}

static void amdxdna_dpt_worker(struct work_struct *w)
{
	struct amdxdna_dpt *dpt = container_of(w, struct amdxdna_dpt, work);

	if (amdxdna_update_tail(dpt)) {
		if (dpt->dump_to_dmesg && dpt->xdna->dev_info->ops->fw_log_parse)
			amdxdna_dpt_fetch_and_dump_to_dmesg(dpt);
	}
}

static void amdxdna_dpt_timer(struct timer_list *t)
{
	struct amdxdna_dpt *dpt = container_of(t, struct amdxdna_dpt, timer);

#ifdef HAVE_system_percpu_wq
	queue_work(system_percpu_wq, &dpt->work);
#else
	queue_work(system_wq, &dpt->work);
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

static int amdxdna_fw_log_init(struct amdxdna_dev *xdna, u8 log_level)
{
	struct amdxdna_mgmt_dma_hdl *dma_hdl;
	struct amdxdna_dpt *log_hdl;
	char print_size[32];
	int ret;

	if (!xdna->dev_info->ops->fw_log_init)
		return -EOPNOTSUPP;

	if (!log_level) {
		XDNA_DBG(xdna, "FW logging disabled. Default level: %d", log_level);
		return 0;
	}

	if (fw_log_size < SZ_8K || fw_log_size > SZ_4M) {
		XDNA_ERR(xdna, "Invalid FW log buffer size: 0x%llx", fw_log_size);
		return -EINVAL;
	}

	log_hdl = kzalloc(sizeof(*log_hdl), GFP_KERNEL);
	if (!log_hdl)
		return -ENOMEM;

	dma_hdl = amdxdna_mgmt_buff_alloc(xdna, fw_log_size, DMA_FROM_DEVICE);
	if (IS_ERR(dma_hdl)) {
		XDNA_ERR(xdna, "Failed to allocate FW log buffer of size: 0x%llx", fw_log_size);
		ret = PTR_ERR(dma_hdl);
		goto kfree;
	}

	string_get_size(fw_log_size, 1, STRING_UNITS_2, print_size, sizeof(print_size));
	XDNA_DBG(xdna, "Allocated %s FW log buffer at 0x%llx with DMA addr: 0x%llx", print_size,
		 (u64)amdxdna_mgmt_buff_get_cpu_addr(dma_hdl, 0),
		 amdxdna_mgmt_buff_get_dma_addr(dma_hdl));

	memset(amdxdna_mgmt_buff_get_cpu_addr(dma_hdl, 0), 0xFF, fw_log_size);
	amdxdna_mgmt_buff_clflush(dma_hdl, 0, 0);

	strscpy(log_hdl->name, AMDXDNA_DPT_FW_LOG_NAME, sizeof(log_hdl->name));
	log_hdl->parse = xdna->dev_info->ops->fw_log_parse;
	log_hdl->size = fw_log_size;
	log_hdl->dma_hdl = dma_hdl;
	log_hdl->xdna = xdna;
	log_hdl->tail = 0;
	log_hdl->head = 0;
	init_waitqueue_head(&log_hdl->wait);
	INIT_WORK(&log_hdl->work, amdxdna_dpt_worker);
	xdna->fw_log = log_hdl;

	ret = xdna->dev_info->ops->fw_log_init(xdna, fw_log_size, log_level);
	if (ret) {
		/* Silently fail for device generation that don't support FW logging */
		if (ret != -EOPNOTSUPP)
			XDNA_ERR(xdna, "Failed to configure FW logging: %d", ret);
		else
			ret = 0;
		goto mfree;
	}

	ret = amdxdna_dpt_irq_init(log_hdl);
	if (ret)
		XDNA_ERR(xdna, "Failed to init FW logging IRQ: %d", ret);

	/* Enable polling, if IRQ initialization fails or enabled by default */
	if (ret || poll_fw_log)
		amdxdna_dpt_enable_polling(log_hdl, true);

	amdxdna_dpt_read_metadata(log_hdl);

	fw_log_level = log_level;
	log_hdl->enabled = true;

	XDNA_DBG(xdna, "FW logging enabled at level: %d", log_level);
	return 0;
mfree:
	amdxdna_mgmt_buff_free(dma_hdl);
kfree:
	kfree(log_hdl);
	xdna->fw_log = NULL;
	return ret;
}

static int amdxdna_fw_log_fini(struct amdxdna_dev *xdna)
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
		XDNA_ERR(xdna, "Failed to disable FW logging: %d", ret);

	amdxdna_dpt_irq_fini(log_hdl);
	amdxdna_dpt_enable_polling(log_hdl, false);
	amdxdna_dpt_dump_to_dmesg(log_hdl, false);
	amdxdna_mgmt_buff_free(log_hdl->dma_hdl);
	kfree(log_hdl);
	xdna->fw_log = NULL;

	XDNA_DBG(xdna, "FW logging disabled");

	return 0;
}

static int amdxdna_dpt_get_data(struct amdxdna_dpt *dpt, struct amdxdna_drm_get_array *args)
{
	struct amdxdna_dpt_metadata footer = {};
	struct amdxdna_dev *xdna = dpt->xdna;
	u32 buf_size, offset;
	void __user *buf;
	int ret = 0;

	buf_size = args->num_element * args->element_size;
	buf = u64_to_user_ptr(args->buffer);
	if (!access_ok(buf, buf_size)) {
		XDNA_ERR(xdna, "Failed to access buffer, element num %d size 0x%x",
			 args->num_element, args->element_size);
		return -EFAULT;
	}

	offset = buf_size - sizeof(footer);
	if (copy_from_user(&footer, buf + offset, sizeof(footer)))
		return -EFAULT;

	XDNA_DBG(xdna, "%s requested at offset 0x%llx with watch %s", dpt->name, footer.offset,
		 footer.watch ? "on" : "off");

	if (footer.offset == READ_ONCE(dpt->tail)) {
		if (footer.watch) {
			ret = wait_event_interruptible(dpt->wait,
						       footer.offset != READ_ONCE(dpt->tail));
			if (ret) {
				XDNA_WARN(xdna, "%s wait for data interrupted by signal: %d",
					  dpt->name, ret);
				footer.size = 0;
				ret = -EINTR;
				goto exit;
			}
		} else {
			footer.size = 0;
			goto exit;
		}
	}

	ret = amdxdna_dpt_fetch_payload(dpt, buf, &footer.offset, &footer.size, true);
	if (ret) {
		XDNA_ERR(xdna, "%s failed to fetch FW buffer: %d", dpt->name, ret);
		footer.offset = 0;
		footer.size = 0;
		ret = -EINVAL;
	}

exit:
	if (copy_to_user(buf + offset, &footer, sizeof(footer)))
		return -EFAULT;

	XDNA_DBG(xdna, "%s returned with size 0x%x offset 0x%llx", dpt->name, footer.size,
		 footer.offset);
	return ret;
}

static int amdxdna_fw_trace_init(struct amdxdna_dev *xdna, u32 categories)
{
	struct amdxdna_mgmt_dma_hdl *dma_hdl;
	struct amdxdna_dpt *trace_hdl;
	char print_size[32];
	int ret;

	if (!xdna->dev_info->ops->fw_trace_init)
		return -EOPNOTSUPP;

	if (!categories) {
		XDNA_DBG(xdna, "FW tracing disabled. Default categories: %d", categories);
		return 0;
	}

	if (fw_trace_size < SZ_8K || fw_trace_size > SZ_4M) {
		XDNA_ERR(xdna, "Invalid FW trace buffer size: 0x%llx", fw_trace_size);
		return -EINVAL;
	}

	trace_hdl = kzalloc(sizeof(*trace_hdl), GFP_KERNEL);
	if (!trace_hdl)
		return -ENOMEM;

	dma_hdl = amdxdna_mgmt_buff_alloc(xdna, fw_trace_size, DMA_FROM_DEVICE);
	if (IS_ERR(dma_hdl)) {
		XDNA_ERR(xdna, "Failed to allocate FW trace buffer of size: 0x%llx", fw_trace_size);
		ret = PTR_ERR(dma_hdl);
		goto kfree;
	}

	string_get_size(fw_trace_size, 1, STRING_UNITS_2, print_size, sizeof(print_size));
	XDNA_DBG(xdna, "Allocated %s FW trace buffer at 0x%llx with DMA addr: 0x%llx", print_size,
		 (u64)amdxdna_mgmt_buff_get_cpu_addr(dma_hdl, 0),
		 amdxdna_mgmt_buff_get_dma_addr(dma_hdl));

	memset(amdxdna_mgmt_buff_get_cpu_addr(dma_hdl, 0), 0xFF, fw_trace_size);
	amdxdna_mgmt_buff_clflush(dma_hdl, 0, 0);

	strscpy(trace_hdl->name, AMDXDNA_DPT_FW_TRACE_NAME, sizeof(trace_hdl->name));
	trace_hdl->parse = xdna->dev_info->ops->fw_trace_parse;
	trace_hdl->size = fw_trace_size;
	trace_hdl->dma_hdl = dma_hdl;
	trace_hdl->xdna = xdna;
	trace_hdl->tail = 0;
	trace_hdl->head = 0;
	init_waitqueue_head(&trace_hdl->wait);
	INIT_WORK(&trace_hdl->work, amdxdna_dpt_worker);
	xdna->fw_trace = trace_hdl;

	ret = xdna->dev_info->ops->fw_trace_init(xdna, fw_trace_size, categories);
	if (ret) {
		/* Silently fail for device generation that don't support FW trace */
		if (ret != -EOPNOTSUPP)
			XDNA_ERR(xdna, "Failed to configure FW trace: %d", ret);
		else
			ret = 0;
		goto mfree;
	}

	ret = amdxdna_dpt_irq_init(trace_hdl);
	if (ret)
		XDNA_ERR(xdna, "Failed to init FW trace IRQ: %d", ret);

	/* Enable polling, if IRQ initialization fails or enabled by default */
	if (ret || poll_fw_trace)
		amdxdna_dpt_enable_polling(trace_hdl, true);

	amdxdna_dpt_read_metadata(trace_hdl);

	fw_trace_categories = categories;
	trace_hdl->enabled = true;

	XDNA_DBG(xdna, "FW tracing enabled for event categories: 0x%x", categories);
	return 0;
mfree:
	amdxdna_mgmt_buff_free(dma_hdl);
kfree:
	kfree(trace_hdl);
	xdna->fw_trace = NULL;
	return ret;
}

static int amdxdna_fw_trace_fini(struct amdxdna_dev *xdna)
{
	struct amdxdna_dpt *trace_hdl = xdna->fw_trace;
	int ret;

	if (!trace_hdl || !trace_hdl->enabled)
		return 0;

	if (!xdna->dev_info->ops->fw_trace_fini)
		return -EOPNOTSUPP;

	/* Retain the state of dump_to_dmesg across suspend/resume */
	fw_trace_dump_to_dmesg = xdna->fw_trace->dump_to_dmesg;

	ret = xdna->dev_info->ops->fw_trace_fini(xdna);
	if (ret)
		XDNA_ERR(xdna, "Failed to disable FW trace: %d", ret);

	amdxdna_dpt_irq_fini(trace_hdl);
	amdxdna_dpt_enable_polling(trace_hdl, false);
	amdxdna_dpt_dump_to_dmesg(trace_hdl, false);
	amdxdna_mgmt_buff_free(trace_hdl->dma_hdl);
	kfree(trace_hdl);
	xdna->fw_trace = NULL;

	XDNA_DBG(xdna, "FW tracing disabled");

	return 0;
}

int amdxdna_dpt_dump_to_dmesg(struct amdxdna_dpt *dpt, bool dump)
{
	if (!dpt)
		return -EINVAL;

	if (dpt->dump_to_dmesg == dump)
		return 0;

	if (dump) {
		dpt->local_buffer = kzalloc(dpt->size, GFP_KERNEL);
		if (!dpt->local_buffer) {
			XDNA_ERR(dpt->xdna, "Failed to allocate FW fetch buffer");
			return -ENOMEM;
		}
		amdxdna_dpt_enable_polling(dpt, true);
		/* Drain any data already logged in the buffer before dump_to_dmesg was enabled */
		amdxdna_dpt_drain_pending_data(dpt);
	} else {
		if (!poll_fw_log)
			amdxdna_dpt_enable_polling(dpt, false);
		kfree(dpt->local_buffer);
		dpt->head = 0;
	}

	dpt->dump_to_dmesg = dump;
	return 0;
}

int amdxdna_dpt_init(struct amdxdna_dev *xdna)
{
	int ret;

	ret = amdxdna_fw_log_init(xdna, fw_log_level);
	if (ret) {
		XDNA_WARN(xdna, "Failed to enable firmware logging: %d", ret);
		return ret;
	}

	ret = amdxdna_fw_trace_init(xdna, fw_trace_categories);
	if (ret) {
		XDNA_WARN(xdna, "Failed to enable firmware tracing: %d", ret);
		return ret;
	}

	return 0;
}

int amdxdna_dpt_fini(struct amdxdna_dev *xdna)
{
	int ret;

	ret = amdxdna_fw_log_fini(xdna);
	if (ret) {
		XDNA_ERR(xdna, "Failed to disable FW logging: %d", ret);
		return ret;
	}

	ret = amdxdna_fw_trace_fini(xdna);
	if (ret) {
		XDNA_ERR(xdna, "Failed to disable FW tracing: %d", ret);
		return ret;
	}

	return 0;
}

int amdxdna_dpt_resume(struct amdxdna_dev *xdna)
{
	int ret;

	ret = amdxdna_fw_log_init(xdna, fw_log_level);
	if (ret) {
		XDNA_WARN(xdna, "Failed to resume firmware logging: %d", ret);
		return ret;
	}

	if (fw_log_level && fw_log_dump_to_dmesg)
		amdxdna_dpt_dump_to_dmesg(xdna->fw_log, true);

	ret = amdxdna_fw_trace_init(xdna, fw_trace_categories);
	if (ret) {
		XDNA_WARN(xdna, "Failed to resume firmware tracing: %d", ret);
		return ret;
	}

	if (fw_trace_categories && fw_trace_dump_to_dmesg)
		amdxdna_dpt_dump_to_dmesg(xdna->fw_trace, true);

	return 0;
}

int amdxdna_dpt_suspend(struct amdxdna_dev *xdna)
{
	int ret;

	ret = amdxdna_fw_log_fini(xdna);
	if (ret)
		XDNA_ERR(xdna, "Failed to suspend FW logging: %d", ret);

	ret = amdxdna_fw_trace_fini(xdna);
	if (ret)
		XDNA_ERR(xdna, "Failed to suspend FW tracing: %d", ret);

	return ret;
}

int amdxdna_get_fw_log(struct amdxdna_dev *xdna, struct amdxdna_drm_get_array *args)
{
	if (!xdna->fw_log) {
		XDNA_ERR(xdna, "FW logging not enabled");
		return -EPERM;
	}

	return amdxdna_dpt_get_data(xdna->fw_log, args);
}

int amdxdna_get_fw_log_configs(struct amdxdna_dev *xdna, struct amdxdna_drm_get_array *args)
{
	struct amdxdna_drm_get_dpt_state config = {};
	void __user *buf;
	u32 buf_size;

	buf_size = args->num_element * args->element_size;
	buf = u64_to_user_ptr(args->buffer);
	if (!access_ok(buf, buf_size)) {
		XDNA_ERR(xdna, "Failed to access buffer, element num %d size 0x%x",
			 args->num_element, args->element_size);
		return -EFAULT;
	}

	if (buf_size < sizeof(config)) {
		XDNA_ERR(xdna, "Insufficient buffer size: 0x%x", buf_size);
		return -ENOSPC;
	}

	if (!xdna->fw_log)
		goto exit;

	config.version = xdna->fw_log->payload_version;
	config.status = xdna->fw_log->enabled;
	config.config = fw_log_level;
exit:
	if (copy_to_user(buf, &config, sizeof(config)))
		return -EFAULT;
	return 0;
}

int amdxdna_get_fw_trace(struct amdxdna_dev *xdna, struct amdxdna_drm_get_array *args)
{
	if (!xdna->fw_trace) {
		XDNA_ERR(xdna, "FW trace not enabled");
		return -EPERM;
	}

	return amdxdna_dpt_get_data(xdna->fw_trace, args);
}

int amdxdna_get_fw_trace_configs(struct amdxdna_dev *xdna, struct amdxdna_drm_get_array *args)
{
	struct amdxdna_drm_get_dpt_state config = {};
	void __user *buf;
	u32 buf_size;

	buf_size = args->num_element * args->element_size;
	buf = u64_to_user_ptr(args->buffer);
	if (!access_ok(buf, buf_size)) {
		XDNA_ERR(xdna, "Failed to access buffer, element num %d size 0x%x",
			 args->num_element, args->element_size);
		return -EFAULT;
	}

	if (buf_size < sizeof(config)) {
		XDNA_ERR(xdna, "Insufficient buffer size: 0x%x", buf_size);
		return -ENOSPC;
	}

	if (!xdna->fw_trace)
		goto exit;

	config.version = xdna->fw_trace->payload_version;
	config.status = xdna->fw_trace->enabled;
	config.config = fw_trace_categories;
exit:
	if (copy_to_user(buf, &config, sizeof(config)))
		return -EFAULT;
	return 0;
}

int amdxdna_set_fw_log_state(struct amdxdna_dev *xdna, struct amdxdna_drm_set_state *args)
{
	struct amdxdna_drm_set_dpt_state fw_log;
	int ret = 0;

	if (args->buffer_size != sizeof(fw_log)) {
		XDNA_ERR(xdna, "Invalid buffer size. Given: %u Need: %lu.",
			 args->buffer_size, sizeof(fw_log));
		return -EINVAL;
	}

	if (copy_from_user(&fw_log, u64_to_user_ptr(args->buffer), sizeof(fw_log)))
		return -EFAULT;

	if (!fw_log.action) {
		if (xdna->fw_log && fw_log.action != xdna->fw_log->enabled) {
			ret = amdxdna_fw_log_fini(xdna);
			if (ret)
				XDNA_ERR(xdna, "Failed to disable FW logging: %d", ret);
		}
		fw_log_level = 0;
		return ret;
	}

	/* Enable log cmd with uninitialized level; fallback to max default value */
	if (!fw_log.config)
		fw_log.config = AMDXDNA_DPT_FW_LOG_MAX_DEFAULT;

	if (!xdna->fw_log)
		return amdxdna_fw_log_init(xdna, fw_log.config);

	if (fw_log.config != fw_log_level) {
		if (!xdna->dev_info->ops->fw_log_config)
			return -EOPNOTSUPP;

		ret = xdna->dev_info->ops->fw_log_config(xdna, fw_log.config);
		if (ret) {
			XDNA_ERR(xdna, "Failed to change FW log level to %d: %d",
				 fw_log.config, ret);
			return ret;
		}
		fw_log_level = fw_log.config;
		XDNA_DBG(xdna, "FW log level changed to %d", fw_log_level);
	}

	return 0;
}

int amdxdna_set_fw_trace_state(struct amdxdna_dev *xdna, struct amdxdna_drm_set_state *args)
{
	struct amdxdna_drm_set_dpt_state fw_trace;
	int ret = 0;

	if (args->buffer_size != sizeof(fw_trace)) {
		XDNA_ERR(xdna, "Invalid buffer size. Given: %u Need: %lu.",
			 args->buffer_size, sizeof(fw_trace));
		return -EINVAL;
	}

	if (copy_from_user(&fw_trace, u64_to_user_ptr(args->buffer), sizeof(fw_trace)))
		return -EFAULT;

	if (!fw_trace.action) {
		if (xdna->fw_trace && fw_trace.action != xdna->fw_trace->enabled) {
			ret = amdxdna_fw_trace_fini(xdna);
			if (ret)
				XDNA_ERR(xdna, "Failed to disable FW traceging: %d", ret);
		}
		fw_trace_categories = 0;
		return ret;
	}

	/* Enable trace cmd with uninitialized categories; fallback to max default value */
	if (!fw_trace.config)
		fw_trace.config = AMDXDNA_DPT_FW_TRACE_MAX_DEFAULT;

	if (!xdna->fw_trace)
		return amdxdna_fw_trace_init(xdna, fw_trace.config);

	if (fw_trace.config != fw_trace_categories) {
		if (!xdna->dev_info->ops->fw_trace_config)
			return -EOPNOTSUPP;

		ret = xdna->dev_info->ops->fw_trace_config(xdna, fw_trace.config);
		if (ret) {
			XDNA_ERR(xdna, "Failed to change FW trace level to %d: %d",
				 fw_trace.config, ret);
			return ret;
		}
		fw_trace_categories = fw_trace.config;
		XDNA_DBG(xdna, "FW event trace categories 0x%x", fw_trace_categories);
	}

	return 0;
}

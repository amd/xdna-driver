// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2025, Advanced Micro Devices, Inc.
 */

#include <linux/kthread.h>
#include <linux/kernel.h>
#include <linux/dma-mapping.h>
#include <linux/timer.h>
#include <linux/jiffies.h>
#include <drm/drm_cache.h>
#include "aie2_msg_priv.h"
#include "aie2_pci.h"
#include "amdxdna_trace.h"
#include "amdxdna_mailbox.h"

struct logging_req_buf {
	struct amdxdna_dev_hdl   *ndev;
	struct workqueue_struct  *wq;
	struct work_struct       work;
	struct timer_list	 poll_timer;
	dma_addr_t               dram_buffer_address;
	u8                       *kern_log_buf;
	u8                       *buf;
	u32                      dram_buffer_size;
	u32                      msi_address;
	u32			 log_level;
	u32			 log_format;
	u32			 log_dest;
	int                      log_ch_irq;
	u64			 rb_head;
	bool                     enabled;
};

struct log_buffer_metadata {
	u32	tail_lo;
	u32	tail_hi;
	u64	head;
	u32	reserved[12];
};

struct log_msg_header {
	u32 format      : 1;
	u32 reserved_1  : 7;
	u32 level       : 3;
	u32 reserved_11	: 5;
	u32 appn        : 8;
	u32 argc        : 8;
	u32 line        : 16;
	u32 module      : 16;
};

static void clear_logging_msix(struct amdxdna_dev_hdl *ndev)
{
	u64 iohub_ptr = ndev->logging_req->msi_address;

	/* Clear the log buffer interrupt */
	writel(0, (void *)((u64)ndev->mbox_base + iohub_ptr));
}

static int aie2_is_dram_logging_supported_on_dev(struct amdxdna_dev_hdl *ndev)
{
	struct pci_dev *pdev = to_pci_dev(ndev->xdna->ddev.dev);

	XDNA_DBG(ndev->xdna, "Dev id: 0x%x, Dev rev: 0x%x\n", pdev->device, pdev->revision);
	return (pdev->device == 0x17f0 && pdev->revision >= 0x10);
}

static int aie2_validate_dram_log_config(struct amdxdna_dev_hdl *ndev, u32 enable,
					 u32 buf_size, u32 log_level)
{
	if (enable > 1) {
		XDNA_ERR(ndev->xdna, "Invalid enable value[0,1]: %u",
			 enable);
		return -EINVAL;
	}

	if (buf_size < 1024 || buf_size > 1024 * 1024 ||
	    (buf_size & (buf_size - 1)) != 0) {
		XDNA_ERR(ndev->xdna, "Invalid buffer size[1K-1M]: %u", buf_size);
		return -EINVAL;
	}

	if (log_level > 4) {
		XDNA_ERR(ndev->xdna, "Invalid log level[0-4]: %u",
			 log_level);
		return -EINVAL;
	}
	return 0;
}

static u32 aie2_get_log_content(struct logging_req_buf *req_buf)
{
	struct amdxdna_dev_hdl *ndev = req_buf->ndev;
	struct log_buffer_metadata log_metadata;
	u8 *kern_buf = req_buf->kern_log_buf;
	u8 *sys_buf = req_buf->buf;
	u32 head_wrap, tail_wrap;
	u64 head, tail;

	u32 log_rb_size = 0;
	u32 log_size = 0;

	log_rb_size = req_buf->dram_buffer_size - sizeof(log_metadata);
	WARN_ON(log_rb_size <= 0);

	drm_clflush_virt_range(sys_buf + log_rb_size, sizeof(log_metadata));
	memcpy(&log_metadata, sys_buf + log_rb_size, sizeof(log_metadata));

	head = req_buf->rb_head;
	tail = make_64bit(log_metadata.tail_lo, log_metadata.tail_hi);

	head_wrap = head % log_rb_size;
	tail_wrap = tail % log_rb_size;
	log_size = tail - head;

	if (!log_size)
		return log_size;

	req_buf->rb_head = tail;

	/* Handle buffer overflow case, dump all log w.r.t timestamp */
	if (log_size > log_rb_size) {
		XDNA_DBG(ndev->xdna, "log_size is %u, buffer overflow!", log_size);
		u32 part_log = log_rb_size - tail_wrap;

		drm_clflush_virt_range((u8 *)sys_buf + tail_wrap, part_log);
		memcpy((u8 *)kern_buf, (u8 *)sys_buf + tail_wrap, part_log);

		drm_clflush_virt_range(sys_buf, tail_wrap);
		memcpy((u8 *)(kern_buf + part_log), (u8 *)sys_buf, tail_wrap);
		return log_rb_size;
	}

	/*Buffer split into two section when tail is wrapped and copy both */
	if (tail_wrap < head_wrap) {
		u32 part_log = log_rb_size - head_wrap;

		drm_clflush_virt_range((u8 *)sys_buf + head_wrap, part_log);
		memcpy((u8 *)kern_buf, (u8 *)sys_buf + head_wrap, part_log);

		drm_clflush_virt_range(sys_buf, tail_wrap);
		memcpy((u8 *)(kern_buf + part_log), (u8 *)sys_buf, tail_wrap);
		return log_size;
	}

	/* General case when tail > head and with in log buff size */
	drm_clflush_virt_range((u8 *)sys_buf + head_wrap, log_size);
	memcpy((u8 *)kern_buf, (u8 *)sys_buf + head_wrap, log_size);
	return log_size;
}

static char *aie2_get_valid_msg_header(char *start, char *end)
{
	while (start && start < end && *start != LOG_FORMAT_FULL)
		start += sizeof(char) * LOG_MSG_ALIGN;
	return start;
}

static void aie2_print_log_buffer_data(struct amdxdna_dev_hdl *ndev)
{
	u32 header_size = sizeof(struct log_msg_header);
	struct logging_req_buf *req_buf;
	u32 log_size;

	req_buf = ndev->logging_req;
	log_size = aie2_get_log_content(req_buf);
	XDNA_DBG(ndev->xdna, "FW log size in bytes %u", log_size);

	if (!log_size)
		return;

	char *str = (char *)req_buf->kern_log_buf;
	char *end = (char *)str + log_size;

	str = aie2_get_valid_msg_header(str, end);
	while (str && str < end) {
		struct log_msg_header *header = (struct log_msg_header *)str;
		char *msg = (char *)(str + header_size);
		u32 msg_size;

		msg_size = (header->argc) * sizeof(u32);
		if (msg_size > 0 && (char *)(msg + msg_size) <= end) {
			*(char *)((char *)msg + msg_size - 1) = 0;
			pr_debug("[NPU FW]%s", msg);
		}

		/* move to next msg */
		msg_size = ((msg_size + LOG_MSG_ALIGN - 1) / LOG_MSG_ALIGN) * LOG_MSG_ALIGN;
		str += (header_size + msg_size);
		str = aie2_get_valid_msg_header(str, end);
	}
}

static void poll_timer_callback(struct timer_list *timer)
{
	struct logging_req_buf *req_buf;

	req_buf = container_of(timer, struct logging_req_buf, poll_timer);

	queue_work(req_buf->wq, &req_buf->work);
	mod_timer(&req_buf->poll_timer, jiffies + msecs_to_jiffies(POLL_INTERVAL_MS));
}

static void deferred_logging_work(struct work_struct *work)
{
	struct logging_req_buf *log_rq;

	log_rq = container_of(work, struct logging_req_buf, work);
	aie2_print_log_buffer_data(log_rq->ndev);
}

static irqreturn_t log_buffer_irq_handler(int irq, void *data)
{
	struct amdxdna_dev_hdl *ndev = (struct amdxdna_dev_hdl *)data;

	trace_mbox_irq_handle("DRAM_LOG_BUFFER", irq);
	clear_logging_msix(ndev);
	queue_work(ndev->logging_req->wq, &ndev->logging_req->work);

	return IRQ_HANDLED;
}

static void aie2_free_log_buf(struct amdxdna_dev_hdl *ndev)
{
	struct logging_req_buf *req_buf = ndev->logging_req;
	struct amdxdna_dev *xdna = ndev->xdna;

	dma_free_noncoherent(xdna->ddev.dev, req_buf->dram_buffer_size, req_buf->buf,
			     req_buf->dram_buffer_address, DMA_FROM_DEVICE);

	req_buf->buf = NULL;
	req_buf->rb_head = 0;
	req_buf->dram_buffer_address = 0;
}

int aie2_configure_log_buf_irq(struct amdxdna_dev_hdl *ndev,
			       struct config_logging_dram_buf_resp *resp)
{
	struct amdxdna_dev *xdna = ndev->xdna;
	struct logging_req_buf *req_buf;
	int ret;

	ndev->logging_req->msi_address = resp->msi_address & MSI_ADDR_MASK;
	req_buf = ndev->logging_req;

	INIT_WORK(&req_buf->work, deferred_logging_work);
	req_buf->wq = alloc_ordered_workqueue("DRAM_LOG_BUFFER", 0);
	if (!req_buf->wq) {
		XDNA_ERR(xdna, "Failed to allocate workqueue");
		ret = -ENOMEM;
		goto free_dma_log_buf;
	}

	ret = pci_irq_vector(to_pci_dev(xdna->ddev.dev), resp->msi_idx);
	if (ret < 0) {
		XDNA_ERR(xdna, "failed to alloc irq vector %d", ret);
		goto destroy_wq;
	}
	req_buf->log_ch_irq = ret;

	ret = request_irq(req_buf->log_ch_irq, log_buffer_irq_handler, 0, "DRAM_LOG_BUFFER", ndev);
	if (ret) {
		XDNA_ERR(xdna, "Failed to register irq %d ret %d", resp->msi_idx, ret);
		goto destroy_wq;
	}

	req_buf->kern_log_buf = kcalloc(req_buf->dram_buffer_size, sizeof(u8), GFP_KERNEL);
	if (!req_buf->kern_log_buf) {
		ret = -ENOMEM;
		goto free_irq;
	}

	return 0;

free_irq:
	free_irq(req_buf->log_ch_irq, ndev);
destroy_wq:
	destroy_workqueue(req_buf->wq);
free_dma_log_buf:
	(void)aie2_configure_dram_logging(ndev, req_buf->dram_buffer_address, 0);
	aie2_free_log_buf(ndev);

	return ret;
}

void aie2_remove_log_buf_irq(struct amdxdna_dev_hdl *ndev)
{
	struct logging_req_buf *req_buf = ndev->logging_req;

	cancel_work_sync(&req_buf->work);
	aie2_print_log_buffer_data(ndev);
	destroy_workqueue(req_buf->wq);

	free_irq(req_buf->log_ch_irq, ndev);
	kfree(req_buf->kern_log_buf);
}

static int aie2_alloc_log_buf(struct amdxdna_dev_hdl *ndev)
{
	struct logging_req_buf *req_buf = ndev->logging_req;
	struct amdxdna_dev *xdna = ndev->xdna;

	XDNA_DBG(ndev->xdna, "Dram logging buf size 0x%x loglevel 0x%x",
		 req_buf->dram_buffer_size, req_buf->log_level);

	req_buf->buf = dma_alloc_noncoherent(xdna->ddev.dev, req_buf->dram_buffer_size,
					     &req_buf->dram_buffer_address,
					     DMA_FROM_DEVICE, GFP_KERNEL);

	if (!req_buf->buf)
		return -ENOMEM;

	req_buf->rb_head = 0;
	drm_clflush_virt_range(req_buf->buf, req_buf->dram_buffer_size);
	XDNA_DBG(ndev->xdna, "Dram logging buf addr: 0x%llx",
		 req_buf->dram_buffer_address);

	return 0;
}

static int aie2_apply_default_runtime_cfg(struct amdxdna_dev_hdl *ndev)
{
	struct logging_req_buf *req_buf = ndev->logging_req;
	struct amdxdna_dev *xdna = ndev->xdna;
	int ret;

	ret = aie2_set_runtime_cfg(ndev, RUNTIME_CONFIGURATION_LOGGING_FORMAT,
				   req_buf->log_format);
	if (ret) {
		XDNA_ERR(xdna, "Failed to cfg log format, ret %d", ret);
		return ret;
	}

	ret = aie2_set_runtime_cfg(ndev, RUNTIME_CONFIGURATION_LOGGING_LEVEL,
				   req_buf->log_level);
	if (ret) {
		XDNA_ERR(xdna, "Failed to cfg log level, ret %d", ret);
		return ret;
	}

	ret = aie2_set_runtime_cfg(ndev, RUNTIME_CONFIGURATION_LOGGING_DESTINATION,
				   req_buf->log_dest);
	if (ret) {
		XDNA_ERR(xdna, "Failed to cfg log destination, ret %d", ret);
		return ret;
	}

	return 0;
}

static int aie2_configure_and_start_logging(struct amdxdna_dev_hdl *ndev)
{
	struct logging_req_buf *req_buf = ndev->logging_req;
	struct amdxdna_dev *xdna = ndev->xdna;
	int ret;

	ret = aie2_alloc_log_buf(ndev);
	if (ret) {
		XDNA_ERR(xdna, "Failed to allocate log buffer, ret %d", ret);
		return ret;
	}

	drm_WARN_ON(&xdna->ddev, !mutex_is_locked(&ndev->aie2_lock));
	ret = aie2_configure_dram_logging(ndev, req_buf->dram_buffer_address,
					  req_buf->dram_buffer_size);
	if (ret) {
		XDNA_ERR(xdna, "Failed to configure FW logging");
		goto free_log_buf;
	}

	ret = aie2_apply_default_runtime_cfg(ndev);
	if (ret)
		goto detach_logger;

	timer_setup(&req_buf->poll_timer, poll_timer_callback, 0);
	mod_timer(&req_buf->poll_timer, jiffies + msecs_to_jiffies(POLL_INTERVAL_MS));

	return 0;

detach_logger:
	aie2_remove_log_buf_irq(ndev);
	(void)aie2_configure_dram_logging(ndev, req_buf->dram_buffer_address, 0);
free_log_buf:
	aie2_free_log_buf(ndev);

	return ret;
}

static int aie2_stop_and_remove_logging_config(struct amdxdna_dev_hdl *ndev)
{
	struct logging_req_buf *req_buf = ndev->logging_req;
	struct amdxdna_dev *xdna = ndev->xdna;
	int ret;

	drm_WARN_ON(&xdna->ddev, !mutex_is_locked(&ndev->aie2_lock));
	ret = aie2_set_runtime_cfg(ndev, RUNTIME_CONFIGURATION_LOGGING_DESTINATION,
				   RUNTIME_CONFIGURATION_LOGGING_DEST_FIXED);
	if (ret) {
		XDNA_ERR(xdna, "Failed to remove FW logging config, ret %d", ret);
		return ret;
	}

	timer_delete_sync(&req_buf->poll_timer);
	aie2_remove_log_buf_irq(ndev);
	ret = aie2_configure_dram_logging(ndev, req_buf->dram_buffer_address, 0);
	if (ret)
		XDNA_ERR(xdna, "Failed to detach logger, ret %d", ret);
	aie2_free_log_buf(ndev);

	return ret;
}

static void aie2_update_logging_state(struct amdxdna_dev_hdl *ndev, bool state)
{
	struct logging_req_buf *req_buf = ndev->logging_req;
	int err;

	if (aie2_is_dram_logging_enable(ndev) == state) {
		XDNA_DBG(ndev->xdna, "Dram logging state is already %d", state);
		return;
	}

	if (!state) {
		err = aie2_stop_and_remove_logging_config(ndev);
		if (err)
			return;

		goto done;
	}

	err = aie2_configure_and_start_logging(ndev);
	if (err)
		return;

done:
	req_buf->enabled = state;
	XDNA_DBG(ndev->xdna, "Dram logging state: %d", state);
}

static void aie2_assign_dram_logging_state(struct amdxdna_dev_hdl *ndev, bool state)
{
	mutex_lock(&ndev->aie2_lock);
	aie2_update_logging_state(ndev, state);
	mutex_unlock(&ndev->aie2_lock);
}

bool aie2_is_dram_logging_enable(struct amdxdna_dev_hdl *ndev)
{
	if (ndev->logging_req)
		return (ndev->logging_req->enabled);
	return false;
}

void aie2_set_dram_log_config(struct amdxdna_dev_hdl *ndev, u32 enable,
			      u32 buff_size, u32 log_level)
{
	if (!aie2_is_dram_logging_supported_on_dev(ndev)) {
		XDNA_DBG(ndev->xdna, "Dram logging is not supported on this device");
		return;
	}

	XDNA_DBG(ndev->xdna, "enable %d buf size 0x%08x loglevel 0x%08x",
		 enable, buff_size, log_level);

	if (!enable) {
		aie2_assign_dram_logging_state(ndev, false);
		return;
	}

	int ret = aie2_validate_dram_log_config(ndev, enable, buff_size, log_level);

	if (ret)
		return;

	ndev->logging_req->dram_buffer_size = buff_size;
	ndev->logging_req->log_level = log_level;
	aie2_assign_dram_logging_state(ndev, true);
}

int aie2_set_log_level(struct amdxdna_dev_hdl *ndev, u32 loglevel)
{
	struct logging_req_buf *req_buf = ndev->logging_req;
	struct amdxdna_dev *xdna = ndev->xdna;
	int ret;

	if (!aie2_is_dram_logging_supported_on_dev(ndev)) {
		XDNA_DBG(ndev->xdna, "Dram logging is not supported on this device");
		return 0;
	}

	if (!aie2_is_dram_logging_enable(ndev)) {
		XDNA_DBG(ndev->xdna, "Dram logging is disabled");
		return 0;
	}

	mutex_lock(&ndev->aie2_lock);
	if (req_buf->log_level != loglevel) {
		ret = aie2_set_runtime_cfg(ndev, RUNTIME_CONFIGURATION_LOGGING_LEVEL,
					   loglevel);
		if (ret) {
			XDNA_ERR(xdna, "Failed to cfg runtime log level: %u, ret %d",
				 loglevel, ret);
			goto out;
		}

		XDNA_DBG(ndev->xdna, "Set loglevel[%u] success prev loglevel[%u]",
			 loglevel, req_buf->log_level);
		req_buf->log_level = loglevel;
	}
	mutex_unlock(&ndev->aie2_lock);

	return 0;

out:
	(void)aie2_configure_dram_logging(ndev, req_buf->dram_buffer_address, 0);
	mutex_unlock(&ndev->aie2_lock);
	aie2_free_log_buf(ndev);
	return ret;
}

u32 aie2_get_log_level(struct amdxdna_dev_hdl *ndev)
{
	return ndev->logging_req->log_level;
}

void aie2_dram_logging_suspend(struct amdxdna_dev_hdl *ndev)
{
	int ret;

	if (!aie2_is_dram_logging_supported_on_dev(ndev)) {
		XDNA_DBG(ndev->xdna, "Dram logging is not supported on this device");
		return;
	}

	mutex_lock(&ndev->aie2_lock);
	if (!aie2_is_dram_logging_enable(ndev)) {
		XDNA_DBG(ndev->xdna, "Dram logging is disabled");
		goto unlock;
	}

	XDNA_DBG(ndev->xdna, "Suspending dram logging ...");
	ret = aie2_stop_and_remove_logging_config(ndev);
	if (ret) {
		XDNA_ERR(ndev->xdna, "Dram logging suspend failed: %d", ret);
		goto unlock;
	}

unlock:
	mutex_unlock(&ndev->aie2_lock);
}

void aie2_dram_logging_resume(struct amdxdna_dev_hdl *ndev)
{
	int ret;

	if (!aie2_is_dram_logging_supported_on_dev(ndev)) {
		XDNA_DBG(ndev->xdna, "Dram logging is not supported on this device");
		return;
	}

	mutex_lock(&ndev->aie2_lock);
	if (!aie2_is_dram_logging_enable(ndev)) {
		XDNA_DBG(ndev->xdna, "Dram logging is disabled");
		goto unlock;
	}

	XDNA_DBG(ndev->xdna, "Resuming dram logging ...");
	ret = aie2_configure_and_start_logging(ndev);
	if (ret) {
		XDNA_ERR(ndev->xdna, "Dram logging resume failed: %d", ret);
		goto unlock;
	}

unlock:
	mutex_unlock(&ndev->aie2_lock);
}

int aie2_dram_logging_init(struct amdxdna_dev_hdl *ndev)
{
	struct logging_req_buf *req_buf;

	req_buf = kzalloc(sizeof(*req_buf), GFP_KERNEL);
	if (!req_buf)
		return -ENOMEM;

	req_buf->log_format = RUNTIME_CONFIGURATION_LOGGING_FORMAT_FULL;
	req_buf->log_level = RUNTIME_CONFIGURATION_LOGGING_LEVEL_INFO;
	req_buf->log_dest = RUNTIME_CONFIGURATION_LOGGING_DEST_DRAM;
	req_buf->dram_buffer_size = DEFAULT_DRAM_LOG_BUF_SIZE;
	req_buf->enabled = false;
	req_buf->ndev = ndev;
	ndev->logging_req = req_buf;

	return 0;
}

void aie2_dram_logging_fini(struct amdxdna_dev_hdl *ndev)
{
	aie2_assign_dram_logging_state(ndev, false);
	kfree(ndev->logging_req);
	ndev->logging_req = NULL;
}

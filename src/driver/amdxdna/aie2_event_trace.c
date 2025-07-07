// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2025, Advanced Micro Devices, Inc.
 */

#include <linux/kthread.h>
#include <linux/kernel.h>
#include <linux/dma-mapping.h>
#include <drm/drm_cache.h>
#include <linux/timer.h>
#include <linux/jiffies.h>
#include "aie2_msg_priv.h"
#include "aie2_pci.h"
#include "amdxdna_trace.h"
#include "amdxdna_mailbox.h"

struct event_trace_req_buf {
	struct amdxdna_dev_hdl   *ndev;
	struct workqueue_struct  *wq;
	struct work_struct       work;
	struct timer_list	 poll_timer;
	dma_addr_t               dram_buffer_address;
	u8                       *kern_log_buf;
	u8                       *buf;
	u64                      resp_timestamp;
	u64                      sys_start_time;
	u32                      dram_buffer_size;
	u32			 msi_address;
	u32			 event_trace_category;
	int                      log_ch_irq;
	u64			 rb_head;
	bool                     enabled;
};

struct trace_event_metadata {
	u64 tail_offset;
	u64 head_offset;
	u32 padding[12];
};

struct trace_event_log_data {
	u64 counter;
	u16 payload_hi;
	u16 type;
	u32 payload_low;
};

static void clear_event_trace_msix(struct amdxdna_dev_hdl *ndev)
{
	u64 iohub_ptr = ndev->event_trace_req->msi_address;

	/* Clear the log buffer interrupt */
	writel(0, (void *)((u64)ndev->mbox_base + iohub_ptr));
}

static int aie2_is_event_trace_supported_on_dev(struct amdxdna_dev_hdl *ndev)
{
	struct pci_dev *pdev = to_pci_dev(ndev->xdna->ddev.dev);

	XDNA_DBG(ndev->xdna, "Dev id: 0x%x, Dev rev: 0x%x\n", pdev->device, pdev->revision);
	return (pdev->device == 0x17f0 && pdev->revision >= 0x10);
}

static int aie2_validate_event_trace_config(struct amdxdna_dev_hdl *ndev, u32 enable,
					    u32 buf_size, u32 category)
{
	if (enable > 1) {
		XDNA_ERR(ndev->xdna, "Invalid event trace enable value[0,1]: %u",
			 enable);
		return -EINVAL;
	}

	if (buf_size < 1024 || buf_size > 1024 * 1024 ||
	    (buf_size & (buf_size - 1)) != 0) {
		XDNA_ERR(ndev->xdna, "Invalid buffer size[1K-1M]: %u", buf_size);
		return -EINVAL;
	}

	if (!category) {
		XDNA_ERR(ndev->xdna, "Invalid event category[0x01-0xFFFFFFFF]: %u",
			 category);
		return -EINVAL;
	}
	return 0;
}

static u32 aie2_get_event_trace_content(struct event_trace_req_buf *req_buf)
{
	struct amdxdna_dev_hdl *ndev = req_buf->ndev;
	struct trace_event_metadata trace_metadata;
	u8 *kern_buf = req_buf->kern_log_buf;
	u8 *sys_buf = req_buf->buf;
	u32 head_wrap, tail_wrap;
	u64 head, tail;

	u32 log_rb_size = 0;
	u32 log_size = 0;

	log_rb_size = req_buf->dram_buffer_size - sizeof(trace_metadata);
	WARN_ON(log_rb_size <= 0);

	drm_clflush_virt_range(sys_buf + log_rb_size, sizeof(trace_metadata));
	memcpy(&trace_metadata, sys_buf + log_rb_size, sizeof(trace_metadata));

	head = req_buf->rb_head;
	tail = trace_metadata.tail_offset;

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

static void aie2_print_trace_event_log(struct amdxdna_dev_hdl *ndev)
{
	struct event_trace_req_buf *req_buf;
	struct trace_event_log_data *log_content;
	u64 payload;
	u32 log_size;

	req_buf = ndev->event_trace_req;
	log_size = aie2_get_event_trace_content(req_buf);
	XDNA_DBG(ndev->xdna, "FW log size in bytes %u", log_size);

	if (!log_size)
		return;

	char *str = (char *)req_buf->kern_log_buf;
	char *end = str + log_size;
	u64 fw_ticks;

	req_buf->kern_log_buf[log_size] = 0;

	while (str < end) {
		log_content = (struct trace_event_log_data *)str;
		payload = ((u64)log_content->payload_hi << 32) | log_content->payload_low;
		fw_ticks = log_content->counter - req_buf->resp_timestamp;
		fw_ticks = fw_ticks / 24 + req_buf->sys_start_time;
		pr_debug("[NPU]::[%llu] type: 0x%04x payload:0x%016llx",
			 fw_ticks, log_content->type, payload);
		str += MAX_ONE_TIME_LOG_INFO_LEN;
	}
}

static void poll_timer_callback(struct timer_list *timer)
{
	struct event_trace_req_buf *req_buf;

	req_buf = container_of(timer, struct event_trace_req_buf, poll_timer);

	queue_work(req_buf->wq, &req_buf->work);
	mod_timer(&req_buf->poll_timer, jiffies + msecs_to_jiffies(POLL_INTERVAL_MS));
}

static void deffered_logging_work(struct work_struct *work)
{
	struct event_trace_req_buf *trace_rq;

	trace_rq = container_of(work, struct event_trace_req_buf, work);
	aie2_print_trace_event_log(trace_rq->ndev);
}

static irqreturn_t log_buffer_irq_handler(int irq, void *data)
{
	struct amdxdna_dev_hdl *ndev = (struct amdxdna_dev_hdl *)data;

	trace_mbox_irq_handle("EVENT_TRACE_BUFFER", irq);
	clear_event_trace_msix(ndev);
	queue_work(ndev->event_trace_req->wq, &ndev->event_trace_req->work);

	return IRQ_HANDLED;
}

static int aie2_register_log_buf_irq_hdl(struct amdxdna_dev_hdl *ndev, u32 msi_idx)
{
	struct amdxdna_dev *xdna = ndev->xdna;
	struct event_trace_req_buf *req_buf;
	int ret;

	req_buf = ndev->event_trace_req;
	INIT_WORK(&req_buf->work, deffered_logging_work);
	req_buf->wq = alloc_ordered_workqueue("EVENT_TRACE_BUFFER", 0);
	if (!req_buf->wq) {
		XDNA_ERR(xdna, "Failed to allocate workqueue");
		ret = -ENOMEM;
		goto free_dma_trace_buf;
	}

	ret = pci_irq_vector(to_pci_dev(xdna->ddev.dev), msi_idx);
	if (ret < 0) {
		XDNA_ERR(xdna, "failed to alloc irq vector %d", ret);
		goto destroy_wq;
	}
	req_buf->log_ch_irq = ret;

	ret = request_irq(req_buf->log_ch_irq, log_buffer_irq_handler, 0,
			  "EVENT_TRACE_BUFFER", ndev);
	if (ret) {
		XDNA_ERR(xdna, "Failed to register irq %d ret %d", msi_idx, ret);
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
free_dma_trace_buf:
	dma_free_noncoherent(xdna->ddev.dev, req_buf->dram_buffer_size, req_buf->buf,
			     req_buf->dram_buffer_address, DMA_FROM_DEVICE);
	req_buf->buf = NULL;
	req_buf->dram_buffer_address = 0;
	return ret;
}

static void aie2_deregister_log_buf_irq_hdl(struct amdxdna_dev_hdl *ndev)
{
	struct event_trace_req_buf *req_buf = ndev->event_trace_req;

	cancel_work_sync(&req_buf->work);
	aie2_print_trace_event_log(ndev);
	destroy_workqueue(req_buf->wq);

	ndev->event_trace_req->resp_timestamp = 0;
	ndev->event_trace_req->sys_start_time = 0;
	free_irq(req_buf->log_ch_irq, ndev);
	kfree(req_buf->kern_log_buf);
}

static int aie2_event_trace_alloc(struct amdxdna_dev_hdl *ndev)
{
	struct event_trace_req_buf *req_buf = ndev->event_trace_req;
	struct amdxdna_dev *xdna = ndev->xdna;

	XDNA_DBG(ndev->xdna, "Event trace buf size 0x%x category 0x%x",
		 req_buf->dram_buffer_size, req_buf->event_trace_category);

	req_buf->buf = dma_alloc_noncoherent(xdna->ddev.dev, req_buf->dram_buffer_size,
					     &req_buf->dram_buffer_address,
					     DMA_FROM_DEVICE, GFP_KERNEL);

	if (!req_buf->buf)
		return -ENOMEM;

	req_buf->rb_head = 0;
	drm_clflush_virt_range(req_buf->buf, req_buf->dram_buffer_size);
	XDNA_DBG(ndev->xdna, "Event trace buf addr: 0x%llx",
		 req_buf->dram_buffer_address);

	return 0;
}

static void aie2_event_trace_free(struct amdxdna_dev_hdl *ndev)
{
	struct event_trace_req_buf *req_buf = ndev->event_trace_req;
	struct amdxdna_dev *xdna = ndev->xdna;

	dma_free_noncoherent(xdna->ddev.dev, req_buf->dram_buffer_size, req_buf->buf,
			     req_buf->dram_buffer_address, DMA_FROM_DEVICE);

	req_buf->buf = NULL;
	req_buf->rb_head = 0;
	req_buf->dram_buffer_address = 0;
}

static int aie2_start_event_trace_send(struct amdxdna_dev_hdl *ndev)
{
	struct event_trace_req_buf *req_buf = ndev->event_trace_req;
	struct amdxdna_dev *xdna = ndev->xdna;
	int ret;

	ret = aie2_event_trace_alloc(ndev);
	if (ret) {
		XDNA_ERR(xdna, "Failed to allocate log buffer, ret %d", ret);
		return ret;
	}

	drm_WARN_ON(&xdna->ddev, !mutex_is_locked(&ndev->aie2_lock));
	ret = aie2_start_event_trace(ndev, req_buf->dram_buffer_address,
				     req_buf->dram_buffer_size,
				     req_buf->event_trace_category);
	if (ret) {
		XDNA_ERR(xdna, "Failed to start event trace, ret %d", ret);
		aie2_event_trace_free(ndev);
		return ret;
	}

	timer_setup(&req_buf->poll_timer, poll_timer_callback, 0);
	mod_timer(&req_buf->poll_timer, jiffies + msecs_to_jiffies(POLL_INTERVAL_MS));
	return 0;
}

static int aie2_stop_event_trace_send(struct amdxdna_dev_hdl *ndev)
{
	struct amdxdna_dev *xdna = ndev->xdna;
	int ret;

	drm_WARN_ON(&xdna->ddev, !mutex_is_locked(&ndev->aie2_lock));
	ret = aie2_stop_event_trace(ndev);
	if (ret) {
		XDNA_ERR(xdna, "Failed to stop event trace, ret %d", ret);
		return ret;
	}
	timer_delete_sync(&ndev->event_trace_req->poll_timer);
	aie2_event_trace_free(ndev);

	return 0;
}

static void aie2_update_event_trace_state(struct amdxdna_dev_hdl *ndev, bool state)
{
	struct event_trace_req_buf *req_buf = ndev->event_trace_req;
	int err;

	if (aie2_is_event_trace_enable(ndev) == state) {
		XDNA_DBG(ndev->xdna, "Event trace state is already %d", state);
		return;
	}

	if (!state) {
		err = aie2_stop_event_trace_send(ndev);
		if (err)
			return;

		goto done;
	}

	err = aie2_start_event_trace_send(ndev);
	if (err)
		return;

done:
	req_buf->enabled = state;
	XDNA_DBG(ndev->xdna, "Event trace state: %d", state);
}

static void aie2_assign_event_trace_state(struct amdxdna_dev_hdl *ndev, bool state)
{
	mutex_lock(&ndev->aie2_lock);
	aie2_update_event_trace_state(ndev, state);
	mutex_unlock(&ndev->aie2_lock);
}

bool aie2_is_event_trace_enable(struct amdxdna_dev_hdl *ndev)
{
	if (ndev->event_trace_req)
		return (ndev->event_trace_req->enabled);
	return false;
}

void aie2_set_trace_timestamp(struct amdxdna_dev_hdl *ndev,
			      struct start_event_trace_resp *resp)
{
	ndev->event_trace_req->resp_timestamp = resp->current_timestamp;
	ndev->event_trace_req->sys_start_time = ktime_get_ns() / 1000; /*Convert ns to us*/
	ndev->event_trace_req->msi_address = resp->msi_address & MSI_ADDR_MASK;
	aie2_register_log_buf_irq_hdl(ndev, resp->msi_idx);
}

void aie2_unset_trace_timestamp(struct amdxdna_dev_hdl *ndev)
{
	aie2_deregister_log_buf_irq_hdl(ndev);
}

void aie2_config_event_trace(struct amdxdna_dev_hdl *ndev, u32 enable,
			     u32 buff_size, u32 category)
{
	if (!aie2_is_event_trace_supported_on_dev(ndev)) {
		XDNA_DBG(ndev->xdna, "Event trace is not supported on this device");
		return;
	}

	XDNA_DBG(ndev->xdna, "enable %d buf size 0x%08x category 0x%08x",
		 enable, buff_size, category);

	if (!enable) {
		aie2_assign_event_trace_state(ndev, false);
		return;
	}

	int ret = aie2_validate_event_trace_config(ndev, enable,
						   buff_size, category);
	if (ret)
		return;

	ndev->event_trace_req->dram_buffer_size = buff_size;
	ndev->event_trace_req->event_trace_category = category;
	aie2_assign_event_trace_state(ndev, true);
}

void aie2_event_trace_suspend(struct amdxdna_dev_hdl *ndev)
{
	int ret;

	if (!aie2_is_event_trace_supported_on_dev(ndev)) {
		XDNA_DBG(ndev->xdna, "Event trace is not supported on this device");
		return;
	}

	mutex_lock(&ndev->aie2_lock);
	if (!aie2_is_event_trace_enable(ndev)) {
		XDNA_DBG(ndev->xdna, "Event tracing is disabled");
		goto unlock;
	}

	XDNA_DBG(ndev->xdna, "Suspending event trace ...");
	ret = aie2_stop_event_trace_send(ndev);
	if (ret) {
		XDNA_ERR(ndev->xdna, "Event trace suspend failed: %d", ret);
		goto unlock;
	}

unlock:
	mutex_unlock(&ndev->aie2_lock);
}

void aie2_event_trace_resume(struct amdxdna_dev_hdl *ndev)
{
	int ret;

	if (!aie2_is_event_trace_supported_on_dev(ndev)) {
		XDNA_DBG(ndev->xdna, "Event trace is not supported on this device");
		return;
	}

	mutex_lock(&ndev->aie2_lock);
	if (!aie2_is_event_trace_enable(ndev)) {
		XDNA_DBG(ndev->xdna, "Event tracing is disabled");
		goto unlock;
	}

	XDNA_DBG(ndev->xdna, "Resuming event trace ...");
	ret = aie2_start_event_trace_send(ndev);
	if (ret) {
		XDNA_ERR(ndev->xdna, "Event trace resume failed: %d", ret);
		goto unlock;
	}

unlock:
	mutex_unlock(&ndev->aie2_lock);
}

int aie2_event_trace_init(struct amdxdna_dev_hdl *ndev)
{
	struct event_trace_req_buf *req_buf;

	req_buf = kzalloc(sizeof(*req_buf), GFP_KERNEL);
	if (!req_buf)
		return -ENOMEM;

	req_buf->ndev = ndev;
	req_buf->enabled = false;
	req_buf->dram_buffer_size = DEFAULT_EVENT_BUF_SIZE;
	req_buf->event_trace_category = DEFAULT_EVENT_CATEGORY;
	ndev->event_trace_req = req_buf;

	return 0;
}

void aie2_event_trace_fini(struct amdxdna_dev_hdl *ndev)
{
	if (!ndev->event_trace_req)
		return;

	if (aie2_is_event_trace_enable(ndev))
		aie2_assign_event_trace_state(ndev, false);

	kfree(ndev->event_trace_req);
	ndev->event_trace_req = NULL;
}

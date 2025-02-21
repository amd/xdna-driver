// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2025, Advanced Micro Devices, Inc.
 */

#include <linux/kthread.h>
#include <linux/kernel.h>
#include <linux/dma-mapping.h>
#include <drm/drm_cache.h>
#include "aie2_msg_priv.h"
#include "aie2_pci.h"
#include "amdxdna_trace.h"
#include "amdxdna_mailbox.h"

struct event_trace_req_buf {
	struct amdxdna_dev_hdl   *ndev;
	struct workqueue_struct  *wq;
	struct work_struct       work;
	u8                       *kern_log_buf;
	u8                       *buf;
	u64                      dram_buffer_address;
	u64                      resp_timestamp;
	u64                      sys_start_time;
	u32                      dram_buffer_size;
	int                      log_ch_irq;
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
	/* Clear the log buffer interrupt */
	writel(0, (void *)((u64)ndev->mbox_base + (u64)LOG_BUF_MB_IOHUB_PTR));
}

static int aie2_is_event_trace_supported_on_dev(struct amdxdna_dev_hdl *ndev)
{
	struct pci_dev *pdev = to_pci_dev(ndev->xdna->ddev.dev);

	XDNA_DBG(ndev->xdna, "Dev id: 0x%x, Dev rev: 0x%x\n", pdev->device, pdev->revision);
	return (pdev->device == 0x17f0 && pdev->revision >= 0x10);
}

static u32 aie2_get_trace_event_content(struct event_trace_req_buf *trace_req_buf)
{
	struct amdxdna_dev_hdl *ndev = trace_req_buf->ndev;
	struct trace_event_metadata *trace_metadata;
	u8 *kern_buf = trace_req_buf->kern_log_buf;
	u8 *sys_buf = trace_req_buf->buf;
	u32 head_ptr, tail_ptr, tail_ptr_wrap;
	u32 log_size = 0, offset = 0;
	u32 total_log_size = 0;

	WARN_ON(LOG_RB_SIZE <= 0);
	trace_metadata = (struct trace_event_metadata *)(sys_buf + LOG_RB_SIZE);
	head_ptr = (u32)(trace_metadata->head_offset % LOG_RB_SIZE);
	tail_ptr = (u32)(trace_metadata->tail_offset);
	tail_ptr_wrap = tail_ptr % LOG_RB_SIZE;

	/* Update the Ring Buffer head pointer */
	trace_metadata->head_offset = tail_ptr;

	do {
		if (tail_ptr_wrap > head_ptr)
			log_size = tail_ptr_wrap - head_ptr;
		else if (tail_ptr_wrap < head_ptr)
			log_size = LOG_RB_SIZE - head_ptr;
		else
			return 0;

		if (log_size > LOG_RB_SIZE) {
			XDNA_ERR(ndev->xdna, "log_size > LOG_RB_SIZE");
			return 0;
		}
		/* Copy the ring buffer content to kernel buffer */
		memcpy(kern_buf + offset, (u8 *)(sys_buf + head_ptr), log_size);

		offset += log_size;
		total_log_size += log_size;
		head_ptr = (head_ptr + log_size) % LOG_RB_SIZE;
	} while (head_ptr < tail_ptr_wrap);

	return total_log_size;
}

static void aie2_print_trace_event_log(struct amdxdna_dev_hdl *ndev)
{
	struct event_trace_req_buf *trace_req_buf;
	struct trace_event_log_data *log_content;
	u64 payload;
	u32 log_size;

	trace_req_buf = ndev->event_trace_req;
	log_size = aie2_get_trace_event_content(trace_req_buf);
	XDNA_DBG(ndev->xdna, "FW log size in bytes %u", log_size);

	if (!log_size) {
		XDNA_ERR(ndev->xdna, "No log data available");
		return;
	}

	char *str = (char *)trace_req_buf->kern_log_buf;
	char *end = str + log_size;
	u64 fwTicks;

	trace_req_buf->kern_log_buf[log_size] = 0;

	while (str < end) {
		log_content = (struct trace_event_log_data *)str;
		payload = ((u64)log_content->payload_hi << 32) | log_content->payload_low;
		fwTicks = log_content->counter - trace_req_buf->resp_timestamp;
		fwTicks = fwTicks / 24 + ndev->event_trace_req->sys_start_time;
		pr_debug("[NPU]::[%llu] type: 0x%04x payload:0x%016llx",
			 fwTicks, log_content->type, payload);
		str += MAX_ONE_TIME_LOG_INFO_LEN;
	}
}

static void deffered_logging_work(struct work_struct *work)
{
	struct event_trace_req_buf *trace_rq = container_of(work, struct event_trace_req_buf, work);

	aie2_print_trace_event_log(trace_rq->ndev);
}

static irqreturn_t log_buffer_irq_handler(int irq, void *data)
{
	struct amdxdna_dev_hdl *ndev = (struct amdxdna_dev_hdl *)data;

	trace_mbox_irq_handle("LOG_BUFFER", irq);
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
	req_buf->wq = alloc_ordered_workqueue("LOG_BUFFER", 0);
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

	ret = request_irq(req_buf->log_ch_irq, log_buffer_irq_handler, 0, "LOG_BUFFER", ndev);
	if (ret) {
		XDNA_ERR(xdna, "Failed to register irq %d ret %d", msi_idx, ret);
		goto destroy_wq;
	}

	req_buf->kern_log_buf = kcalloc(TRACE_EVENT_BUF_SIZE, sizeof(u8), GFP_KERNEL);
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
			     (dma_addr_t)req_buf->dram_buffer_address, DMA_BIDIRECTIONAL);
	req_buf->buf = NULL;
	req_buf->dram_buffer_address = 0;
	req_buf->dram_buffer_size = 0;
	return ret;
}

static void aie2_deregister_log_buf_irq_hdl(struct amdxdna_dev_hdl *ndev)
{
	struct event_trace_req_buf *req_buf = ndev->event_trace_req;

	cancel_work_sync(&req_buf->work);
	/* print already accumulated FW logs */
	aie2_print_trace_event_log(ndev);
	destroy_workqueue(req_buf->wq);

	free_irq(req_buf->log_ch_irq, ndev);
	kfree(req_buf->kern_log_buf);
}

static int aie2_event_trace_alloc(struct amdxdna_dev_hdl *ndev)
{
	struct event_trace_req_buf *req_buf = ndev->event_trace_req;
	struct amdxdna_dev *xdna = ndev->xdna;

	req_buf->buf = dma_alloc_noncoherent(xdna->ddev.dev, TRACE_EVENT_BUF_SIZE,
					     (dma_addr_t *)&req_buf->dram_buffer_address,
					     DMA_BIDIRECTIONAL, GFP_KERNEL);

	if (!req_buf->buf)
		return -ENOMEM;

	req_buf->dram_buffer_size = TRACE_EVENT_BUF_SIZE;
	XDNA_DBG(ndev->xdna, "Start event trace buf addr: 0x%llx size 0x%x",
		 req_buf->dram_buffer_address, req_buf->dram_buffer_size);

	return 0;
}

static void aie2_event_trace_free(struct amdxdna_dev_hdl *ndev)
{
	struct event_trace_req_buf *req_buf = ndev->event_trace_req;
	struct amdxdna_dev *xdna = ndev->xdna;

	dma_free_noncoherent(xdna->ddev.dev, req_buf->dram_buffer_size, req_buf->buf,
			     (dma_addr_t)req_buf->dram_buffer_address, DMA_BIDIRECTIONAL);

	req_buf->buf = NULL;
	req_buf->dram_buffer_address = 0;
	req_buf->dram_buffer_size = 0;
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

	drm_WARN_ON(&xdna->ddev, !mutex_is_locked(&xdna->dev_lock));
	ret = aie2_start_event_trace(ndev, req_buf->dram_buffer_address,
				     req_buf->dram_buffer_size);
	if (ret) {
		XDNA_ERR(xdna, "Failed to start event trace, ret %d", ret);
		aie2_event_trace_free(ndev);
		return ret;
	}

	return 0;
}

static int aie2_stop_event_trace_send(struct amdxdna_dev_hdl *ndev)
{
	struct amdxdna_dev *xdna = ndev->xdna;
	int ret;

	if (!ndev->event_trace_req) {
		XDNA_DBG(xdna, "Event tracing is not started");
		return 0;
	}

	drm_WARN_ON(&xdna->ddev, !mutex_is_locked(&xdna->dev_lock));
	ret = aie2_stop_event_trace(ndev);
	if (ret) {
		XDNA_ERR(xdna, "Failed to stop event trace, ret %d", ret);
		return ret;
	}
	aie2_event_trace_free(ndev);

	return 0;
}

bool aie2_is_event_trace_enable(struct amdxdna_dev_hdl *ndev)
{
	if (ndev->event_trace_req)
		return (ndev->event_trace_req->enabled);
	return false;
}

void aie2_set_trace_timestamp(struct amdxdna_dev_hdl *ndev,  struct start_event_trace_resp *resp)
{
	ndev->event_trace_req->resp_timestamp = resp->current_timestamp;
	ndev->event_trace_req->sys_start_time = ktime_get_ns() / 1000; /*Convert ns to us*/
	aie2_register_log_buf_irq_hdl(ndev, resp->msi_idx);
}

void aie2_unset_trace_timestamp(struct amdxdna_dev_hdl *ndev)
{
	ndev->event_trace_req->resp_timestamp = 0;
	ndev->event_trace_req->sys_start_time = 0;
	aie2_deregister_log_buf_irq_hdl(ndev);
}

void aie2_assign_event_trace_state(struct amdxdna_dev_hdl *ndev, bool state)
{
	int err;

	if (!aie2_is_event_trace_supported_on_dev(ndev)) {
		XDNA_ERR(ndev->xdna, "Event trace is not supported on this device");
		return;
	}

	if (!ndev->event_trace_req) {
		XDNA_DBG(ndev->xdna, "Event trace req buffer is not allocated!");
		return;
	}

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
	ndev->event_trace_req->enabled = state;
	XDNA_DBG(ndev->xdna, "Event trace state: %d", state);
}

int aie2_event_trace_init(struct amdxdna_dev_hdl *ndev)
{
	struct event_trace_req_buf *req_buf;

	req_buf = kzalloc(sizeof(*req_buf), GFP_KERNEL);
	if (!req_buf)
		return -ENOMEM;

	req_buf->ndev = ndev;
	req_buf->enabled = false;
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

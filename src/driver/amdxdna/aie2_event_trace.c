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

struct trace_event_metadata {
	uint64_t tail_offset;
	uint64_t head_offset;
	uint32_t padding[12];
};

struct trace_event_log_data {
	uint64_t counter;
	uint16_t payload_hi;
	uint16_t type;
	uint32_t payload_low;
};

static void clear_event_trace_msix(struct amdxdna_dev_hdl *ndev)
{
	/* Clear the log buffer interrupt */
	writel(0, (void *)((u64)ndev->mbox_base + (u64)LOG_BUF_MB_IOHUB_PTR));
}

int aie2_is_event_trace_supported_on_dev(struct amdxdna_dev_hdl *ndev)
{
	struct pci_dev *pdev = to_pci_dev(ndev->xdna->ddev.dev);

	if (!pdev) {
		XDNA_ERR(ndev->xdna, "pdev is null");
		return 0;
	}

	XDNA_DBG(ndev->xdna, "Dev id: 0x%x, Dev rev: 0x%x\n", pdev->device, pdev->revision);
	return (pdev->device == 0x17f0 && pdev->revision >= 0x10);
}

static uint32_t aie2_get_trace_event_content(struct event_trace_req_buf *trace_req_buf, uint8_t *kern_buf)
{
	u8 *sysBuf;
	uint32_t rd_ptr, wr_ptr, wr_ptr_wrap;
	uint32_t total_log_size = 0, log_size = 0;
	uint32_t rb_size, offset = 0;
	struct trace_event_metadata *trace_metadata;
	struct amdxdna_dev_hdl *ndev = trace_req_buf->ndev;

	sysBuf = (u8 *)trace_req_buf->buf;
	rb_size = TRACE_EVENT_BUFFER_SIZE - TRACE_EVENT_BUFFER_METADATA_SIZE;
	if (rb_size == 0)
		return 0;

	trace_metadata = (struct trace_event_metadata *)(sysBuf + rb_size);
	if (!trace_metadata) {
		XDNA_ERR(ndev->xdna, "FW trace buffer metadata is null!");
		return 0;
	}

	/* Get the ring buffer read and write pointers, update the ring buffer content size */
	rd_ptr = (uint32_t)(trace_metadata->head_offset % rb_size);
	wr_ptr = (uint32_t)(trace_metadata->tail_offset);
	wr_ptr_wrap = wr_ptr % rb_size;

	/* Update the Ring Buffer read pointer */
	trace_metadata->head_offset = wr_ptr;

	do {
		if (wr_ptr_wrap > rd_ptr)
			log_size = wr_ptr_wrap - rd_ptr;
		else if (wr_ptr_wrap < rd_ptr)
			log_size = rb_size - rd_ptr;
		else
			return 0;

		if (log_size > rb_size) {
			XDNA_ERR(ndev->xdna, "log_size > rb_size");
			return 0;
		}
		/* Copy the ring buffer content to the kernel buffer */
		memcpy(kern_buf + offset, (u8 *)(sysBuf + rd_ptr), log_size);

		offset += log_size;
		total_log_size += log_size;
		rd_ptr = (rd_ptr + log_size) % rb_size;
	} while (rd_ptr < wr_ptr_wrap);

	return total_log_size;
}

static void aie2_print_trace_event_log(struct amdxdna_dev_hdl *ndev)
{
	uint32_t log_size;
	uint64_t payload;
	struct event_trace_req_buf *trace_req_buf;
	struct trace_event_log_data *log_content;

	trace_req_buf = ndev->event_trace_req;

	if (!trace_req_buf) {
		XDNA_ERR(ndev->xdna, "FW resp trace buffer is null!");
		return;
	}

	if (!ndev->fw_log_buf) {
		XDNA_ERR(ndev->xdna, "Kernel log buffer is null!");
		return;
	}

	log_size = aie2_get_trace_event_content(trace_req_buf, ndev->fw_log_buf);
	XDNA_DBG(ndev->xdna, "FW log size in bytes %u", log_size);

	if (log_size) {
		uint64_t fwTicks;
		char *str = (char *)ndev->fw_log_buf;
		char *end = ((char *)str + log_size);

		ndev->fw_log_buf[log_size] = 0;

		while (str < end) {
			log_content = (struct trace_event_log_data *)str;
			payload = (uint64_t)((uint64_t)(log_content->payload_hi) << 32 | log_content->payload_low);
			fwTicks = log_content->counter - trace_req_buf->resp_timestamp;
			fwTicks = fwTicks/24 + ndev->event_trace_req->sys_start_time;
			XDNA_INFO(ndev->xdna, "[%llu][FW] type: 0x%04x payload:0x%016llx", fwTicks, log_content->type, payload);
			str += MAX_ONE_TIME_LOG_INFO_LEN;
		}
	}
}

static irqreturn_t log_buffer_irq_handler(int irq, void *data)
{
	struct amdxdna_dev_hdl *ndev = (struct amdxdna_dev_hdl *)data;

	if (!ndev) {
		XDNA_INFO(ndev->xdna, "xdna dev is null !");
		return IRQ_NONE;
	}

	trace_mbox_irq_handle("LOG_BUFFER", irq);
	clear_event_trace_msix(ndev);

	if (ndev->event_trace_enabled)
		aie2_print_trace_event_log(ndev);
	return IRQ_HANDLED;
}

static int aie2_register_log_buf_irq_hdl(struct amdxdna_dev_hdl *ndev, uint32_t msi_idx)
{
	int ret;
	struct amdxdna_dev *xdna = ndev->xdna;
	struct event_trace_req_buf *req_buf;

	if (!ndev->event_trace_req) {
		XDNA_ERR(xdna, "Event trace req is null");
		return -EINVAL;
	}

	req_buf = ndev->event_trace_req;
	req_buf->log_ch_irq = pci_irq_vector(to_pci_dev(xdna->ddev.dev), msi_idx);
	ret = request_irq(req_buf->log_ch_irq, log_buffer_irq_handler, 0, "LOG_BUFFER", ndev);
	if (ret) {
		XDNA_ERR(xdna, "Failed to register irq %d ret %d", msi_idx, ret);
		goto free_dma_trace_buf;
	}

	ndev->fw_log_buf = kzalloc((sizeof(uint8_t)*TRACE_EVENT_BUFFER_SIZE), GFP_KERNEL);
	if (!ndev->fw_log_buf) {
		XDNA_ERR(xdna, "Failed to allocate kernel log buffer");
		ret = -ENOMEM;
		goto free_dma_trace_buf;
	}
	return 0;

free_dma_trace_buf:
	dma_free_noncoherent(xdna->ddev.dev, req_buf->trace_req.dram_buffer_size, req_buf->buf,
					(dma_addr_t)req_buf->trace_req.dram_buffer_address, DMA_BIDIRECTIONAL);
	kfree(req_buf);
	ndev->event_trace_req = NULL;
	ndev->fw_log_buf = NULL;
	return ret;
}

void aie2_set_trace_timestamp(struct amdxdna_dev_hdl *ndev, uint32_t *resp)
{
	struct start_event_trace_resp *trace_resp = (struct start_event_trace_resp *)resp;

	ndev->event_trace_req->resp_timestamp = trace_resp->current_timestamp;
	ndev->event_trace_req->sys_start_time = ktime_get_ns()/1000; /*Convert ns to us*/
	aie2_register_log_buf_irq_hdl(ndev, trace_resp->msi_idx);
}

int aie2_stop_event_trace_send(struct amdxdna_dev_hdl *ndev)
{
	struct amdxdna_dev *xdna = ndev->xdna;

	if (!ndev->event_trace_req) {
		XDNA_DBG(xdna, "Event tracing is not started");
		return 0;
	}

	drm_WARN_ON(&xdna->ddev, !mutex_is_locked(&xdna->dev_lock));
	return aie2_stop_event_trace(ndev);
}

static int aie2_event_trace_alloc(struct amdxdna_dev_hdl *ndev)
{
	int ret;
	struct amdxdna_dev *xdna = ndev->xdna;
	struct event_trace_req_buf *req_buf;

	req_buf = kzalloc(sizeof(struct event_trace_req_buf), GFP_KERNEL);
	if (!req_buf)
		return -ENOMEM;

	req_buf->buf = dma_alloc_noncoherent(xdna->ddev.dev, TRACE_EVENT_BUFFER_SIZE,
	(dma_addr_t *)&req_buf->trace_req.dram_buffer_address, DMA_BIDIRECTIONAL, GFP_KERNEL);

	if (!req_buf->buf) {
		ret = -ENOMEM;
		goto free_event_trace_req_buf;
	}
	req_buf->trace_req.dram_buffer_size = TRACE_EVENT_BUFFER_SIZE;
	ndev->event_trace_req = req_buf;
	req_buf->ndev = ndev;

	XDNA_DBG(xdna, "Start event trace buf addr: 0x%llx size 0x%x", req_buf->trace_req.dram_buffer_address,
		req_buf->trace_req.dram_buffer_size);
	return 0;

free_event_trace_req_buf:
	ndev->event_trace_req = NULL;
	kfree(req_buf);
	return ret;
}

void aie2_event_trace_free(struct amdxdna_dev_hdl *ndev)
{
	struct amdxdna_dev *xdna = ndev->xdna;
	struct event_trace_req_buf *req_buf = ndev->event_trace_req;

	if (!req_buf)
		return;

	dma_free_noncoherent(xdna->ddev.dev, req_buf->trace_req.dram_buffer_size, req_buf->buf,
					(dma_addr_t)req_buf->trace_req.dram_buffer_address, DMA_BIDIRECTIONAL);
	ndev->event_trace_req = NULL;
	free_irq(req_buf->log_ch_irq, ndev);
	kfree(req_buf);
	kfree(ndev->fw_log_buf);
	ndev->fw_log_buf = NULL;
}

static int aie2_start_event_trace_send(struct amdxdna_dev_hdl *ndev)
{
	int ret;
	struct event_trace_req_buf *trace_req_buf = NULL;
	struct amdxdna_dev *xdna = ndev->xdna;

	ret = aie2_event_trace_alloc(ndev);

	if (!ret) {
		trace_req_buf = ndev->event_trace_req;
		drm_WARN_ON(&xdna->ddev, !mutex_is_locked(&xdna->dev_lock));
		ret = aie2_start_event_trace(ndev, trace_req_buf->trace_req.dram_buffer_address,
				trace_req_buf->trace_req.dram_buffer_size);
	} else {
		XDNA_ERR(xdna, "Failed to allocate and register event trace");
	}

	return ret;
}

void aie2_assign_event_trace_state(struct amdxdna_dev_hdl *ndev, bool state)
{
	if (!ndev) {
		XDNA_ERR(ndev->xdna, "xdna dev is null !");
		return;
	}

	if (!aie2_is_event_trace_supported_on_dev(ndev)) {
		XDNA_ERR(ndev->xdna, "Event trace is not supported on this device");
		return;
	}

	if (ndev->event_trace_enabled == state) {
		XDNA_DBG(ndev->xdna, "Event trace state is already %d", state);
		return;
	}

	if (state) {
		int ret = aie2_start_event_trace_send(ndev);

		if (ret) {
			XDNA_ERR(ndev->xdna, "Send start event trace failed, ret %d", ret);
			/*
			 * Currently this feature is supported on limited HW's,
			 * driver loading should not fail if FW logging not supported.
			 */
			aie2_event_trace_free(ndev);
		} else {
			ndev->event_trace_enabled = state;
			XDNA_DBG(ndev->xdna, "Event trace state: %d", state);
		}
	} else {
		if (ndev->dev_status >= AIE2_DEV_START) {
			aie2_stop_event_trace_send(ndev);
			aie2_event_trace_free(ndev);
		} else {
			XDNA_DBG(ndev->xdna, "Event trace is not started");
		}
		ndev->event_trace_enabled = state;
	}
	clear_event_trace_msix(ndev);
}

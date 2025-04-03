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

struct logging_req_buf {
	struct amdxdna_dev_hdl   *ndev;
	struct workqueue_struct  *wq;
	struct work_struct       work;
	u8                       *kern_log_buf;
	u8                       *buf;
	u64                      dram_buffer_address;
	u32                      dram_buffer_size;
	u32                      msi_address;
	int                      log_ch_irq;
	bool                     enabled;
};

struct log_buffer_metadata {
	u32	tail_offset_lo;
	u32	tail_offset_hi;
	u32	head_offset_lo;
	u32	head_offset_hi;
	u8	reserved[48];
};

static void clear_logging_msix(struct amdxdna_dev_hdl *ndev)
{
	u64 iohub_ptr = ndev->logging_req->msi_address;

	/* Clear the log buffer interrupt */
	writel(0, (void *)((u64)ndev->mbox_base + iohub_ptr));
}

static int aie2_is_logging_supported_on_dev(struct amdxdna_dev_hdl *ndev)
{
	struct pci_dev *pdev = to_pci_dev(ndev->xdna->ddev.dev);

	XDNA_DBG(ndev->xdna, "Dev id: 0x%x, Dev rev: 0x%x\n", pdev->device, pdev->revision);
	return (pdev->device == 0x17f0 && pdev->revision >= 0x10);
}

static u32 aie2_get_log_content(struct logging_req_buf *log_req_buf)
{
	struct amdxdna_dev_hdl *ndev = log_req_buf->ndev;
	struct log_buffer_metadata *log_metadata;
	u8 *kern_buf = log_req_buf->kern_log_buf;
	u8 *sys_buf = log_req_buf->buf;
	u32 head_ptr, tail_ptr, tail_ptr_wrap;
	u32 log_size = 0, offset = 0;
	u32 total_log_size = 0;

	WARN_ON(LOG_RB_SIZE <= 0);
	log_metadata = (struct log_buffer_metadata *)(sys_buf + LOG_RB_SIZE);
	head_ptr = (u32)(log_metadata->head_offset % LOG_RB_SIZE);
	tail_ptr = (u32)(log_metadata->tail_offset);
	tail_ptr_wrap = tail_ptr % LOG_RB_SIZE;

	/* Update the Ring Buffer head pointer */
	log_metadata->head_offset = tail_ptr;

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

static void aie2_print_log_buffer_data(struct amdxdna_dev_hdl *ndev)
{
	struct logging_req_buf *log_req_buf;
	struct log_data *log_content;
	u64 payload;
	u32 log_size;

	log_req_buf = ndev->logging_req;
	log_size = aie2_get_log_content(log_req_buf);
	XDNA_DBG(ndev->xdna, "FW log size in bytes %u", log_size);

	if (!log_size) {
		XDNA_ERR(ndev->xdna, "No log data available");
		return;
	}

	char *str = (char *)log_req_buf->kern_log_buf;
	char *end = str + log_size;
	u64 fwTicks;

	log_req_buf->kern_log_buf[log_size] = 0;

	while (str < end) {
		log_content = (struct log_data *)str;
		payload = ((u64)log_content->payload_hi << 32) | log_content->payload_low;
		fwTicks = log_content->counter - log_req_buf->resp_timestamp;
		fwTicks = fwTicks / 24 + ndev->logging_req->sys_start_time;
		pr_debug("[NPU]::[%llu] type: 0x%04x payload:0x%016llx",
			 fwTicks, log_content->type, payload);
		str += MAX_ONE_TIME_LOG_INFO_LEN;
	}
}

static void deffered_logging_work(struct work_struct *work)
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

int aie2_register_log_buf_irq_hdl(struct amdxdna_dev_hdl *ndev, u32 msi_idx)
{
	struct amdxdna_dev *xdna = ndev->xdna;
	struct logging_req_buf *req_buf;
	int ret;

	ndev->logging_req->msi_address = resp->msi_address & MSI_ADDR_MASK;
	req_buf = ndev->logging_req;

	INIT_WORK(&req_buf->work, deffered_logging_work);
	req_buf->wq = alloc_ordered_workqueue("DRAM_LOG_BUFFER", 0);
	if (!req_buf->wq) {
		XDNA_ERR(xdna, "Failed to allocate workqueue");
		ret = -ENOMEM;
		goto free_dma_log_buf;
	}

	ret = pci_irq_vector(to_pci_dev(xdna->ddev.dev), msi_idx);
	if (ret < 0) {
		XDNA_ERR(xdna, "failed to alloc irq vector %d", ret);
		goto destroy_wq;
	}
	req_buf->log_ch_irq = ret;

	ret = request_irq(req_buf->log_ch_irq, log_buffer_irq_handler, 0, "DRAM_LOG_BUFFER", ndev);
	if (ret) {
		XDNA_ERR(xdna, "Failed to register irq %d ret %d", msi_idx, ret);
		goto destroy_wq;
	}

	req_buf->kern_log_buf = kcalloc(DRAM_LOG_BUF_SIZE, sizeof(u8), GFP_KERNEL);
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
	dma_free_noncoherent(xdna->ddev.dev, req_buf->dram_buffer_size, req_buf->buf,
			     (dma_addr_t)req_buf->dram_buffer_address, DMA_BIDIRECTIONAL);
	req_buf->buf = NULL;
	req_buf->dram_buffer_address = 0;
	req_buf->dram_buffer_size = 0;
	return ret;
}

void aie2_deregister_log_buf_irq_hdl(struct amdxdna_dev_hdl *ndev)
{
	struct logging_req_buf *req_buf = ndev->logging_req;

	cancel_work_sync(&req_buf->work);
	/* print already accumulated FW logs */
	aie2_print_log_buffer_data(ndev);
	destroy_workqueue(req_buf->wq);

	free_irq(req_buf->log_ch_irq, ndev);
	kfree(req_buf->kern_log_buf);
}

static int aie2_alloc_log_buf(struct amdxdna_dev_hdl *ndev)
{
	struct logging_req_buf *req_buf = ndev->logging_req;
	struct amdxdna_dev *xdna = ndev->xdna;

	req_buf->buf = dma_alloc_noncoherent(xdna->ddev.dev, DRAM_LOG_BUF_SIZE,
					     (dma_addr_t *)&req_buf->dram_buffer_address,
					     DMA_BIDIRECTIONAL, GFP_KERNEL);

	if (!req_buf->buf)
		return -ENOMEM;

	req_buf->dram_buffer_size = DRAM_LOG_BUF_SIZE;
	XDNA_DBG(ndev->xdna, "Start log buf addr: 0x%llx size 0x%x",
		 req_buf->dram_buffer_address, req_buf->dram_buffer_size);

	return 0;
}

static void aie2_free_log_buf(struct amdxdna_dev_hdl *ndev)
{
	struct logging_req_buf *req_buf = ndev->logging_req;
	struct amdxdna_dev *xdna = ndev->xdna;

	dma_free_noncoherent(xdna->ddev.dev, req_buf->dram_buffer_size, req_buf->buf,
			     (dma_addr_t)req_buf->dram_buffer_address, DMA_BIDIRECTIONAL);

	req_buf->buf = NULL;
	req_buf->dram_buffer_address = 0;
	req_buf->dram_buffer_size = 0;
}

static int aie2_configure_logging(struct amdxdna_dev_hdl *ndev)
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
		XDNA_ERR(xdna, "Failed to configure FW logging, ret %d", ret);
		aie2_free_log_buf(ndev);
		return ret;
	}

	return 0;
}

static int aie2_update_runtime_logging_config(struct amdxdna_dev_hdl *ndev, u32 config)
{
	struct amdxdna_dev *xdna = ndev->xdna;
	int ret;

	if (!ndev->logging_req) {
		XDNA_DBG(xdna, "FW logging is not started");
		return 0;
	}

	drm_WARN_ON(&xdna->ddev, !mutex_is_locked(&ndev->aie2_lock));
	ret = aie2_set_runtime_logging_config(ndev, config);
	if (ret) {
		XDNA_ERR(xdna, "Failed to update FW logging config, ret %d", ret);
		return ret;
	}
	aie2_free_log_buf(ndev);

	return 0;
}

static void aie2_update_logging_state(struct amdxdna_dev_hdl *ndev, bool state)
{
	int err;

	if (!aie2_is_logging_supported_on_dev(ndev)) {
		XDNA_DBG(ndev->xdna, "FW logging is not supported on this device");
		return;
	}

	if (!ndev->logging_req) {
		XDNA_DBG(ndev->xdna, "FW logging req buffer is not allocated!");
		return;
	}

	if (aie2_is_logging_enable(ndev) == state) {
		XDNA_DBG(ndev->xdna, "FW logging state is already %d", state);
		return;
	}

	err = aie2_update_runtime_logging_config(ndev);
	if (err)
		return;

	ndev->logging_req->enabled = state;
	XDNA_DBG(ndev->xdna, "FW logging state: %d", state);
}

bool aie2_is_logging_enable(struct amdxdna_dev_hdl *ndev)
{
	if (ndev->logging_req)
		return (ndev->logging_req->enabled);
	return false;
}

void aie2_assign_logging_state(struct amdxdna_dev_hdl *ndev, bool state)
{
	mutex_lock(&ndev->aie2_lock);
	aie2_update_logging_state(ndev, state);
	mutex_unlock(&ndev->aie2_lock);
}

int aie2_logging_init(struct amdxdna_dev_hdl *ndev)
{
	struct logging_req_buf *req_buf;

	req_buf = kzalloc(sizeof(*req_buf), GFP_KERNEL);
	if (!req_buf)
		return -ENOMEM;

	req_buf->ndev = ndev;
	req_buf->enabled = false;
	ndev->logging_req = req_buf;

	return 0;
}

void aie2_logging_fini(struct amdxdna_dev_hdl *ndev)
{
	if (!ndev->logging_req)
		return;

	if (aie2_is_logging_enable(ndev))
		aie2_assign_logging_state(ndev, false);

	kfree(ndev->logging_req);
	ndev->logging_req = NULL;
}

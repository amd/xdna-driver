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

struct event_trace_req_buf {
	struct amdxdna_dev_hdl		*ndev;
	struct start_event_trace_req trace_req;
	u8				*buf;
};

int aie2_start_event_trace_send(struct amdxdna_dev_hdl *ndev)
{
	struct amdxdna_dev *xdna = ndev->xdna;
	struct event_trace_req_buf *trace_req_buf;
	int ret;

	trace_req_buf = ndev->event_trace_req;
	printk(KERN_ERR "vs- aie2_start_event_trace_send\n");
	drm_WARN_ON(&xdna->ddev, !mutex_is_locked(&xdna->dev_lock));
	/* Send only two log buffers first , 1. for logging 2. ping-pong*/
	drm_clflush_virt_range(trace_req_buf->buf, trace_req_buf->trace_req.dram_buffer_size); /* device can access */
	ret = aie2_start_event_trace_msg(ndev, trace_req_buf->trace_req.dram_buffer_address,
							trace_req_buf->trace_req.dram_buffer_size, &trace_req_buf->trace_req);
	return ret;
}

void aie2_event_trace_free(struct amdxdna_dev_hdl *ndev)
{
	struct amdxdna_dev *xdna = ndev->xdna;
	struct event_trace_req_buf *req_buf;

	req_buf = ndev->event_trace_req;

	printk(KERN_ERR "vs- aie2_event_trace_free\n");
	dma_free_noncoherent(xdna->ddev.dev, req_buf->trace_req.dram_buffer_size, req_buf->buf,
			 (dma_addr_t)req_buf->trace_req.dram_buffer_address, DMA_BIDIRECTIONAL);
	
	kfree(req_buf);
}

int aie2_event_trace_alloc(struct amdxdna_dev_hdl *ndev)
{
	int ret;
	struct amdxdna_dev *xdna = ndev->xdna;
	struct event_trace_req_buf *req_buf;

	printk(KERN_ERR "vs- aie2_event_trace_alloc\n");
	req_buf = kzalloc(sizeof(struct event_trace_req_buf), GFP_KERNEL);
	if (!req_buf)
		return -ENOMEM;

	req_buf->buf = dma_alloc_noncoherent(xdna->ddev.dev, TRACE_EVENT_BUFFER_SIZE,
						(dma_addr_t*)&req_buf->trace_req.dram_buffer_address, DMA_BIDIRECTIONAL, GFP_KERNEL);
	
	if (!req_buf->buf) {
		ret = -ENOMEM;
		goto free_event_trace_req_buf;
	}
	req_buf->trace_req.dram_buffer_size = TRACE_EVENT_BUFFER_SIZE;
	ndev->event_trace_req = req_buf;

	XDNA_INFO(xdna, "vs- trace event buf size %d, dram_buffer_address 0x%llx",
		 req_buf->trace_req.dram_buffer_size, req_buf->trace_req.dram_buffer_address);
	return 0;

free_event_trace_req_buf:
	kfree(req_buf);
	return ret;
}

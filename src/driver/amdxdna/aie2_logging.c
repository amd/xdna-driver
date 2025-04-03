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
	u64	tail_offset;
	u64	head_offset;
	u32	reserved[12];
};

struct log_msg_header {
	u32 format      : 1; ///< ipu_log_format_e value
	u32 reserved_1  : 7; ///< reserved: set to 0x60 for backward compatibility
	u32 level       : 3; ///< ipu_log_level_e value
	u32 reserved_11 : 5; ///< reserved: set to zero
	u32 appn        : 8; ///< application number
	u32 argc        : 8;
	u32 line        : 16; ///< line of file (0 for unknown)
	u32 module      : 16; ///< file ID (0 for unknown)
};

/*struct fw_log {
	struct log_msg_header *header;
	u8 *msg;
};*/

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

static u32 aie2_get_log_content(struct logging_req_buf *req_buf)
{
	u32 head_ptr, tail_ptr, head_ptr_wrap, tail_ptr_wrap;
	struct amdxdna_dev_hdl *ndev = req_buf->ndev;
	struct log_buffer_metadata *log_metadata;
	u8 *kern_buf = req_buf->kern_log_buf;
	u8 *sys_buf = req_buf->buf;
        u32 log_size = 0;

	WARN_ON(LOG_RB_SIZE <= 0);
	log_metadata = (struct log_buffer_metadata *)(sys_buf + LOG_RB_SIZE);
	head_ptr = (u32)(log_metadata->head_offset);
	tail_ptr = (u32)(log_metadata->tail_offset);
	head_ptr_wrap = head_ptr % LOG_RB_SIZE;
	tail_ptr_wrap = tail_ptr % LOG_RB_SIZE;
	log_size = tail_ptr - head_ptr;

	XDNA_INFO(ndev->xdna, "log_size %u head_ptr 0x%u tail_ptr 0x%u head_wp 0x%u tail_wp 0x%u",
		  log_size, head_ptr, tail_ptr, head_ptr_wrap, tail_ptr_wrap);

	if (!log_size)
		return log_size;

	/*print_hex_dump_debug("Log data: ", DUMP_PREFIX_ADDRESS, 8, 1, sys_buf,
			     log_size, true);*/

	log_metadata->head_offset = tail_ptr;
        dma_sync_single_for_device(ndev->xdna->ddev.dev, req_buf->dram_buffer_address,
                                req_buf->dram_buffer_size, DMA_TO_DEVICE);

	/* Handle buffer overflow case, dump all log w.r.t timestamp */
        if (log_size > LOG_RB_SIZE) {
                XDNA_ERR(ndev->xdna, "log_size is %u, buffer overflow!", log_size);
                u32 part_log = LOG_RB_SIZE - tail_ptr_wrap;

                memcpy((u8 *)kern_buf, (u8 *)(sys_buf + tail_ptr_wrap), part_log);
                memcpy((u8 *)(kern_buf + part_log), (u8 *)sys_buf, tail_ptr_wrap);
                return LOG_RB_SIZE;
        }

        /*Buffer split into two section when tail is wrapped and copy both */
        if (tail_ptr_wrap < head_ptr_wrap) {
		XDNA_ERR(ndev->xdna, "Under buffer split");
                u32 part_log = LOG_RB_SIZE - head_ptr_wrap;

                memcpy((u8 *)kern_buf, (u8 *)(sys_buf + head_ptr_wrap), part_log);
                memcpy((u8 *)(kern_buf + part_log), (u8 *)sys_buf, tail_ptr_wrap);
                return log_size;
        }
        /* General case when tail > head and with in log buff size */
        memcpy((u8 *)kern_buf, (u8 *)(sys_buf + head_ptr_wrap), log_size);
        return log_size;
}

static void aie2_print_log_buffer_data(struct amdxdna_dev_hdl *ndev)
{
	u32 header_size = sizeof(struct log_msg_header);
	struct logging_req_buf *req_buf;
	u32 log_size;

	req_buf = ndev->logging_req;
	dma_sync_single_for_cpu(ndev->xdna->ddev.dev, req_buf->dram_buffer_address,
				req_buf->dram_buffer_size, DMA_FROM_DEVICE);

	log_size = aie2_get_log_content(req_buf);
	//XDNA_INFO(ndev->xdna, "FW log size in bytes %u", log_size);

	if (!log_size) {
		XDNA_ERR(ndev->xdna, "No log data available");
		return;
	}

	char *str = (char *)req_buf->kern_log_buf;
	char *end = (char *)str + log_size;

	/*print_hex_dump_debug("kern_buff: ", DUMP_PREFIX_ADDRESS, 8, 1, (u8 *)str,
                              log_size+8, true);*/

	while (str && *str != 0xc0 && str < end)
		str += sizeof(char)*8;

	while (str && str < end) {
		struct log_msg_header *header = (struct log_msg_header *)str;
		char *msg = (char *)(str+header_size);
		u32 msg_size;

		if (!header) {
			XDNA_ERR(ndev->xdna, "vs- header is null !");
			return;
		}

		if (!msg) {
			XDNA_ERR(ndev->xdna, "vs- msg is null, not aligned to 8 bit? ");
			return;
		}

		msg_size = (header->argc)*4;
		msg_size = ((msg_size/ 8) + (msg_size % 8 ? 1 : 0)) * 8 + header_size;
		str += msg_size;
		XDNA_INFO(ndev->xdna, "[NPU FW]:%s", msg);

	        while (str && *str != 0xc0 && str < end) {
			str += sizeof(char)*8;
			XDNA_ERR(ndev->xdna, "vs- str is null after msg!");
		}
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

int aie2_configure_log_buf_irq(struct amdxdna_dev_hdl *ndev,
			       struct config_logging_dram_buf_resp *resp)
{
	struct amdxdna_dev *xdna = ndev->xdna;
	struct logging_req_buf *req_buf;
	int ret;

	ndev->logging_req->msi_address = resp->msi_address & MSI_ADDR_MASK;
	req_buf = ndev->logging_req;

	XDNA_INFO(xdna, "FW resp msi_idx: %u msi_addr: 0x%x", resp->msi_idx, resp->msi_address);
	INIT_WORK(&req_buf->work, deffered_logging_work);
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

	req_buf->kern_log_buf = kcalloc(DRAM_LOG_BUF_SIZE, sizeof(u8), GFP_KERNEL);
	if (!req_buf->kern_log_buf) {
		ret = -ENOMEM;
		goto free_irq;
	}
	XDNA_ERR(xdna, "Configure log_buf_irq success");
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

void aie2_remove_log_buf_irq(struct amdxdna_dev_hdl *ndev)
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
	XDNA_INFO(ndev->xdna, "Dram log buf addr: 0x%llx size 0x%x",
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
		XDNA_ERR(xdna, "Failed to configure FW logging, ret %d", ret);
		aie2_free_log_buf(ndev);
		return ret;
	}

	ret = aie2_set_runtime_cfg(ndev, RUNTIME_CONFIGURATION_LOGGING_FORMAT,
				   RUNTIME_CONFIGURATION_LOGGING_FORMAT_FULL);

	if (ret) {
		XDNA_ERR(xdna, "Failed to set runtime log format, ret %d", ret);
		return ret;
	}
	XDNA_INFO(xdna, "Set runtime log format, ret %d", ret);

	ret = aie2_set_runtime_cfg(ndev, RUNTIME_CONFIGURATION_LOGGING_LEVEL,
				   RUNTIME_CONFIGURATION_LOGGING_LEVEL_INFO);

	if (ret) {
		XDNA_ERR(xdna, "Failed to set runtime log level, ret %d", ret);
		return ret;
	}
	XDNA_INFO(xdna, "Set runtime log level, ret %d", ret);

	ret = aie2_set_runtime_cfg(ndev, RUNTIME_CONFIGURATION_LOGGING_DESTINATION,
				   RUNTIME_CONFIGURATION_LOGGING_DEST_DRAM);

	if (ret) {
		XDNA_ERR(xdna, "Failed to set runtime log destination, ret %d", ret);
		aie2_free_log_buf(ndev);
		return ret;
	}

	XDNA_INFO(xdna, "Configure logging destination success!");
	return 0;
}

static int aie2_stop_and_remove_logging_config(struct amdxdna_dev_hdl *ndev)
{
	struct amdxdna_dev *xdna = ndev->xdna;
	int ret;

	if (!ndev->logging_req) {
		XDNA_DBG(xdna, "FW logging is not started");
		return 0;
	}

	drm_WARN_ON(&xdna->ddev, !mutex_is_locked(&ndev->aie2_lock));
	ret = aie2_set_runtime_cfg(ndev, RUNTIME_CONFIGURATION_LOGGING_DESTINATION,
				   RUNTIME_CONFIGURATION_LOGGING_DEST_FIXED);
	if (ret) {
		XDNA_ERR(xdna, "Failed to remove FW logging config, ret %d", ret);
		return ret;
	}
	XDNA_INFO(xdna, "Set runtime cfg logging dest fixed success!");

	aie2_remove_log_buf_irq(ndev);
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

	if (aie2_is_dram_logging_enable(ndev) == state) {
		XDNA_DBG(ndev->xdna, "FW logging state is already %d", state);
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
	ndev->logging_req->enabled = state;
	XDNA_INFO(ndev->xdna, "FW logging state: %d", state);
}

bool aie2_is_dram_logging_enable(struct amdxdna_dev_hdl *ndev)
{
	if (ndev->logging_req)
		return (ndev->logging_req->enabled);
	return false;
}

void aie2_assign_dram_logging_state(struct amdxdna_dev_hdl *ndev, bool state)
{
	mutex_lock(&ndev->aie2_lock);
	aie2_update_logging_state(ndev, state);
	mutex_unlock(&ndev->aie2_lock);
}

int aie2_dram_logging_init(struct amdxdna_dev_hdl *ndev)
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

void aie2_dram_logging_fini(struct amdxdna_dev_hdl *ndev)
{
	if (!ndev->logging_req)
		return;

	if (aie2_is_dram_logging_enable(ndev))
		aie2_assign_dram_logging_state(ndev, false);

	kfree(ndev->logging_req);
	ndev->logging_req = NULL;
}

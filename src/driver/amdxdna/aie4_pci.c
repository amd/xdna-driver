// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2024-2026, Advanced Micro Devices, Inc.
 */

#include <linux/version.h>
#include <linux/errno.h>
#include <linux/kthread.h>
#include <linux/iommu.h>
#include <linux/firmware.h>
#include <linux/string_helpers.h>
#include <linux/uaccess.h>
#include <drm/drm_cache.h>
#include "drm_local/amdxdna_accel.h"

#include "aie4_pci.h"
#include "aie4_message.h"
#include "aie4_solver.h"
#include "aie4_devel.h"
#include "amdxdna_dpt.h"
#include "amdxdna_pm.h"
#include "amdxdna_trace.h"
#include "amdxdna_mgmt.h"
#ifdef AMDXDNA_DEVEL
#include "amdxdna_devel.h"
#endif

#include "aie4_msg_priv.h"

#define AIE4_MAX_COL 128
uint aie4_max_col = AIE4_MAX_COL;
module_param(aie4_max_col, uint, 0600);
MODULE_PARM_DESC(aie4_max_col, "Maximum column could be used");

int enable_aie4_polling;
module_param(enable_aie4_polling, int, 0644);
MODULE_PARM_DESC(enable_aie4_polling, "Enable aie4 polling mode");

static int skip_fw_load;
module_param(skip_fw_load, int, 0644);
MODULE_PARM_DESC(skip_fw_load, "Skip fw load via psp");

static int fw_reload;
module_param(fw_reload, int, 0644);
MODULE_PARM_DESC(fw_reload, "enforce fw reload during flr");

static int skip_work_buffer;
module_param(skip_work_buffer, int, 0644);
MODULE_PARM_DESC(skip_work_buffer, "Skip MPNPU work buffer attach");

/*
 * This struct is the register layout.
 */
struct mailbox_info {
	u32 valid;
	u32 protocol_major;
	u32 protocol_minor;
	u32 x2i_tail_offset;
	u32 x2i_head_offset;
	u32 x2i_buffer_addr;
	u32 x2i_buffer_size;
	u32 i2x_tail_offset;
	u32 i2x_head_offset;
	u32 i2x_buffer_addr;
	u32 i2x_buffer_size;
	u32 i2x_msi_idx;
	u32 reserved[4];
};

static inline void aie4_dump_mbox_info(struct amdxdna_dev *xdna, struct mailbox_info *m)
{
	XDNA_DBG(xdna, "MAILBOX_VALID: 0x%x", m->valid);
	XDNA_DBG(xdna, "MAILBOX_MAJOR 0x%x", m->protocol_major);
	XDNA_DBG(xdna, "MAILBOX_MINOR: 0x%x", m->protocol_minor);
	XDNA_DBG(xdna, "MAILBOX_X2I_TAIL_OFF: 0x%x", m->x2i_tail_offset);
	XDNA_DBG(xdna, "MAILBOX_X2I_HEAD_OFF: 0x%x", m->x2i_head_offset);
	XDNA_DBG(xdna, "MAILBOX_X2I_BUF_ADDR: 0x%x", m->x2i_buffer_addr);
	XDNA_DBG(xdna, "MAILBOX_X2I_BUF_SIZE: 0x%x", m->x2i_buffer_size);
	XDNA_DBG(xdna, "MAILBOX_I2X_TAIL_OFF: 0x%x", m->i2x_tail_offset);
	XDNA_DBG(xdna, "MAILBOX_I2X_HEAD_OFF: 0x%x", m->i2x_head_offset);
	XDNA_DBG(xdna, "MAILBOX_I2X_BUF_ADDR: 0x%x", m->i2x_buffer_addr);
	XDNA_DBG(xdna, "MAILBOX_I2X_BUF_SIZE: 0x%x", m->i2x_buffer_size);
	XDNA_DBG(xdna, "MAILBOX_I2X_MSI_IDX: 0x%x", m->i2x_msi_idx);
}

static int aie4_fw_clear_alive(struct amdxdna_dev *xdna)
{
	const struct amdxdna_dev_priv *npriv = xdna->dev_info->dev_priv;
	struct amdxdna_dev_hdl *ndev = xdna->dev_handle;
	u32 __iomem *src;
	u32 val;

	src = ndev->rbuf_base + npriv->mbox_info_off + offsetof(struct mailbox_info, valid);

	writel(0, src);

	val = readl(src);
	XDNA_DBG(xdna, "mailbox ready is %s (%d)", val ? "not cleared" : "cleared", val);

	return val;
}

static int aie4_fw_is_alive(struct amdxdna_dev *xdna)
{
	const struct amdxdna_dev_priv *npriv = xdna->dev_info->dev_priv;
	struct amdxdna_dev_hdl *ndev = xdna->dev_handle;
	u32 __iomem *src;
	u32 fw_is_ready;
	int ret;

	src = ndev->rbuf_base + npriv->mbox_info_off;

	ret = readx_poll_timeout(readl, src + offsetof(struct mailbox_info, valid),
				 fw_is_ready, (fw_is_ready == 0x1),
				 AIE4_INTERVAL, AIE4_TIMEOUT);
	if (ret) {
		XDNA_ERR(xdna, "firmware is not ready (%d) after %d ms",
			 fw_is_ready, DIV_ROUND_CLOSEST(AIE4_TIMEOUT, 1000000));
	}

	XDNA_DBG(xdna, "firmware is ready (%d)", fw_is_ready);
	return ret;
}

static void aie4_read_mbox_info(struct amdxdna_dev *xdna,
				struct mailbox_info *mbox_info)
{
	const struct amdxdna_dev_priv *npriv = xdna->dev_info->dev_priv;
	struct amdxdna_dev_hdl *ndev = xdna->dev_handle;
	u32 *dst = (u32 *)mbox_info;
	u32 __iomem *src;
	int i;

	src = ndev->rbuf_base + npriv->mbox_info_off;

	for (i = 0; i < sizeof(*mbox_info) / sizeof(u32); i++)
		dst[i] = readl(&src[i]);
}

static int aie4_mailbox_info(struct amdxdna_dev *xdna,
			     struct mailbox_info *mbox_info)
{
	int ret;

	ret = aie4_fw_is_alive(xdna);
	if (ret)
		return ret;

	aie4_read_mbox_info(xdna, mbox_info);
	aie4_dump_mbox_info(xdna, mbox_info);

	return 0;
}

static void col_timer(struct timer_list *t)
{
#if defined from_timer
	struct amdxdna_dev_hdl *ndev = from_timer(ndev, t, event_timer);
#elif defined timer_container_of
	struct amdxdna_dev_hdl *ndev = timer_container_of(ndev, t, event_timer);
#endif
	struct amdxdna_dev *xdna = ndev->xdna;
	struct col_entry *col_entry;

	mutex_lock(&ndev->col_list_lock);
	list_for_each_entry(col_entry, &ndev->col_entry_list, col_list) {
		XDNA_DBG(xdna, "wake up all for idx %d", col_entry->msix_idx);
		wake_up_all(&col_entry->col_event);
	}
	mutex_unlock(&ndev->col_list_lock);

	mod_timer(&ndev->event_timer, jiffies + msecs_to_jiffies(1000));
}

static void aie4_mailbox_fini(struct amdxdna_dev_hdl *ndev)
{
	xdna_mailbox_stop_channel(ndev->mgmt_chann);
	xdna_mailbox_destroy_channel(ndev->mgmt_chann);
	ndev->mgmt_chann = NULL;
	xdna_mailbox_destroy(ndev->mbox);
}

static inline void aie4_irq_fini(struct amdxdna_dev_hdl *ndev)
{
	struct amdxdna_dev *xdna = ndev->xdna;
	struct pci_dev *pdev = to_pci_dev(xdna->ddev.dev);

	if (enable_aie4_polling)
		timer_delete_sync(&ndev->event_timer);
	else
		pci_free_irq_vectors(pdev);
}

static int aie4_irq_init(struct amdxdna_dev *xdna)
{
	struct pci_dev *pdev = to_pci_dev(xdna->ddev.dev);
	struct amdxdna_dev_hdl *ndev = xdna->dev_handle;
	int ret = 0, nvec;

	if (enable_aie4_polling) {
		XDNA_DBG(xdna, "enable_aie4 polling mode");
		timer_setup(&ndev->event_timer, col_timer, 0);
		mod_timer(&ndev->event_timer, jiffies + msecs_to_jiffies(1000));
	} else {
		nvec = pci_msix_vec_count(pdev);
		XDNA_DBG(xdna, "enable_aie4 interrupt mode, irq vectors:%d", nvec);
		if (nvec <= 0) {
			XDNA_ERR(xdna, "does not get number of interrupt vector");
			return -EINVAL;
		}

		ret = pci_alloc_irq_vectors(pdev, nvec, nvec, PCI_IRQ_MSIX);
		if (ret < 0) {
			XDNA_ERR(xdna, "failed to alloc irq vector, ret: %d", ret);
			return ret;
		}
	}

	return 0;
}

static int aie4_mailbox_start(struct amdxdna_dev *xdna,
			      struct mailbox_info *mbi)
{
	struct pci_dev *pdev = to_pci_dev(xdna->ddev.dev);
	struct amdxdna_dev_hdl *ndev = xdna->dev_handle;
	int ret = 0;

	struct xdna_mailbox_res mbox_res = {
		.ringbuf_base = ndev->rbuf_base,
		.ringbuf_size = pci_resource_len(pdev, xdna->dev_info->sram_bar),
		.mbox_base = ndev->mbox_base,
		.mbox_size = pci_resource_len(pdev, xdna->dev_info->mbox_bar),
		.name = "xdna_aie4_mailbox",
	};

	struct xdna_mailbox_chann_info chann_info = {
		.x2i = {
			.rb_start_addr = mbi->x2i_buffer_addr,
			.rb_size = mbi->x2i_buffer_size,
			.mb_head_ptr_reg = mbi->x2i_head_offset,
			.mb_tail_ptr_reg = mbi->x2i_tail_offset,
		},
		.i2x = {
			.rb_start_addr = mbi->i2x_buffer_addr,
			.rb_size = mbi->i2x_buffer_size,
			.mb_head_ptr_reg = mbi->i2x_head_offset,
			.mb_tail_ptr_reg = mbi->i2x_tail_offset,
		},
		.msix_id = mbi->i2x_msi_idx,
		.intr_reg = 0,
	};

	ndev->mbox = xdna_mailbox_create(&pdev->dev, &mbox_res);
	if (!ndev->mbox) {
		XDNA_ERR(xdna, "failed to create mailbox device, ret: %d", ret);
		return -ENODEV;
	}

	ndev->mgmt_chann = xdna_mailbox_create_channel(ndev->mbox, &chann_info, MB_CHANNEL_MGMT);
	if (!ndev->mgmt_chann) {
		XDNA_ERR(xdna, "failed to create management mailbox channel, ret:%d", ret);
		ret = -EINVAL;
		goto create_channel_failed;
	}

	XDNA_DBG(xdna, "Mailbox management channel created");
	return 0;

create_channel_failed:
	xdna_mailbox_destroy(ndev->mbox);
	ndev->mbox = NULL;

	return ret;
}

static int aie4_mailbox_init(struct amdxdna_dev *xdna)
{
	struct mailbox_info mbox_info = { 0 };
	int ret = 0;

	ret = aie4_mailbox_info(xdna, &mbox_info);
	if (ret)
		return ret;

	return aie4_mailbox_start(xdna, &mbox_info);
}

static int aie4_mgmt_fw_init(struct amdxdna_dev_hdl *ndev)
{
	struct pci_dev *pdev = to_pci_dev(ndev->xdna->ddev.dev);
	struct amdxdna_mgmt_dma_hdl *dma_hdl;
	dma_addr_t dma_addr;
	int ret;

	if (is_npu3_vf_dev(pdev))
		return 0;

	ret = aie4_calibrate_clock(ndev);
	if (ret) {
		XDNA_ERR(ndev->xdna, "Calibrate system clock failed");
		return ret;
	}

	if (skip_work_buffer)
		return 0;

	dma_hdl = ndev->mpnpu_work_buffer;
	dma_addr = amdxdna_mgmt_buff_get_dma_addr(dma_hdl);

	if (!dma_addr)
		XDNA_ERR(ndev->xdna, "Invalid DMA address: 0x%llx", dma_addr);

	ret = aie4_attach_work_buffer(ndev, 0, dma_addr, dma_hdl->size);
	if (ret) {
		XDNA_ERR(ndev->xdna, "Failed to attach DRAM work buffer");
		return ret;
	}

	return aie4_set_ctx_hysteresis(ndev, AIE4_CTX_HYSTERESIS_US);
}

static int aie4_mgmt_fw_query(struct amdxdna_dev_hdl *ndev)
{
	struct amdxdna_dev *xdna = ndev->xdna;
	struct pci_dev *pdev = to_pci_dev(xdna->ddev.dev);
	int ret;

	ret = aie4_check_firmware_version(ndev);
	if (ret) {
		XDNA_ERR(ndev->xdna, "query firmware version failed");
		return ret;
	}

	if (is_npu3_pf_dev(pdev)) {
		XDNA_DBG(ndev->xdna, "skip aie check on non npu3 pf device");
		return 0;
	}

	ret = aie4_query_aie_version(ndev, &ndev->version);
	if (ret) {
		XDNA_ERR(ndev->xdna, "Query AIE version failed");
		return ret;
	}

	ret = aie4_query_aie_metadata(ndev, &ndev->metadata);
	if (ret) {
		XDNA_ERR(ndev->xdna, "Query AIE metadata failed");
		return ret;
	}

	ndev->total_col = min(aie4_max_col, ndev->metadata.cols);

	return 0;
}

static inline int aie4_fw_load_support(struct amdxdna_dev_hdl *ndev)
{
	struct amdxdna_dev *xdna = ndev->xdna;
	struct pci_dev *pdev = to_pci_dev(xdna->ddev.dev);

	if (is_npu3_vf_dev(pdev)) {
		XDNA_DBG(xdna, "skip loading fw on vf device");
		return 0;
	}

	if (skip_fw_load) {
		XDNA_INFO(xdna, "skip fw_load");
		return 0;
	}

	return 1;
}

static void aie4_fw_unload(struct amdxdna_dev_hdl *ndev)
{
	if (!aie4_fw_load_support(ndev))
		return;

	aie4_psp_stop(ndev->psp_hdl);
	aie4_smu_stop(ndev);
}

static int aie4_fw_load(struct amdxdna_dev_hdl *ndev)
{
	struct amdxdna_dev *xdna = ndev->xdna;
	int ret;

	if (!aie4_fw_load_support(ndev))
		return 0;

	ret = aie4_smu_start(ndev);
	if (ret) {
		XDNA_ERR(xdna, "failed to init smu, ret %d", ret);
		return ret;
	}

	ret = aie4_psp_start(ndev->psp_hdl);
	if (ret) {
		XDNA_ERR(xdna, "failed to start psp, ret %d", ret);
		goto stop_smu;
	}

	return ret;
stop_smu:
	aie4_smu_stop(ndev);
	return ret;
}

static int aie4_hw_start(struct amdxdna_dev *xdna)
{
	struct pci_dev *pdev = to_pci_dev(xdna->ddev.dev);
	struct amdxdna_dev_hdl *ndev = xdna->dev_handle;
	int ret;

	if (ndev->dev_status >= AIE4_DEV_START) {
		XDNA_INFO(xdna, "device is already started");
		return 0;
	}

	ret = pci_enable_device(pdev);
	if (ret) {
		XDNA_ERR(xdna, "pcim enable device failed, ret %d", ret);
		return ret;
	}
	pci_set_master(pdev);

	/* This lock will be released in disable_device */
	mutex_lock(&ndev->aie4_lock);

	ret = aie4_fw_load(ndev);
	if (ret)
		goto disable_device;

	ret = aie4_irq_init(xdna);
	if (ret)
		goto fw_unload;

	ret = aie4_mailbox_init(xdna);
	if (ret)
		goto disable_irq;

	ret = aie4_mgmt_fw_init(ndev);
	if (ret)
		goto disable_mailbox;

	ret = aie4_pm_init(ndev);
	if (ret)
		goto disable_mailbox;

	ret = aie4_mgmt_fw_query(ndev);
	if (ret)
		goto stop_pm;

	ret = aie4_error_async_events_alloc(ndev);
	if (ret)
		goto stop_pm;

	mutex_unlock(&ndev->aie4_lock);
	ndev->dev_status = AIE4_DEV_START;

	return 0;

stop_pm:
	aie4_pm_fini(ndev);
disable_mailbox:
	aie4_mailbox_fini(ndev);
disable_irq:
	aie4_irq_fini(ndev);
fw_unload:
	aie4_fw_unload(ndev);
disable_device:
	mutex_unlock(&ndev->aie4_lock);
	pci_clear_master(pdev);
	pci_disable_device(pdev);

	return ret;
}

static int aie4_partition_init(struct amdxdna_dev_hdl *ndev)
{
	DECLARE_AIE4_MSG(aie4_msg_create_partition, AIE4_MSG_OP_CREATE_PARTITION);
	struct amdxdna_dev *xdna = ndev->xdna;
	struct pci_dev *pdev = to_pci_dev(xdna->ddev.dev);
	int ret;

	if (is_npu3_pf_dev(pdev)) {
		XDNA_DBG(xdna, "skip on pf device");
		return 0;
	}

	/*
	 * There is only single partition for the entire 3*4 aie hardware for now.
	 * In the future, we may have multiple partitions start from different
	 * start_cols, different num_tiles, mem_size, and application_mode can
	 * be SINGLE|DUAL_A|DUAL_B.
	 */
	req.partition_col_start = 0;
	req.partition_col_count = 3;

	ret = aie4_send_msg_wait(ndev, &msg);
	if (ret) {
		XDNA_ERR(xdna, "partition init failed: %d", ret);
		return ret;
	}

	XDNA_DBG(xdna, "partition_id %d", resp.partition_id);
	ndev->partition_id = resp.partition_id;

	return 0;
}

static void aie4_mgmt_fw_fini(struct amdxdna_dev_hdl *ndev)
{
	struct pci_dev *pdev = to_pci_dev(ndev->xdna->ddev.dev);
	int ret;

	if (!is_npu3_vf_dev(pdev) && !skip_work_buffer)
		aie4_detach_work_buffer(ndev);

	ret = aie4_suspend_fw(ndev);
	if (ret) {
		XDNA_ERR(ndev->xdna, "suspend_fw failed, ret %d", ret);
		return;
	}

	XDNA_DBG(ndev->xdna, "npu firmware suspended");
}

static void aie4_partition_fini(struct amdxdna_dev_hdl *ndev)
{
	DECLARE_AIE4_MSG(aie4_msg_destroy_partition, AIE4_MSG_OP_DESTROY_PARTITION);
	struct amdxdna_dev *xdna = ndev->xdna;
	struct pci_dev *pdev = to_pci_dev(xdna->ddev.dev);
	int ret;

	if (is_npu3_pf_dev(pdev)) {
		XDNA_DBG(xdna, "skip on pf device");
		return;
	}

	req.partition_id = ndev->partition_id;

	ret = aie4_send_msg_wait(ndev, &msg);
	if (ret)
		XDNA_ERR(xdna, "id %d fini failed: %d", ndev->partition_id, ret);
	else
		XDNA_DBG(xdna, "id %d", ndev->partition_id);
}

static void aie4_hw_stop(struct amdxdna_dev *xdna)
{
	struct pci_dev *pdev = to_pci_dev(xdna->ddev.dev);
	struct amdxdna_dev_hdl *ndev = xdna->dev_handle;

	drm_WARN_ON(&xdna->ddev, !mutex_is_locked(&ndev->aie4_lock));

	if (ndev->dev_status <= AIE4_DEV_INIT) {
		XDNA_ERR(xdna, "device is already stopped");
		return;
	}

	aie4_partition_fini(ndev);
	aie4_pm_fini(ndev);
	aie4_mgmt_fw_fini(ndev);
	aie4_mailbox_fini(ndev);
	ndev->mbox = NULL;

	aie4_irq_fini(ndev);

	aie4_fw_unload(ndev);

	pci_clear_master(pdev);
	pci_disable_device(pdev);

	ndev->dev_status = AIE4_DEV_INIT;
}

static int aie4_request_firmware(struct amdxdna_dev_hdl *ndev,
				 const struct firmware **npufw,
				 const struct firmware **certfw)
{
	struct amdxdna_dev *xdna = ndev->xdna;
	struct pci_dev *pdev = to_pci_dev(xdna->ddev.dev);
	char fw_name[128];
	int ret;

	if (!aie4_fw_load_support(ndev))
		return 0;

	ret = snprintf(fw_name, sizeof(fw_name), "amdnpu/%04x_%02x/%s",
		       pdev->device, pdev->revision, ndev->priv->npufw_path);
	if (ret >= sizeof(fw_name)) {
		XDNA_ERR(xdna, "fw_name %s is truncated", fw_name);
		return -EINVAL;
	}

	XDNA_DBG(xdna, "Request fw %s", fw_name);
	ret = request_firmware(npufw, fw_name, &pdev->dev);
	if (ret) {
		XDNA_ERR(xdna, "failed to request_firmware %s, ret %d", fw_name, ret);
		return ret;
	}

	memset(fw_name, 0, sizeof(fw_name));
	ret = snprintf(fw_name, sizeof(fw_name), "amdnpu/%04x_%02x/%s",
		       pdev->device, pdev->revision, ndev->priv->certfw_path);
	if (ret >= sizeof(fw_name)) {
		XDNA_ERR(xdna, "fw_name %s is truncated", fw_name);
		return -EINVAL;
	}

	XDNA_DBG(xdna, "Request fw %s", fw_name);
	ret = request_firmware(certfw, fw_name, &pdev->dev);
	if (ret) {
		XDNA_ERR(xdna, "failed to request_firmware %s, ret %d", fw_name, ret);
		goto release_npufw;
	}

	if ((*certfw)->size > CERTFW_MAX_SIZE) {
		XDNA_ERR(xdna, "CERTFW over maximum size of 32 KB + 256 B");
		ret = -EINVAL;
		goto release_certfw;
	}

	return 0;

release_certfw:
	release_firmware(*certfw);
release_npufw:
	release_firmware(*npufw);

	return ret;
}

static int aie4_release_firmware(struct amdxdna_dev_hdl *ndev,
				 const struct firmware *npufw,
				 const struct firmware *certfw)
{
	if (!aie4_fw_load_support(ndev))
		return 0;

	release_firmware(certfw);
	release_firmware(npufw);
	return 0;
}

static int aie4_prepare_firmware(struct amdxdna_dev_hdl *ndev,
				 const struct firmware *npufw,
				 const struct firmware *certfw)
{
	struct amdxdna_dev *xdna = ndev->xdna;
	struct pci_dev *pdev = to_pci_dev(xdna->ddev.dev);
	struct aie4_psp_config psp_conf;
	int i;

	if (!aie4_fw_load_support(ndev))
		return 0;

	psp_conf.fw_size = npufw->size;
	psp_conf.fw_buf = npufw->data;
	psp_conf.certfw_size = certfw->size;
	psp_conf.certfw_buf = certfw->data;
	for (i = 0; i < PSP_MAX_REGS; i++)
		psp_conf.psp_regs[i] = ndev->psp_base + PSP_REG_OFF(ndev, i);

	ndev->psp_hdl = aie4_psp_create(&pdev->dev, &psp_conf);
	if (!ndev->psp_hdl) {
		XDNA_ERR(xdna, "failed to create psp");
		return -ENOMEM;
	}

	return 0;
}

static int aie4_alloc_work_buffer(struct amdxdna_dev_hdl *ndev)
{
	struct amdxdna_dev *xdna = ndev->xdna;
	struct pci_dev *pdev = to_pci_dev(xdna->ddev.dev);
	struct amdxdna_mgmt_dma_hdl *dma_hdl;
	char print_size[32];

	if (is_npu3_vf_dev(pdev) || skip_work_buffer) {
		XDNA_DBG(xdna, "skip alloc work buffer");
		return 0;
	}

	dma_hdl = amdxdna_mgmt_buff_alloc(xdna, AIE4_MPNPUFW_DRAM_WORK_BUFFER_MIN_SIZE,
					  DMA_FROM_DEVICE);
	if (IS_ERR(dma_hdl)) {
		XDNA_ERR(xdna, "Failed to allocate MPNPU buffer of size: 0x%x",
			 AIE4_MPNPUFW_DRAM_WORK_BUFFER_MIN_SIZE);
		return PTR_ERR(dma_hdl);
	}

	memset(amdxdna_mgmt_buff_get_cpu_addr(dma_hdl, 0), 0,
	       AIE4_MPNPUFW_DRAM_WORK_BUFFER_MIN_SIZE);
	amdxdna_mgmt_buff_clflush(dma_hdl, 0, 0);
	string_get_size(dma_hdl->size, 1, STRING_UNITS_2, print_size, sizeof(print_size));
	XDNA_DBG(xdna, "Allocated %s MPNPU work buffer at 0x%llx with DMA addr: 0x%llx",
		 print_size, (u64)amdxdna_mgmt_buff_get_cpu_addr(dma_hdl, 0),
		 amdxdna_mgmt_buff_get_dma_addr(dma_hdl));
	ndev->mpnpu_work_buffer = dma_hdl;

	return 0;
}

static void aie4_free_work_buffer(struct amdxdna_dev_hdl *ndev)
{
	struct amdxdna_dev *xdna = ndev->xdna;
	struct pci_dev *pdev = to_pci_dev(xdna->ddev.dev);

	if (is_npu3_vf_dev(pdev) || skip_work_buffer) {
		XDNA_DBG(xdna, "skip free work buffer");
		return;
	}

	if (ndev->mpnpu_work_buffer)
		amdxdna_mgmt_buff_free(ndev->mpnpu_work_buffer);
}

static int aie4_pcidev_init(struct amdxdna_dev_hdl *ndev)
{
	struct amdxdna_dev *xdna = ndev->xdna;
	struct pci_dev *pdev = to_pci_dev(xdna->ddev.dev);
	void __iomem *tbl[PCI_NUM_RESOURCES] = {0};
	const struct firmware *npufw, *certfw;
	unsigned long bars = 0;
	int ret, i;

	/* Enable managed PCI device */
	ret = pcim_enable_device(pdev);
	if (ret) {
		XDNA_ERR(xdna, "pcim enable device failed, ret %d", ret);
		return ret;
	}

	ret = dma_set_mask_and_coherent(&pdev->dev, DMA_BIT_MASK(64));
	if (ret) {
		XDNA_ERR(xdna, "failed to set DMA mask to 64:%d", ret);
		return ret;
	}

	set_bit(xdna->dev_info->mbox_bar, &bars);
	set_bit(xdna->dev_info->sram_bar, &bars);
	set_bit(xdna->dev_info->psp_bar, &bars);
	set_bit(xdna->dev_info->smu_bar, &bars);
	set_bit(xdna->dev_info->doorbell_bar, &bars);

	for (i = 0; i < PCI_NUM_RESOURCES; i++) {
		if (!test_bit(i, &bars))
			continue;
		tbl[i] = pcim_iomap(pdev, i, 0);
		if (!tbl[i]) {
			XDNA_ERR(xdna, "map bar %d failed", i);
			ret = -ENOMEM;
			goto release_fw;
		}
	}

	ndev->mbox_base = tbl[xdna->dev_info->mbox_bar];
	ndev->rbuf_base = tbl[xdna->dev_info->sram_bar];
	ndev->psp_base = tbl[xdna->dev_info->psp_bar];
	ndev->smu_base = tbl[xdna->dev_info->smu_bar];
	ndev->doorbell_base = tbl[xdna->dev_info->doorbell_bar];

	ret = aie4_request_firmware(ndev, &npufw, &certfw);
	if (ret)
		return ret;
	ret = aie4_prepare_firmware(ndev, npufw, certfw);
	if (ret)
		goto release_fw;
	aie4_release_firmware(ndev, npufw, certfw);

	ret = aie4_alloc_work_buffer(ndev);
	if (ret)
		goto release_fw;

	ret = aie4_hw_start(xdna);
	if (ret) {
		XDNA_ERR(xdna, "aie4 hw start failed, ret %d", ret);
		goto free_work_buf;
	}

	mutex_lock(&ndev->aie4_lock);
	ret = aie4_partition_init(ndev);
	mutex_unlock(&ndev->aie4_lock);
	if (ret)
		goto hw_stop;

	return ret;

hw_stop:
	mutex_lock(&ndev->aie4_lock);
	aie4_hw_stop(xdna);
	mutex_unlock(&ndev->aie4_lock);
free_work_buf:
	aie4_free_work_buffer(ndev);
release_fw:
	aie4_release_firmware(ndev, npufw, certfw);

	return ret;
}

static irqreturn_t col_irq_handler(int irq, void *p)
{
	struct col_entry *col = (struct col_entry *)p;

	trace_amdxdna_debug_point("ISR fired", col->col_irq, "command completed");
	wake_up_all(&col->col_event);
	return IRQ_HANDLED;
}

static struct col_entry *get_col_entry(struct amdxdna_dev_hdl *ndev, u32 msix_idx)
{
	struct amdxdna_dev *xdna = ndev->xdna;
	struct pci_dev *pdev = to_pci_dev(xdna->ddev.dev);
	struct col_entry *col_entry;
	struct list_head *pos = NULL, *next = NULL;
	int ret;

	mutex_lock(&ndev->col_list_lock);
	list_for_each_safe(pos, next, &ndev->col_entry_list) {
		col_entry = list_entry(pos, struct col_entry, col_list);

		if (col_entry->msix_idx == msix_idx) {
			kref_get(&col_entry->col_ref_count);
			mutex_unlock(&ndev->col_list_lock);
			return col_entry;
		}
	}

	col_entry = kzalloc(sizeof(*col_entry), GFP_KERNEL);
	if (!col_entry) {
		XDNA_ERR(xdna, "no memory for col_entry");
		goto done;
	}
	col_entry->msix_idx = msix_idx;
	col_entry->ndev = ndev;

	if (enable_aie4_polling)
		goto skip;

	col_entry->col_irq = pci_irq_vector(pdev, col_entry->msix_idx);
	ret = request_irq(col_entry->col_irq, col_irq_handler, 0, "xdna_hsa", col_entry);
	if (ret) {
		XDNA_ERR(xdna, "request irq %d failed %d", col_entry->col_irq, ret);
		kfree(col_entry);
		col_entry = NULL;
		goto done;
	}
skip:
	init_waitqueue_head(&col_entry->col_event);
	kref_init(&col_entry->col_ref_count);
	INIT_LIST_HEAD(&col_entry->col_list);

	list_add_tail(&col_entry->col_list, &ndev->col_entry_list);

done:
	mutex_unlock(&ndev->col_list_lock);
	return col_entry;
}

static void col_release(struct kref *kref)
{
	/* all handled in put_col_entry list_del */
}

static void put_col_entry(struct amdxdna_dev_hdl *ndev, u32 msix_idx)
{
	struct col_entry *col_entry;
	struct list_head *pos = NULL, *next = NULL;

	mutex_lock(&ndev->col_list_lock);
	list_for_each_safe(pos, next, &ndev->col_entry_list) {
		col_entry = list_entry(pos, struct col_entry, col_list);

		if (col_entry->msix_idx == msix_idx) {
			if (kref_put(&col_entry->col_ref_count, col_release)) {
				/* last refcount, remove from list and free memory */
				list_del(pos);
				if (!enable_aie4_polling)
					free_irq(col_entry->col_irq, col_entry);

				/* safely clean up all pending wait call */
				col_entry->needs_reset = true;
				wake_up_all(&col_entry->col_event);

				kfree(col_entry);
				col_entry = NULL;
			}
			mutex_unlock(&ndev->col_list_lock);
			return;
		}
	}
	mutex_unlock(&ndev->col_list_lock);
	XDNA_ERR(ndev->xdna, "no refcount for idx %d!", msix_idx);
}

static int aie4_msg_destroy_context(struct amdxdna_dev_hdl *ndev, u32 hw_context_id,
				    int graceful)
{
	DECLARE_AIE4_MSG(aie4_msg_destroy_hw_context, AIE4_MSG_OP_DESTROY_HW_CONTEXT);

	req.hw_context_id = hw_context_id;
	req.graceful_flag = graceful ? 1 : 0;
	return aie4_send_msg_wait(ndev, &msg);
}

int aie4_create_context(struct amdxdna_dev_hdl *ndev, struct amdxdna_ctx *ctx)
{
	DECLARE_AIE4_MSG(aie4_msg_create_hw_context, AIE4_MSG_OP_CREATE_HW_CONTEXT);
	struct amdxdna_client *client = ctx->client;
	struct amdxdna_ctx_priv *nctx = ctx->priv;
	struct amdxdna_dev *xdna = ndev->xdna;
	int ret;

	drm_WARN_ON(&xdna->ddev, !mutex_is_locked(&ndev->aie4_lock));

	if (ndev->dev_status <= AIE4_DEV_INIT) {
		XDNA_INFO(xdna, "device is not ready, try again later.");
		return -EBUSY;
	}

#ifdef UMQ_HELLO_TEST
	return aie4_hello_test(ndev, ctx);
#endif
	if (!nctx || nctx->umq_bo == AMDXDNA_INVALID_BO_HANDLE) {
		XDNA_WARN(xdna, "cannot create hwctx due to NULL nctx or umq buffer");
		return -EINVAL;
	}

	req.partition_id = ndev->partition_id;
	ctx->start_col = 0; // for now partition is always full NPU
	ctx->num_col = 3;
	req.request_num_tiles = ctx->num_tiles;

	req.pasid.raw = 0;
	req.pasid.f.pasid = client->pasid;
	req.pasid.f.pasid_vld = 1;

#ifdef AMDXDNA_DEVEL
	if (iommu_mode == AMDXDNA_IOMMU_NO_PASID)
		req.pasid.raw = 0;
#endif

	req.hsa_addr_high = upper_32_bits(amdxdna_gem_dev_addr(nctx->umq_bo));
	req.hsa_addr_low = lower_32_bits(amdxdna_gem_dev_addr(nctx->umq_bo));

	req.priority_band = ctx->qos.priority;

	XDNA_DBG(xdna, "set pasid raw 0x%x", req.pasid.raw);

	XDNA_DBG(xdna, "part_id %d, tiles %d, mem_size 1.5 MB",
		 req.partition_id, req.request_num_tiles);
	XDNA_DBG(xdna, "hsa[0x%x 0x%x]",
		 req.hsa_addr_high, req.hsa_addr_low);
	XDNA_DBG(xdna, "dma/phy addr 0x%llx", nctx->umq_bo->mem.dma_addr);

	if (!req.partition_id || !req.request_num_tiles) {
		/* sanity check failed, skip sending request which can crash fw */
		XDNA_ERR(xdna, "req is invalid");
		ret = -EINVAL;
		goto done;
	}

	ret = aie4_send_msg_wait(ndev, &msg);
	if (ret) {
		XDNA_ERR(xdna, "create ctx failed: %d", ret);
		goto done;
	}

	XDNA_DBG(xdna, "resp msix %d, ctx %d, doorbell %d, irq %d",
		 resp.job_complete_msix_idx,
		 resp.hw_context_id,
		 resp.doorbell_offset,
		 resp.job_complete_msix_idx);

	if (ndev->force_preempt_enabled) {
		ret = aie4_force_preemption(ndev);
		WARN_ONCE(ret, "Failed to config force preemption");
	}

	nctx->col_entry = get_col_entry(ndev, resp.job_complete_msix_idx);
	if (!nctx->col_entry) {
		aie4_msg_destroy_context(ndev, resp.hw_context_id, 0);
		ret = -EINVAL;
		goto done;
	}

	nctx->hw_ctx_id = resp.hw_context_id;
	nctx->doorbell_addr = ndev->doorbell_base + resp.doorbell_offset;
	nctx->status = CTX_STATE_CONNECTED;
	/*
	 * If user-mode-submission, pass doorbell offset to user via
	 * ctx->doorbell_offset. Driver will not ring the doorbell.
	 * Otherwise, pass AMDXDNA_INVALID_DOORBELL_OFFSET to user to
	 * prevent user space code from mapping/ringing the doorbell.
	 */
	ctx->doorbell_offset = kernel_mode_submission ?
		AMDXDNA_INVALID_DOORBELL_OFFSET : resp.doorbell_offset;

	XDNA_DBG(xdna, "created hw context id %d", nctx->hw_ctx_id);

	return 0;
done:

	XDNA_ERR(xdna, "failed %d", ret);
	return ret;
}

int aie4_destroy_context(struct amdxdna_dev_hdl *ndev, struct amdxdna_ctx *ctx,
			 int graceful)
{
	struct amdxdna_dev *xdna = ndev->xdna;
	struct amdxdna_ctx_priv *nctx = ctx->priv;
	int ret;

	XDNA_DBG(xdna, "hwctx id %d", ctx->priv->hw_ctx_id);

	drm_WARN_ON(&xdna->ddev, !mutex_is_locked(&ndev->aie4_lock));

	put_col_entry(ndev, nctx->col_entry->msix_idx);

	ret = aie4_msg_destroy_context(ndev, ctx->priv->hw_ctx_id, graceful);

	return ret;
}

static int aie4_xrs_load(void *cb_arg, struct xrs_action_load *action)
{
	struct amdxdna_ctx *ctx = cb_arg;
	struct amdxdna_dev *xdna;
	int ret;

	xdna = ctx->client->xdna;

	ctx->start_col = action->part.start_col;
	ctx->num_col = action->part.ncols;

	mutex_lock(&xdna->dev_handle->aie4_lock);
	ret = aie4_create_context(xdna->dev_handle, ctx);
	mutex_unlock(&xdna->dev_handle->aie4_lock);

	if (ret)
		XDNA_ERR(xdna, "create context failed, ret %d", ret);

	return ret;
}

static int aie4_xrs_unload(void *cb_arg)
{
	struct amdxdna_ctx *ctx = cb_arg;
	struct amdxdna_dev *xdna;
	int ret;

	xdna = ctx->client->xdna;

	mutex_lock(&xdna->dev_handle->aie4_lock);
	ret = aie4_destroy_context(xdna->dev_handle, ctx, 0);
	mutex_unlock(&xdna->dev_handle->aie4_lock);

	if (ret)
		XDNA_ERR(xdna, "destroy context failed, ret %d", ret);

	return ret;
}

static struct xrs_action_ops aie4_xrs_actions = {
	.load = aie4_xrs_load,
	.unload = aie4_xrs_unload,
};

static void aie4_ctx_suspend_all(struct amdxdna_dev *xdna)
{
	struct amdxdna_dev_hdl *ndev = xdna->dev_handle;
	struct amdxdna_client *client;
	struct amdxdna_ctx *ctx;
	unsigned long ctx_id;
	int idx;

	drm_WARN_ON(&xdna->ddev, !mutex_is_locked(&ndev->aie4_lock));

	list_for_each_entry(client, &xdna->client_list, node) {
		idx = srcu_read_lock(&client->ctx_srcu);
		amdxdna_for_each_ctx(client, ctx_id, ctx)
			aie4_ctx_suspend(ctx, true);
		srcu_read_unlock(&client->ctx_srcu, idx);
	}

	XDNA_DBG(xdna, "finished ctx_suspend_all");
}

static void aie4_ctx_resume_all(struct amdxdna_dev *xdna)
{
	struct amdxdna_dev_hdl *ndev = xdna->dev_handle;
	struct amdxdna_client *client;
	struct amdxdna_ctx *ctx;
	unsigned long ctx_id;
	int idx;

	drm_WARN_ON(&xdna->ddev, !mutex_is_locked(&ndev->aie4_lock));

	list_for_each_entry(client, &xdna->client_list, node) {
		idx = srcu_read_lock(&client->ctx_srcu);
		amdxdna_for_each_ctx(client, ctx_id, ctx)
			aie4_ctx_resume(ctx);
		srcu_read_unlock(&client->ctx_srcu, idx);
	}

	XDNA_DBG(xdna, "finished ctx_resume_all");
}

static int aie4_fw_reload(struct amdxdna_dev_hdl *ndev)
{
	struct amdxdna_dev *xdna = ndev->xdna;
	int ret;

	if (!fw_reload) {
		XDNA_DBG(xdna, "skip fw_reload");
		return 0;
	}

	/*
	 * The key step is suspend fw, then power off and on
	 */
	aie4_pm_fini(ndev);
	aie4_mgmt_fw_fini(ndev);
	aie4_mailbox_fini(ndev);
	ndev->mbox = NULL;
	aie4_fw_unload(ndev);

	ret = aie4_fw_load(ndev);
	if (ret)
		return ret;

	ret = aie4_mailbox_init(xdna);
	if (ret)
		return ret;

	ret = aie4_mgmt_fw_init(ndev);
	if (ret)
		return ret;

	ret = aie4_pm_init(ndev);

	return ret;
}

void aie4_reset_prepare(struct amdxdna_dev *xdna)
{
	struct amdxdna_dev_hdl *ndev = xdna->dev_handle;
	struct pci_dev *pdev = to_pci_dev(xdna->ddev.dev);

	XDNA_INFO(xdna, "reset prepare start");

	mutex_lock(&ndev->aie4_lock);

	/* mark dev status to avoid new incoming requests */
	ndev->dev_status = AIE4_DEV_INIT;

	if (!is_npu3_pf_dev(pdev))
		aie4_ctx_suspend_all(xdna);

	/* fini mailbox service */
	aie4_mailbox_fini(ndev);

	/* set mailbox alive to 0 */
	aie4_fw_clear_alive(xdna);

	mutex_unlock(&ndev->aie4_lock);

	XDNA_INFO(xdna, "reset prepare finished");
}

int aie4_reset_done(struct amdxdna_dev *xdna)
{
	struct amdxdna_dev_hdl *ndev = xdna->dev_handle;
	struct pci_dev *pdev = to_pci_dev(xdna->ddev.dev);
	int ret;

	XDNA_INFO(xdna, "reset done start");

	mutex_lock(&ndev->aie4_lock);
	ret = aie4_mailbox_init(xdna);
	if (ret)
		goto error;

	ret = aie4_fw_reload(ndev);
	if (ret)
		goto error;

	ret = aie4_partition_init(ndev);
	if (ret) {
		aie4_mailbox_fini(ndev);
		goto error;
	}

	if (is_npu3_pf_dev(pdev)) {
		int numvfs;

		mutex_unlock(&ndev->aie4_lock);
		numvfs = aie4_sriov_configure(xdna, ndev->num_vfs);
		mutex_lock(&ndev->aie4_lock);

		if (numvfs != ndev->num_vfs) {
			XDNA_ERR(xdna, "reconfigure %d num_vfs but configured %d",
				 ndev->num_vfs, numvfs);
			ret = -EINVAL;
			goto error;
		}
	} else {
		aie4_ctx_resume_all(xdna);
	}

	/* mark dev status to allow new incoming requests */
	ndev->dev_status = AIE4_DEV_START;

	mutex_unlock(&ndev->aie4_lock);

	XDNA_INFO(xdna, "reset done finished");
	return 0;

error:
	mutex_unlock(&ndev->aie4_lock);
	return ret;
}

static void aie4_hw_suspend(struct amdxdna_dev *xdna)
{
	struct amdxdna_dev_hdl *ndev = xdna->dev_handle;

	mutex_lock(&ndev->aie4_lock);
	aie4_ctx_suspend_all(xdna);
	aie4_hw_stop(xdna);
	mutex_unlock(&ndev->aie4_lock);
}

static int aie4_hw_resume(struct amdxdna_dev *xdna)
{
	struct amdxdna_dev_hdl *ndev = xdna->dev_handle;
	int ret;

	ret = aie4_hw_start(xdna);
	if (ret) {
		XDNA_ERR(xdna, "resume hw failed ret %d", ret);
		return ret;
	}

	mutex_lock(&ndev->aie4_lock);
	ret = aie4_partition_init(ndev);
	if (ret)
		goto hw_stop;

	aie4_ctx_resume_all(xdna);
	mutex_unlock(&ndev->aie4_lock);

	return 0;
hw_stop:
	aie4_hw_stop(xdna);
	mutex_unlock(&ndev->aie4_lock);

	return ret;
}

static void aie4_iommu_fini(struct amdxdna_dev_hdl *ndev)
{
#ifdef AMDXDNA_DEVEL
	if (iommu_mode != AMDXDNA_IOMMU_PASID)
		return;
#endif

#ifdef HAVE_iommu_dev_enable_disable_feature
	iommu_dev_disable_feature(ndev->xdna->ddev.dev, IOMMU_DEV_FEAT_SVA);
#endif
}

static void aie4_pcidev_fini(struct amdxdna_dev_hdl *ndev)
{
	struct amdxdna_dev *xdna = ndev->xdna;

	mutex_lock(&ndev->aie4_lock);
	aie4_hw_stop(xdna);
	mutex_unlock(&ndev->aie4_lock);
	aie4_free_work_buffer(ndev);
}

static void aie4_pci_fini(struct amdxdna_dev *xdna)
{
	struct amdxdna_dev_hdl *ndev = xdna->dev_handle;

	aie4_iommu_fini(ndev);

	aie4_pcidev_fini(ndev);

	mutex_destroy(&ndev->aie4_lock);
}

static int aie4_iommu_init(struct amdxdna_dev_hdl *ndev)
{
	struct amdxdna_dev *xdna = ndev->xdna;
	int ret;

#ifdef AMDXDNA_DEVEL
	ret = amdxdna_iommu_mode_setup(xdna);
	if (ret) {
		XDNA_ERR(xdna, "Setup iommu mode %d failed, ret %d", iommu_mode, ret);
		return ret;
	}
	if (iommu_mode != AMDXDNA_IOMMU_PASID)
		goto skip_pasid;
#endif

#ifdef HAVE_iommu_dev_enable_disable_feature
	ret = iommu_dev_enable_feature(xdna->ddev.dev, IOMMU_DEV_FEAT_SVA);
	if (ret) {
		XDNA_ERR(xdna, "Enable PASID failed, ret %d", ret);
		return ret;
	}
#endif

#ifdef AMDXDNA_DEVEL
skip_pasid:
	XDNA_INFO(xdna, "(Develop) IOMMU mode is %d", iommu_mode);
#endif

	return ret;
}

static int aie4_pci_init(struct amdxdna_dev *xdna)
{
	struct pci_dev *pdev = to_pci_dev(xdna->ddev.dev);
	struct init_config xrs_cfg = { 0 };
	struct amdxdna_dev_hdl *ndev;
	int ret;

	ndev = devm_kzalloc(&pdev->dev, sizeof(*ndev), GFP_KERNEL);
	if (!ndev)
		return -ENOMEM;

	ndev->priv = xdna->dev_info->dev_priv;
	ndev->xdna = xdna;
	xdna->dev_handle = ndev;
	mutex_init(&ndev->aie4_lock);

	/*
	 * irq is dynamic per lead column, which is managed by context create/destroy.
	 * all live columns are stored in col_entry_list.
	 */
	mutex_init(&ndev->col_list_lock);
	INIT_LIST_HEAD(&ndev->col_entry_list);

	ret = aie4_pcidev_init(ndev);
	if (ret) {
		XDNA_ERR(xdna, "Setup PCI device failed, ret %d", ret);
		return ret;
	}

	ret = aie4_iommu_init(ndev);
	if (ret)
		goto pcidev_fini;

	ndev->pw_mode = POWER_MODE_DEFAULT;

	/* the metadata.cols should be get via ipu_msg_mailbox */
	xrs_cfg.clk_list.num_levels = 3;
	xrs_cfg.clk_list.cu_clk_list[0] = 0;
	xrs_cfg.clk_list.cu_clk_list[1] = 800;
	xrs_cfg.clk_list.cu_clk_list[2] = 1000;
	xrs_cfg.sys_eff_factor = 1;
	xrs_cfg.dev = xdna->ddev.dev;
	xrs_cfg.mode = XRS_MODE_SPATIAL_STATIC;
	xrs_cfg.total_col = 10;

	xrs_cfg.actions = &aie4_xrs_actions;

	ndev->xrs_hdl = aie4_xrsm_init(&xrs_cfg);
	if (!ndev->xrs_hdl) {
		XDNA_ERR(xdna, "Initialize resolver failed");
		ret = -EINVAL;
		goto iommu_fini;
	}

	XDNA_DBG(xdna, "aie4 init finished");
	return 0;

iommu_fini:
	aie4_iommu_fini(ndev);
pcidev_fini:
	aie4_pcidev_fini(ndev);

	return ret;
}

static int aie4_doorbell_mmap(struct amdxdna_dev *xdna, struct vm_area_struct *vma)
{
	struct pci_dev *pdev = to_pci_dev(xdna->ddev.dev);
	const struct amdxdna_dev_priv *npriv = xdna->dev_info->dev_priv;
	phys_addr_t res_start, res_end;
	unsigned long pfn;
	int ret;

	XDNA_DBG(xdna, "mmap res at bar %d, off 0x%x",
		 xdna->dev_info->doorbell_bar, npriv->doorbell_off);

	res_start = pci_resource_start(pdev, xdna->dev_info->doorbell_bar) + npriv->doorbell_off;
	res_end = pci_resource_end(pdev, xdna->dev_info->doorbell_bar);
	pfn = (res_start >> PAGE_SHIFT) + vma->vm_pgoff;
	if (pfn > (res_end >> PAGE_SHIFT)) {
		XDNA_ERR(xdna, "Invalid doorbell page offset 0x%lx", vma->vm_pgoff);
		return -EINVAL;
	}

	vma->vm_page_prot = pgprot_noncached(vma->vm_page_prot);
	vm_flags_set(vma, VM_IO | VM_DONTEXPAND | VM_DONTDUMP);
	ret = io_remap_pfn_range(vma, vma->vm_start,
				 pfn,
				 PAGE_SIZE,
				 vma->vm_page_prot);

	XDNA_DBG(xdna, "mmap of pfn 0x%lx ret: %d", pfn, ret);
	return ret;
}

static int aie4_query_status(struct amdxdna_client *client,
			     struct amdxdna_drm_get_info *args)
{
	struct amdxdna_drm_query_aie_status status;
	struct amdxdna_dev *xdna = client->xdna;
	struct amdxdna_dev_hdl *ndev;
	int ret, min;

	if (!access_ok(u64_to_user_ptr(args->buffer), args->buffer_size)) {
		XDNA_ERR(xdna, "Failed to access buffer size %d", args->buffer_size);
		return -EFAULT;
	}

	ndev = xdna->dev_handle;
	min = min(args->buffer_size, sizeof(status));
	if (copy_from_user(&status, u64_to_user_ptr(args->buffer), min)) {
		XDNA_ERR(xdna, "Failed to copy AIE request into kernel");
		return -EFAULT;
	}

	if (ndev->metadata.cols * ndev->metadata.size > status.buffer_size) {
		XDNA_ERR(xdna, "Invalid buffer size. Given Size: %u. Need Size: %u.",
			 status.buffer_size, ndev->metadata.cols * ndev->metadata.size);
		return -EINVAL;
	}

	ret = aie4_query_aie_status(ndev, u64_to_user_ptr(status.buffer),
				    status.buffer_size, &status.cols_filled);
	if (ret) {
		XDNA_ERR(xdna, "Failed to get AIE status info. Ret: %d", ret);
		return ret;
	}

	if (copy_to_user(u64_to_user_ptr(args->buffer), &status, min)) {
		XDNA_ERR(xdna, "Failed to copy AIE request info to user space");
		return -EFAULT;
	}

	return 0;
}

static int aie4_query_metadata(struct amdxdna_client *client,
			       struct amdxdna_drm_get_info *args)
{
	struct amdxdna_drm_query_aie_metadata *meta;
	struct amdxdna_dev *xdna = client->xdna;
	struct amdxdna_dev_hdl *ndev;
	int ret = 0;
	int min;

	if (!access_ok(u64_to_user_ptr(args->buffer), args->buffer_size)) {
		XDNA_ERR(xdna, "Failed to access buffer size %d", args->buffer_size);
		return -EFAULT;
	}

	ndev = xdna->dev_handle;
	min = min(args->buffer_size, sizeof(*meta));
	meta = kzalloc(sizeof(*meta), GFP_KERNEL);
	if (!meta)
		return -ENOMEM;

	meta->col_size = ndev->metadata.size;
	meta->cols = ndev->metadata.cols;
	meta->rows = ndev->metadata.rows;

	meta->version.major = ndev->metadata.version.major;
	meta->version.minor = ndev->metadata.version.minor;

	meta->core.row_count = ndev->metadata.core.row_count;
	meta->core.row_start = ndev->metadata.core.row_start;
	meta->core.dma_channel_count = ndev->metadata.core.dma_channel_count;
	meta->core.lock_count = ndev->metadata.core.lock_count;
	meta->core.event_reg_count = ndev->metadata.core.event_reg_count;

	meta->mem.row_count = ndev->metadata.mem.row_count;
	meta->mem.row_start = ndev->metadata.mem.row_start;
	meta->mem.dma_channel_count = ndev->metadata.mem.dma_channel_count;
	meta->mem.lock_count = ndev->metadata.mem.lock_count;
	meta->mem.event_reg_count = ndev->metadata.mem.event_reg_count;

	meta->shim.row_count = ndev->metadata.shim.row_count;
	meta->shim.row_start = ndev->metadata.shim.row_start;
	meta->shim.dma_channel_count = ndev->metadata.shim.dma_channel_count;
	meta->shim.lock_count = ndev->metadata.shim.lock_count;
	meta->shim.event_reg_count = ndev->metadata.shim.event_reg_count;

	if (copy_to_user(u64_to_user_ptr(args->buffer), meta, min))
		ret = -EFAULT;

	kfree(meta);
	return ret;
}

static int aie4_query_version(struct amdxdna_client *client,
			      struct amdxdna_drm_get_info *args)
{
	struct amdxdna_drm_query_aie_version version;
	struct amdxdna_dev *xdna = client->xdna;
	struct amdxdna_dev_hdl *ndev;
	int min;

	if (!access_ok(u64_to_user_ptr(args->buffer), args->buffer_size)) {
		XDNA_ERR(xdna, "Failed to access buffer size %d", args->buffer_size);
		return -EFAULT;
	}

	ndev = xdna->dev_handle;
	version.major = ndev->version.major;
	version.minor = ndev->version.minor;

	min = min(args->buffer_size, sizeof(version));
	if (copy_to_user(u64_to_user_ptr(args->buffer), &version, min))
		return -EFAULT;

	return 0;
}

static int aie4_query_clock_metadata(struct amdxdna_client *client,
				     struct amdxdna_drm_get_info *args)
{
	struct amdxdna_drm_query_clock_metadata clock = {};
	struct amdxdna_dev *xdna = client->xdna;
	struct amdxdna_dev_hdl *ndev;
	int ret = 0;
	int min;

	if (!access_ok(u64_to_user_ptr(args->buffer), args->buffer_size)) {
		XDNA_ERR(xdna, "Failed to access buffer size %d", args->buffer_size);
		return -EFAULT;
	}

	ndev = xdna->dev_handle;

	snprintf(clock.mp_npu_clock.name, sizeof(clock.mp_npu_clock.name),
		 "MP-NPU Clock");
	clock.mp_npu_clock.freq_mhz = ndev->mp_npu_clock.freq_mhz;
	snprintf(clock.h_clock.name, sizeof(clock.h_clock.name), "H Clock");
	clock.h_clock.freq_mhz = ndev->h_clock.freq_mhz;

	min = min(args->buffer_size, sizeof(clock));
	if (copy_to_user(u64_to_user_ptr(args->buffer), &clock, min))
		ret = -EFAULT;

	return ret;
}

static int aie4_query_sensors(struct amdxdna_client *client,
			      struct amdxdna_drm_get_info *args)
{
	struct amdxdna_drm_query_sensor *sensor;
	struct amdxdna_dev *xdna = client->xdna;
	int ret = 0;
	int min;

	if (!access_ok(u64_to_user_ptr(args->buffer), args->buffer_size)) {
		XDNA_ERR(xdna, "Failed to access buffer size %d", args->buffer_size);
		return -EFAULT;
	}

	min = min(args->buffer_size, sizeof(*sensor));
	sensor = kzalloc(sizeof(*sensor), GFP_KERNEL);
	if (!sensor)
		return -ENOMEM;

	sensor->type = AMDXDNA_SENSOR_TYPE_POWER;
	sensor->input = __UINT32_MAX__; /* TODO: query the device and get the power data */
	sensor->unitm = -3; /* in milliwatts */
	snprintf(sensor->label, sizeof(sensor->label), "Total Power");
	snprintf(sensor->units, sizeof(sensor->units), "mW");

	if (copy_to_user(u64_to_user_ptr(args->buffer), sensor, min))
		ret = -EFAULT;

	kfree(sensor);
	return ret;
}

static int aie4_get_power_mode(struct amdxdna_client *client,
			       struct amdxdna_drm_get_info *args)
{
	struct amdxdna_drm_get_power_mode mode = {};
	struct amdxdna_dev *xdna = client->xdna;
	struct amdxdna_dev_hdl *ndev;
	int min;

	if (!access_ok(u64_to_user_ptr(args->buffer), args->buffer_size)) {
		XDNA_ERR(xdna, "Failed to access buffer size %d", args->buffer_size);
		return -EFAULT;
	}

	ndev = xdna->dev_handle;
	mode.power_mode = ndev->pw_mode;

	min = min(args->buffer_size, sizeof(mode));
	if (copy_to_user(u64_to_user_ptr(args->buffer), &mode, min))
		return -EFAULT;

	return 0;
}

static int aie4_query_ctx_status(struct amdxdna_client *client,
				 struct amdxdna_drm_get_info *args)
{
	struct amdxdna_drm_query_hwctx __user *buf;
	struct amdxdna_dev *xdna = client->xdna;
	struct amdxdna_drm_query_hwctx *tmp;
	struct amdxdna_client *tmp_client;
	struct amdxdna_ctx *ctx;
	unsigned long ctx_id;
	bool overflow = false;
	u32 req_bytes = 0;
	u32 hw_i = 0;
	int ret = 0;
	int idx;

	buf = u64_to_user_ptr(args->buffer);
	if (!access_ok(buf, args->buffer_size)) {
		XDNA_ERR(xdna, "Failed to access buffer size %d", args->buffer_size);
		return -EFAULT;
	}

	tmp = kzalloc(sizeof(*tmp), GFP_KERNEL);
	if (!tmp)
		return -ENOMEM;

	mutex_lock(&xdna->dev_lock);
	list_for_each_entry(tmp_client, &xdna->client_list, node) {
		idx = srcu_read_lock(&tmp_client->ctx_srcu);
		amdxdna_for_each_ctx(tmp_client, ctx_id, ctx) {
			if (!ctx->priv)
				continue;

			req_bytes += sizeof(*tmp);
			if (args->buffer_size < req_bytes) {
				/* Continue iterating to get the required size */
				overflow = true;
				continue;
			}

			tmp->pid = tmp_client->pid;
			tmp->context_id = ctx->id;
			tmp->start_col = ctx->start_col;
			tmp->num_col = ctx->num_col;
			tmp->command_submissions = ctx->submitted;
			tmp->command_completions = ctx->completed;
			tmp->migrations = 0;
			tmp->preemptions = 0;
			tmp->errors = 0;

			if (copy_to_user(&buf[hw_i], tmp, sizeof(*tmp))) {
				ret = -EFAULT;
				srcu_read_unlock(&tmp_client->ctx_srcu, idx);
				goto out;
			}
			hw_i++;
		}
		srcu_read_unlock(&tmp_client->ctx_srcu, idx);
	}

	if (overflow) {
		XDNA_ERR(xdna, "Invalid buffer size. Given: %u Need: %u.",
			 args->buffer_size, req_bytes);
		ret = -EINVAL;
	}

out:
	mutex_unlock(&xdna->dev_lock);
	kfree(tmp);
	args->buffer_size = req_bytes;
	return ret;
}

static int aie4_query_telemetry(struct amdxdna_client *client,
				struct amdxdna_drm_get_info *args)
{
	struct amdxdna_dev *xdna = client->xdna;
	struct amdxdna_mgmt_dma_hdl *dma_hdl;
	struct amdxdna_dev_hdl *ndev;
	dma_addr_t dma_addr;
	size_t aligned_sz, size;
	void *buff;
	u32 type;
	int ret;

	if (!access_ok(u64_to_user_ptr(args->buffer), args->buffer_size)) {
		XDNA_ERR(xdna, "Failed to access buffer size %d", args->buffer_size);
		return -EFAULT;
	}

	if (copy_from_user(&type, u64_to_user_ptr(args->buffer), sizeof(type))) {
		XDNA_ERR(xdna, "Failed to copy telemetry type from user");
		return -EFAULT;
	}

	/* AIE4 firmware requires minimum 128KB buffer for telemetry */
	ndev = xdna->dev_handle;
	size = max_t(size_t, args->buffer_size, SZ_128K);

	if (args->buffer_size < SZ_128K)
		XDNA_DBG(xdna, "Telemetry: user buffer %u bytes < minimum %u bytes",
			 args->buffer_size, SZ_128K);

	dma_hdl = amdxdna_mgmt_buff_alloc(xdna, size, DMA_FROM_DEVICE);
	if (IS_ERR(dma_hdl))
		return PTR_ERR(dma_hdl);

	buff = amdxdna_mgmt_buff_get_cpu_addr(dma_hdl, 0);
	if (IS_ERR(buff)) {
		XDNA_ERR(xdna, "Failed to get CPU address for telemetry buffer");
		ret = PTR_ERR(buff);
		goto free_buf;
	}

	dma_addr = amdxdna_mgmt_buff_get_dma_addr(dma_hdl);
	aligned_sz = dma_hdl->aligned_size;

	memset(buff, 0, aligned_sz);
	amdxdna_mgmt_buff_clflush(dma_hdl, 0, 0);
	ret = aie4_query_aie_telemetry(ndev, type, dma_addr, aligned_sz);
	if (ret) {
		XDNA_ERR(xdna, "Get telemetry failed ret %d", ret);
		goto free_buf;
	}

	if (copy_to_user(u64_to_user_ptr(args->buffer), buff, args->buffer_size))
		ret = -EFAULT;

free_buf:
	amdxdna_mgmt_buff_free(dma_hdl);
	return ret;
}

static int aie4_query_firmware_version(struct amdxdna_client *client,
				       struct amdxdna_drm_get_info *args)
{
	struct amdxdna_drm_query_firmware_version version;
	struct amdxdna_dev *xdna = client->xdna;
	int min;

	if (!access_ok(u64_to_user_ptr(args->buffer), args->buffer_size)) {
		XDNA_ERR(xdna, "Failed to access buffer size %d", args->buffer_size);
		return -EFAULT;
	}

	version.major = xdna->fw_ver.major;
	version.minor = xdna->fw_ver.minor;
	version.patch = xdna->fw_ver.sub;
	version.build = xdna->fw_ver.build;

	min = min(args->buffer_size, sizeof(version));
	if (copy_to_user(u64_to_user_ptr(args->buffer), &version, min))
		return -EFAULT;

	return 0;
}

static int aie4_get_force_preempt_state(struct amdxdna_client *client,
					struct amdxdna_drm_get_info *args)
{
	struct amdxdna_drm_attribute_state force = {};
	struct amdxdna_dev *xdna = client->xdna;
	struct amdxdna_dev_hdl *ndev;
	int min;

	if (!access_ok(u64_to_user_ptr(args->buffer), args->buffer_size)) {
		XDNA_ERR(xdna, "Failed to access buffer size %d", args->buffer_size);
		return -EFAULT;
	}

	ndev = xdna->dev_handle;
	force.state = ndev->force_preempt_enabled ? 1 : 0;

	min = min(args->buffer_size, sizeof(force));
	if (copy_to_user(u64_to_user_ptr(args->buffer), &force, min))
		return -EFAULT;

	return 0;
}

static int aie4_get_frame_boundary_preempt_state(struct amdxdna_client *client,
						 struct amdxdna_drm_get_info *args)
{
	struct amdxdna_drm_attribute_state preempt = {};
	struct amdxdna_dev *xdna = client->xdna;
	int min;

	if (!access_ok(u64_to_user_ptr(args->buffer), args->buffer_size)) {
		XDNA_ERR(xdna, "Failed to access buffer size %d", args->buffer_size);
		return -EFAULT;
	}

	preempt.state = 1;

	min = min(args->buffer, sizeof(preempt));
	if (copy_to_user(u64_to_user_ptr(args->buffer), &preempt, min))
		return -EFAULT;

	return 0;
}

static int aie4_get_info(struct amdxdna_client *client, struct amdxdna_drm_get_info *args)
{
	struct amdxdna_dev *xdna = client->xdna;
	int ret;

	ret = amdxdna_pm_resume_get(xdna);
	if (ret)
		return ret;

	mutex_lock(&xdna->dev_lock);
	mutex_lock(&xdna->dev_handle->aie4_lock);
	switch (args->param) {
	case DRM_AMDXDNA_QUERY_AIE_STATUS:
		ret = aie4_query_status(client, args);
		break;
	case DRM_AMDXDNA_QUERY_AIE_METADATA:
		ret = aie4_query_metadata(client, args);
		break;
	case DRM_AMDXDNA_QUERY_AIE_VERSION:
		ret = aie4_query_version(client, args);
		break;
	case DRM_AMDXDNA_QUERY_CLOCK_METADATA:
		ret = aie4_query_clock_metadata(client, args);
		break;
	case DRM_AMDXDNA_QUERY_SENSORS:
		ret = aie4_query_sensors(client, args);
		break;
	case DRM_AMDXDNA_QUERY_HW_CONTEXTS:
		ret = aie4_query_ctx_status(client, args);
		break;
	case DRM_AMDXDNA_QUERY_FIRMWARE_VERSION:
		ret = aie4_query_firmware_version(client, args);
		break;
	case DRM_AMDXDNA_QUERY_TELEMETRY:
		ret = aie4_query_telemetry(client, args);
		break;
	case DRM_AMDXDNA_GET_POWER_MODE:
		ret = aie4_get_power_mode(client, args);
		break;
	case DRM_AMDXDNA_GET_FORCE_PREEMPT_STATE:
		ret = aie4_get_force_preempt_state(client, args);
		break;
	case DRM_AMDXDNA_GET_FRAME_BOUNDARY_PREEMPT_STATE:
		ret = aie4_get_frame_boundary_preempt_state(client, args);
		break;
	default:
		XDNA_ERR(xdna, "Not supported request parameter %u", args->param);
		ret = -EOPNOTSUPP;
	}
	mutex_unlock(&xdna->dev_handle->aie4_lock);
	mutex_unlock(&xdna->dev_lock);
	amdxdna_pm_suspend_put(xdna);
	XDNA_DBG(xdna, "Got param %d", args->param);

	return ret;
}

static int aie4_get_array_async_error(struct amdxdna_dev *xdna, struct amdxdna_drm_get_array *args)
{
	struct amdxdna_async_error tmp;
	int ret;

	ret = aie4_error_get_last_async(xdna, &xdna->dev_handle->async_errs_cache, 1, &tmp);
	if (ret < 0)
		goto exit;

	ret = amdxdna_drm_copy_array_to_user(args, &tmp, sizeof(tmp), ret);
exit:
	return ret;
}

static int aie4_get_ctx_status_array(struct amdxdna_client *client,
				     struct amdxdna_drm_get_array *args)
{
	struct amdxdna_drm_hwctx_entry __user *buf;
	struct amdxdna_drm_hwctx_entry *tmp;
	struct amdxdna_dev *xdna = client->xdna;
	struct amdxdna_client *tmp_client;
	struct amdxdna_ctx *ctx;
	unsigned long ctx_id;
	int idx, min, i;
	u32 hw_i = 0;
	u32 buf_size;
	int ret = 0;

	buf_size = args->num_element * args->element_size;
	buf = u64_to_user_ptr(args->buffer);
	if (!access_ok(buf, buf_size)) {
		XDNA_ERR(xdna, "Failed to access buffer, element num %d size 0x%x",
			 args->num_element, args->element_size);
		return -EFAULT;
	}

	tmp = kcalloc(args->num_element, sizeof(*tmp), GFP_KERNEL);
	if (!tmp)
		return -ENOMEM;

	mutex_lock(&xdna->dev_lock);

	list_for_each_entry(tmp_client, &xdna->client_list, node) {
		int heap_usage;

		mutex_lock(&tmp_client->mm_lock);
		heap_usage = tmp_client->heap_usage;
		mutex_unlock(&tmp_client->mm_lock);

		idx = srcu_read_lock(&tmp_client->ctx_srcu);
		amdxdna_for_each_ctx(tmp_client, ctx_id, ctx) {
			if (!ctx->priv)
				continue;

			if (hw_i >= args->num_element) {
				hw_i++;
				continue;
			}

			tmp[hw_i].pid = tmp_client->pid;
			tmp[hw_i].context_id = ctx->id;
			tmp[hw_i].hwctx_id = ctx->priv->hw_ctx_id;
			tmp[hw_i].start_col = ctx->start_col;
			tmp[hw_i].num_col = ctx->num_col;
			tmp[hw_i].command_submissions = ctx->submitted;
			tmp[hw_i].command_completions = ctx->completed;
			tmp[hw_i].migrations = 0;
			tmp[hw_i].preemptions = 0;
			tmp[hw_i].errors = 0;
			tmp[hw_i].pasid = tmp_client->pasid;
			tmp[hw_i].priority = aie4_parse_priority(ctx->qos.priority);
			tmp[hw_i].gops = ctx->qos.gops;
			tmp[hw_i].fps = ctx->qos.fps;
			tmp[hw_i].dma_bandwidth = ctx->qos.dma_bandwidth;
			tmp[hw_i].latency = ctx->qos.latency;
			tmp[hw_i].frame_exec_time = ctx->qos.frame_exec_time;
			tmp[hw_i].heap_usage = heap_usage;

			hw_i++;
		}
		srcu_read_unlock(&tmp_client->ctx_srcu, idx);
	}

	if (hw_i >= args->num_element) {
		XDNA_DBG(xdna, "Not enough space for all ctx. Total ctx %d, requested %d",
			 hw_i, args->num_element);
		kfree(tmp);
		args->num_element = hw_i;
		return -ENOSPC;
	}

	min = min(args->element_size, sizeof(*tmp));
	for (i = 0; i < hw_i; i++) {
		if (copy_to_user(&buf[i], &tmp[i], min)) {
			ret = -EFAULT;
			break;
		}
	}

	mutex_unlock(&xdna->dev_lock);

	kfree(tmp);
	args->element_size = min;
	args->num_element = hw_i;
	return ret;
}

static int aie4_get_array(struct amdxdna_client *client, struct amdxdna_drm_get_array *args)
{
	struct amdxdna_dev *xdna = client->xdna;
	int ret;

	ret = amdxdna_pm_resume_get(xdna);
	if (ret)
		return ret;

	switch (args->param) {
	case DRM_AMDXDNA_HW_LAST_ASYNC_ERR:
		ret = aie4_get_array_async_error(xdna, args);
		break;
	case DRM_AMDXDNA_HW_CONTEXT_ALL:
		ret = aie4_get_ctx_status_array(client, args);
		break;
	case DRM_AMDXDNA_FW_LOG:
		ret = amdxdna_get_fw_log(xdna, args);
		break;
	case DRM_AMDXDNA_FW_TRACE:
		ret = amdxdna_get_fw_trace(xdna, args);
		break;
	case DRM_AMDXDNA_FW_LOG_CONFIG:
		ret = amdxdna_get_fw_log_configs(xdna, args);
		break;
	case DRM_AMDXDNA_FW_TRACE_CONFIG:
		ret = amdxdna_get_fw_trace_configs(xdna, args);
		break;
	default:
		XDNA_ERR(xdna, "Not supported request parameter %u", args->param);
		ret = -EOPNOTSUPP;
	}

	amdxdna_pm_suspend_put(xdna);
	XDNA_DBG(xdna, "Got param %d", args->param);

	return ret;
}

static int aie4_set_power_mode(struct amdxdna_client *client, struct amdxdna_drm_set_state *args)
{
	struct amdxdna_drm_set_power_mode power_state;
	struct amdxdna_dev *xdna = client->xdna;
	int power_mode, min;

	if (!access_ok(u64_to_user_ptr(args->buffer), args->buffer_size)) {
		XDNA_ERR(xdna, "Failed to access buffer size %d", args->buffer_size);
		return -EFAULT;
	}

	min = min(args->buffer_size, sizeof(power_state));
	if (copy_from_user(&power_state, u64_to_user_ptr(args->buffer), min)) {
		XDNA_ERR(xdna, "Failed to copy power mode request into kernel");
		return -EFAULT;
	}

	power_mode = power_state.power_mode;
	if (power_mode > POWER_MODE_TURBO) {
		XDNA_ERR(xdna, "Invalid power mode %d", power_mode);
		return -EINVAL;
	}

	return aie4_pm_set_mode(xdna->dev_handle, power_mode);
}

static int aie4_set_force_preempt_state(struct amdxdna_client *client,
					struct amdxdna_drm_set_state *args)
{
	struct amdxdna_drm_attribute_state force;
	struct amdxdna_dev *xdna = client->xdna;
	int min;

	if (!access_ok(u64_to_user_ptr(args->buffer), args->buffer_size)) {
		XDNA_ERR(xdna, "Failed to access buffer size %d", args->buffer_size);
		return -EFAULT;
	}

	min = min(args->buffer_size, sizeof(force));
	if (copy_from_user(&force, u64_to_user_ptr(args->buffer), min))
		return -EFAULT;

	if (force.state && force.state > 1) {
		XDNA_ERR(xdna, "Invalid state: %d", force.state);
		return -EINVAL;
	}

	xdna->dev_handle->force_preempt_enabled = force.state;

	XDNA_DBG(xdna, "Force preemption %s", force.state ? "enabled" : "disabled");

	return 0;
}

static int aie4_set_state(struct amdxdna_client *client, struct amdxdna_drm_set_state *args)
{
	struct amdxdna_dev *xdna = client->xdna;
	int ret;

	ret = amdxdna_pm_resume_get(xdna);
	if (ret)
		return ret;

	switch (args->param) {
	case DRM_AMDXDNA_SET_POWER_MODE:
		mutex_lock(&xdna->dev_handle->aie4_lock);
		ret = aie4_set_power_mode(client, args);
		mutex_unlock(&xdna->dev_handle->aie4_lock);
		break;
	case DRM_AMDXDNA_SET_FORCE_PREEMPT:
		mutex_lock(&xdna->dev_handle->aie4_lock);
		ret = aie4_set_force_preempt_state(client, args);
		mutex_unlock(&xdna->dev_handle->aie4_lock);
		break;
	case DRM_AMDXDNA_SET_FW_LOG_STATE:
		ret = amdxdna_set_fw_log_state(xdna, args);
		break;
	case DRM_AMDXDNA_SET_FW_TRACE_STATE:
		ret = amdxdna_set_fw_trace_state(xdna, args);
		break;
	default:
		XDNA_ERR(xdna, "Not supported request parameter %u", args->param);
		ret = -EOPNOTSUPP;
	}

	amdxdna_pm_suspend_put(xdna);
	return ret;
}

const struct amdxdna_dev_ops aie4_ops = {
	.mmap			= aie4_doorbell_mmap,
	.init			= aie4_pci_init,
	.fini			= aie4_pci_fini,
	.resume			= aie4_hw_resume,
	.suspend		= aie4_hw_suspend,
	.fw_log_init		= aie4_fw_log_init,
	.fw_log_config		= aie4_fw_log_config,
	.fw_log_fini		= aie4_fw_log_fini,
	.fw_log_parse		= aie4_fw_log_parse,
	.fw_trace_init		= aie4_fw_trace_init,
	.fw_trace_config	= aie4_fw_trace_config,
	.fw_trace_fini		= aie4_fw_trace_fini,
	.fw_trace_parse		= aie4_fw_trace_parse,
	.reset_prepare		= aie4_reset_prepare,
	.reset_done		= aie4_reset_done,
	.get_aie_info		= aie4_get_info,
	.get_aie_array		= aie4_get_array,
	.set_aie_state		= aie4_set_state,
	.ctx_init		= aie4_ctx_init,
	.ctx_fini		= aie4_ctx_fini,
	.ctx_config		= aie4_ctx_config,
	.cmd_submit		= aie4_cmd_submit,
	.cmd_wait		= aie4_cmd_wait,
	.debugfs		= aie4_debugfs_init,
	.sriov_configure        = aie4_sriov_configure,
};

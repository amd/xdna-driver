// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2023-2024, Advanced Micro Devices, Inc.
 */

#include <linux/errno.h>
#include <linux/kthread.h>
#include <linux/iommu.h>
#include "drm_local/amdxdna_accel.h"

#include "ipu_common.h"
#include "ipu_error.h"
#include "ipu_pci.h"
#ifdef AMDXDNA_DEVEL
#include "amdxdna_devel.h"
#endif

/*
 * The management mailbox channel is allocated by IPU firmware.
 * The related register and ring buffer information is on SRAM BAR.
 * This struct is the register layout.
 */
struct mgmt_mbox_chann_info {
	u32	x2i_tail;
	u32	x2i_head;
	u32	x2i_buf;
	u32	x2i_buf_sz;
	u32	i2x_tail;
	u32	i2x_head;
	u32	i2x_buf;
	u32	i2x_buf_sz;
};

static int ipu_setup_pcidev(struct ipu_device *idev)
{
	struct amdxdna_dev *xdna = idev->xdna;
	int bar_mask, nvec;
	int ret;

	ret = dma_set_mask_and_coherent(&xdna->pdev->dev, DMA_BIT_MASK(64));
	if (ret) {
		XDNA_ERR(xdna, "Failed to set DMA mask: %d", ret);
		return ret;
	}

	/* Enable managed PCI device */
	ret = pcim_enable_device(xdna->pdev);
	if (ret) {
		XDNA_ERR(xdna, "pcim enable device failed, ret %d", ret);
		return ret;
	}

	/* Need to enable IPU device master capability for MSI interrupt and DMA */
	pci_set_master(xdna->pdev);

	bar_mask = pci_select_bars(xdna->pdev, IORESOURCE_MEM);
	ret = pcim_iomap_regions(xdna->pdev, bar_mask, "amdxdna-ipu");
	if (ret) {
		XDNA_ERR(xdna, "map regions failed, ret %d", ret);
		return ret;
	}

	nvec = pci_msix_vec_count(xdna->pdev);
	ret = pci_alloc_irq_vectors(xdna->pdev, nvec, nvec, PCI_IRQ_MSIX);
	if (ret < 0) {
		XDNA_ERR(xdna, "failed to alloc irq vectors, ret %d", ret);
		return ret;
	}

	return 0;
}

static void ipu_teardown_pcidev(struct ipu_device *idev)
{
	struct amdxdna_dev *xdna = idev->xdna;

	pci_free_irq_vectors(xdna->pdev);
	pci_clear_master(xdna->pdev);
}

static inline void ipu_dump_chann_info_debug(struct ipu_device *idev)
{
	struct amdxdna_dev *xdna = idev->xdna;

	XDNA_DBG(xdna, "i2x tail    0x%x", idev->mgmt_i2x.mb_tail_ptr_reg);
	XDNA_DBG(xdna, "i2x head    0x%x", idev->mgmt_i2x.mb_head_ptr_reg);
	XDNA_DBG(xdna, "i2x ringbuf 0x%x", idev->mgmt_i2x.rb_start_addr);
	XDNA_DBG(xdna, "i2x rsize   0x%x", idev->mgmt_i2x.rb_size);
	XDNA_DBG(xdna, "x2i tail    0x%x", idev->mgmt_x2i.mb_tail_ptr_reg);
	XDNA_DBG(xdna, "x2i head    0x%x", idev->mgmt_x2i.mb_head_ptr_reg);
	XDNA_DBG(xdna, "x2i ringbuf 0x%x", idev->mgmt_x2i.rb_start_addr);
	XDNA_DBG(xdna, "x2i rsize   0x%x", idev->mgmt_x2i.rb_size);
	XDNA_DBG(xdna, "x2i chann index 0x%x", idev->mgmt_chan_idx);
}

static int ipu_get_mgmt_chann_info(struct ipu_device *idev)
{
	struct mgmt_mbox_chann_info info_regs;
	struct xdna_mailbox_chann_res *i2x;
	struct xdna_mailbox_chann_res *x2i;
	u32 addr, off;
	u32 *reg;
	int ret;
	int i;

	/*
	 * Once IPU firmware is alive, it will write management channel
	 * information in SRAM BAR and write the address of that information
	 * at FW_ALIVE_OFF offset in SRMA BAR.
	 *
	 * Read a non-zero value from FW_ALIVE_OFF implies that firmware
	 * is alive.
	 */
	ret = readx_poll_timeout(readl, SRAM_GET_ADDR(idev, FW_ALIVE_OFF),
				 addr, addr, IPU_INTERVAL, IPU_TIMEOUT);
	if (ret || !addr)
		return -ETIME;

	off = IPU_SRAM_OFF(idev, addr);
	reg = (u32 *)&info_regs;
	for (i = 0; i < sizeof(info_regs) / sizeof(u32); i++)
		reg[i] = readl(idev->sram_base + off + i * sizeof(u32));

	i2x = &idev->mgmt_i2x;
	x2i = &idev->mgmt_x2i;

	i2x->mb_head_ptr_reg = IPU_MBOX_OFF(idev, info_regs.i2x_head);
	i2x->mb_tail_ptr_reg = IPU_MBOX_OFF(idev, info_regs.i2x_tail);
	i2x->rb_start_addr   = IPU_SRAM_OFF(idev, info_regs.i2x_buf);
	i2x->rb_size         = info_regs.i2x_buf_sz;

	x2i->mb_head_ptr_reg = IPU_MBOX_OFF(idev, info_regs.x2i_head);
	x2i->mb_tail_ptr_reg = IPU_MBOX_OFF(idev, info_regs.x2i_tail);
	x2i->rb_start_addr   = IPU_SRAM_OFF(idev, info_regs.x2i_buf);
	x2i->rb_size         = info_regs.x2i_buf_sz;
	idev->mgmt_chan_idx  = CHANN_INDEX(idev, x2i->rb_start_addr);

	ipu_dump_chann_info_debug(idev);

	/* Must clear address at FW_ALIVE_OFF */
	writel(0, SRAM_GET_ADDR(idev, FW_ALIVE_OFF));

	return 0;
}

static int ipu_xdna_reset(struct ipu_device *idev)
{
	int ret;

	ret = ipu_suspend_fw(idev);
	if (ret) {
		XDNA_ERR(idev->xdna, "suspend firmware failed");
		return ret;
	}

	ret = ipu_resume_fw(idev);
	if (ret) {
		XDNA_ERR(idev->xdna, "resume firmware failed");
		return ret;
	}

	return 0;
}

static int ipu_mgmt_fw_init(struct ipu_device *idev)
{
	int ret;

	ret = ipu_check_header_hash(idev);
	if (ret) {
		XDNA_ERR(idev->xdna, "Check header hash failed");
		return ret;
	}

	/*
	 * PASID is not supported yet. But, we need to send this command
	 * to make firmware work. Any value of pasid will work for now.
	 */
	ret = ipu_assign_mgmt_pasid(idev, 0);
	if (ret) {
		XDNA_ERR(idev->xdna, "Can not assign PASID");
		return ret;
	}

	ret = ipu_xdna_reset(idev);
	if (ret) {
		XDNA_ERR(idev->xdna, "Reset firmware failed");
		return ret;
	}

	ret = ipu_query_version(idev, &idev->version);
	if (ret) {
		XDNA_ERR(idev->xdna, "Query AIE version failed");
		return ret;
	}

	ret = ipu_query_metadata(idev, &idev->metadata);
	if (ret) {
		XDNA_ERR(idev->xdna, "Query AIE metadata failed");
		return ret;
	}

	return 0;
}

static void ipu_mgmt_fw_fini(struct ipu_device *idev)
{
	if (ipu_suspend_fw(idev))
		XDNA_ERR(idev->xdna, "suspend_fw failed");
	XDNA_DBG(idev->xdna, "ipu firmware suspended");
}

static int ipu_xrs_load(void *cb_arg, struct xrs_action_load *action)
{
	struct amdxdna_hwctx *hwctx = cb_arg;
	struct amdxdna_dev *xdna;
	int ret;

	xdna = hwctx->client->xdna;

	hwctx->start_col = action->part.start_col;
	hwctx->num_col = action->part.ncol;
	ret = ipu_create_context(xdna->dev_handle, hwctx);
	if (ret)
		XDNA_ERR(xdna, "create context failed, ret %d", ret);

	return ret;
}

static int ipu_xrs_unload(void *cb_arg)
{
	struct amdxdna_hwctx *hwctx = cb_arg;
	struct amdxdna_dev *xdna;
	int ret;

	xdna = hwctx->client->xdna;

	ret = ipu_destroy_context(xdna->dev_handle, hwctx);
	if (ret)
		XDNA_ERR(xdna, "destroy context failed, ret %d", ret);

	return ret;
}

static struct xrs_action_ops ipu_xrs_actions = {
	.load = ipu_xrs_load,
	.unload = ipu_xrs_unload,
};

int ipu_alloc_resource(struct amdxdna_hwctx *hwctx)
{
	struct amdxdna_xclbin *xclbin = hwctx->xclbin;
	struct amdxdna_dev *xdna = hwctx->client->xdna;
	struct ipu_device *idev = xdna->dev_handle;
	struct aie_qos_cap cqos = { 0 };
	struct alloc_requests xrs_req;
	struct amdxdna_partition *part;
	struct cdo_parts *cdo;
	struct part_meta pmp;
	int ret, i;

	cdo = kzalloc(sizeof(*cdo), GFP_KERNEL);
	if (!cdo)
		return -ENOMEM;

	part = &xclbin->partition;
	cdo->cdo_uuid = &part->pdis[0].uuid;
	cdo->ncols = part->ncols;
	cdo->nparts = part->nparts;
	cdo->qos_cap = &cqos;
	cdo->qos_cap->opc = part->ops;

	cdo->start_col_list = kcalloc(cdo->nparts, sizeof(u32), GFP_KERNEL);
	if (!cdo->start_col_list) {
		ret = -ENOMEM;
		goto out;
	}

	for (i = 0; i < cdo->nparts; i++)
		cdo->start_col_list[i] = part->start_cols[i];

	pmp.xclbin_uuid = &xclbin->uuid;
	pmp.cdo = cdo;

	xrs_req.rid = (uintptr_t)hwctx;
	xrs_req.rqos = &hwctx->qos;
	xrs_req.pmp = &pmp;

	ret = xrs_allocate_resource(idev->xrs_hdl, &xrs_req, hwctx);
	if (ret)
		XDNA_ERR(xdna, "allocate AIE resource failed, ret %d", ret);

	kfree(cdo->start_col_list);
out:
	kfree(cdo);
	return ret;
}

int ipu_release_resource(struct amdxdna_hwctx *hwctx)
{
	struct amdxdna_dev *xdna = hwctx->client->xdna;
	struct ipu_device *idev = xdna->dev_handle;
	int ret;

	ret = xrs_release_resource(idev->xrs_hdl, (uintptr_t)hwctx);
	if (ret)
		XDNA_ERR(xdna, "release AIE resource failed, ret %d", ret);

	return ret;
}

int ipu_init(struct amdxdna_dev *xdna)
{
	struct init_config xrs_cfg = { 0 };
	struct pci_dev *pdev = xdna->pdev;
	struct xdna_mailbox_res mbox_res;
	struct psp_config psp_conf;
	void __iomem * const *tbl;
	struct ipu_device *idev;
	u32 xdna_mailbox_intr_reg;
	int mgmt_mb_irq;
	int i, ret;

#ifdef AMDXDNA_DEVEL
	ret = amdxdna_iommu_mode_setup(xdna);
	if (ret) {
		XDNA_ERR(xdna, "Setup iommu mode %d failed, ret %d", iommu_mode, ret);
		return ret;
	}
	if (iommu_mode != AMDXDNA_IOMMU_PASID)
		goto skip_pasid;
#endif
	ret = iommu_dev_enable_feature(&xdna->pdev->dev, IOMMU_DEV_FEAT_SVA);
	if (ret) {
		XDNA_ERR(xdna, "Enable PASID failed, ret %d", ret);
		return ret;
	}

#ifdef AMDXDNA_DEVEL
skip_pasid:
	XDNA_INFO(xdna, "(Develop) IOMMU mode is %d", iommu_mode);
#endif
	idev = devm_kzalloc(&pdev->dev, sizeof(*idev), GFP_KERNEL);
	if (!idev) {
		ret = -ENOMEM;
		goto disable_pasid;
	}

	idev->xdna = xdna;
	idev->priv = xdna->dev_info->dev_priv;

	ret = ipu_setup_pcidev(idev);
	if (ret) {
		XDNA_ERR(xdna, "Setup PCI device failed, ret %d", ret);
		goto disable_pasid;
	}

	tbl = pcim_iomap_table(pdev);
	if (!tbl) {
		XDNA_ERR(xdna, "Cannot get iomap table");
		ret = -ENOMEM;
		goto teardown_pci_dev;
	}
	idev->sram_base = tbl[xdna->dev_info->sram_bar];
	idev->smu_base = tbl[xdna->dev_info->smu_bar];

	ret = ipu_smu_init(idev);
	if (ret) {
		XDNA_ERR(xdna, "failed to init smu, ret %d", ret);
		goto teardown_pci_dev;
	}

	psp_conf.fw_path = idev->priv->fw_path;
	for (i = 0; i < PSP_MAX_REGS; i++)
		psp_conf.psp_regs[i] = tbl[PSP_REG_BAR(idev, i)] + PSP_REG_OFF(idev, i);
	idev->psp_hdl = amdxdna_psp_create(&pdev->dev, &psp_conf);
	if (!idev->psp_hdl) {
		XDNA_ERR(xdna, "failed to create psp");
		ret = -EINVAL;
		goto fini_smu;
	}

	ret = ipu_get_mgmt_chann_info(idev);
	if (ret) {
		XDNA_ERR(xdna, "firmware is not alive");
		goto remove_psp;
	}

	mbox_res.ringbuf_base = (u64)idev->sram_base;
	mbox_res.ringbuf_size = pci_resource_len(xdna->pdev, xdna->dev_info->sram_bar);
	mbox_res.mbox_base = (u64)tbl[xdna->dev_info->mbox_bar];
	mbox_res.mbox_size = MBOX_SIZE(idev);
	mbox_res.name = "xdna_mailbox";
	xdna->mbox = xdna_mailbox_create(&pdev->dev, &mbox_res);
	if (!xdna->mbox) {
		XDNA_ERR(xdna, "failed to create mailbox device");
		ret = -ENODEV;
		goto remove_psp;
	}

	mgmt_mb_irq = pci_irq_vector(xdna->pdev, idev->mgmt_chan_idx);
	if (mgmt_mb_irq < 0) {
		ret = mgmt_mb_irq;
		XDNA_ERR(xdna, "failed to alloc irq vector, ret %d", ret);
		goto destroy_mbox;
	}

	xdna_mailbox_intr_reg = idev->mgmt_i2x.mb_head_ptr_reg + 4;
	xdna->mgmt_chann = xdna_mailbox_create_channel(xdna->mbox,
						       &idev->mgmt_x2i,
						       &idev->mgmt_i2x,
						       xdna_mailbox_intr_reg,
						       mgmt_mb_irq);
	if (!xdna->mgmt_chann) {
		XDNA_ERR(xdna, "failed to create management mailbox channel");
		ret = -EINVAL;
		goto destroy_mbox;
	}

	ret = ipu_mgmt_fw_init(idev);
	if (ret) {
		XDNA_ERR(xdna, "initial mgmt firmware failed, ret %d", ret);
		goto destroy_mgmt_chann;
	}

	xrs_cfg.clk_list.num_levels = 3;
	xrs_cfg.clk_list.cu_clk_list[0] = 0;
	xrs_cfg.clk_list.cu_clk_list[1] = 800;
	xrs_cfg.clk_list.cu_clk_list[2] = 1000;
	xrs_cfg.sys_eff_factor = 1;
	xrs_cfg.actions = &ipu_xrs_actions;
	xrs_cfg.total_col = idev->metadata.cols;
	xrs_cfg.mode = XRS_MODE_TEMPORAL_BEST;
	xrs_cfg.dev = &xdna->pdev->dev;
	idev->xrs_hdl = xrs_init(&xrs_cfg);
	if (!idev->xrs_hdl) {
		XDNA_ERR(xdna, "Initialize resolver failed");
		ret = -EINVAL;
		goto fw_fini;
	}

	xdna->async_msgd = kthread_run(ipu_error_async_msg_thread, xdna, "async_msgd");
	if (IS_ERR(xdna->async_msgd)) {
		ret = PTR_ERR(xdna->async_msgd);
		xdna->async_msgd = NULL;
		XDNA_ERR(xdna, "failed to create async message handler");
		goto fw_fini;
	}

	xdna->dev_handle = idev;

	XDNA_INFO(xdna, "Mailbox mgmt channel created (irq: %d, msix_id: %d)",
		  mgmt_mb_irq, idev->mgmt_chan_idx);

	return 0;

fw_fini:
	ipu_mgmt_fw_fini(idev);
destroy_mgmt_chann:
	xdna_mailbox_destroy_channel(xdna->mgmt_chann);
destroy_mbox:
	xdna_mailbox_destroy(xdna->mbox);
remove_psp:
	amdxdna_psp_remove(idev->psp_hdl);
fini_smu:
	ipu_smu_fini(idev);
teardown_pci_dev:
	ipu_teardown_pcidev(idev);
disable_pasid:
	iommu_dev_disable_feature(&xdna->pdev->dev, IOMMU_DEV_FEAT_SVA);
	return ret;
}

int ipu_get_aie_status(struct amdxdna_dev *xdna, struct amdxdna_drm_query_aie_status *args)
{
	struct ipu_device *idev = xdna->dev_handle;
	int ret;

	XDNA_DBG(xdna, "Start Col: %u Num Col: %u", args->start_col, args->num_cols);

	if (args->start_col + args->num_cols > idev->metadata.cols) {
		XDNA_ERR(xdna, "Invalid Columnns. Start: %u. Req Size: %u. Avail Size: %u",
			 args->start_col, args->num_cols, idev->metadata.cols);
		return -EINVAL;
	}

	if (args->num_cols * idev->metadata.size < args->buffer_size) {
		XDNA_ERR(xdna, "Invalid buffer size. Given Size: %u. Need Size: %u.",
			 args->buffer_size, args->num_cols * idev->metadata.size);
		return -EINVAL;
	}

	ret = ipu_query_status(idev, args->start_col, args->num_cols,
			       u64_to_user_ptr(args->buffer), args->buffer_size,
			       &args->cols_filled);

	if (ret)
		XDNA_ERR(xdna, "Failed to get AIE status info. Ret: %d", ret);

	return ret;
}

void ipu_fini(struct amdxdna_dev *xdna)
{
	struct ipu_device *idev = xdna->dev_handle;

	if (xdna->async_msgd)
		kthread_stop(xdna->async_msgd);

	ipu_mgmt_fw_fini(idev);

	xdna_mailbox_destroy_channel(xdna->mgmt_chann);
	xdna_mailbox_destroy(xdna->mbox);

	amdxdna_psp_remove(idev->psp_hdl);
	ipu_smu_fini(idev);

#ifdef AMDXDNA_DEVEL
	if (iommu_mode != AMDXDNA_IOMMU_PASID)
		goto skip_pasid;
#endif
	iommu_dev_disable_feature(&xdna->pdev->dev, IOMMU_DEV_FEAT_SVA);
#ifdef AMDXDNA_DEVEL
skip_pasid:
#endif
	ipu_teardown_pcidev(idev);
}

void ipu_debugfs_add(struct ipu_device *idev)
{
	ipu_debugfs_init(idev);
}

// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2023-2024, Advanced Micro Devices, Inc.
 */

#include <linux/errno.h>
#include <linux/kthread.h>
#include <linux/iommu.h>
#include <linux/firmware.h>
#include "drm_local/amdxdna_accel.h"

#include "npu_common.h"
#include "npu_error.h"
#include "npu_pci.h"
#ifdef AMDXDNA_DEVEL
#include "amdxdna_devel.h"
#endif

/*
 * The management mailbox channel is allocated by NPU firmware.
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

static int npu_setup_pcidev(struct npu_device *ndev)
{
	struct amdxdna_dev *xdna = ndev->xdna;
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

	/* Need to enable NPU device master capability for MSI interrupt and DMA */
	pci_set_master(xdna->pdev);

	bar_mask = pci_select_bars(xdna->pdev, IORESOURCE_MEM);
	ret = pcim_iomap_regions(xdna->pdev, bar_mask, "amdxdna-npu");
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

static void npu_teardown_pcidev(struct npu_device *ndev)
{
	struct amdxdna_dev *xdna = ndev->xdna;

	pci_free_irq_vectors(xdna->pdev);
	pci_clear_master(xdna->pdev);
}

static inline void npu_dump_chann_info_debug(struct npu_device *ndev)
{
	struct amdxdna_dev *xdna = ndev->xdna;

	XDNA_DBG(xdna, "i2x tail    0x%x", ndev->mgmt_i2x.mb_tail_ptr_reg);
	XDNA_DBG(xdna, "i2x head    0x%x", ndev->mgmt_i2x.mb_head_ptr_reg);
	XDNA_DBG(xdna, "i2x ringbuf 0x%x", ndev->mgmt_i2x.rb_start_addr);
	XDNA_DBG(xdna, "i2x rsize   0x%x", ndev->mgmt_i2x.rb_size);
	XDNA_DBG(xdna, "x2i tail    0x%x", ndev->mgmt_x2i.mb_tail_ptr_reg);
	XDNA_DBG(xdna, "x2i head    0x%x", ndev->mgmt_x2i.mb_head_ptr_reg);
	XDNA_DBG(xdna, "x2i ringbuf 0x%x", ndev->mgmt_x2i.rb_start_addr);
	XDNA_DBG(xdna, "x2i rsize   0x%x", ndev->mgmt_x2i.rb_size);
	XDNA_DBG(xdna, "x2i chann index 0x%x", ndev->mgmt_chan_idx);
}

static int npu_get_mgmt_chann_info(struct npu_device *ndev)
{
	struct mgmt_mbox_chann_info info_regs;
	struct xdna_mailbox_chann_res *i2x;
	struct xdna_mailbox_chann_res *x2i;
	u32 addr, off;
	u32 *reg;
	int ret;
	int i;

	/*
	 * Once NPU firmware is alive, it will write management channel
	 * information in SRAM BAR and write the address of that information
	 * at FW_ALIVE_OFF offset in SRMA BAR.
	 *
	 * Read a non-zero value from FW_ALIVE_OFF implies that firmware
	 * is alive.
	 */
	ret = readx_poll_timeout(readl, SRAM_GET_ADDR(ndev, FW_ALIVE_OFF),
				 addr, addr, NPU_INTERVAL, NPU_TIMEOUT);
	if (ret || !addr)
		return -ETIME;

	off = NPU_SRAM_OFF(ndev, addr);
	reg = (u32 *)&info_regs;
	for (i = 0; i < sizeof(info_regs) / sizeof(u32); i++)
		reg[i] = readl(ndev->sram_base + off + i * sizeof(u32));

	i2x = &ndev->mgmt_i2x;
	x2i = &ndev->mgmt_x2i;

	i2x->mb_head_ptr_reg = NPU_MBOX_OFF(ndev, info_regs.i2x_head);
	i2x->mb_tail_ptr_reg = NPU_MBOX_OFF(ndev, info_regs.i2x_tail);
	i2x->rb_start_addr   = NPU_SRAM_OFF(ndev, info_regs.i2x_buf);
	i2x->rb_size         = info_regs.i2x_buf_sz;

	x2i->mb_head_ptr_reg = NPU_MBOX_OFF(ndev, info_regs.x2i_head);
	x2i->mb_tail_ptr_reg = NPU_MBOX_OFF(ndev, info_regs.x2i_tail);
	x2i->rb_start_addr   = NPU_SRAM_OFF(ndev, info_regs.x2i_buf);
	x2i->rb_size         = info_regs.x2i_buf_sz;
	ndev->mgmt_chan_idx  = CHANN_INDEX(ndev, x2i->rb_start_addr);

	npu_dump_chann_info_debug(ndev);

	/* Must clear address at FW_ALIVE_OFF */
	writel(0, SRAM_GET_ADDR(ndev, FW_ALIVE_OFF));

	return 0;
}

static int npu_xdna_reset(struct npu_device *ndev)
{
	int ret;

	ret = npu_suspend_fw(ndev);
	if (ret) {
		XDNA_ERR(ndev->xdna, "suspend firmware failed");
		return ret;
	}

	ret = npu_resume_fw(ndev);
	if (ret) {
		XDNA_ERR(ndev->xdna, "resume firmware failed");
		return ret;
	}

	return 0;
}

static int npu_mgmt_fw_init(struct npu_device *ndev)
{
	int ret;

	ret = npu_check_header_hash(ndev);
	if (ret) {
		XDNA_ERR(ndev->xdna, "Check header hash failed");
		return ret;
	}

	/*
	 * PASID is not supported yet. But, we need to send this command
	 * to make firmware work. Any value of pasid will work for now.
	 */
	ret = npu_assign_mgmt_pasid(ndev, 0);
	if (ret) {
		XDNA_ERR(ndev->xdna, "Can not assign PASID");
		return ret;
	}

	ret = npu_xdna_reset(ndev);
	if (ret) {
		XDNA_ERR(ndev->xdna, "Reset firmware failed");
		return ret;
	}

	ret = npu_query_version(ndev, &ndev->version);
	if (ret) {
		XDNA_ERR(ndev->xdna, "Query AIE version failed");
		return ret;
	}

	ret = npu_query_metadata(ndev, &ndev->metadata);
	if (ret) {
		XDNA_ERR(ndev->xdna, "Query AIE metadata failed");
		return ret;
	}

	return 0;
}

static void npu_mgmt_fw_fini(struct npu_device *ndev)
{
	if (npu_suspend_fw(ndev))
		XDNA_ERR(ndev->xdna, "suspend_fw failed");
	XDNA_DBG(ndev->xdna, "npu firmware suspended");
}

static int npu_xrs_load(void *cb_arg, struct xrs_action_load *action)
{
	struct amdxdna_hwctx *hwctx = cb_arg;
	struct amdxdna_dev *xdna;
	int ret;

	xdna = hwctx->client->xdna;

	hwctx->start_col = action->part.start_col;
	hwctx->num_col = action->part.ncol;
	ret = npu_create_context(xdna->dev_handle, hwctx);
	if (ret)
		XDNA_ERR(xdna, "create context failed, ret %d", ret);

	return ret;
}

static int npu_xrs_unload(void *cb_arg)
{
	struct amdxdna_hwctx *hwctx = cb_arg;
	struct amdxdna_dev *xdna;
	int ret;

	xdna = hwctx->client->xdna;

	ret = npu_destroy_context(xdna->dev_handle, hwctx);
	if (ret)
		XDNA_ERR(xdna, "destroy context failed, ret %d", ret);

	return ret;
}

static struct xrs_action_ops npu_xrs_actions = {
	.load = npu_xrs_load,
	.unload = npu_xrs_unload,
};

int npu_alloc_resource(struct amdxdna_hwctx *hwctx)
{
	struct amdxdna_xclbin *xclbin = hwctx->xclbin;
	struct amdxdna_dev *xdna = hwctx->client->xdna;
	struct npu_device *ndev = xdna->dev_handle;
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

	ret = xrs_allocate_resource(ndev->xrs_hdl, &xrs_req, hwctx);
	if (ret)
		XDNA_ERR(xdna, "allocate AIE resource failed, ret %d", ret);

	kfree(cdo->start_col_list);
out:
	kfree(cdo);
	return ret;
}

int npu_release_resource(struct amdxdna_hwctx *hwctx)
{
	struct amdxdna_dev *xdna = hwctx->client->xdna;
	struct npu_device *ndev = xdna->dev_handle;
	int ret;

	ret = xrs_release_resource(ndev->xrs_hdl, (uintptr_t)hwctx);
	if (ret)
		XDNA_ERR(xdna, "release AIE resource failed, ret %d", ret);

	return ret;
}

int npu_init(struct amdxdna_dev *xdna)
{
	struct init_config xrs_cfg = { 0 };
	struct pci_dev *pdev = xdna->pdev;
	struct xdna_mailbox_res mbox_res;
	struct psp_config psp_conf;
	const struct firmware *fw;
	void __iomem * const *tbl;
	struct npu_device *ndev;
	u32 xdna_mailbox_intr_reg;
	int mgmt_mb_irq;
	int i, ret;

	ret = request_firmware(&fw, xdna->dev_info->dev_priv->fw_path, &pdev->dev);
	if (ret) {
		XDNA_ERR(xdna, "failed to request_firmware %s, ret %d",
			 xdna->dev_info->dev_priv->fw_path, ret);
		return ret;
	}

#ifdef AMDXDNA_DEVEL
	ret = amdxdna_iommu_mode_setup(xdna);
	if (ret) {
		XDNA_ERR(xdna, "Setup iommu mode %d failed, ret %d", iommu_mode, ret);
		goto release_fw;
	}
	if (iommu_mode != AMDXDNA_IOMMU_PASID)
		goto skip_pasid;
#endif
	ret = iommu_dev_enable_feature(&xdna->pdev->dev, IOMMU_DEV_FEAT_SVA);
	if (ret) {
		XDNA_ERR(xdna, "Enable PASID failed, ret %d", ret);
		goto release_fw;
	}

#ifdef AMDXDNA_DEVEL
skip_pasid:
	XDNA_INFO(xdna, "(Develop) IOMMU mode is %d", iommu_mode);
#endif
	ndev = devm_kzalloc(&pdev->dev, sizeof(*ndev), GFP_KERNEL);
	if (!ndev) {
		ret = -ENOMEM;
		goto disable_pasid;
	}

	ndev->xdna = xdna;
	ndev->priv = xdna->dev_info->dev_priv;

	ret = npu_setup_pcidev(ndev);
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
	ndev->sram_base = tbl[xdna->dev_info->sram_bar];
	ndev->smu_base = tbl[xdna->dev_info->smu_bar];

	ret = npu_smu_init(ndev);
	if (ret) {
		XDNA_ERR(xdna, "failed to init smu, ret %d", ret);
		goto teardown_pci_dev;
	}

	psp_conf.fw_size = fw->size;
	psp_conf.fw_buf = fw->data;
	for (i = 0; i < PSP_MAX_REGS; i++)
		psp_conf.psp_regs[i] = tbl[PSP_REG_BAR(ndev, i)] + PSP_REG_OFF(ndev, i);
	ndev->psp_hdl = amdxdna_psp_create(&pdev->dev, &psp_conf);
	if (!ndev->psp_hdl) {
		XDNA_ERR(xdna, "failed to create psp");
		ret = -EINVAL;
		goto fini_smu;
	}

	ret = npu_get_mgmt_chann_info(ndev);
	if (ret) {
		XDNA_ERR(xdna, "firmware is not alive");
		goto remove_psp;
	}

	mbox_res.ringbuf_base = (u64)ndev->sram_base;
	mbox_res.ringbuf_size = pci_resource_len(xdna->pdev, xdna->dev_info->sram_bar);
	mbox_res.mbox_base = (u64)tbl[xdna->dev_info->mbox_bar];
	mbox_res.mbox_size = MBOX_SIZE(ndev);
	mbox_res.name = "xdna_mailbox";
	xdna->mbox = xdna_mailbox_create(&pdev->dev, &mbox_res);
	if (!xdna->mbox) {
		XDNA_ERR(xdna, "failed to create mailbox device");
		ret = -ENODEV;
		goto remove_psp;
	}

	mgmt_mb_irq = pci_irq_vector(xdna->pdev, ndev->mgmt_chan_idx);
	if (mgmt_mb_irq < 0) {
		ret = mgmt_mb_irq;
		XDNA_ERR(xdna, "failed to alloc irq vector, ret %d", ret);
		goto destroy_mbox;
	}

	xdna_mailbox_intr_reg = ndev->mgmt_i2x.mb_head_ptr_reg + 4;
	xdna->mgmt_chann = xdna_mailbox_create_channel(xdna->mbox,
						       &ndev->mgmt_x2i,
						       &ndev->mgmt_i2x,
						       xdna_mailbox_intr_reg,
						       mgmt_mb_irq);
	if (!xdna->mgmt_chann) {
		XDNA_ERR(xdna, "failed to create management mailbox channel");
		ret = -EINVAL;
		goto destroy_mbox;
	}

	ret = npu_mgmt_fw_init(ndev);
	if (ret) {
		XDNA_ERR(xdna, "initial mgmt firmware failed, ret %d", ret);
		goto destroy_mgmt_chann;
	}

	xrs_cfg.clk_list.num_levels = 3;
	xrs_cfg.clk_list.cu_clk_list[0] = 0;
	xrs_cfg.clk_list.cu_clk_list[1] = 800;
	xrs_cfg.clk_list.cu_clk_list[2] = 1000;
	xrs_cfg.sys_eff_factor = 1;
	xrs_cfg.actions = &npu_xrs_actions;
	xrs_cfg.total_col = ndev->metadata.cols;
	xrs_cfg.mode = XRS_MODE_TEMPORAL_BEST;
	xrs_cfg.dev = &xdna->pdev->dev;
	ndev->xrs_hdl = xrs_init(&xrs_cfg);
	if (!ndev->xrs_hdl) {
		XDNA_ERR(xdna, "Initialize resolver failed");
		ret = -EINVAL;
		goto fw_fini;
	}

	xdna->async_msgd = kthread_run(npu_error_async_msg_thread, xdna, "async_msgd");
	if (IS_ERR(xdna->async_msgd)) {
		ret = PTR_ERR(xdna->async_msgd);
		xdna->async_msgd = NULL;
		XDNA_ERR(xdna, "failed to create async message handler");
		goto fw_fini;
	}

	xdna->dev_handle = ndev;

	XDNA_INFO(xdna, "Mailbox mgmt channel created (irq: %d, msix_id: %d)",
		  mgmt_mb_irq, ndev->mgmt_chan_idx);

	release_firmware(fw);
	return 0;

fw_fini:
	npu_mgmt_fw_fini(ndev);
destroy_mgmt_chann:
	xdna_mailbox_destroy_channel(xdna->mgmt_chann);
destroy_mbox:
	xdna_mailbox_destroy(xdna->mbox);
remove_psp:
	amdxdna_psp_remove(ndev->psp_hdl);
fini_smu:
	npu_smu_fini(ndev);
teardown_pci_dev:
	npu_teardown_pcidev(ndev);
disable_pasid:
	iommu_dev_disable_feature(&xdna->pdev->dev, IOMMU_DEV_FEAT_SVA);
release_fw:
	release_firmware(fw);
	return ret;
}

int npu_get_aie_status(struct amdxdna_dev *xdna, struct amdxdna_drm_query_aie_status *args)
{
	struct npu_device *ndev = xdna->dev_handle;
	int ret;

	XDNA_DBG(xdna, "Start Col: %u Num Col: %u", args->start_col, args->num_cols);

	if (args->start_col + args->num_cols > ndev->metadata.cols) {
		XDNA_ERR(xdna, "Invalid Columnns. Start: %u. Req Size: %u. Avail Size: %u",
			 args->start_col, args->num_cols, ndev->metadata.cols);
		return -EINVAL;
	}

	if (args->num_cols * ndev->metadata.size < args->buffer_size) {
		XDNA_ERR(xdna, "Invalid buffer size. Given Size: %u. Need Size: %u.",
			 args->buffer_size, args->num_cols * ndev->metadata.size);
		return -EINVAL;
	}

	ret = npu_query_status(ndev, args->start_col, args->num_cols,
			       u64_to_user_ptr(args->buffer), args->buffer_size,
			       &args->cols_filled);

	if (ret)
		XDNA_ERR(xdna, "Failed to get AIE status info. Ret: %d", ret);

	return ret;
}

void npu_fini(struct amdxdna_dev *xdna)
{
	struct npu_device *ndev = xdna->dev_handle;

	if (xdna->async_msgd)
		kthread_stop(xdna->async_msgd);

	npu_mgmt_fw_fini(ndev);

	xdna_mailbox_destroy_channel(xdna->mgmt_chann);
	xdna_mailbox_destroy(xdna->mbox);

	amdxdna_psp_remove(ndev->psp_hdl);
	npu_smu_fini(ndev);

#ifdef AMDXDNA_DEVEL
	if (iommu_mode != AMDXDNA_IOMMU_PASID)
		goto skip_pasid;
#endif
	iommu_dev_disable_feature(&xdna->pdev->dev, IOMMU_DEV_FEAT_SVA);
#ifdef AMDXDNA_DEVEL
skip_pasid:
#endif
	npu_teardown_pcidev(ndev);
}

void npu_debugfs_add(struct npu_device *ndev)
{
	npu_debugfs_init(ndev);
}

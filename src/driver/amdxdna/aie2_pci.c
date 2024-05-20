// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2023-2024, Advanced Micro Devices, Inc.
 */

#include <linux/errno.h>
#include <linux/kthread.h>
#include <linux/iommu.h>
#include <linux/firmware.h>
#include "drm_local/amdxdna_accel.h"

#include "aie2_pci.h"
#include "aie2_solver.h"
#include "aie2_msg_priv.h"

int aie2_max_col = XRS_MAX_COL;
module_param(aie2_max_col, int, 0600);
MODULE_PARM_DESC(aie2_max_col, "Maximum column could be used");

/*
 * The management mailbox channel is allocated by firmware.
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

static inline void aie2_dump_chann_info_debug(struct amdxdna_dev_hdl *ndev)
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

static int aie2_get_mgmt_chann_info(struct amdxdna_dev_hdl *ndev)
{
	struct mgmt_mbox_chann_info info_regs;
	struct xdna_mailbox_chann_res *i2x;
	struct xdna_mailbox_chann_res *x2i;
	u32 addr, off;
	u32 *reg;
	int ret;
	int i;

	/*
	 * Once firmware is alive, it will write management channel
	 * information in SRAM BAR and write the address of that information
	 * at FW_ALIVE_OFF offset in SRMA BAR.
	 *
	 * Read a non-zero value from FW_ALIVE_OFF implies that firmware
	 * is alive.
	 */
	ret = readx_poll_timeout(readl, SRAM_GET_ADDR(ndev, FW_ALIVE_OFF),
				 addr, addr, AIE2_INTERVAL, AIE2_TIMEOUT);
	if (ret || !addr)
		return -ETIME;

	off = AIE2_SRAM_OFF(ndev, addr);
	reg = (u32 *)&info_regs;
	for (i = 0; i < sizeof(info_regs) / sizeof(u32); i++)
		reg[i] = readl(ndev->sram_base + off + i * sizeof(u32));

	i2x = &ndev->mgmt_i2x;
	x2i = &ndev->mgmt_x2i;

	i2x->mb_head_ptr_reg = AIE2_MBOX_OFF(ndev, info_regs.i2x_head);
	i2x->mb_tail_ptr_reg = AIE2_MBOX_OFF(ndev, info_regs.i2x_tail);
	i2x->rb_start_addr   = AIE2_SRAM_OFF(ndev, info_regs.i2x_buf);
	i2x->rb_size         = info_regs.i2x_buf_sz;

	x2i->mb_head_ptr_reg = AIE2_MBOX_OFF(ndev, info_regs.x2i_head);
	x2i->mb_tail_ptr_reg = AIE2_MBOX_OFF(ndev, info_regs.x2i_tail);
	x2i->rb_start_addr   = AIE2_SRAM_OFF(ndev, info_regs.x2i_buf);
	x2i->rb_size         = info_regs.x2i_buf_sz;
	ndev->mgmt_chan_idx  = CHANN_INDEX(ndev, x2i->rb_start_addr);

	aie2_dump_chann_info_debug(ndev);

	/* Must clear address at FW_ALIVE_OFF */
	writel(0, SRAM_GET_ADDR(ndev, FW_ALIVE_OFF));

	return 0;
}

static int aie2_runtime_cfg(struct amdxdna_dev_hdl *ndev)
{
	const struct rt_config *cfg = &ndev->priv->rt_config;
	u64 value;
	int ret;

#ifdef AMDXDNA_DEVEL
	if (priv_load) {
		cfg = &ndev->priv->dbg_rt_cfgs;
		XDNA_INFO(ndev->xdna, "Set runtime type %d value %d",
			  cfg->type, cfg->value);
	}
#endif
	ret = aie2_set_runtime_cfg(ndev, cfg->type, cfg->value);
	if (ret) {
		XDNA_ERR(ndev->xdna, "Set runtime type %d value %d failed",
			 cfg->type, cfg->value);
		return ret;
	}

	ret = aie2_get_runtime_cfg(ndev, cfg->type, &value);
	if (ret) {
		XDNA_ERR(ndev->xdna, "Get runtime cfg failed");
		return ret;
	}

	if (value != cfg->value)
		return -EINVAL;

	return 0;
}

static int aie2_xdna_reset(struct amdxdna_dev_hdl *ndev)
{
	int ret;

	ret = aie2_suspend_fw(ndev);
	if (ret) {
		XDNA_ERR(ndev->xdna, "Suspend firmware failed");
		return ret;
	}

	ret = aie2_resume_fw(ndev);
	if (ret) {
		XDNA_ERR(ndev->xdna, "Resume firmware failed");
		return ret;
	}

	return 0;
}

static int aie2_mgmt_fw_init(struct amdxdna_dev_hdl *ndev)
{
	int ret;

	ret = aie2_check_protocol_version(ndev);
	if (ret) {
		XDNA_ERR(ndev->xdna, "Check header hash failed");
		return ret;
	}

	ret = aie2_runtime_cfg(ndev);
	if (ret) {
		XDNA_ERR(ndev->xdna, "Runtime config failed");
		return ret;
	}

	ret = aie2_assign_mgmt_pasid(ndev, 0);
	if (ret) {
		XDNA_ERR(ndev->xdna, "Can not assign PASID");
		return ret;
	}

	ret = aie2_xdna_reset(ndev);
	if (ret) {
		XDNA_ERR(ndev->xdna, "Reset firmware failed");
		return ret;
	}

	if (!ndev->async_events)
		return 0;

	ret = aie2_error_async_events_send(ndev);
	if (ret) {
		XDNA_ERR(ndev->xdna, "Send async events failed");
		return ret;
	}

	return 0;
}

static int aie2_mgmt_fw_query(struct amdxdna_dev_hdl *ndev)
{
	int ret;

	ret = aie2_query_firmware_version(ndev, &ndev->xdna->fw_ver);
	if (ret) {
		XDNA_ERR(ndev->xdna, "query firmware version failed");
		return ret;
	}

	ret = aie2_query_aie_version(ndev, &ndev->version);
	if (ret) {
		XDNA_ERR(ndev->xdna, "Query AIE version failed");
		return ret;
	}

	ret = aie2_query_aie_metadata(ndev, &ndev->metadata);
	if (ret) {
		XDNA_ERR(ndev->xdna, "Query AIE metadata failed");
		return ret;
	}

	return 0;
}

static void aie2_mgmt_fw_fini(struct amdxdna_dev_hdl *ndev)
{
	if (aie2_suspend_fw(ndev))
		XDNA_ERR(ndev->xdna, "suspend_fw failed");
	XDNA_DBG(ndev->xdna, "npu firmware suspended");
}

/* TODO: move below two functions to aie2_ctx.c? */
static int aie2_xrs_load(void *cb_arg, struct xrs_action_load *action)
{
	struct amdxdna_hwctx *hwctx = cb_arg;
	struct amdxdna_dev *xdna;
	int ret;

	xdna = hwctx->client->xdna;

	hwctx->start_col = action->part.start_col;
	hwctx->num_col = action->part.ncols;
	ret = aie2_create_context(xdna->dev_handle, hwctx);
	if (ret)
		XDNA_ERR(xdna, "create context failed, ret %d", ret);

	return ret;
}

static int aie2_xrs_unload(void *cb_arg)
{
	struct amdxdna_hwctx *hwctx = cb_arg;
	struct amdxdna_dev *xdna;
	int ret;

	xdna = hwctx->client->xdna;

	ret = aie2_destroy_context(xdna->dev_handle, hwctx);
	if (ret)
		XDNA_ERR(xdna, "destroy context failed, ret %d", ret);

	return ret;
}

static struct xrs_action_ops aie2_xrs_actions = {
	.load = aie2_xrs_load,
	.unload = aie2_xrs_unload,
};

static void aie2_hw_stop(struct amdxdna_dev *xdna)
{
	struct pci_dev *pdev = to_pci_dev(xdna->ddev.dev);
	struct amdxdna_dev_hdl *ndev = xdna->dev_handle;

	aie2_mgmt_fw_fini(ndev);
	xdna_mailbox_stop_channel(ndev->mgmt_chann);
	xdna_mailbox_destroy_channel(ndev->mgmt_chann);
	aie2_psp_stop(ndev->psp_hdl);
	aie2_smu_fini(ndev);
	pci_clear_master(pdev);
	pci_disable_device(pdev);
}

static int aie2_hw_start(struct amdxdna_dev *xdna)
{
	struct pci_dev *pdev = to_pci_dev(xdna->ddev.dev);
	struct amdxdna_dev_hdl *ndev = xdna->dev_handle;
	struct xdna_mailbox_res mbox_res;
	u32 xdna_mailbox_intr_reg;
	int mgmt_mb_irq, ret;

	ret = pci_enable_device(pdev);
	if (ret) {
		XDNA_ERR(xdna, "failed to enable device, ret %d", ret);
		return ret;
	}
	pci_set_master(pdev);

	ret = aie2_smu_init(ndev);
	if (ret) {
		XDNA_ERR(xdna, "failed to init smu, ret %d", ret);
		goto disable_dev;
	}

	ret = aie2_psp_start(ndev->psp_hdl);
	if (ret) {
		XDNA_ERR(xdna, "failed to start psp, ret %d", ret);
		goto fini_smu;
	}

	ret = aie2_get_mgmt_chann_info(ndev);
	if (ret) {
		XDNA_ERR(xdna, "firmware is not alive");
		goto stop_psp;
	}

	mbox_res.ringbuf_base = (u64)ndev->sram_base;
	mbox_res.ringbuf_size = pci_resource_len(pdev, xdna->dev_info->sram_bar);
	mbox_res.mbox_base = (u64)ndev->mbox_base;
	mbox_res.mbox_size = MBOX_SIZE(ndev);
	mbox_res.name = "xdna_mailbox";
	ndev->mbox = xdna_mailbox_create(&pdev->dev, &mbox_res);
	if (!ndev->mbox) {
		XDNA_ERR(xdna, "failed to create mailbox device");
		ret = -ENODEV;
		goto stop_psp;
	}

	mgmt_mb_irq = pci_irq_vector(pdev, ndev->mgmt_chan_idx);
	if (mgmt_mb_irq < 0) {
		ret = mgmt_mb_irq;
		XDNA_ERR(xdna, "failed to alloc irq vector, ret %d", ret);
		goto stop_psp;
	}

	xdna_mailbox_intr_reg = ndev->mgmt_i2x.mb_head_ptr_reg + 4;
	ndev->mgmt_chann = xdna_mailbox_create_channel(ndev->mbox,
						       &ndev->mgmt_x2i,
						       &ndev->mgmt_i2x,
						       xdna_mailbox_intr_reg,
						       mgmt_mb_irq);
	if (!ndev->mgmt_chann) {
		XDNA_ERR(xdna, "failed to create management mailbox channel");
		ret = -EINVAL;
		goto stop_psp;
	}

	ret = aie2_mgmt_fw_init(ndev);
	if (ret) {
		XDNA_ERR(xdna, "initial mgmt firmware failed, ret %d", ret);
		goto destroy_mgmt_chann;
	}

	return 0;

destroy_mgmt_chann:
	xdna_mailbox_stop_channel(ndev->mgmt_chann);
	xdna_mailbox_destroy_channel(ndev->mgmt_chann);
stop_psp:
	aie2_psp_stop(ndev->psp_hdl);
fini_smu:
	aie2_smu_fini(ndev);
disable_dev:
	pci_disable_device(pdev);
	pci_clear_master(pdev);

	return ret;
}

static int aie2_init(struct amdxdna_dev *xdna)
{
	struct pci_dev *pdev = to_pci_dev(xdna->ddev.dev);
	struct init_config xrs_cfg = { 0 };
	struct amdxdna_dev_hdl *ndev;
	struct psp_config psp_conf;
	const struct firmware *fw;
	void __iomem * const *tbl;
	int i, bars, nvec, ret;

	ndev = devm_kzalloc(&pdev->dev, sizeof(*ndev), GFP_KERNEL);
	if (!ndev)
		return -ENOMEM;

	ndev->priv = xdna->dev_info->dev_priv;
	ndev->xdna = xdna;

	ret = request_firmware(&fw, ndev->priv->fw_path, &pdev->dev);
	if (ret) {
		XDNA_ERR(xdna, "failed to request_firmware %s, ret %d",
			 ndev->priv->fw_path, ret);
		return ret;
	}

	ret = pcim_enable_device(pdev);
	if (ret) {
		XDNA_ERR(xdna, "pcim enable device failed, ret %d", ret);
		goto release_fw;
	}

	bars = pci_select_bars(pdev, IORESOURCE_MEM);
	for (i = 0; i < PSP_MAX_REGS; i++) {
		if (!(BIT(PSP_REG_BAR(ndev, i)) && bars)) {
			XDNA_ERR(xdna, "does not get pci bar%d",
				 PSP_REG_BAR(ndev, i));
			ret = -EINVAL;
			goto release_fw;
		}
	}

	ret = pcim_iomap_regions(pdev, bars, "amdxdna-npu");
	if (ret) {
		XDNA_ERR(xdna, "map regions failed, ret %d", ret);
		goto release_fw;
	}

	tbl = pcim_iomap_table(pdev);
	if (!tbl) {
		XDNA_ERR(xdna, "Cannot get iomap table");
		ret = -ENOMEM;
		goto release_fw;
	}
	ndev->sram_base = tbl[xdna->dev_info->sram_bar];
	ndev->smu_base = tbl[xdna->dev_info->smu_bar];
	ndev->mbox_base = tbl[xdna->dev_info->mbox_bar];

	ret = dma_set_mask_and_coherent(&pdev->dev, DMA_BIT_MASK(64));
	if (ret) {
		XDNA_ERR(xdna, "Failed to set DMA mask: %d", ret);
		goto release_fw;
	}

	nvec = pci_msix_vec_count(pdev);
	if (nvec <= 0) {
		XDNA_ERR(xdna, "does not get number of interrupt vector");
		ret = -EINVAL;
		goto release_fw;
	}

	ret = pci_alloc_irq_vectors(pdev, nvec, nvec, PCI_IRQ_MSIX);
	if (ret < 0) {
		XDNA_ERR(xdna, "failed to alloc irq vectors, ret %d", ret);
		goto release_fw;
	}

	ret = iommu_dev_enable_feature(&pdev->dev, IOMMU_DEV_FEAT_SVA);
	if (ret) {
		XDNA_ERR(xdna, "Enable PASID failed, ret %d", ret);
		goto free_irq;
	}

	psp_conf.fw_size = fw->size;
	psp_conf.fw_buf = fw->data;
	for (i = 0; i < PSP_MAX_REGS; i++)
		psp_conf.psp_regs[i] = tbl[PSP_REG_BAR(ndev, i)] + PSP_REG_OFF(ndev, i);
	ndev->psp_hdl = aie2m_psp_create(&pdev->dev, &psp_conf);
	if (!ndev->psp_hdl) {
		XDNA_ERR(xdna, "failed to create psp");
		ret = -ENOMEM;
		goto disable_sva;
	}
	xdna->dev_handle = ndev;

	ret = aie2_hw_start(xdna);
	if (ret) {
		XDNA_ERR(xdna, "start npu failed, ret %d", ret);
		goto disable_sva;
	}

	ret = aie2_mgmt_fw_query(ndev);
	if (ret) {
		XDNA_ERR(xdna, "Query firmware failed, ret %d", ret);
		goto stop_hw;
	}
	ndev->total_col = min(aie2_max_col, ndev->metadata.cols);

	xrs_cfg.clk_list.num_levels = 3;
	xrs_cfg.clk_list.cu_clk_list[0] = 0;
	xrs_cfg.clk_list.cu_clk_list[1] = 800;
	xrs_cfg.clk_list.cu_clk_list[2] = 1000;
	xrs_cfg.sys_eff_factor = 1;
	xrs_cfg.dev = xdna->ddev.dev;
	xrs_cfg.actions = &aie2_xrs_actions;
	xrs_cfg.total_col = ndev->total_col;

	xdna->xrs_hdl = xrsm_init(&xrs_cfg);
	if (!xdna->xrs_hdl) {
		XDNA_ERR(xdna, "Initialize resolver failed");
		ret = -EINVAL;
		goto stop_hw;
	}

	ret = aie2_error_async_events_alloc(ndev);
	if (ret) {
		XDNA_ERR(xdna, "Allocate async events failed, ret %d", ret);
		goto stop_hw;
	}

	ret = aie2_error_async_events_send(ndev);
	if (ret) {
		XDNA_ERR(xdna, "Send async events failed, ret %d", ret);
		goto async_event_free;
	}

	/* Just to make sure firmware handled async events */
	ret = aie2_query_firmware_version(ndev, &ndev->xdna->fw_ver);
	if (ret) {
		XDNA_ERR(xdna, "Re-query firmware version failed");
		goto async_event_free;
	}

	release_firmware(fw);
	return 0;

async_event_free:
	aie2_error_async_events_free(ndev);
stop_hw:
	aie2_hw_stop(xdna);
disable_sva:
	iommu_dev_disable_feature(&pdev->dev, IOMMU_DEV_FEAT_SVA);
free_irq:
	pci_free_irq_vectors(pdev);
release_fw:
	release_firmware(fw);

	return ret;
}

static void aie2_fini(struct amdxdna_dev *xdna)
{
	struct pci_dev *pdev = to_pci_dev(xdna->ddev.dev);
	struct amdxdna_dev_hdl *ndev = xdna->dev_handle;

	aie2_hw_stop(xdna);
	aie2_error_async_events_free(ndev);
	iommu_dev_disable_feature(&pdev->dev, IOMMU_DEV_FEAT_SVA);
	pci_free_irq_vectors(pdev);
}

static int aie2_get_aie_status(struct amdxdna_dev *xdna,
			       struct amdxdna_drm_get_info *args)
{
	struct amdxdna_dev_hdl *ndev = xdna->dev_handle;
	struct amdxdna_drm_query_aie_status status;
	int ret;

	if (copy_from_user(&status, u64_to_user_ptr(args->buffer), sizeof(status))) {
		XDNA_ERR(xdna, "Failed to copy AIE request into kernel");
		return -EFAULT;
	}

	if (ndev->metadata.cols * ndev->metadata.size < status.buffer_size) {
		XDNA_ERR(xdna, "Invalid buffer size. Given Size: %u. Need Size: %u.",
			 status.buffer_size, ndev->metadata.cols * ndev->metadata.size);
		return -EINVAL;
	}

	ret = aie2_query_status(ndev, u64_to_user_ptr(status.buffer),
				status.buffer_size, &status.cols_filled);
	if (ret) {
		XDNA_ERR(xdna, "Failed to get AIE status info. Ret: %d", ret);
		return ret;
	}

	if (copy_to_user(u64_to_user_ptr(args->buffer), &status, sizeof(status))) {
		XDNA_ERR(xdna, "Failed to copy AIE request info to user space");
		return -EFAULT;
	}

	return 0;
}

static int aie2_get_aie_metadata(struct amdxdna_dev *xdna,
				 struct amdxdna_drm_get_info *args)
{
	struct amdxdna_dev_hdl *ndev = xdna->dev_handle;
	struct amdxdna_drm_query_aie_metadata *meta;
	int ret = 0;

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

	if (copy_to_user(u64_to_user_ptr(args->buffer), meta, sizeof(*meta)))
		ret = -EFAULT;

	kfree(meta);
	return ret;
}

static int aie2_get_aie_version(struct amdxdna_dev *xdna,
				struct amdxdna_drm_get_info *args)
{
	struct amdxdna_dev_hdl *ndev = xdna->dev_handle;
	struct amdxdna_drm_query_aie_version version;

	version.major = ndev->version.major;
	version.minor = ndev->version.minor;

	if (copy_to_user(u64_to_user_ptr(args->buffer), &version, sizeof(version)))
		return -EFAULT;

	return 0;
}

static int aie2_get_clock_metadata(struct amdxdna_dev *xdna,
				   struct amdxdna_drm_get_info *args)
{
	struct amdxdna_dev_hdl *ndev = xdna->dev_handle;
	struct amdxdna_drm_query_clock_metadata *clock;
	int ret = 0;

	clock = kzalloc(sizeof(*clock), GFP_KERNEL);
	if (!clock)
		return -ENOMEM;

	memcpy(clock->mp_npu_clock.name, ndev->mp_npu_clock.name,
	       sizeof(clock->mp_npu_clock.name));
	clock->mp_npu_clock.freq_mhz = ndev->mp_npu_clock.freq_mhz;
	memcpy(clock->h_clock.name, ndev->h_clock.name, sizeof(clock->h_clock.name));
	clock->h_clock.freq_mhz = ndev->h_clock.freq_mhz;

	if (copy_to_user(u64_to_user_ptr(args->buffer), clock, sizeof(*clock)))
		ret = -EFAULT;

	kfree(clock);
	return ret;
}

static int aie2_get_sensors(struct amdxdna_dev *xdna,
			    struct amdxdna_drm_get_info *args)
{
	struct amdxdna_drm_query_sensor *sensor;
	int ret = 0;

	sensor = kzalloc(sizeof(*sensor), GFP_KERNEL);
	if (!sensor)
		return -ENOMEM;

	sensor->type = AMDXDNA_SENSOR_TYPE_POWER;
	sensor->input = 1234; /* TODO: query the device and get the power data */
	sensor->unitm = -3; /* in milliwatts */
	snprintf(sensor->label, sizeof(sensor->label), "Total Power");
	snprintf(sensor->units, sizeof(sensor->units), "mW");

	if (copy_to_user(u64_to_user_ptr(args->buffer), sensor, sizeof(*sensor)))
		ret = -EFAULT;

	kfree(sensor);
	return ret;
}

static int aie2_get_hwctx_status(struct amdxdna_dev *xdna,
				 struct amdxdna_drm_get_info *args)
{
	struct amdxdna_drm_query_hwctx __user *buf;
	struct amdxdna_drm_query_hwctx *tmp;
	struct amdxdna_client *client;
	struct amdxdna_hwctx *hwctx;
	bool overflow = false;
	u32 req_bytes = 0;
	u32 hw_i = 0;
	int ret = 0;
	int next;
	int idx;

	drm_WARN_ON(&xdna->ddev, !mutex_is_locked(&xdna->dev_lock));

	tmp = kzalloc(sizeof(*tmp), GFP_KERNEL);
	if (!tmp)
		return -ENOMEM;

	buf = u64_to_user_ptr(args->buffer);
	list_for_each_entry(client, &xdna->client_list, node) {
		idx = srcu_read_lock(&client->hwctx_srcu);
		next = 0;
		idr_for_each_entry_continue(&client->hwctx_idr, hwctx, next) {
			req_bytes += sizeof(tmp);
			if (args->buffer_size < req_bytes) {
				/* Continue iterating to get the required size */
				overflow = true;
				continue;
			}

			tmp->pid = client->pid;
			tmp->context_id = hwctx->id;
			tmp->start_col = hwctx->start_col;
			tmp->num_col = hwctx->num_col;
			tmp->command_submissions = hwctx->priv->seq;
			/* TODO Not implemented section */
			tmp->command_completions = 0;
			tmp->migrations = 0;
			tmp->preemptions = 0;
			tmp->errors = 0;

			if (copy_to_user(&buf[hw_i], tmp, sizeof(*tmp))) {
				ret = -EFAULT;
				srcu_read_unlock(&client->hwctx_srcu, idx);
				goto out;
			}
			hw_i++;
		}
		srcu_read_unlock(&client->hwctx_srcu, idx);
	}

	if (overflow) {
		XDNA_ERR(xdna, "Invalid buffer size. Given: %u Need: %u.",
			 args->buffer_size, req_bytes);
		ret = -EINVAL;
	}

out:
	kfree(tmp);
	args->buffer_size = req_bytes;
	return ret;
}

static int aie2_get_info(struct amdxdna_dev *xdna, struct amdxdna_drm_get_info *args)
{
	int ret, idx;

	if (!drm_dev_enter(&xdna->ddev, &idx))
		return -ENODEV;

	switch (args->param) {
	case DRM_AMDXDNA_QUERY_AIE_STATUS:
		ret = aie2_get_aie_status(xdna, args);
		break;
	case DRM_AMDXDNA_QUERY_AIE_METADATA:
		ret = aie2_get_aie_metadata(xdna, args);
		break;
	case DRM_AMDXDNA_QUERY_AIE_VERSION:
		ret = aie2_get_aie_version(xdna, args);
		break;
	case DRM_AMDXDNA_QUERY_CLOCK_METADATA:
		ret = aie2_get_clock_metadata(xdna, args);
		break;
	case DRM_AMDXDNA_QUERY_SENSORS:
		ret = aie2_get_sensors(xdna, args);
		break;
	case DRM_AMDXDNA_QUERY_HW_CONTEXTS:
		ret = aie2_get_hwctx_status(xdna, args);
		break;
	default:
		XDNA_ERR(xdna, "Not supported request parameter %u", args->param);
		ret = -EOPNOTSUPP;
	}
	XDNA_DBG(xdna, "Got param %d", args->param);

	drm_dev_exit(idx);
	return ret;
}

static int aie2_set_power_mode(struct amdxdna_dev *xdna, struct amdxdna_drm_set_state *args)
{
	struct amdxdna_drm_set_power_mode power_state;

	if (args->buffer_size != sizeof(power_state)) {
		XDNA_ERR(xdna, "Invalid buffer size. Given: %u Need: %lu.",
			 args->buffer_size, sizeof(power_state));
		return -EINVAL;
	}

	if (copy_from_user(&power_state, u64_to_user_ptr(args->buffer), sizeof(power_state))) {
		XDNA_ERR(xdna, "Failed to copy power mode request into kernel");
		return -EFAULT;
	}

	/* Interpret the given buf->power_mode into the correct power mode*/

	/* Set resource solver power property to the user choice */

	/* Set power level within the device */
	return 0;
}

static int aie2_set_state(struct amdxdna_dev *xdna, struct amdxdna_drm_set_state *args)
{
	int ret, idx;

	if (!drm_dev_enter(&xdna->ddev, &idx))
		return -ENODEV;

	switch (args->param) {
	case DRM_AMDXDNA_SET_POWER_MODE:
		ret = aie2_set_power_mode(xdna, args);
		break;
	default:
		XDNA_ERR(xdna, "Not supported request parameter %u", args->param);
		ret = -EOPNOTSUPP;
	}

	drm_dev_exit(idx);
	return ret;
}

const struct amdxdna_dev_ops aie2_ops = {
	.mmap           = NULL,
	.init           = aie2_init,
	.fini           = aie2_fini,
	.resume         = aie2_hw_start,
	.suspend        = aie2_hw_stop,
	.get_info       = aie2_get_info,
	.set_state      = aie2_set_state,
	.hwctx_init     = aie2_hwctx_init,
	.hwctx_fini     = aie2_hwctx_fini,
	.hwctx_config   = aie2_hwctx_config,
	.hwctx_suspend  = aie2_hwctx_suspend,
	.hwctx_resume   = aie2_hwctx_resume,
	.cmd_submit     = aie2_cmd_submit,
	.cmd_wait       = aie2_cmd_wait,
	.debugfs	= aie2_debugfs_init,
};

// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2023-2025, Advanced Micro Devices, Inc.
 */

#include <linux/errno.h>
#include <linux/kthread.h>
#include <linux/iommu.h>
#include <linux/firmware.h>
#include <linux/uaccess.h>
#include <drm/drm_cache.h>
#include "drm_local/amdxdna_accel.h"

#include "aie2_pci.h"
#include "aie2_solver.h"
#include "aie2_msg_priv.h"

#ifdef AMDXDNA_DEVEL
#include "amdxdna_devel.h"
#endif

#ifdef AMDXDNA_AIE2_PRIV
#include "aie2_internal.h"
#endif

uint aie2_max_col = XRS_MAX_COL;
module_param(aie2_max_col, uint, 0600);
MODULE_PARM_DESC(aie2_max_col, "Maximum column could be used");

uint aie2_control_flags;
module_param(aie2_control_flags, uint, 0400);
MODULE_PARM_DESC(aie2_control_flags,
		 " Bit " __stringify(AIE2_BIT_BYPASS_POWER_SWITCH) ": Bypass power on/off,"
		 " Bit " __stringify(AIE2_BIT_BYPASS_SET_FREQ) ": Bypass set freq,"
		 " Bit " __stringify(AIE2_BIT_BYPASS_FW_LOAD) ": Bypass FW loading");

bool disable_fine_preemption;
module_param(disable_fine_preemption, bool, 0600);
MODULE_PARM_DESC(disable_fine_preemption, "Disable fine grain preemption");

/*
 * The management mailbox channel is allocated by firmware.
 * The related register and ring buffer information is on SRAM BAR.
 * This struct is the register layout.
 *
 * Mgmt channel info query flow:
 * 1. Poll alive pointer register until it is non zero
 * 2. The alive pointer pointing to Mgmt Mbox Info on SRAM bar
 * 4. Read x2i_* and i2x_*
 * 3. If magic number MGMT_MBOX_MAGIC not presented, done;
 * Otherwise, read msi_id, major, minor etc..
 */
#define MGMT_MBOX_MAGIC 0x55504e5f /* _NPU */
#define MAGIC_OFFSET offsetof(struct mgmt_mbox_chann_info, magic[0])
struct mgmt_mbox_chann_info {
	__u32	x2i_tail;
	__u32	x2i_head;
	__u32	x2i_buf;
	__u32	x2i_buf_sz;
	__u32	i2x_tail;
	__u32	i2x_head;
	__u32	i2x_buf;
	__u32	i2x_buf_sz;
	__u32	magic;
	__u32	msi_id;
	__u32	prot_major;
	__u32	prot_minor;
	__u32	rsvd[4];
};

int aie2_check_protocol(struct amdxdna_dev_hdl *ndev, u32 fw_major, u32 fw_minor)
{
	struct amdxdna_dev *xdna = ndev->xdna;

	/*
	 * The driver supported mailbox behavior is defined by
	 * ndev->priv->protocol_major and protocol_minor.
	 *
	 * When major different, it means incompatible behavior.
	 * When only minor different, the greater minor means more opcode etc.
	 *
	 * Thus,
	 * 1. driver and fw major must be the same
	 * 2. driver minor must smaller than or equal to fw minor
	 */
	if (ndev->priv->protocol_major != fw_major) {
		XDNA_ERR(xdna, "Incompatible firmware protocol major %d minor %d",
			 fw_major, fw_minor);
		return -EINVAL;
	}

	/*
	 * Greater protocol minor version means new messages/status/emun are
	 * added into the firmware interface protocol.
	 */
	if (ndev->priv->protocol_minor > fw_minor) {
		XDNA_ERR(xdna, "Firmware minor version smaller than supported");
		return -EINVAL;
	}
	return 0;
}

static inline void aie2_dump_chann_info_debug(struct amdxdna_dev_hdl *ndev)
{
	struct amdxdna_dev *xdna = ndev->xdna;

	XDNA_DBG(xdna, "i2x tail    0x%x", ndev->mgmt_info.i2x.mb_tail_ptr_reg);
	XDNA_DBG(xdna, "i2x head    0x%x", ndev->mgmt_info.i2x.mb_head_ptr_reg);
	XDNA_DBG(xdna, "i2x ringbuf 0x%x", ndev->mgmt_info.i2x.rb_start_addr);
	XDNA_DBG(xdna, "i2x rsize   0x%x", ndev->mgmt_info.i2x.rb_size);
	XDNA_DBG(xdna, "x2i tail    0x%x", ndev->mgmt_info.x2i.mb_tail_ptr_reg);
	XDNA_DBG(xdna, "x2i head    0x%x", ndev->mgmt_info.x2i.mb_head_ptr_reg);
	XDNA_DBG(xdna, "x2i ringbuf 0x%x", ndev->mgmt_info.x2i.rb_start_addr);
	XDNA_DBG(xdna, "x2i rsize   0x%x", ndev->mgmt_info.x2i.rb_size);
	XDNA_DBG(xdna, "x2i chann index 0x%x", ndev->mgmt_info.msix_id);
	if (!ndev->mgmt_prot_major)
		return;

	XDNA_DBG(xdna, "mailbox protocol major 0x%x", ndev->mgmt_prot_major);
	XDNA_DBG(xdna, "mailbox protocol minor 0x%x", ndev->mgmt_prot_minor);
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

	i2x = &ndev->mgmt_info.i2x;
	x2i = &ndev->mgmt_info.x2i;

	i2x->mb_head_ptr_reg = AIE2_MBOX_OFF(ndev, info_regs.i2x_head);
	i2x->mb_tail_ptr_reg = AIE2_MBOX_OFF(ndev, info_regs.i2x_tail);
	i2x->rb_start_addr   = AIE2_SRAM_OFF(ndev, info_regs.i2x_buf);
	i2x->rb_size         = info_regs.i2x_buf_sz;

	x2i->mb_head_ptr_reg = AIE2_MBOX_OFF(ndev, info_regs.x2i_head);
	x2i->mb_tail_ptr_reg = AIE2_MBOX_OFF(ndev, info_regs.x2i_tail);
	x2i->rb_start_addr   = AIE2_SRAM_OFF(ndev, info_regs.x2i_buf);
	x2i->rb_size         = info_regs.x2i_buf_sz;

	if (info_regs.magic != MGMT_MBOX_MAGIC) {
		ndev->mgmt_info.msix_id = CHANN_INDEX(ndev, x2i->rb_start_addr);
		goto done;
	}

	ndev->mgmt_info.msix_id  = info_regs.msi_id;
	ndev->mgmt_prot_major = info_regs.prot_major;
	ndev->mgmt_prot_minor = info_regs.prot_minor;
	if (aie2_check_protocol(ndev, ndev->mgmt_prot_major, ndev->mgmt_prot_minor))
		ret = -EINVAL;

done:
	aie2_calc_intr_reg(&ndev->mgmt_info);
	aie2_dump_chann_info_debug(ndev);

	/* Must clear address at FW_ALIVE_OFF */
	writel(0, SRAM_GET_ADDR(ndev, FW_ALIVE_OFF));

	return ret;
}

int aie2_runtime_cfg(struct amdxdna_dev_hdl *ndev,
		     enum rt_config_category category, u32 *val)
{
	const struct rt_config *cfg;
	u32 value;
	int ret;

	for (cfg = ndev->priv->rt_config; cfg->type; cfg++) {
		if (cfg->category != category)
			continue;

		value = val ? *val : cfg->value;
#ifdef AMDXDNA_DEVEL
		if (priv_load && cfg->type == ndev->priv->priv_load_cfg.type) {
			cfg = &ndev->priv->priv_load_cfg;
			value = cfg->value;
			XDNA_INFO(ndev->xdna, "Set runtime type %d value %d",
				  cfg->type, cfg->value);
		}
#endif
		ret = aie2_set_runtime_cfg(ndev, cfg->type, value);
		if (ret) {
			XDNA_ERR(ndev->xdna, "Set runtime type %d value %d failed",
				 cfg->type, value);
			return ret;
		}
	}

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
	u32 preempt;
	int ret;

	if (!ndev->mgmt_prot_major) {
		ret = aie2_check_protocol_version(ndev);
		if (ret) {
			XDNA_ERR(ndev->xdna, "Check protocol version failed");
			return ret;
		}
	}

	ret = aie2_runtime_cfg(ndev, AIE2_RT_CFG_INIT, NULL);
	if (ret) {
		XDNA_ERR(ndev->xdna, "Runtime config failed");
		return ret;
	}

	if (disable_fine_preemption)
		preempt = 0;
	else
		preempt = 1;

	ret = aie2_runtime_cfg(ndev, AIE2_RT_CFG_FINE_PREEMPTION, &preempt);
	if (ret) {
		XDNA_ERR(ndev->xdna, "Failed to %s fine grain preemption",
			 disable_fine_preemption ? "disable" : "enable");
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

static int aie2_xrs_set_dft_dpm_level(struct drm_device *ddev, u32 dpm_level)
{
	struct amdxdna_dev *xdna = to_xdna_dev(ddev);
	struct amdxdna_dev_hdl *ndev;

	ndev = xdna->dev_handle;
	drm_WARN_ON(&xdna->ddev, !mutex_is_locked(&ndev->aie2_lock));
	ndev->dft_dpm_level = dpm_level;
	if (ndev->pw_mode != POWER_MODE_DEFAULT || ndev->dpm_level == dpm_level)
		return 0;

	return ndev->priv->hw_ops.set_dpm(ndev, dpm_level);
}

static struct xrs_action_ops aie2_xrs_actions = {
	.load_hwctx = aie2_xrs_load_hwctx,
	.unload_hwctx = aie2_xrs_unload_hwctx,
	.set_dft_dpm_level = aie2_xrs_set_dft_dpm_level,
};

static void aie2_hw_stop(struct amdxdna_dev *xdna)
{
	struct pci_dev *pdev = to_pci_dev(xdna->ddev.dev);
	struct amdxdna_dev_hdl *ndev = xdna->dev_handle;

	if (ndev->dev_status <= AIE2_DEV_INIT) {
		XDNA_ERR(xdna, "device is already stopped");
		return;
	}

	mutex_lock(&ndev->aie2_lock);
	aie2_pm_fini(ndev);
	aie2_mgmt_fw_fini(ndev);
	xdna_mailbox_stop_channel(ndev->mgmt_chann);
	xdna_mailbox_destroy_channel(ndev->mgmt_chann);
	ndev->mgmt_chann = NULL;
	if (ndev->mbox) {
		xdna_mailbox_destroy(ndev->mbox);
		ndev->mbox = NULL;
	}
	aie2_psp_stop(ndev->psp_hdl);
	aie2_smu_stop(ndev);
	mutex_unlock(&ndev->aie2_lock);
	pci_clear_master(pdev);
	pci_disable_device(pdev);

	ndev->dev_status = AIE2_DEV_INIT;
}

static int aie2_hw_start(struct amdxdna_dev *xdna)
{
	struct pci_dev *pdev = to_pci_dev(xdna->ddev.dev);
	struct amdxdna_dev_hdl *ndev = xdna->dev_handle;
	struct xdna_mailbox_res mbox_res;
	int ret;

	if (ndev->dev_status >= AIE2_DEV_START) {
		XDNA_INFO(xdna, "device is already started");
		return 0;
	}

	ret = pci_enable_device(pdev);
	if (ret) {
		XDNA_ERR(xdna, "failed to enable device, ret %d", ret);
		return ret;
	}
	pci_set_master(pdev);

	/*
	 * aie2_smu_start(), aie2_pm_init() and aie2_mgmt_fw_init() require
	 * aie2_lock. One mutex_lock() and mutex_unlock() is simpler.
	 */
	mutex_lock(&ndev->aie2_lock);
	ret = aie2_smu_start(ndev);
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
		XDNA_ERR(xdna, "firmware mgmt info ret %d", ret);
		goto stop_psp;
	}

	mbox_res.ringbuf_base = ndev->sram_base;
	mbox_res.ringbuf_size = pci_resource_len(pdev, xdna->dev_info->sram_bar);
	mbox_res.mbox_base = ndev->mbox_base;
	mbox_res.mbox_size = MBOX_SIZE(ndev);
	mbox_res.name = "xdna_mailbox";
	ndev->mbox = xdna_mailbox_create(&pdev->dev, &mbox_res);
	if (!ndev->mbox) {
		XDNA_ERR(xdna, "failed to create mailbox device");
		ret = -ENODEV;
		goto stop_psp;
	}

	ndev->mgmt_chann = xdna_mailbox_create_channel(ndev->mbox, &ndev->mgmt_info,
						       MB_CHANNEL_MGMT);
	if (!ndev->mgmt_chann) {
		XDNA_ERR(xdna, "failed to create management mailbox channel");
		ret = -EINVAL;
		goto destroy_mbox;
	}

	ret = aie2_pm_init(ndev);
	if (ret) {
		XDNA_ERR(xdna, "failed to init pm, ret %d", ret);
		goto destroy_mgmt_chann;
	}

	ret = aie2_mgmt_fw_init(ndev);
	if (ret) {
		XDNA_ERR(xdna, "initial mgmt firmware failed, ret %d", ret);
		goto destroy_mgmt_chann;
	}

	mutex_unlock(&ndev->aie2_lock);
	ndev->dev_status = AIE2_DEV_START;

	return 0;

destroy_mgmt_chann:
	xdna_mailbox_stop_channel(ndev->mgmt_chann);
	xdna_mailbox_destroy_channel(ndev->mgmt_chann);
	ndev->mgmt_chann = NULL;
destroy_mbox:
	xdna_mailbox_destroy(ndev->mbox);
	ndev->mbox = NULL;
stop_psp:
	aie2_psp_stop(ndev->psp_hdl);
fini_smu:
	aie2_smu_stop(ndev);
disable_dev:
	mutex_unlock(&ndev->aie2_lock);
	pci_disable_device(pdev);
	pci_clear_master(pdev);

	return ret;
}

static void aie2_hw_suspend(struct amdxdna_dev *xdna)
{
	aie2_rq_pause_all(&xdna->dev_handle->ctx_rq);
	aie2_hw_stop(xdna);
}

static int aie2_hw_resume(struct amdxdna_dev *xdna)
{
	int ret;

	XDNA_INFO(xdna, "firmware resuming...");
	ret = aie2_hw_start(xdna);
	if (ret) {
		XDNA_ERR(xdna, "resume NPU firmware failed");
		return ret;
	}

	XDNA_INFO(xdna, "context resuming...");
	aie2_rq_run_all(&xdna->dev_handle->ctx_rq);
	return 0;
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

	XDNA_DBG(xdna, "Control flags 0x%x", aie2_control_flags);
	ndev = devm_kzalloc(&pdev->dev, sizeof(*ndev), GFP_KERNEL);
	if (!ndev)
		return -ENOMEM;

	ndev->priv = xdna->dev_info->dev_priv;
	ndev->xdna = xdna;
	mutex_init(&ndev->aie2_lock);

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

#ifdef AMDXDNA_DEVEL
	ret = amdxdna_iommu_mode_setup(xdna);
	if (ret) {
		XDNA_ERR(xdna, "Setup iommu mode %d failed, ret %d", iommu_mode, ret);
		goto free_irq;
	}
	if (iommu_mode != AMDXDNA_IOMMU_PASID)
		goto skip_pasid;
#endif
	ret = iommu_dev_enable_feature(&pdev->dev, IOMMU_DEV_FEAT_SVA);
	if (ret) {
		XDNA_ERR(xdna, "Enable PASID failed, ret %d", ret);
		goto free_irq;
	}
#ifdef AMDXDNA_DEVEL
skip_pasid:
		XDNA_INFO(xdna, "(Develop) IOMMU mode is %d", iommu_mode);
#endif

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

	ret = aie2_rq_init(&ndev->ctx_rq);
	if (ret) {
		XDNA_ERR(xdna, "Context runqueue init failed");
		goto stop_hw;
	}

	mutex_lock(&ndev->aie2_lock);
	ret = aie2_mgmt_fw_query(ndev);
	if (ret) {
		XDNA_ERR(xdna, "Query firmware failed, ret %d", ret);
		goto failed_rq_fini;
	}
	ndev->total_col = min(aie2_max_col, ndev->metadata.cols);

	xrs_cfg.clk_list.num_levels = ndev->max_dpm_level + 1;
	for (i = 0; i < xrs_cfg.clk_list.num_levels; i++)
		xrs_cfg.clk_list.cu_clk_list[i] = ndev->priv->dpm_clk_tbl[i].hclk;
	xrs_cfg.sys_eff_factor = 1;
	xrs_cfg.ddev = &xdna->ddev;
	xrs_cfg.actions = &aie2_xrs_actions;
	xrs_cfg.total_col = ndev->total_col;

	ndev->xrs_hdl = xrsm_init(&xrs_cfg);
	if (!ndev->xrs_hdl) {
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
	mutex_unlock(&ndev->aie2_lock);

	ret = aie2_event_trace_init(ndev);
	if (ret)
		XDNA_DBG(xdna, "Event trace init failed, ret %d", ret);

	release_firmware(fw);
	return 0;

async_event_free:
	mutex_unlock(&ndev->aie2_lock);
	aie2_error_async_events_free(ndev);
failed_rq_fini:
	aie2_rq_fini(&ndev->ctx_rq);
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

	aie2_event_trace_fini(ndev);
	aie2_rq_fini(&ndev->ctx_rq);
	aie2_hw_stop(xdna);
	aie2_error_async_events_free(ndev);
#ifdef AMDXDNA_DEVEL
	if (iommu_mode != AMDXDNA_IOMMU_PASID)
		goto skip_pasid;
#endif
	iommu_dev_disable_feature(&pdev->dev, IOMMU_DEV_FEAT_SVA);
#ifdef AMDXDNA_DEVEL
skip_pasid:
#endif
	pci_free_irq_vectors(pdev);
	mutex_destroy(&ndev->aie2_lock);
}

/* This function returns recover is needed or not */
static bool aie2_detect(struct amdxdna_dev *xdna)
{
	struct aie2_ctx_rq *rq = &xdna->dev_handle->ctx_rq;

	if (aie2_rq_handle_idle_ctx(rq))
		return false;

	return aie2_rq_is_all_context_stuck(rq);
}

static void aie2_recover(struct amdxdna_dev *xdna, bool dump_only)
{
	struct aie2_ctx_rq *rq = &xdna->dev_handle->ctx_rq;
	struct amdxdna_client *client;

	if (dump_only) {
		mutex_lock(&xdna->dev_lock);
		list_for_each_entry(client, &xdna->client_list, node)
			aie2_dump_ctx(client);
		mutex_unlock(&xdna->dev_lock);
		return;
	}

	mutex_lock(&xdna->dev_lock);
	aie2_rq_pause_all_nolock(rq);

	aie2_rq_run_all_nolock(rq);
	mutex_unlock(&xdna->dev_lock);
}

static int aie2_get_aie_status(struct amdxdna_client *client,
			       struct amdxdna_drm_get_info *args)
{
	struct amdxdna_drm_query_aie_status status;
	struct amdxdna_dev *xdna = client->xdna;
	struct amdxdna_dev_hdl *ndev;
	int ret;

	ndev = xdna->dev_handle;
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

static int aie2_get_aie_metadata(struct amdxdna_client *client,
				 struct amdxdna_drm_get_info *args)
{
	struct amdxdna_drm_query_aie_metadata *meta;
	struct amdxdna_dev *xdna = client->xdna;
	struct amdxdna_dev_hdl *ndev;
	int ret = 0;

	ndev = xdna->dev_handle;
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

static int aie2_get_aie_version(struct amdxdna_client *client,
				struct amdxdna_drm_get_info *args)
{
	struct amdxdna_drm_query_aie_version version;
	struct amdxdna_dev *xdna = client->xdna;
	struct amdxdna_dev_hdl *ndev;

	ndev = xdna->dev_handle;
	version.major = ndev->version.major;
	version.minor = ndev->version.minor;

	if (copy_to_user(u64_to_user_ptr(args->buffer), &version, sizeof(version)))
		return -EFAULT;

	return 0;
}

static int aie2_get_firmware_version(struct amdxdna_client *client,
				     struct amdxdna_drm_get_info *args)
{
	struct amdxdna_drm_query_firmware_version version;
	struct amdxdna_dev *xdna = client->xdna;

	version.major = xdna->fw_ver.major;
	version.minor = xdna->fw_ver.minor;
	version.patch = xdna->fw_ver.sub;
	version.build = xdna->fw_ver.build;

	if (copy_to_user(u64_to_user_ptr(args->buffer), &version, sizeof(version)))
		return -EFAULT;

	return 0;
}

static int aie2_get_power_mode(struct amdxdna_client *client,
			       struct amdxdna_drm_get_info *args)
{
	struct amdxdna_drm_get_power_mode mode = {};
	struct amdxdna_dev *xdna = client->xdna;
	struct amdxdna_dev_hdl *ndev;

	ndev = xdna->dev_handle;
	mode.power_mode = ndev->pw_mode;

	if (copy_to_user(u64_to_user_ptr(args->buffer), &mode, sizeof(mode)))
		return -EFAULT;

	return 0;
}

static int aie2_get_clock_metadata(struct amdxdna_client *client,
				   struct amdxdna_drm_get_info *args)
{
	struct amdxdna_drm_query_clock_metadata *clock;
	struct amdxdna_dev *xdna = client->xdna;
	struct amdxdna_dev_hdl *ndev;
	int ret = 0;

	ndev = xdna->dev_handle;
	clock = kzalloc(sizeof(*clock), GFP_KERNEL);
	if (!clock)
		return -ENOMEM;

	snprintf(clock->mp_npu_clock.name, sizeof(clock->mp_npu_clock.name),
		 "MP-NPU Clock");
	clock->mp_npu_clock.freq_mhz = ndev->npuclk_freq;
	snprintf(clock->h_clock.name, sizeof(clock->h_clock.name), "H Clock");
	clock->h_clock.freq_mhz = ndev->hclk_freq;

	if (copy_to_user(u64_to_user_ptr(args->buffer), clock, sizeof(*clock)))
		ret = -EFAULT;

	kfree(clock);
	return ret;
}

static int aie2_get_sensors(struct amdxdna_client *client,
			    struct amdxdna_drm_get_info *args)
{
	struct amdxdna_drm_query_sensor *sensor;
	int ret = 0;

	sensor = kzalloc(sizeof(*sensor), GFP_KERNEL);
	if (!sensor)
		return -ENOMEM;

	sensor->type = AMDXDNA_SENSOR_TYPE_POWER;
	sensor->input = __UINT32_MAX__; /* TODO: query the device and get the power data */
	sensor->unitm = -3; /* in milliwatts */
	snprintf(sensor->label, sizeof(sensor->label), "Total Power");
	snprintf(sensor->units, sizeof(sensor->units), "mW");

	if (copy_to_user(u64_to_user_ptr(args->buffer), sensor, sizeof(*sensor)))
		ret = -EFAULT;

	kfree(sensor);
	return ret;
}

static int aie2_get_ctx_status(struct amdxdna_client *client,
			       struct amdxdna_drm_get_info *args)
{
	struct amdxdna_drm_query_ctx __user *buf;
	struct amdxdna_dev *xdna = client->xdna;
	struct amdxdna_drm_query_ctx *tmp;
	struct amdxdna_client *tmp_client;
	struct amdxdna_ctx *ctx;
	unsigned long ctx_id;
	bool overflow = false;
	u32 req_bytes = 0;
	u32 hw_i = 0;
	int ret = 0;
	int idx;

	tmp = kzalloc(sizeof(*tmp), GFP_KERNEL);
	if (!tmp)
		return -ENOMEM;

	buf = u64_to_user_ptr(args->buffer);
	mutex_lock(&xdna->dev_lock);
	list_for_each_entry(tmp_client, &xdna->client_list, node) {
		idx = srcu_read_lock(&tmp_client->ctx_srcu);
		amdxdna_for_each_ctx(tmp_client, ctx_id, ctx) {
			req_bytes += sizeof(*tmp);
			if (args->buffer_size < req_bytes) {
				/* Continue iterating to get the required size */
				overflow = true;
				continue;
			}

			tmp->pid = tmp_client->pid;
			tmp->context_id = ctx->id;
			tmp->hwctx_id = ctx->priv->id;
			tmp->start_col = ctx->start_col;
			tmp->num_col = ctx->num_col;
			tmp->command_submissions = ctx->submitted;
			tmp->command_completions = ctx->completed;
			tmp->migrations = 0;
			tmp->preemptions = 0;
			tmp->errors = 0;
			tmp->priority = ctx->qos.priority;

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

static int aie2_get_telemetry(struct amdxdna_client *client,
			      struct amdxdna_drm_get_info *args)
{
	struct amdxdna_dev *xdna = client->xdna;
	struct amdxdna_dev_hdl *ndev;
	struct aie_version ver;
	dma_addr_t dma_addr;
	size_t aligned_sz;
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

	ndev = xdna->dev_handle;
	aligned_sz = PAGE_ALIGN(args->buffer_size);
	buff = dma_alloc_noncoherent(xdna->ddev.dev, aligned_sz, &dma_addr,
				     DMA_FROM_DEVICE, GFP_KERNEL);
	if (!buff)
		return -ENOMEM;

	memset(buff, 0, aligned_sz);
	drm_clflush_virt_range(buff, aligned_sz); /* device can access */
	/* The first two words of the buffer is reserved for major and minor */
	ret = aie2_query_telemetry(ndev, type, dma_addr + sizeof(u64), aligned_sz, &ver);
	if (ret) {
		XDNA_ERR(xdna, "Get telemetry failed ret %d", ret);
		goto free_buf;
	}

	((u32 *)buff)[0] = ver.major;
	((u32 *)buff)[1] = ver.minor;
	print_hex_dump_debug("telemetry: ", DUMP_PREFIX_OFFSET, 16, 4, buff,
			     aligned_sz, false);
	if (copy_to_user(u64_to_user_ptr(args->buffer), buff, args->buffer_size))
		ret = -EFAULT;

free_buf:
	dma_free_noncoherent(xdna->ddev.dev, aligned_sz, buff, dma_addr, DMA_FROM_DEVICE);
	return ret;
}

static int aie2_get_force_preempt_state(struct amdxdna_client *client,
					struct amdxdna_drm_get_info *args)
{
	struct amdxdna_drm_get_force_preempt_state force = {};
	struct amdxdna_dev *xdna = client->xdna;
	struct amdxdna_dev_hdl *ndev;

	ndev = xdna->dev_handle;
	force.state = ndev->force_preempt_enabled;

	if (copy_to_user(u64_to_user_ptr(args->buffer), &force, sizeof(force)))
		return -EFAULT;

	return 0;
}

static int aie2_get_info(struct amdxdna_client *client, struct amdxdna_drm_get_info *args)
{
	struct amdxdna_dev *xdna = client->xdna;
	int ret, idx;

	if (!drm_dev_enter(&xdna->ddev, &idx))
		return -ENODEV;

	mutex_lock(&xdna->dev_handle->aie2_lock);
	switch (args->param) {
	case DRM_AMDXDNA_QUERY_AIE_STATUS:
		ret = aie2_get_aie_status(client, args);
		break;
	case DRM_AMDXDNA_QUERY_AIE_METADATA:
		ret = aie2_get_aie_metadata(client, args);
		break;
	case DRM_AMDXDNA_QUERY_AIE_VERSION:
		ret = aie2_get_aie_version(client, args);
		break;
	case DRM_AMDXDNA_QUERY_CLOCK_METADATA:
		ret = aie2_get_clock_metadata(client, args);
		break;
	case DRM_AMDXDNA_QUERY_SENSORS:
		ret = aie2_get_sensors(client, args);
		break;
	case DRM_AMDXDNA_QUERY_HW_CONTEXTS:
		mutex_unlock(&xdna->dev_handle->aie2_lock);
		ret = aie2_get_ctx_status(client, args);
		mutex_lock(&xdna->dev_handle->aie2_lock);
		break;
#ifdef AMDXDNA_AIE2_PRIV
	case DRM_AMDXDNA_READ_AIE_MEM:
		ret = aie2_read_aie_mem(client, args);
		break;
	case DRM_AMDXDNA_READ_AIE_REG:
		ret = aie2_read_aie_reg(client, args);
		break;
#endif
	case DRM_AMDXDNA_QUERY_FIRMWARE_VERSION:
		ret = aie2_get_firmware_version(client, args);
		break;
	case DRM_AMDXDNA_GET_POWER_MODE:
		ret = aie2_get_power_mode(client, args);
		break;
	case DRM_AMDXDNA_QUERY_TELEMETRY:
		ret = aie2_get_telemetry(client, args);
		break;
	case DRM_AMDXDNA_GET_FORCE_PREEMPT_STATE:
		ret = aie2_get_force_preempt_state(client, args);
		break;
	default:
		XDNA_ERR(xdna, "Not supported request parameter %u", args->param);
		ret = -EOPNOTSUPP;
	}
	mutex_unlock(&xdna->dev_handle->aie2_lock);
	XDNA_DBG(xdna, "Got param %d", args->param);

	drm_dev_exit(idx);
	return ret;
}

static int aie2_set_power_mode(struct amdxdna_client *client, struct amdxdna_drm_set_state *args)
{
	struct amdxdna_drm_set_power_mode power_state;
	struct amdxdna_dev *xdna = client->xdna;
	int power_mode;

	if (args->buffer_size != sizeof(power_state)) {
		XDNA_ERR(xdna, "Invalid buffer size. Given: %u Need: %lu.",
			 args->buffer_size, sizeof(power_state));
		return -EINVAL;
	}

	if (copy_from_user(&power_state, u64_to_user_ptr(args->buffer), sizeof(power_state))) {
		XDNA_ERR(xdna, "Failed to copy power mode request into kernel");
		return -EFAULT;
	}

	power_mode = power_state.power_mode;
	if (power_mode > POWER_MODE_TURBO) {
		XDNA_ERR(xdna, "Invalid power mode %d", power_mode);
		return -EINVAL;
	}

	return aie2_pm_set_mode(xdna->dev_handle, power_mode);
}

static int aie2_set_force_preempt_state(struct amdxdna_client *client,
					struct amdxdna_drm_set_state *args)
{
	struct amdxdna_drm_set_force_preempt_state force;
	struct amdxdna_dev *xdna = client->xdna;

	if (args->buffer_size != sizeof(force)) {
		XDNA_ERR(xdna, "Invalid buffer size. Given: %u Need: %lu.",
			 args->buffer_size, sizeof(force));
		return -EINVAL;
	}

	if (copy_from_user(&force, u64_to_user_ptr(args->buffer), sizeof(force))) {
		XDNA_ERR(xdna, "Failed to copy force preemption request into kernel");
		return -EFAULT;
	}

	xdna->dev_handle->force_preempt_enabled = force.state;

	XDNA_WARN(xdna, "Force preemption %s", force.state ? "enabled" : "disabled");

	return 0;
}

static int aie2_set_state(struct amdxdna_client *client, struct amdxdna_drm_set_state *args)
{
	struct amdxdna_dev *xdna = client->xdna;
	int ret, idx;

	if (!drm_dev_enter(&xdna->ddev, &idx))
		return -ENODEV;

	mutex_lock(&xdna->dev_handle->aie2_lock);
	switch (args->param) {
	case DRM_AMDXDNA_SET_POWER_MODE:
		ret = aie2_set_power_mode(client, args);
		break;
	case DRM_AMDXDNA_SET_FORCE_PREEMPT:
		ret = aie2_set_force_preempt_state(client, args);
		break;
#ifdef AMDXDNA_AIE2_PRIV
	case DRM_AMDXDNA_WRITE_AIE_MEM:
		ret = aie2_write_aie_mem(client, args);
		break;
	case DRM_AMDXDNA_WRITE_AIE_REG:
		ret = aie2_write_aie_reg(client, args);
		break;
#endif
	default:
		XDNA_ERR(xdna, "Not supported request parameter %u", args->param);
		ret = -EOPNOTSUPP;
	}
	mutex_unlock(&xdna->dev_handle->aie2_lock);

	drm_dev_exit(idx);
	return ret;
}

const struct amdxdna_dev_ops aie2_ops = {
	.mmap			= NULL,
	.init			= aie2_init,
	.fini			= aie2_fini,
	.detect			= aie2_detect,
	.recover		= aie2_recover,
	.resume			= aie2_hw_resume,
	.suspend		= aie2_hw_suspend,
	.get_aie_info		= aie2_get_info,
	.set_aie_state		= aie2_set_state,
	.ctx_init		= aie2_ctx_init,
	.ctx_fini		= aie2_ctx_fini,
	.ctx_config		= aie2_ctx_config,
	.cmd_submit		= aie2_cmd_submit,
	.cmd_wait		= aie2_cmd_wait,
	.hmm_invalidate		= aie2_hmm_invalidate,
	.debugfs		= aie2_debugfs_init,
	.cmd_get_out_fence	= aie2_cmd_get_out_fence,
};

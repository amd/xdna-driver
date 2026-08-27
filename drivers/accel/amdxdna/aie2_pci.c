// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2023-2024, Advanced Micro Devices, Inc.
 */

#include "drm/amdxdna_accel.h"
#include <drm/drm_cache.h>
#include <drm/drm_device.h>
#include <drm/drm_drv.h>
#include <drm/drm_gem_shmem_helper.h>
#include <drm/drm_managed.h>
#include <drm/drm_print.h>
#include <drm/gpu_scheduler.h>
#include <linux/bitfield.h>
#include <linux/cleanup.h>
#include <linux/errno.h>
#include <linux/firmware.h>
#include <linux/iommu.h>
#include <linux/iopoll.h>
#include <linux/pci.h>
#include <linux/rcupdate.h>
#include <linux/xarray.h>
#include <asm/hypervisor.h>

#include "aie.h"
#include "amdxdna_coredump.h"
#include "amdxdna_tile_read_write.h"
#include "aie2_msg_priv.h"
#include "aie2_pci.h"
#include "aie2_solver.h"
#include "amdxdna_ctx.h"
#include "amdxdna_dpt.h"
#include "amdxdna_gem.h"
#include "amdxdna_mailbox.h"
#include "amdxdna_mailbox_helper.h"
#include "amdxdna_pci_drv.h"
#include "amdxdna_pm.h"
#include "amdxdna_sensors.h"

static int aie2_max_col = XRS_MAX_COL;
module_param(aie2_max_col, uint, 0600);
MODULE_PARM_DESC(aie2_max_col, "Maximum column could be used");

#define DEFAULT_TIME_QUANTUM 30000 /* microseconds */

static char *npu_fw[] = {
	"npu.dev.sbin",
	"npu_7.sbin",
	"npu.sbin"
};

/*
 * The management mailbox channel is allocated by firmware.
 * The related register and ring buffer information is on SRAM BAR.
 * This struct is the register layout.
 */
#define MGMT_MBOX_MAGIC 0x55504e5f /* _NPU */
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
				 addr, addr, AIE_INTERVAL, AIE_TIMEOUT);
	if (ret || !addr)
		return -ETIME;

	off = AIE2_SRAM_OFF(ndev, addr);
	reg = (u32 *)&info_regs;
	for (i = 0; i < sizeof(info_regs) / sizeof(u32); i++)
		reg[i] = readl(ndev->sram_base + off + i * sizeof(u32));

	if (info_regs.magic != MGMT_MBOX_MAGIC) {
		XDNA_ERR(ndev->aie.xdna, "Invalid mbox magic 0x%x", info_regs.magic);
		ret = -EINVAL;
		goto done;
	}

	i2x = &ndev->aie.mgmt_i2x;
	x2i = &ndev->aie.mgmt_x2i;

	i2x->mb_head_ptr_reg = AIE2_MBOX_OFF(ndev, info_regs.i2x_head);
	i2x->mb_tail_ptr_reg = AIE2_MBOX_OFF(ndev, info_regs.i2x_tail);
	i2x->rb_start_addr   = AIE2_SRAM_OFF(ndev, info_regs.i2x_buf);
	i2x->rb_size         = info_regs.i2x_buf_sz;

	x2i->mb_head_ptr_reg = AIE2_MBOX_OFF(ndev, info_regs.x2i_head);
	x2i->mb_tail_ptr_reg = AIE2_MBOX_OFF(ndev, info_regs.x2i_tail);
	x2i->rb_start_addr   = AIE2_SRAM_OFF(ndev, info_regs.x2i_buf);
	x2i->rb_size         = info_regs.x2i_buf_sz;

	ndev->aie.mgmt_chan_idx  = info_regs.msi_id;
	ndev->aie.mgmt_prot_major = info_regs.prot_major;
	ndev->aie.mgmt_prot_minor = info_regs.prot_minor;

	ret = aie_check_protocol(&ndev->aie, ndev->aie.mgmt_prot_major,
				 ndev->aie.mgmt_prot_minor);

done:
	aie_dump_mgmt_chann_debug(&ndev->aie);

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

		if (cfg->feature_mask &&
		    bitmap_subset(&cfg->feature_mask, &ndev->aie.feature_mask,
				  AIE2_FEATURE_MAX))
			continue;

		value = val ? *val : cfg->value;
		ret = aie2_set_runtime_cfg(ndev, cfg->type, value);
		if (ret) {
			XDNA_ERR(ndev->aie.xdna, "Set type %d value %d failed",
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
		XDNA_ERR(ndev->aie.xdna, "Suspend firmware failed");
		return ret;
	}

	ret = aie2_resume_fw(ndev);
	if (ret) {
		XDNA_ERR(ndev->aie.xdna, "Resume firmware failed");
		return ret;
	}

	return 0;
}

static int aie2_mgmt_fw_init(struct amdxdna_dev_hdl *ndev)
{
	int ret;

	ret = aie2_runtime_cfg(ndev, AIE2_RT_CFG_INIT, NULL);
	if (ret) {
		XDNA_ERR(ndev->aie.xdna, "Runtime config failed");
		return ret;
	}

	ret = aie2_assign_mgmt_pasid(ndev, 0);
	if (ret) {
		XDNA_ERR(ndev->aie.xdna, "Can not assign PASID");
		return ret;
	}

	ret = aie2_update_prop_time_quota(ndev, DEFAULT_TIME_QUANTUM);
	if (ret) {
		XDNA_ERR(ndev->aie.xdna, "Failed to update execution time quantum");
		return ret;
	}

	ret = aie2_xdna_reset(ndev);
	if (ret) {
		XDNA_ERR(ndev->aie.xdna, "Reset firmware failed");
		return ret;
	}

	ret = aie2_calibrate_clock(ndev);
	if (ret) {
		XDNA_ERR(ndev->aie.xdna, "Calibrate system clock failed");
		return ret;
	}

	return 0;
}

static int aie2_mgmt_fw_query(struct amdxdna_dev_hdl *ndev)
{
	struct amdxdna_dev *xdna = ndev->aie.xdna;
	int ret;

	ret = aie2_query_firmware_version(ndev, &xdna->fw_ver);
	if (ret) {
		XDNA_ERR(ndev->aie.xdna, "query firmware version failed");
		return ret;
	}

	ret = aie2_query_aie_version(ndev, &ndev->aie.version);
	if (ret) {
		XDNA_ERR(ndev->aie.xdna, "Query AIE version failed");
		return ret;
	}

	ret = aie2_query_aie_metadata(ndev, &ndev->aie.metadata);
	if (ret) {
		XDNA_ERR(ndev->aie.xdna, "Query AIE metadata failed");
		return ret;
	}

	ndev->total_col = min(aie2_max_col, ndev->aie.metadata.cols);

	return 0;
}

static void aie2_mgmt_fw_fini(struct amdxdna_dev_hdl *ndev)
{
	if (aie2_suspend_fw(ndev))
		XDNA_ERR(ndev->aie.xdna, "Suspend_fw failed");
	XDNA_DBG(ndev->aie.xdna, "Firmware suspended");
}

static int aie2_xrs_load(void *cb_arg, struct xrs_action_load *action)
{
	struct amdxdna_hwctx *hwctx = cb_arg;
	struct amdxdna_dev *xdna;
	int ret;

	xdna = hwctx->client->xdna;

	hwctx->start_col = action->part.start_col;
	hwctx->num_unused_col = action->part.ncols - hwctx->num_col;
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

static int aie2_xrs_set_dft_dpm_level(struct drm_device *ddev, u32 dpm_level)
{
	struct amdxdna_dev *xdna = to_xdna_dev(ddev);
	struct amdxdna_dev_hdl *ndev;

	drm_WARN_ON(&xdna->ddev, !mutex_is_locked(&xdna->dev_lock));

	ndev = xdna->dev_handle;
	ndev->dft_dpm_level = dpm_level;
	if (ndev->pw_mode != POWER_MODE_DEFAULT || ndev->dpm_level == dpm_level)
		return 0;

	return aie2_pm_set_dpm(ndev, dpm_level);
}

static struct xrs_action_ops aie2_xrs_actions = {
	.load = aie2_xrs_load,
	.unload = aie2_xrs_unload,
	.set_dft_dpm_level = aie2_xrs_set_dft_dpm_level,
};

static void aie2_smu_fini(struct amdxdna_dev_hdl *ndev)
{
	ndev->priv->hw_ops->set_dpm(&ndev->aie, 0);
	aie_smu_fini(ndev->aie.smu_hdl);
}

static void aie2_hw_stop(struct amdxdna_dev *xdna)
{
	struct pci_dev *pdev = to_pci_dev(xdna->ddev.dev);
	struct amdxdna_dev_hdl *ndev = xdna->dev_handle;

	if (ndev->dev_status <= AIE2_DEV_INIT) {
		XDNA_ERR(xdna, "device is already stopped");
		return;
	}

	aie2_runtime_cfg(ndev, AIE2_RT_CFG_CLK_GATING, NULL);
	aie2_mgmt_fw_fini(ndev);
	aie_destroy_chann(&ndev->aie, &ndev->aie.mgmt_chann);
	drmm_kfree(&xdna->ddev, ndev->mbox);
	ndev->mbox = NULL;
	aie_psp_stop(ndev->aie.psp_hdl);
	aie2_smu_fini(ndev);
	amdxdna_async_events_free(&ndev->aie);
	pci_disable_device(pdev);

	ndev->dev_status = AIE2_DEV_INIT;
}

static int aie2_hw_start(struct amdxdna_dev *xdna)
{
	struct pci_dev *pdev = to_pci_dev(xdna->ddev.dev);
	struct amdxdna_dev_hdl *ndev = xdna->dev_handle;
	struct xdna_mailbox_res mbox_res;
	u32 xdna_mailbox_intr_reg;
	int mgmt_mb_irq, ret;

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

	mbox_res.ringbuf_base = ndev->sram_base;
	mbox_res.ringbuf_size = pci_resource_len(pdev, xdna->dev_info->sram_bar);
	mbox_res.mbox_base = ndev->mbox_base;
	mbox_res.mbox_size = MBOX_SIZE(ndev);
	mbox_res.name = "xdna_mailbox";
	ndev->mbox = xdnam_mailbox_create(&xdna->ddev, &mbox_res);
	if (!ndev->mbox) {
		XDNA_ERR(xdna, "failed to create mailbox device");
		ret = -ENODEV;
		goto disable_dev;
	}

	ndev->aie.mgmt_chann = xdna_mailbox_alloc_channel(ndev->mbox);
	if (!ndev->aie.mgmt_chann) {
		XDNA_ERR(xdna, "failed to alloc channel");
		ret = -ENODEV;
		goto disable_dev;
	}

	ret = aie_smu_init(ndev->aie.smu_hdl);
	if (ret) {
		XDNA_ERR(xdna, "failed to init smu, ret %d", ret);
		goto free_channel;
	}

	ret = aie_psp_start(ndev->aie.psp_hdl);
	if (ret) {
		XDNA_ERR(xdna, "failed to start psp, ret %d", ret);
		goto fini_smu;
	}

	ret = aie2_get_mgmt_chann_info(ndev);
	if (ret) {
		XDNA_ERR(xdna, "firmware is not alive");
		goto stop_psp;
	}

	mgmt_mb_irq = pci_irq_vector(pdev, ndev->aie.mgmt_chan_idx);
	if (mgmt_mb_irq < 0) {
		ret = mgmt_mb_irq;
		XDNA_ERR(xdna, "failed to alloc irq vector, ret %d", ret);
		goto stop_psp;
	}

	xdna_mailbox_intr_reg = ndev->aie.mgmt_i2x.mb_head_ptr_reg + 4;
	ret = xdna_mailbox_start_channel(ndev->aie.mgmt_chann,
					 &ndev->aie.mgmt_x2i,
					 &ndev->aie.mgmt_i2x,
					 xdna_mailbox_intr_reg,
					 mgmt_mb_irq);
	if (ret) {
		XDNA_ERR(xdna, "failed to start management mailbox channel");
		ret = -EINVAL;
		goto stop_psp;
	}

	ret = aie2_mgmt_fw_init(ndev);
	if (ret) {
		XDNA_ERR(xdna, "initial mgmt firmware failed, ret %d", ret);
		goto stop_fw;
	}

	ret = aie2_pm_start(ndev);
	if (ret) {
		XDNA_ERR(xdna, "failed to init pm, ret %d", ret);
		goto stop_fw;
	}

	ret = aie2_mgmt_fw_query(ndev);
	if (ret) {
		XDNA_ERR(xdna, "failed to query fw, ret %d", ret);
		goto stop_fw;
	}

	ret = amdxdna_async_events_alloc(&ndev->aie, ndev->total_col);
	if (ret) {
		XDNA_ERR(xdna, "Allocate async events failed, ret %d", ret);
		goto stop_fw;
	}

	ndev->dev_status = AIE2_DEV_START;

	return 0;

stop_fw:
	aie2_suspend_fw(ndev);
	xdna_mailbox_stop_channel(ndev->aie.mgmt_chann);
	/* Reclaim a partially-armed async pool now that the channel is stopped. */
	amdxdna_async_events_free(&ndev->aie);
stop_psp:
	aie_psp_stop(ndev->aie.psp_hdl);
fini_smu:
	aie2_smu_fini(ndev);
free_channel:
	xdna_mailbox_free_channel(ndev->aie.mgmt_chann);
	ndev->aie.mgmt_chann = NULL;
disable_dev:
	pci_disable_device(pdev);

	return ret;
}

static int aie2_hw_suspend(struct amdxdna_dev *xdna)
{
	struct amdxdna_client *client;

	list_for_each_entry(client, &xdna->client_list, node)
		aie2_hwctx_suspend(client);

	aie2_hw_stop(xdna);

	return 0;
}

static int aie2_hw_resume(struct amdxdna_dev *xdna)
{
	struct amdxdna_client *client;
	int ret;

	ret = aie2_hw_start(xdna);
	if (ret) {
		XDNA_ERR(xdna, "Start hardware failed, %d", ret);
		return ret;
	}

	list_for_each_entry(client, &xdna->client_list, node) {
		ret = aie2_hwctx_resume(client);
		if (ret)
			break;
	}

	return ret;
}

/*
 * aie2_hw_reset - recover a wedged NPU via full hardware power-cycle.
 *
 * Suspends every context, tears the device down, powers the NPU off and on
 * through the SMU (reloading the firmware), then re-creates every context.
 * The mailbox path cannot recover a dead firmware — only a hardware reset
 * can. Called from aie2_sched_job_timedout() when per-context recovery
 * fails or the firmware reports a fatal error. dev_lock must be held
 * (aie2_hwctx_suspend requires it).
 *
 * Rate-limited: if the firmware re-wedges immediately after a reset, a
 * reset storm must not hammer the SMU power-cycle. One reset per window
 * is enough; repeated timeouts after that indicate a deeper firmware
 * problem and are reported to the log instead of resetting in a loop.
 */
int aie2_hw_reset(struct amdxdna_dev *xdna)
{
	struct amdxdna_dev_hdl *ndev = xdna->dev_handle;
	struct amdxdna_client *client;
	int ret, first_ret = 0;

	if (ndev->dev_status <= AIE2_DEV_INIT) {
		XDNA_DBG(xdna, "device not started, nothing to reset");
		return 0;
	}

	if (time_before(jiffies, ndev->last_reset_jiffies +
				msecs_to_jiffies(AIE2_HW_RESET_MIN_INTERVAL_MS))) {
		XDNA_WARN(xdna, "NPU reset skipped: last reset %d ms ago",
			  jiffies_to_msecs(jiffies - ndev->last_reset_jiffies));
		return -EAGAIN;
	}

	/*
	 * Stamp before resetting: if the power-cycle itself fails (NPU stays
	 * wedged), retries stay bounded to one per window instead of storming
	 * the SMU on every job timeout.
	 */
	ndev->last_reset_jiffies = jiffies;

	XDNA_WARN(xdna, "NPU firmware unhealthy: power-cycling NPU");
	aie2_hw_suspend(xdna);

	ret = aie2_hw_start(xdna);
	if (ret) {
		XDNA_ERR(xdna, "NPU power-cycle start failed: %d", ret);
		return ret;
	}

	/*
	 * Resume every client even if one fails, so a single broken context
	 * does not leave the rest of the device suspended.
	 */
	list_for_each_entry(client, &xdna->client_list, node) {
		ret = aie2_hwctx_resume(client);
		if (ret && !first_ret) {
			XDNA_ERR(xdna, "resume failed after NPU reset: %d", ret);
			first_ret = ret;
		}
	}

	return first_ret;
}

static int aie2_init(struct amdxdna_dev *xdna)
{
	struct pci_dev *pdev = to_pci_dev(xdna->ddev.dev);
	void __iomem *tbl[PCI_NUM_RESOURCES] = {0};
	struct init_config xrs_cfg = { 0 };
	struct amdxdna_dev_hdl *ndev;
	struct psp_config psp_conf = { 0 };
	struct smu_config smu_conf;
	const struct firmware *fw;
	unsigned long bars = 0;
	char *fw_full_path;
	int i, nvec, ret;

#if defined(CONFIG_X86) && !defined(HAVE_xen_phy_dma_ops)
	if (!hypervisor_is_type(X86_HYPER_NATIVE)) {
		XDNA_ERR(xdna, "Running under hypervisor not supported");
		return -EINVAL;
	}
#endif

	ndev = drmm_kzalloc(&xdna->ddev, sizeof(*ndev), GFP_KERNEL);
	if (!ndev)
		return -ENOMEM;

	ndev->priv = xdna->dev_info->dev_priv;
	ndev->aie.xdna = xdna;

	for (i = 0; i < ARRAY_SIZE(npu_fw); i++) {
		fw_full_path = kasprintf(GFP_KERNEL, "%s%s", ndev->priv->fw_path, npu_fw[i]);
		if (!fw_full_path)
			return -ENOMEM;

		ret = firmware_request_nowarn(&fw, fw_full_path, &pdev->dev);
		kfree(fw_full_path);
		if (!ret) {
			XDNA_INFO(xdna, "Load firmware %s%s", ndev->priv->fw_path, npu_fw[i]);
			break;
		}
	}

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

	for (i = 0; i < PSP_MAX_REGS; i++)
		set_bit(PSP_REG_BAR(ndev, i), &bars);
	for (i = 0; i < SMU_MAX_REGS; i++)
		set_bit(SMU_REG_BAR(ndev, i), &bars);

	set_bit(xdna->dev_info->sram_bar, &bars);
	set_bit(xdna->dev_info->mbox_bar, &bars);

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

	ndev->sram_base = tbl[xdna->dev_info->sram_bar];
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

	psp_conf.fw_size = fw->size;
	psp_conf.fw_buf = fw->data;
	psp_conf.arg2_mask = GENMASK(23, 0);
	psp_conf.notify_val = 1;
	for (i = 0; i < PSP_MAX_REGS; i++)
		psp_conf.psp_regs[i] = tbl[PSP_REG_BAR(ndev, i)] + PSP_REG_OFF(ndev, i);
	ndev->aie.psp_hdl = aiem_psp_create(&xdna->ddev, &psp_conf);
	if (!ndev->aie.psp_hdl) {
		XDNA_ERR(xdna, "failed to create psp");
		ret = -ENOMEM;
		goto release_fw;
	}

	for (i = 0; i < SMU_MAX_REGS; i++)
		smu_conf.smu_regs[i] = tbl[SMU_REG_BAR(ndev, i)] + SMU_REG_OFF(ndev, i);
	smu_conf.intr_enabled = ndev->priv->smu_intr_enabled;
	ndev->aie.smu_hdl = aiem_smu_create(&xdna->ddev, &smu_conf);
	if (!ndev->aie.smu_hdl) {
		XDNA_ERR(xdna, "failed to create smu");
		ret = -ENOMEM;
		goto release_fw;
	}
	xdna->dev_handle = ndev;

	ret = aie2_hw_start(xdna);
	if (ret) {
		XDNA_ERR(xdna, "start npu failed, ret %d", ret);
		goto release_fw;
	}

	xrs_cfg.clk_list.num_levels = ndev->max_dpm_level + 1;
	for (i = 0; i < xrs_cfg.clk_list.num_levels; i++)
		xrs_cfg.clk_list.cu_clk_list[i] = ndev->priv->dpm_clk_tbl[i].hclk;
	xrs_cfg.sys_eff_factor = 2;
	xrs_cfg.ddev = &xdna->ddev;
	xrs_cfg.actions = &aie2_xrs_actions;
	xrs_cfg.total_col = ndev->total_col;

	xdna->xrs_hdl = xrsm_init(&xrs_cfg);
	if (!xdna->xrs_hdl) {
		XDNA_ERR(xdna, "Initialize resolver failed");
		ret = -EINVAL;
		goto stop_hw;
	}

	release_firmware(fw);
	aie2_msg_init(ndev);
	amdxdna_dpt_init(&ndev->aie);
	amdxdna_vbnv_init(xdna);
	amdxdna_pm_init(xdna);
	aie2_tdr_start(xdna);
	return 0;

stop_hw:
	aie2_hw_stop(xdna);
release_fw:
	release_firmware(fw);

	return ret;
}

static void aie2_fini(struct amdxdna_dev *xdna)
{
	aie2_tdr_stop(xdna);
	amdxdna_pm_fini(xdna);
	amdxdna_dpt_fini(&xdna->dev_handle->aie);
	aie2_hw_stop(xdna);
}

static int aie2_get_power_mode(struct amdxdna_client *client,
			       struct amdxdna_drm_get_info *args)
{
	struct amdxdna_drm_get_power_mode mode = {};
	struct amdxdna_dev *xdna = client->xdna;
	struct amdxdna_dev_hdl *ndev;
	u32 buf_sz;

	ndev = xdna->dev_handle;
	mode.power_mode = ndev->pw_mode;

	buf_sz = min(args->buffer_size, sizeof(mode));
	if (copy_to_user(u64_to_user_ptr(args->buffer), &mode, buf_sz))
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
	u32 buf_sz;

	ndev = xdna->dev_handle;
	clock = kzalloc_obj(*clock);
	if (!clock)
		return -ENOMEM;

	aie_update_counters(ndev);
	snprintf(clock->mp_npu_clock.name, sizeof(clock->mp_npu_clock.name),
		 "MP-NPU Clock");
	clock->mp_npu_clock.freq_mhz = ndev->aie.npuclk_freq;
	snprintf(clock->h_clock.name, sizeof(clock->h_clock.name), "H Clock");
	clock->h_clock.freq_mhz = ndev->aie.hclk_freq;

	buf_sz = min(args->buffer_size, sizeof(*clock));
	if (copy_to_user(u64_to_user_ptr(args->buffer), clock, buf_sz))
		ret = -EFAULT;

	kfree(clock);
	return ret;
}

int aie2_fill_hwctx_health(struct aie_device *aie, struct amdxdna_hwctx *hwctx,
			   struct amdxdna_drm_hwctx_entry *entry)
{
	struct amdxdna_dev_hdl *ndev = container_of(aie, struct amdxdna_dev_hdl, aie);
	struct app_health_report report;
	int ret;

	ret = aie2_query_app_health(ndev, hwctx->fw_ctx_id, &report);
	if (ret)
		return ret;

	entry->txn_op_idx = report.txn_op_id;
	entry->ctx_pc = report.ctx_pc;
	entry->fatal_error_type = report.fatal_info.fatal_type;
	entry->fatal_error_exception_type = report.fatal_info.exception_type;
	entry->fatal_error_exception_pc = report.fatal_info.exception_pc;
	entry->fatal_error_app_module = report.fatal_info.app_module;

	return 0;
}

static int aie2_query_resource_info(struct amdxdna_client *client,
				    struct amdxdna_drm_get_info *args)
{
	struct amdxdna_drm_get_resource_info res_info;
	const struct amdxdna_dev_priv *priv;
	struct amdxdna_dev_hdl *ndev;
	struct amdxdna_dev *xdna;
	u32 buf_sz;

	xdna = client->xdna;
	ndev = xdna->dev_handle;
	priv = ndev->priv;

	aie_update_counters(ndev);
	res_info.npu_clk_max = priv->dpm_clk_tbl[ndev->max_dpm_level].hclk;
	res_info.npu_tops_max = ndev->aie.max_tops;
	res_info.npu_task_max = priv->hwctx_limit;
	res_info.npu_tops_curr = ndev->aie.curr_tops;
	res_info.npu_task_curr = ndev->hwctx_num;

	buf_sz = min(args->buffer_size, sizeof(res_info));
	if (copy_to_user(u64_to_user_ptr(args->buffer), &res_info, buf_sz))
		return -EFAULT;

	return 0;
}

static int aie2_get_info(struct amdxdna_client *client, struct amdxdna_drm_get_info *args)
{
	struct amdxdna_dev *xdna = client->xdna;
	struct amdxdna_dev_hdl *ndev = xdna->dev_handle;
	int ret, idx;

	if (!drm_dev_enter(&xdna->ddev, &idx))
		return -ENODEV;

	ret = amdxdna_pm_resume_get_locked(xdna);
	if (ret)
		goto dev_exit;

	switch (args->param) {
	case DRM_AMDXDNA_QUERY_AIE_STATUS:
		ret = amdxdna_get_aie_status(&ndev->aie, client, args);
		break;
	case DRM_AMDXDNA_QUERY_AIE_METADATA:
		ret = amdxdna_get_metadata(&ndev->aie, client, args);
		break;
	case DRM_AMDXDNA_QUERY_AIE_VERSION:
		ret = amdxdna_get_aie_version(client, args, &ndev->aie.version);
		break;
	case DRM_AMDXDNA_QUERY_CLOCK_METADATA:
		ret = aie2_get_clock_metadata(client, args);
		break;
	case DRM_AMDXDNA_QUERY_SENSORS:
		ret = amdxdna_query_sensors(args, ndev->total_col);
		break;
	case DRM_AMDXDNA_QUERY_HW_CONTEXTS:
		ret = amdxdna_get_hwctx_status(&ndev->aie, client, args);
		break;
	case DRM_AMDXDNA_QUERY_FIRMWARE_VERSION:
		ret = amdxdna_get_firmware_version(client, args, &xdna->fw_ver);
		break;
	case DRM_AMDXDNA_GET_POWER_MODE:
		ret = aie2_get_power_mode(client, args);
		break;
	case DRM_AMDXDNA_QUERY_TELEMETRY:
		ret = amdxdna_get_telemetry(&ndev->aie, client, args);
		break;
	case DRM_AMDXDNA_QUERY_RESOURCE_INFO:
		ret = aie2_query_resource_info(client, args);
		break;
	case DRM_AMDXDNA_GET_FORCE_PREEMPT_STATE:
		ret = amdxdna_get_force_preempt_state(&ndev->aie, args);
		break;
	case DRM_AMDXDNA_GET_FRAME_BOUNDARY_PREEMPT_STATE:
		ret = amdxdna_get_frame_boundary_preempt_state(&ndev->aie, args);
		break;
	case DRM_AMDXDNA_GET_AUTO_COREDUMP:
		ret = amdxdna_get_auto_coredump_mode(client, args);
		break;
	default:
		XDNA_ERR(xdna, "Not supported request parameter %u", args->param);
		ret = -EOPNOTSUPP;
	}

	amdxdna_pm_suspend_put(xdna);
	XDNA_DBG(xdna, "Got param %d", args->param);

dev_exit:
	drm_dev_exit(idx);
	return ret;
}

static int aie2_get_array(struct amdxdna_client *client,
			  struct amdxdna_drm_get_array *args)
{
	struct amdxdna_dev_hdl *ndev = client->xdna->dev_handle;
	struct amdxdna_dev *xdna = client->xdna;
	bool needs_dev_lock;
	int ret, idx;

	if (!drm_dev_enter(&xdna->ddev, &idx))
		return -ENODEV;

	/* FW_LOG / FW_TRACE paths use SRCU instead of dev_lock so multiple
	 * xrt-smi watchers can sleep in wait_event_interruptible concurrently
	 * while an admin can still disable logging / tracing via the
	 * corresponding SET state ioctl.
	 */
	switch (args->param) {
	case DRM_AMDXDNA_FW_LOG:
	case DRM_AMDXDNA_FW_LOG_CONFIG:
	case DRM_AMDXDNA_FW_TRACE:
	case DRM_AMDXDNA_FW_TRACE_CONFIG:
		needs_dev_lock = false;
		break;
	default:
		needs_dev_lock = true;
		break;
	}

	ret = amdxdna_pm_resume_get(xdna);
	if (ret)
		goto dev_exit;

	if (needs_dev_lock)
		mutex_lock(&xdna->dev_lock);

	switch (args->param) {
	case DRM_AMDXDNA_HW_CONTEXT_ALL:
		ret = amdxdna_query_ctx_status_array(&ndev->aie, client, args);
		break;
	case DRM_AMDXDNA_HW_CONTEXT_BY_ID:
		ret = amdxdna_query_ctx_status_by_id(&ndev->aie, client, args);
		break;
	case DRM_AMDXDNA_HW_LAST_ASYNC_ERR:
		ret = aie2_get_array_async_error(xdna->dev_handle, args);
		break;
	case DRM_AMDXDNA_AIE_COREDUMP:
		ret = amdxdna_get_coredump(&ndev->aie, client, args);
		break;
	case DRM_AMDXDNA_BO_USAGE:
		ret = amdxdna_drm_get_bo_usage(&xdna->ddev, args);
		break;
	case DRM_AMDXDNA_AIE_TILE_READ:
		ret = amdxdna_aie_tile_read(&ndev->aie, client, args);
		break;
	case DRM_AMDXDNA_FW_LOG:
		ret = amdxdna_get_fw_log(&ndev->aie, args);
		break;
	case DRM_AMDXDNA_FW_LOG_CONFIG:
		ret = amdxdna_get_fw_log_configs(&ndev->aie, args);
		break;
	case DRM_AMDXDNA_FW_TRACE:
		ret = amdxdna_get_fw_trace(&ndev->aie, args);
		break;
	case DRM_AMDXDNA_FW_TRACE_CONFIG:
		ret = amdxdna_get_fw_trace_configs(&ndev->aie, args);
		break;
	default:
		XDNA_ERR(xdna, "Not supported request parameter %u", args->param);
		ret = -EOPNOTSUPP;
	}

	if (needs_dev_lock)
		mutex_unlock(&xdna->dev_lock);

	amdxdna_pm_suspend_put(xdna);
	XDNA_DBG(xdna, "Got param %d", args->param);

dev_exit:
	drm_dev_exit(idx);
	return ret;
}

static int aie2_set_power_mode(struct amdxdna_client *client,
			       struct amdxdna_drm_set_state *args, u32 *settle_ms)
{
	struct amdxdna_drm_set_power_mode power_state;
	enum amdxdna_power_mode_type power_mode;
	struct amdxdna_dev *xdna = client->xdna;

	if (copy_from_user(&power_state, u64_to_user_ptr(args->buffer),
			   sizeof(power_state))) {
		XDNA_ERR(xdna, "Failed to copy power mode request into kernel");
		return -EFAULT;
	}

	if (XDNA_MBZ_DBG(xdna, power_state.pad, sizeof(power_state.pad)))
		return -EINVAL;

	power_mode = power_state.power_mode;
	if (power_mode > POWER_MODE_TURBO) {
		XDNA_ERR(xdna, "Invalid power mode %d", power_mode);
		return -EINVAL;
	}

	return aie2_pm_set_mode(xdna->dev_handle, power_mode, settle_ms);
}

/*
 * aie2 names the hardware context in its force preemption runtime config, so
 * the flag is armed per context when that context is configured and there is
 * nothing to send to firmware here. Recording the state is the whole job: it
 * selects what contexts created from now on are armed with. aie4 has one global
 * flag instead and pushes each change down immediately.
 */
static int aie2_set_force_preempt(struct amdxdna_client *client,
				  struct amdxdna_drm_set_state *args)
{
	struct amdxdna_dev_hdl *ndev = client->xdna->dev_handle;
	struct amdxdna_drm_attribute_state state;

	if (copy_from_user(&state, u64_to_user_ptr(args->buffer), sizeof(state)))
		return -EFAULT;

	if (state.state > 1)
		return -EINVAL;

	if (XDNA_MBZ_DBG(client->xdna, state.pad, sizeof(state.pad)))
		return -EINVAL;

	ndev->aie.force_preempt_enabled = state.state;

	return 0;
}

static int aie2_set_frame_boundary_preempt(struct amdxdna_client *client,
					   struct amdxdna_drm_set_state *args)
{
	struct amdxdna_dev_hdl *ndev = client->xdna->dev_handle;
	struct amdxdna_drm_attribute_state state;
	u32 val;
	int ret;

	if (copy_from_user(&state, u64_to_user_ptr(args->buffer), sizeof(state)))
		return -EFAULT;

	if (state.state > 1)
		return -EINVAL;

	if (XDNA_MBZ_DBG(client->xdna, state.pad, sizeof(state.pad)))
		return -EINVAL;

	val = state.state;
	ret = aie2_runtime_cfg(ndev, AIE2_RT_CFG_FRAME_BOUNDARY_PREEMPT, &val);
	if (ret)
		return ret;

	ndev->aie.frame_boundary_preempt_enabled = state.state;

	return 0;
}

static int aie2_set_state(struct amdxdna_client *client,
			  struct amdxdna_drm_set_state *args, u32 *settle_ms)
{
	struct amdxdna_dev_hdl *ndev = client->xdna->dev_handle;
	struct amdxdna_dev *xdna = client->xdna;
	int ret, idx;

	if (!drm_dev_enter(&xdna->ddev, &idx))
		return -ENODEV;

	ret = amdxdna_pm_resume_get_locked(xdna);
	if (ret)
		goto dev_exit;

	switch (args->param) {
	case DRM_AMDXDNA_SET_POWER_MODE:
		ret = aie2_set_power_mode(client, args, settle_ms);
		break;
	case DRM_AMDXDNA_SET_FORCE_PREEMPT:
		ret = aie2_set_force_preempt(client, args);
		break;
	case DRM_AMDXDNA_SET_FRAME_BOUNDARY_PREEMPT:
		ret = aie2_set_frame_boundary_preempt(client, args);
		break;
	case DRM_AMDXDNA_AIE_TILE_WRITE:
		ret = amdxdna_aie_tile_write(&ndev->aie, client, args);
		break;
	case DRM_AMDXDNA_SET_FW_LOG_STATE:
		ret = amdxdna_set_fw_log_state(&ndev->aie, args);
		break;
	case DRM_AMDXDNA_SET_FW_TRACE_STATE:
		ret = amdxdna_set_fw_trace_state(&ndev->aie, args);
		break;
	case DRM_AMDXDNA_SET_AUTO_COREDUMP:
		ret = amdxdna_set_auto_coredump_mode(client, args);
		break;
	default:
		XDNA_ERR(xdna, "Not supported request parameter %u", args->param);
		ret = -EOPNOTSUPP;
		break;
	}

	amdxdna_pm_suspend_put(xdna);
dev_exit:
	drm_dev_exit(idx);
	return ret;
}

static int aie2_get_dev_rev(struct amdxdna_dev *xdna, u32 *rev)
{
	struct amdxdna_dev_hdl *ndev = xdna->dev_handle;
	enum aie2_dev_revision aie2_rev;
	int ret;

	drm_WARN_ON(&xdna->ddev, !mutex_is_locked(&xdna->dev_lock));
	ret = aie2_get_dev_revision(ndev, &aie2_rev);

	if (!ret)
		*rev = (u32)aie2_rev;

	return ret;
}

#define AIE2_MGMT_APP_ID		0xFF

static const char * const aie2_fw_log_level_str[] = {
	"OFF",
	"ERR",
	"WRN",
	"INF",
	"DBG",
	"MAX"
};

/*
 * AIE2 firmware log entries are structured (unlike the plain newline-
 * delimited AIE4 stream): each record is a header, a u64-aligned payload,
 * and a footer. The header and footer carry a magic byte and a matching
 * sequence number / word length so a torn or overwritten record in the
 * wrapping DRAM ring can be detected and skipped.
 */
struct aie2_fw_log_header {
#define AIE2_DPT_ENTRY_MAGIC_HEAD	0xCA
	u8	magic;
	u8	data_word_len;
	__le16	seq_num;
	u32	reserved;
} __packed;

/*
 * The two 32-bit words following the timestamp pack the record metadata.
 * The kernel avoids C bitfields for wire/DRAM layouts (their bit ordering
 * and padding are implementation-defined), so the fields are decoded with
 * explicit masks via FIELD_GET on this little-endian target. Only @level
 * and @appn (word0) are consumed today; the remaining masks document the
 * firmware layout.
 */
struct aie2_fw_log_data {
	u64	timestamp;
	u32	word0;
	u32	word1;
} __packed;

/* word0 */
#define AIE2_FW_LOG_FORMAT	GENMASK(0, 0)
#define AIE2_FW_LOG_LEVEL	GENMASK(10, 8)
#define AIE2_FW_LOG_APPN	GENMASK(23, 16)
#define AIE2_FW_LOG_ARGC	GENMASK(31, 24)
/* word1 */
#define AIE2_FW_LOG_LINE	GENMASK(15, 0)
#define AIE2_FW_LOG_MODULE	GENMASK(31, 16)

struct aie2_fw_log_footer {
	u32	reserved;
	__le16	seq_num;
	u8	data_word_len;
#define AIE2_DPT_ENTRY_MAGIC_FOOTER	0xBA
	u8	magic;
} __packed;

static void aie2_fw_log_print(struct amdxdna_dev *xdna, const char *payload,
			      size_t size)
{
	u32 level, appn, word0;
	const char *level_str;
	__le64 raw_timestamp;
	__le32 raw_word0;
	char appid[20];
	u64 timestamp;

	if (size < sizeof(struct aie2_fw_log_data))
		return;

	/*
	 * The resync path (aie2_fw_log_parse) advances in 4-byte steps, so a
	 * valid-looking header can be found at 4-byte alignment and @payload
	 * may not be 8-byte aligned. Copy the little-endian wire fields into
	 * aligned locals before converting, instead of dereferencing a
	 * possibly misaligned struct. This also makes the DRAM layout
	 * endianness explicit rather than baking in host endianness, and
	 * avoids depending on <linux/unaligned.h>, which does not exist on
	 * kernels older than 6.12.
	 */
	memcpy(&raw_timestamp, payload, sizeof(raw_timestamp));
	memcpy(&raw_word0, payload + offsetof(struct aie2_fw_log_data, word0),
	       sizeof(raw_word0));
	timestamp = le64_to_cpu(raw_timestamp);
	word0 = le32_to_cpu(raw_word0);

	level = FIELD_GET(AIE2_FW_LOG_LEVEL, word0);
	appn = FIELD_GET(AIE2_FW_LOG_APPN, word0);

	if (level < ARRAY_SIZE(aie2_fw_log_level_str))
		level_str = aie2_fw_log_level_str[level];
	else
		level_str = "UNK";

	if (appn == AIE2_MGMT_APP_ID)
		scnprintf(appid, sizeof(appid), "MGMNT");
	else
		scnprintf(appid, sizeof(appid), "APP%2d", appn);

	XDNA_INFO(xdna, "[FW LOG] [%llu] [%s] [%s]: %.*s", timestamp,
		  level_str, appid, (int)(size - sizeof(struct aie2_fw_log_data)),
		  payload + sizeof(struct aie2_fw_log_data));
}

/*
 * Walk the fetched ring payload record by record, validating each entry's
 * header/footer magic, sequence continuity and length before emitting it.
 * On any inconsistency, advance by the minimum alignment (4 bytes) and
 * resynchronize on the next valid header rather than trusting a possibly
 * corrupted length.
 */
void aie2_fw_log_parse(struct amdxdna_dev *xdna, char *buffer, size_t size)
{
	char *end = buffer + size;
	bool has_prev_seq = false;
	char *p = buffer;
	u16 prev_seq = 0;

	if (!buffer || size == 0)
		return;

	while ((size_t)(end - p) >= sizeof(struct aie2_fw_log_header)) {
		const struct aie2_fw_log_header *hdr = (const struct aie2_fw_log_header *)p;
		unsigned int increment_bytes = 4; /* default resync step */
		bool corrupted = true;

		if (likely(hdr->magic == AIE2_DPT_ENTRY_MAGIC_HEAD)) {
			size_t payload_bytes = hdr->data_word_len * sizeof(u64);
			size_t total_entry_size = sizeof(struct aie2_fw_log_header) +
						  payload_bytes +
						  sizeof(struct aie2_fw_log_footer);
			const char *payload = p + sizeof(struct aie2_fw_log_header);
			const struct aie2_fw_log_footer *ftr;
			u16 seq = le16_to_cpu(hdr->seq_num);
			bool valid;

			/* Partial entry at the ring end: stop to avoid overread. */
			if ((size_t)(end - p) < total_entry_size)
				break;

			ftr = (const struct aie2_fw_log_footer *)(payload + payload_bytes);
			valid = (ftr->magic == AIE2_DPT_ENTRY_MAGIC_FOOTER) &&
				(seq > 0) && (seq == le16_to_cpu(ftr->seq_num)) &&
				(hdr->data_word_len == ftr->data_word_len);

			if (likely(valid) &&
			    likely(!has_prev_seq || seq == (u16)(prev_seq + 1))) {
				has_prev_seq = true;
				prev_seq = seq;
				aie2_fw_log_print(xdna, payload, payload_bytes);
				corrupted = false;
				increment_bytes = (unsigned int)total_entry_size;
			}

			if (unlikely(corrupted)) {
				/*
				 * Torn/overwritten records are expected at the
				 * wrap boundary of a continuously overwritten
				 * ring and the poll worker runs every
				 * AMDXDNA_DPT_POLL_INTERVAL_MS, so ratelimit to
				 * avoid drowning the log in the resync path.
				 */
				dev_warn_ratelimited(xdna->ddev.dev,
						     "FW log entry overwritten/corrupted\n");
				has_prev_seq = false;
			}
		}

		if (unlikely(increment_bytes == 0) ||
		    (size_t)(end - p) < increment_bytes)
			break;

		p += increment_bytes;
	}
}

int aie2_fw_log_init(struct amdxdna_dev *xdna, size_t size, u32 level)
{
	struct amdxdna_dev_hdl *ndev = xdna->dev_handle;
	struct amdxdna_dpt *dpt;
	u32 msi_idx, msi_address;
	int ret;

	if (level >= AIE2_FW_LOG_LEVEL_MAX) {
		XDNA_ERR(xdna, "Invalid firmware log level: %d", level);
		return -EINVAL;
	}

	dpt = rcu_dereference_protected(xdna->fw_log.data,
					lockdep_is_held(&xdna->dev_lock));
	if (!dpt) {
		XDNA_ERR(xdna, "FW log handle not allocated");
		return -ENXIO;
	}

	ret = aie2_config_fw_log(ndev, dpt->buf, size, &msi_idx, &msi_address);
	if (ret) {
		if (ret != -EOPNOTSUPP)
			XDNA_ERR(xdna, "Failed to init fw log buffer: %d", ret);
		return ret;
	}

	ret = aie2_set_log_level(ndev, level);
	if (ret) {
		XDNA_ERR(xdna, "Failed to init fw log level: %d", ret);
		goto detach;
	}

	ret = aie2_set_log_format(ndev, AIE2_FW_LOG_FORMAT_FULL);
	if (ret) {
		XDNA_ERR(xdna, "Failed to init fw log format: %d", ret);
		goto detach;
	}

	ret = aie2_set_log_destination(ndev, AIE2_FW_LOG_DESTINATION_DRAM);
	if (ret) {
		XDNA_ERR(xdna, "Failed to init fw log destination: %d", ret);
		goto detach;
	}

	dpt->io_base = ndev->mbox_base;
	dpt->msi_address = msi_address & AIE2_DPT_MSI_ADDR_MASK;
	dpt->msi_idx = msi_idx;

	return 0;

detach:
	aie2_config_fw_log(ndev, dpt->buf, 0, NULL, NULL);
	return ret;
}

int aie2_fw_log_config(struct amdxdna_dev *xdna, u32 level)
{
	if (level == AIE2_FW_LOG_LEVEL_OFF || level >= AIE2_FW_LOG_LEVEL_MAX) {
		XDNA_ERR(xdna, "Invalid firmware log level: %d", level);
		return -EINVAL;
	}

	return aie2_set_log_level(xdna->dev_handle, level);
}

int aie2_fw_log_fini(struct amdxdna_dev *xdna)
{
	struct amdxdna_dev_hdl *ndev = xdna->dev_handle;
	struct amdxdna_dpt *dpt;
	int ret;

	dpt = rcu_dereference_protected(xdna->fw_log.data,
					lockdep_is_held(&xdna->dev_lock));
	if (!dpt)
		return 0;

	ret = aie2_set_log_destination(ndev, AIE2_FW_LOG_DESTINATION_NULL);
	if (ret) {
		XDNA_ERR(xdna, "Failed to reset fw log destination: %d", ret);
		return ret;
	}

	ret = aie2_config_fw_log(ndev, dpt->buf, 0, NULL, NULL);
	if (ret) {
		XDNA_ERR(xdna, "Failed to reset fw log buffer: %d", ret);
		return ret;
	}

	return 0;
}

int aie2_fw_trace_init(struct amdxdna_dev *xdna, size_t size, u32 categories)
{
	struct amdxdna_dev_hdl *ndev = xdna->dev_handle;
	u32 msi_idx = 0, msi_address = 0;
	struct amdxdna_dpt *dpt;
	int ret;

	dpt = rcu_dereference_protected(xdna->fw_trace.data,
					lockdep_is_held(&xdna->dev_lock));
	if (!dpt) {
		XDNA_ERR(xdna, "FW trace handle not allocated");
		return -ENXIO;
	}

	ret = aie2_start_fw_trace(ndev, dpt->buf, size, categories, &msi_idx,
				  &msi_address);
	if (ret) {
		if (ret != -EOPNOTSUPP)
			XDNA_ERR(xdna, "Failed to start FW trace: %d", ret);
		return ret;
	}

	dpt->io_base = ndev->mbox_base;
	dpt->msi_address = msi_address & AIE2_DPT_MSI_ADDR_MASK;
	dpt->msi_idx = msi_idx;

	return 0;
}

int aie2_fw_trace_config(struct amdxdna_dev *xdna, u32 categories)
{
	struct amdxdna_dev_hdl *ndev = xdna->dev_handle;
	DECLARE_AIE_MSG(set_fw_trace_categories, MSG_OP_SET_FW_TRACE_CATEGORIES);
	int ret;

	req.categories = categories;

	ret = aie_send_mgmt_msg_wait(&ndev->aie, &msg);
	if (ret)
		XDNA_ERR(xdna,
			 "Set FW trace categories failed, ret %d status 0x%x",
			 ret, resp.status);
	return ret;
}

int aie2_fw_trace_fini(struct amdxdna_dev *xdna)
{
	struct amdxdna_dev_hdl *ndev = xdna->dev_handle;
	DECLARE_AIE_MSG(stop_fw_trace, MSG_OP_STOP_FW_TRACE);
	int ret;

	ret = aie_send_mgmt_msg_wait(&ndev->aie, &msg);
	if (ret)
		XDNA_ERR(xdna,
			 "Stop FW trace failed, ret %d status 0x%x",
			 ret, resp.status);
	return ret;
}

const struct amdxdna_dev_ops aie2_ops = {
	.init = aie2_init,
	.fini = aie2_fini,
	.resume = aie2_hw_resume,
	.suspend = aie2_hw_suspend,
	.runtime_resume = aie2_hw_resume,
	.runtime_suspend = aie2_hw_suspend,
	.get_aie_info = aie2_get_info,
	.set_aie_state = aie2_set_state,
	.hwctx_init = aie2_hwctx_init,
	.hwctx_fini = aie2_hwctx_fini,
	.hwctx_config = aie2_hwctx_config,
	.hwctx_sync_debug_bo = aie2_hwctx_sync_debug_bo,
	.cmd_submit = aie2_cmd_submit,
	.get_array = aie2_get_array,
	.get_dev_revision = aie2_get_dev_rev,
	.hwctx_heap_expand = aie2_hwctx_heap_expand,
	.register_async_event = aie2_async_event_register,
};

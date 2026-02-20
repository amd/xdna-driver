// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2023-2025, Advanced Micro Devices, Inc.
 */

#include <linux/errno.h>
#include <linux/kthread.h>
#include <linux/iommu.h>
#include <linux/firmware.h>
#include <linux/uaccess.h>
#include <linux/version.h>
#include <drm/drm_cache.h>
#include "drm_local/amdxdna_accel.h"

#include "aie2_pci.h"
#include "aie2_msg_priv.h"
#include "amdxdna_mgmt.h"

#ifdef AMDXDNA_DEVEL
#include "amdxdna_devel.h"
#endif

#ifdef AMDXDNA_AIE2_PRIV
#include "aie2_internal.h"
#endif

#define AIE2_MAX_COL 128
uint aie2_max_col = AIE2_MAX_COL;
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

#define MAX_TIME_QUANTUM_MS 2000 /* milliseconds */
uint time_quantum_ms = 30; /* milliseconds */
module_param(time_quantum_ms, uint, 0400);
MODULE_PARM_DESC(time_quantum_ms, "Execution time quantum. Default 30 ms, MAX 2000 ms");

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
	u64 min_fw_version = ndev->priv->min_fw_version;
	const struct aie2_fw_feature_tbl *feature;
	struct amdxdna_dev *xdna = ndev->xdna;
	u64 fw_version;

	fw_version = AIE2_FW_VERSION(fw_major, fw_minor);

	if (fw_version < min_fw_version) {
		XDNA_ERR(xdna, "Firmware %d.%d below minimum %d.%d", fw_major, fw_minor,
			 AIE2_FW_MAJOR(min_fw_version), AIE2_FW_MINOR(min_fw_version));
		return -EINVAL;
	}

	/* Store unified version for later use */
	ndev->mgmt_fw_version = fw_version;

	/* Enable features based on unified version comparison */
	for (feature = ndev->priv->fw_feature_tbl;
	     feature && feature->min_fw_version; feature++) {
		if (fw_version < feature->min_fw_version)
			continue;
		if (feature->max_fw_version && fw_version > feature->max_fw_version)
			continue;

		set_bit(feature->feature, &ndev->feature_mask);
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

	if (!ndev->mgmt_fw_version)
		return;

	XDNA_DBG(xdna, "mailbox protocol version %d.%d",
		 AIE2_FW_MAJOR(ndev->mgmt_fw_version),
		 AIE2_FW_MINOR(ndev->mgmt_fw_version));
}

static int aie2_mgmt_chann_init(struct amdxdna_dev_hdl *ndev)
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
	if (aie2_check_protocol(ndev, info_regs.prot_major, info_regs.prot_minor))
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
	int ret;

	ret = aie2_runtime_cfg(ndev, AIE2_RT_CFG_INIT, NULL);
	if (ret) {
		XDNA_ERR(ndev->xdna, "Runtime config failed");
		return ret;
	}

	ret = aie2_fine_preemption(ndev, disable_fine_preemption);
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

	if (time_quantum_ms > MAX_TIME_QUANTUM_MS) {
		XDNA_ERR(ndev->xdna, "Bad time quantum %d", time_quantum_ms);
		return -EINVAL;
	}

	ret = aie2_update_prop_time_quota(ndev, NULL, time_quantum_ms * 1000);
	if (ret) {
		XDNA_ERR(ndev->xdna, "Failed to update execution time quantum");
		return ret;
	}

	ret = aie2_xdna_reset(ndev);
	if (ret) {
		XDNA_ERR(ndev->xdna, "Reset firmware failed");
		return ret;
	}

	ret = aie2_calibrate_time(ndev);
	if (ret) {
		XDNA_ERR(ndev->xdna, "Calibrate system clock failed");
		return ret;
	}

	return 0;
}

static int aie2_mgmt_fw_query(struct amdxdna_dev_hdl *ndev)
{
	int ret;

	ret = aie2_query_aie_firmware_version(ndev, &ndev->xdna->fw_ver);
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

	ndev->total_col = min(aie2_max_col, ndev->metadata.cols);

	return 0;
}

static void aie2_mgmt_fw_fini(struct amdxdna_dev_hdl *ndev)
{
	if (aie2_suspend_fw(ndev))
		XDNA_ERR(ndev->xdna, "suspend_fw failed");
	XDNA_DBG(ndev->xdna, "npu firmware suspended");
}

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

	aie2_error_async_events_free(ndev);
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

	ret = aie2_mgmt_chann_init(ndev);
	if (ret) {
		XDNA_ERR(xdna, "firmware mgmt channel init failed, ret %d", ret);
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

	ret = aie2_mgmt_fw_init(ndev);
	if (ret) {
		XDNA_ERR(xdna, "initial mgmt firmware failed, ret %d", ret);
		goto destroy_mgmt_chann;
	}

	ret = aie2_pm_init(ndev);
	if (ret) {
		XDNA_ERR(xdna, "failed to init pm, ret %d", ret);
		goto destroy_mgmt_chann;
	}

	ret = aie2_mgmt_fw_query(ndev);
	if (ret) {
		XDNA_ERR(xdna, "failed to query fw, ret %d", ret);
		goto pm_fini;
	}

	ret = aie2_error_async_events_alloc(ndev);
	if (ret) {
		XDNA_ERR(xdna, "Allocate async events failed, ret %d", ret);
		goto pm_fini;
	}

	mutex_unlock(&ndev->aie2_lock);
	ndev->dev_status = AIE2_DEV_START;

	return 0;

pm_fini:
	aie2_pm_fini(ndev);
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
	guard(mutex)(&xdna->dev_lock);
	aie2_rq_stop_all(&xdna->dev_handle->ctx_rq);
	aie2_hw_stop(xdna);
}

static int aie2_hw_resume(struct amdxdna_dev *xdna)
{
	int ret;

	XDNA_DBG(xdna, "firmware resuming...");
	guard(mutex)(&xdna->dev_lock);
	ret = aie2_hw_start(xdna);
	if (ret) {
		XDNA_ERR(xdna, "resume NPU firmware failed");
		return ret;
	}

	XDNA_DBG(xdna, "context resuming...");
	aie2_rq_restart_all(&xdna->dev_handle->ctx_rq);
	return 0;
}

/*
 * Tear down the firmware stack: PM, firmware, mailbox, PSP, SMU.
 * Caller must hold aie2_lock. Sets dev_status to AIE2_DEV_INIT.
 */
static void aie2_fw_teardown(struct amdxdna_dev_hdl *ndev)
{
	ndev->dev_status = AIE2_DEV_INIT;
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
}

/*
 * Rebuild the firmware stack: SMU, PSP, mailbox, firmware, PM.
 * Caller must hold aie2_lock. On success, sets dev_status to
 * AIE2_DEV_START. On failure, the stack is torn back down.
 */
static int aie2_fw_rebuild(struct amdxdna_dev_hdl *ndev)
{
	struct amdxdna_dev *xdna = ndev->xdna;
	struct pci_dev *pdev = to_pci_dev(xdna->ddev.dev);
	struct xdna_mailbox_res mbox_res;
	int ret;

	ret = aie2_smu_start(ndev);
	if (ret) {
		XDNA_ERR(xdna, "SMU start failed, ret %d", ret);
		return ret;
	}

	ret = aie2_psp_start(ndev->psp_hdl);
	if (ret) {
		XDNA_ERR(xdna, "PSP start failed, ret %d", ret);
		goto fini_smu;
	}

	ret = aie2_mgmt_chann_init(ndev);
	if (ret) {
		XDNA_ERR(xdna, "mgmt channel init failed, ret %d", ret);
		goto stop_psp;
	}

	mbox_res.ringbuf_base = ndev->sram_base;
	mbox_res.ringbuf_size = pci_resource_len(pdev,
						 xdna->dev_info->sram_bar);
	mbox_res.mbox_base = ndev->mbox_base;
	mbox_res.mbox_size = MBOX_SIZE(ndev);
	mbox_res.name = "xdna_mailbox";
	ndev->mbox = xdna_mailbox_create(&pdev->dev, &mbox_res);
	if (!ndev->mbox) {
		XDNA_ERR(xdna, "failed to create mailbox");
		ret = -ENODEV;
		goto stop_psp;
	}

	ndev->mgmt_chann = xdna_mailbox_create_channel(ndev->mbox,
						       &ndev->mgmt_info,
						       MB_CHANNEL_MGMT);
	if (!ndev->mgmt_chann) {
		XDNA_ERR(xdna, "failed to create mgmt channel");
		ret = -EINVAL;
		goto destroy_mbox;
	}

	ret = aie2_mgmt_fw_init(ndev);
	if (ret) {
		XDNA_ERR(xdna, "firmware init failed, ret %d", ret);
		goto destroy_mgmt_chann;
	}

	ret = aie2_pm_init(ndev);
	if (ret) {
		XDNA_ERR(xdna, "PM init failed, ret %d", ret);
		goto destroy_mgmt_chann;
	}

	ret = aie2_mgmt_fw_query(ndev);
	if (ret) {
		XDNA_ERR(xdna, "firmware query failed, ret %d", ret);
		goto pm_fini;
	}

	ret = aie2_error_async_events_alloc(ndev);
	if (ret) {
		XDNA_ERR(xdna, "async events alloc failed, ret %d", ret);
		goto pm_fini;
	}

	ndev->dev_status = AIE2_DEV_START;
	return 0;

pm_fini:
	aie2_pm_fini(ndev);
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
	return ret;
}

static void aie2_reset_prepare(struct amdxdna_dev *xdna)
{
	struct amdxdna_dev_hdl *ndev = xdna->dev_handle;

	XDNA_INFO(xdna, "FLR reset prepare start");

	/*
	 * Stop TDR before taking dev_lock. cancel_work_sync() waits
	 * for any in-progress TDR work, which also takes dev_lock.
	 */
	aie2_tdr_stop(xdna);

	mutex_lock(&xdna->dev_lock);
	aie2_rq_stop_all(&ndev->ctx_rq);

	mutex_lock(&ndev->aie2_lock);
	aie2_fw_teardown(ndev);
	mutex_unlock(&ndev->aie2_lock);

	mutex_unlock(&xdna->dev_lock);

	if (ndev->async_events) {
		aie2_error_async_events_free(ndev);
		ndev->async_events = NULL;
	}

	XDNA_INFO(xdna, "FLR reset prepare finished");
}

static int aie2_reset_done(struct amdxdna_dev *xdna)
{
	struct amdxdna_dev_hdl *ndev = xdna->dev_handle;
	int ret;

	XDNA_INFO(xdna, "FLR reset done start");

	mutex_lock(&xdna->dev_lock);
	mutex_lock(&ndev->aie2_lock);

	ret = aie2_fw_rebuild(ndev);

	mutex_unlock(&ndev->aie2_lock);

	if (ret) {
		mutex_unlock(&xdna->dev_lock);
		return ret;
	}

	aie2_rq_restart_all(&ndev->ctx_rq);
	mutex_unlock(&xdna->dev_lock);

	aie2_tdr_start(xdna);

	XDNA_INFO(xdna, "FLR reset done finished");
	return 0;
}

/*
 * Perform a full FLR cycle: tear down firmware, PCI reset, rebuild.
 * Must be called WITHOUT dev_lock or aie2_lock held.
 * Does not manage TDR start/stop or runqueue start/stop.
 */
int aie2_flr(struct amdxdna_dev *xdna)
{
	struct pci_dev *pdev = to_pci_dev(xdna->ddev.dev);
	struct amdxdna_dev_hdl *ndev = xdna->dev_handle;
	int ret;

	mutex_lock(&ndev->aie2_lock);
	aie2_fw_teardown(ndev);
	mutex_unlock(&ndev->aie2_lock);

	if (ndev->async_events) {
		aie2_error_async_events_free(ndev);
		ndev->async_events = NULL;
	}

	pci_save_state(pdev);
	ret = pcie_reset_flr(pdev, PCI_RESET_DO_RESET);
	pci_restore_state(pdev);
	if (ret) {
		XDNA_ERR(xdna, "pcie_reset_flr failed, ret %d", ret);
		return ret;
	}

	mutex_lock(&ndev->aie2_lock);
	ret = aie2_fw_rebuild(ndev);
	mutex_unlock(&ndev->aie2_lock);

	if (ret)
		XDNA_ERR(xdna, "FLR firmware rebuild failed, ret %d", ret);

	return ret;
}

static int aie2_init(struct amdxdna_dev *xdna)
{
	struct pci_dev *pdev = to_pci_dev(xdna->ddev.dev);
	void __iomem *tbl[PCI_NUM_RESOURCES] = {0};
	struct amdxdna_dev_hdl *ndev;
	struct psp_config psp_conf;
	const struct firmware *fw;
	unsigned long bars = 0;
	int i, nvec, ret;

	XDNA_DBG(xdna, "Control flags 0x%x", aie2_control_flags);
	ndev = devm_kzalloc(&pdev->dev, sizeof(*ndev), GFP_KERNEL);
	if (!ndev)
		return -ENOMEM;

	ndev->priv = xdna->dev_info->dev_priv;
	ndev->xdna = xdna;
	mutex_init(&ndev->aie2_lock);

	XDNA_DBG(xdna, "Request fw %s", ndev->priv->fw_path);
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

	for (i = 0; i < PSP_MAX_REGS; i++)
		set_bit(PSP_REG_BAR(ndev, i), &bars);

	set_bit(xdna->dev_info->sram_bar, &bars);
	set_bit(xdna->dev_info->smu_bar, &bars);
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
	if (ret)
		goto free_irq;
	if (iommu_mode != AMDXDNA_IOMMU_PASID)
		goto skip_pasid;
#endif

#ifdef HAVE_iommu_dev_enable_disable_feature
	ret = iommu_dev_enable_feature(&pdev->dev, IOMMU_DEV_FEAT_SVA);
	if (ret) {
		XDNA_ERR(xdna, "Enable PASID failed, ret %d", ret);
		goto free_irq;
	}
#endif
#ifdef AMDXDNA_DEVEL
skip_pasid:
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

	mutex_init(&ndev->async_errs_cache.lock);

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

	release_firmware(fw);
	aie2_msg_init(ndev);
	return 0;

stop_hw:
	aie2_hw_stop(xdna);
disable_sva:
#ifdef HAVE_iommu_dev_enable_disable_feature
	iommu_dev_disable_feature(&pdev->dev, IOMMU_DEV_FEAT_SVA);
#endif
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

	aie2_rq_fini(&ndev->ctx_rq);
	aie2_hw_stop(xdna);
	aie2_psp_destroy(&pdev->dev, ndev->psp_hdl);
#ifdef AMDXDNA_DEVEL
	if (iommu_mode != AMDXDNA_IOMMU_PASID)
		goto skip_pasid;
#endif

#ifdef HAVE_iommu_dev_enable_disable_feature
	iommu_dev_disable_feature(&pdev->dev, IOMMU_DEV_FEAT_SVA);
#endif

#ifdef AMDXDNA_DEVEL
skip_pasid:
#endif
	pci_free_irq_vectors(pdev);
	mutex_destroy(&ndev->aie2_lock);
}

static int aie2_query_status(struct amdxdna_client *client,
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

	ret = aie2_query_aie_status(ndev, u64_to_user_ptr(status.buffer),
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

static int aie2_query_metadata(struct amdxdna_client *client,
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

static int aie2_query_version(struct amdxdna_client *client,
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

static int aie2_query_firmware_version(struct amdxdna_client *client,
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

static int aie2_get_power_mode(struct amdxdna_client *client,
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

static int aie2_query_clock_metadata(struct amdxdna_client *client,
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
	clock.mp_npu_clock.freq_mhz = ndev->npuclk_freq;
	snprintf(clock.h_clock.name, sizeof(clock.h_clock.name), "H Clock");
	clock.h_clock.freq_mhz = ndev->hclk_freq;

	min = min(args->buffer_size, sizeof(clock));
	if (copy_to_user(u64_to_user_ptr(args->buffer), &clock, min))
		ret = -EFAULT;

	return ret;
}

static int aie2_query_sensors(struct amdxdna_client *client,
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

static int aie2_query_ctx_status(struct amdxdna_client *client,
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
	kfree(tmp);
	args->buffer_size = req_bytes;
	return ret;
}

static int aie2_query_telemetry(struct amdxdna_client *client,
				struct amdxdna_drm_get_info *args)
{
	struct amdxdna_drm_query_telemetry_header header = {}, *tmp = NULL;
	struct amdxdna_dev *xdna = client->xdna;
	struct amdxdna_mgmt_dma_hdl *dma_hdl;
	struct aie_version ver;
	size_t size, offset;
	int ret, i, min;
	void *buff;

	if (!access_ok(u64_to_user_ptr(args->buffer), args->buffer_size)) {
		XDNA_ERR(xdna, "Failed to access buffer size %d", args->buffer_size);
		return -EFAULT;
	}

	min = min(args->buffer_size, sizeof(header));
	if (copy_from_user(&header, u64_to_user_ptr(args->buffer), min)) {
		XDNA_ERR(xdna, "Failed to copy telemetry header from user");
		return -EFAULT;
	}

	header.map_num_elements = xdna->dev_handle->ctx_rq.hwctx_limit;
	offset = struct_size(&header, map, header.map_num_elements);
	if (args->buffer_size < offset)
		return -EINVAL;

	/*
	 * struct amdxdna_drm_query_telemetry_header sized bytes are reserved for metadata shared
	 * between the driver and shim. Rest is for the data shared between the firmware and shim
	 */
	size = max_t(size_t, args->buffer_size - offset, SZ_8K);

	dma_hdl = amdxdna_mgmt_buff_alloc(xdna, size, DMA_FROM_DEVICE);
	if (IS_ERR(dma_hdl))
		return PTR_ERR(dma_hdl);

	buff = amdxdna_mgmt_buff_get_cpu_addr(dma_hdl, 0);
	if (IS_ERR(buff)) {
		XDNA_ERR(xdna, "Failed to get CPU address for telemetry buffer");
		ret = PTR_ERR(buff);
		goto free_mbuf;
	}

	memset(buff, 0, size);
	amdxdna_mgmt_buff_clflush(dma_hdl, 0, 0);

	ret = aie2_query_aie_telemetry(xdna->dev_handle, dma_hdl, header.type, size, &ver);
	if (ret) {
		XDNA_ERR(xdna, "Get telemetry failed ret %d", ret);
		goto free_mbuf;
	}

	tmp = kzalloc(offset, GFP_KERNEL);
	if (!tmp) {
		ret = -ENOMEM;
		goto free_kbuf;
	}

	tmp->map_num_elements = header.map_num_elements;
	tmp->type = header.type;
	tmp->major = ver.major;
	tmp->minor = ver.minor;

	for (i = 0; i < xdna->dev_handle->ctx_rq.num_parts; i++) {
		struct aie2_partition *part = &xdna->dev_handle->ctx_rq.parts[i];
		struct amdxdna_ctx *ctx;

		list_for_each_entry(ctx, &part->conn_list, entry) {
			tmp->map[ctx->priv->id] = ctx->id;
		}
	}

	print_hex_dump_debug("telemetry: ", DUMP_PREFIX_OFFSET, 16, 4, buff, size, false);

	if (copy_to_user(u64_to_user_ptr(args->buffer), tmp, offset)) {
		ret = -EFAULT;
		goto free_kbuf;
	}

	if (copy_to_user(u64_to_user_ptr(args->buffer + offset), buff, args->buffer_size - offset))
		ret = -EFAULT;

free_kbuf:
	kfree(tmp);
free_mbuf:
	amdxdna_mgmt_buff_free(dma_hdl);
	return ret;
}

static int aie2_get_force_preempt_state(struct amdxdna_client *client,
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

static int aie2_query_frame_boundary_preempt_state(struct amdxdna_client *client,
						   struct amdxdna_drm_get_info *args)
{
	struct amdxdna_drm_attribute_state preempt = {};
	struct amdxdna_dev *xdna = client->xdna;
	struct amdxdna_dev_hdl *ndev;
	int min;

	if (!access_ok(u64_to_user_ptr(args->buffer), args->buffer_size)) {
		XDNA_ERR(xdna, "Failed to access buffer size %d", args->buffer_size);
		return -EFAULT;
	}

	ndev = xdna->dev_handle;
	preempt.state = ndev->frame_boundary_preempt ? 1 : 0;

	min = min(args->buffer, sizeof(preempt));
	if (copy_to_user(u64_to_user_ptr(args->buffer), &preempt, min))
		return -EFAULT;

	return 0;
}

static int aie2_query_resource_info(struct amdxdna_client *client,
				    struct amdxdna_drm_get_info *args)
{
	struct amdxdna_drm_get_resource_info res_info;
	const struct amdxdna_dev_priv *priv;
	struct amdxdna_dev_hdl *ndev;
	struct amdxdna_dev *xdna;
	int min;

	xdna = client->xdna;
	ndev = xdna->dev_handle;
	priv = ndev->priv;

	if (!access_ok(u64_to_user_ptr(args->buffer), args->buffer_size)) {
		XDNA_ERR(xdna, "Failed to access buffer size %d", args->buffer_size);
		return -EFAULT;
	}

	res_info.npu_clk_max = priv->dpm_clk_tbl[ndev->max_dpm_level].hclk;
	res_info.npu_tops_max = ndev->max_tops;
	res_info.npu_task_max = priv->hwctx_limit;
	res_info.npu_tops_curr = ndev->curr_tops;
	res_info.npu_task_curr = ndev->hwctx_cnt;

	min = min(args->buffer_size, sizeof(res_info));
	if (copy_to_user(u64_to_user_ptr(args->buffer), &res_info, min))
		return -EFAULT;

	return 0;
}

static int aie2_get_info(struct amdxdna_client *client, struct amdxdna_drm_get_info *args)
{
	struct amdxdna_dev *xdna = client->xdna;
	int ret;

	ret = amdxdna_pm_resume_get(xdna);
	if (ret)
		return ret;

	mutex_lock(&xdna->dev_lock);
	mutex_lock(&xdna->dev_handle->aie2_lock);
	switch (args->param) {
	case DRM_AMDXDNA_QUERY_AIE_STATUS:
		ret = aie2_query_status(client, args);
		break;
	case DRM_AMDXDNA_QUERY_AIE_METADATA:
		ret = aie2_query_metadata(client, args);
		break;
	case DRM_AMDXDNA_QUERY_AIE_VERSION:
		ret = aie2_query_version(client, args);
		break;
	case DRM_AMDXDNA_QUERY_CLOCK_METADATA:
		ret = aie2_query_clock_metadata(client, args);
		break;
	case DRM_AMDXDNA_QUERY_SENSORS:
		ret = aie2_query_sensors(client, args);
		break;
	case DRM_AMDXDNA_QUERY_HW_CONTEXTS:
		ret = aie2_query_ctx_status(client, args);
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
		ret = aie2_query_firmware_version(client, args);
		break;
	case DRM_AMDXDNA_GET_POWER_MODE:
		ret = aie2_get_power_mode(client, args);
		break;
	case DRM_AMDXDNA_QUERY_TELEMETRY:
		if (!amdxdna_admin_access_allowed(xdna)) {
			ret = -EPERM;
			break;
		}
		ret = aie2_query_telemetry(client, args);
		break;
	case DRM_AMDXDNA_GET_FORCE_PREEMPT_STATE:
		ret = aie2_get_force_preempt_state(client, args);
		break;
	case DRM_AMDXDNA_QUERY_RESOURCE_INFO:
		ret = aie2_query_resource_info(client, args);
		break;
	case DRM_AMDXDNA_GET_FRAME_BOUNDARY_PREEMPT_STATE:
		ret = aie2_query_frame_boundary_preempt_state(client, args);
		break;
	default:
		XDNA_ERR(xdna, "Not supported request parameter %u", args->param);
		ret = -EOPNOTSUPP;
	}
	mutex_unlock(&xdna->dev_handle->aie2_lock);
	mutex_unlock(&xdna->dev_lock);

	amdxdna_pm_suspend_put(xdna);
	XDNA_DBG(xdna, "Got param %d", args->param);

	return ret;
}

static int aie2_query_ctx_status_array(struct amdxdna_client *client,
				       struct amdxdna_drm_hwctx_entry *tmp, pid_t pid, u32 ctx_id,
				       u32 max_entries)
{
	struct amdxdna_dev *xdna = client->xdna;
	struct amdxdna_mgmt_dma_hdl *dma_hdl;
	struct amdxdna_client *tmp_client;
	struct app_health_report *r;
	struct amdxdna_ctx *ctx;
	unsigned long id;
	int ret = 0, idx;
	u32 hw_i = 0;
	size_t size;

	size = max_t(size_t, sizeof(*r), SZ_8K);
	dma_hdl = amdxdna_mgmt_buff_alloc(xdna, size, DMA_FROM_DEVICE);
	if (IS_ERR(dma_hdl)) {
		XDNA_ERR(xdna, "Failed to allocate memory for app health");
		return PTR_ERR(dma_hdl);
	}

	r = amdxdna_mgmt_buff_get_cpu_addr(dma_hdl, 0);
	if (IS_ERR(r)) {
		XDNA_ERR(xdna, "Failed to get CPU address for app health");
		ret = PTR_ERR(r);
		goto exit;
	}

	list_for_each_entry(tmp_client, &xdna->client_list, node) {
		int heap_usage;

		if (pid && pid != tmp_client->pid)
			continue;

		mutex_lock(&tmp_client->mm_lock);
		heap_usage = tmp_client->heap_usage;
		mutex_unlock(&tmp_client->mm_lock);

		idx = srcu_read_lock(&tmp_client->ctx_srcu);
		amdxdna_for_each_ctx(tmp_client, id, ctx) {
			if (!ctx->priv)
				continue;

			if (ctx_id && ctx_id != ctx->id)
				continue;

			/*
			 * Guard against TOCTOU between the runqueue count
			 * (used to size the buffer) and the xarray iteration
			 * (used to fill it). A context that is in the xarray
			 * with priv set but not yet added to the runqueue is
			 * invisible to the count but visible here. Without
			 * this check the loop writes past the allocated buffer,
			 * corrupting adjacent kernel heap memory.
			 */
			if (hw_i >= max_entries) {
				XDNA_ERR(xdna, "Context count exceeds buffer size %u",
					 max_entries);
				ret = -ENOSPC;
				goto out_unlock;
			}
			tmp[hw_i].pid = tmp_client->pid;
			tmp[hw_i].context_id = ctx->id;
			tmp[hw_i].hwctx_id = ctx->priv->id;
			tmp[hw_i].start_col = ctx->start_col;
			tmp[hw_i].num_col = ctx->num_col;
			tmp[hw_i].command_submissions = ctx->submitted;
			tmp[hw_i].command_completions = ctx->completed;
			tmp[hw_i].migrations = 0;
			tmp[hw_i].preemptions = 0;
			tmp[hw_i].errors = 0;
			tmp[hw_i].pasid = tmp_client->pasid;
			tmp[hw_i].priority = ctx->qos.priority;
			tmp[hw_i].gops = ctx->qos.gops;
			tmp[hw_i].fps = ctx->qos.fps;
			tmp[hw_i].dma_bandwidth = ctx->qos.dma_bandwidth;
			tmp[hw_i].latency = ctx->qos.latency;
			tmp[hw_i].frame_exec_time = ctx->qos.frame_exec_time;
			tmp[hw_i].heap_usage = heap_usage;
			tmp[hw_i].suspensions = ctx->priv->disconn_cnt;

			if (ctx->priv->active)
				tmp[hw_i].state = AMDXDNA_HWCTX_STATE_ACTIVE;
			else
				tmp[hw_i].state = AMDXDNA_HWCTX_STATE_IDLE;

			if (aie2_is_ctx_connected(ctx)) {
				amdxdna_mgmt_buff_clflush(dma_hdl, 0, 0);

				mutex_lock(&xdna->dev_handle->aie2_lock);
				ret = aie2_get_app_health(xdna->dev_handle, dma_hdl,
							  ctx->priv->id, size);
				mutex_unlock(&xdna->dev_handle->aie2_lock);
				if (ret) {
					aie2_reset_app_health_report(r);
					/*
					 * App health information is optional and may be
					 * unsupported on certain device generations or
					 * firmware versions. Other information can still be
					 * valid even if app health is unavailable.
					 */
					if (ret == -EOPNOTSUPP)
						ret = 0;
				}
			} else {
				aie2_reset_app_health_report(r);
			}

			tmp[hw_i].fatal_error_exception_type = r->fatal_info.exception_type;
			tmp[hw_i].fatal_error_exception_pc = r->fatal_info.exception_pc;
			tmp[hw_i].fatal_error_app_module = r->fatal_info.app_module;
			tmp[hw_i].fatal_error_type = r->fatal_info.fatal_type;
			tmp[hw_i].txn_op_idx = r->txn_op_id;
			tmp[hw_i].ctx_pc = r->ctx_pc;

			hw_i++;
		}
out_unlock:
		srcu_read_unlock(&tmp_client->ctx_srcu, idx);
		if (ret)
			goto exit;
	}

	if (pid && ctx_id && !hw_i) {
		XDNA_ERR(xdna, "Invalid context ID %d for PID %d", ctx_id, pid);
		ret = -EINVAL;
	}

exit:
	amdxdna_mgmt_buff_free(dma_hdl);
	return ret;
}

static int aie2_get_array_async_error(struct amdxdna_dev *xdna, struct amdxdna_drm_get_array *args)
{
	struct amdxdna_async_error tmp;
	int ret;

	ret = aie2_error_get_last_async(xdna, &xdna->dev_handle->async_errs_cache, 1, &tmp);
	if (ret < 0)
		goto exit;

	ret = amdxdna_drm_copy_array_to_user(args, &tmp, sizeof(tmp), ret);
exit:
	return ret;
}

static int aie2_get_coredump(struct amdxdna_client *client, struct amdxdna_drm_get_array *args)
{
	struct amdxdna_mgmt_dma_hdl **data_hdls = NULL;
	struct amdxdna_mgmt_dma_hdl *list_hdl = NULL;
	struct amdxdna_drm_aie_coredump config = {};
	struct amdxdna_client *ctx_client = NULL;
	struct amdxdna_client *tmp_client;
	struct amdxdna_ctx *hwctx = NULL;
	struct amdxdna_dev_hdl *ndev;
	struct buffer_list *buf_list;
	struct amdxdna_dev *xdna;
	int ret = 0, idx = 0, i;
	unsigned long hwctx_id;
	size_t total_size;
	size_t list_size;
	size_t buf_size;
	void __user *buf;
	u32 offset = 0;
	u32 num_bufs;

	xdna = client->xdna;
	ndev = xdna->dev_handle;

	if (args->num_element != 1) {
		XDNA_ERR(xdna, "Invalid num_element %u, expected 1",
			 args->num_element);
		return -EINVAL;
	}

	if (!args->element_size ||
	    args->element_size > AMDXDNA_MAX_ELEMENT_SIZE) {
		XDNA_ERR(xdna, "Invalid element_size %u (max %u)",
			 args->element_size, AMDXDNA_MAX_ELEMENT_SIZE);
		return -EINVAL;
	}

	buf_size = (size_t)args->num_element * args->element_size;
	buf = u64_to_user_ptr(args->buffer);
	if (!access_ok(buf, buf_size)) {
		XDNA_ERR(xdna, "Failed to access buffer, element num %d size 0x%x",
			 args->num_element, args->element_size);
		return -EFAULT;
	}

	if (buf_size < sizeof(config)) {
		XDNA_ERR(xdna, "Insufficient buffer size: 0x%zx", buf_size);
		return -ENOSPC;
	}

	ret = amdxdna_drm_copy_array_from_user(args, &config, sizeof(config), 1);
	if (ret) {
		XDNA_ERR(xdna, "Failed to copy config from user");
		return ret;
	}

	XDNA_DBG(xdna, "AIE Coredump request for context_id=%u pid=%llu",
		 config.context_id, config.pid);

	/* Search and validate if context coredump can be fetched for given PID and context ID */
	mutex_lock(&xdna->dev_lock);
	list_for_each_entry(tmp_client, &xdna->client_list, node) {
		struct amdxdna_ctx *hw_ctx;

		idx = srcu_read_lock(&tmp_client->ctx_srcu);
		amdxdna_for_each_ctx(tmp_client, hwctx_id, hw_ctx) {
			if (config.context_id == hwctx_id && config.pid == hw_ctx->client->pid) {
				hwctx = hw_ctx;
				ctx_client = tmp_client;
				break;
			}
		}
		if (hwctx)
			break;
		srcu_read_unlock(&tmp_client->ctx_srcu, idx);
	}
	mutex_unlock(&xdna->dev_lock);

	if (!hwctx) {
		XDNA_ERR(xdna, "Context %u for pid %llu not found", config.context_id, config.pid);
		return -EINVAL;
	}

	/* Check if caller is root or owns the context */
	if (!amdxdna_ctx_access_allowed(hwctx, false)) {
		XDNA_ERR(xdna, "Permission denied for context %u", config.context_id);
		ret = -EPERM;
		goto unlock_srcu;
	}

	num_bufs = ndev->metadata.rows * hwctx->priv->orig_num_col;
	total_size = (size_t)num_bufs * SZ_1M;

	if (buf_size < total_size) {
		XDNA_DBG(xdna, "Insufficient buffer size %zu, need %zu", buf_size, total_size);
		args->element_size = total_size;
		ret = -ENOSPC;
		goto unlock_srcu;
	}

	list_size = max_t(size_t, num_bufs * sizeof(struct buffer_list), SZ_8K);
	list_hdl = amdxdna_mgmt_buff_alloc(xdna, list_size, DMA_TO_DEVICE);
	if (IS_ERR(list_hdl)) {
		XDNA_ERR(xdna, "Failed to allocate buffer list");
		ret = PTR_ERR(list_hdl);
		goto unlock_srcu;
	}

	buf_list = amdxdna_mgmt_buff_get_cpu_addr(list_hdl, 0);
	if (IS_ERR(buf_list)) {
		XDNA_ERR(xdna, "Failed to get CPU address for buffer list");
		ret = PTR_ERR(buf_list);
		goto free_list_hdl;
	}
	memset(buf_list, 0, list_size);

	/* Allocate array to track data buffer handles */
	data_hdls = kcalloc(num_bufs, sizeof(*data_hdls), GFP_KERNEL);
	if (!data_hdls) {
		ret = -ENOMEM;
		goto free_list_hdl;
	}

	for (i = 0; i < num_bufs; i++) {
		void *buf_addr;

		data_hdls[i] = amdxdna_mgmt_buff_alloc(xdna, SZ_1M, DMA_FROM_DEVICE);
		if (IS_ERR(data_hdls[i])) {
			XDNA_ERR(xdna, "Failed to allocate data buffer %d", i);
			ret = PTR_ERR(data_hdls[i]);
			data_hdls[i] = NULL;
			goto free_data_hdls;
		}

		buf_addr = amdxdna_mgmt_buff_get_cpu_addr(data_hdls[i], 0);
		if (IS_ERR(buf_addr)) {
			ret = PTR_ERR(buf_addr);
			goto free_data_hdls;
		}
		memset(buf_addr, 0, SZ_1M);
		amdxdna_mgmt_buff_clflush(data_hdls[i], 0, 0);

		buf_list[i].buf_addr = amdxdna_mgmt_buff_get_dma_addr(data_hdls[i]);
		buf_list[i].buf_size = SZ_1M;
		buf_list[i].reserved = 0;
	}

	amdxdna_mgmt_buff_clflush(list_hdl, 0, 0);

	mutex_lock(&ndev->aie2_lock);
	ret = aie2_get_aie_coredump(ndev, list_hdl, hwctx->priv->id, num_bufs);
	mutex_unlock(&ndev->aie2_lock);

	if (ret) {
		XDNA_ERR(xdna, "Failed to get coredump from firmware, ret=%d", ret);
		goto free_data_hdls;
	}

	for (i = 0; i < num_bufs; i++) {
		void *data = amdxdna_mgmt_buff_get_cpu_addr(data_hdls[i], 0);

		if (IS_ERR(data)) {
			ret = PTR_ERR(data);
			goto free_data_hdls;
		}

		if (copy_to_user(buf + offset, data, SZ_1M)) {
			ret = -EFAULT;
			goto free_data_hdls;
		}
		offset += SZ_1M;
	}

free_data_hdls:
	for (i = 0; i < num_bufs; i++) {
		if (data_hdls[i])
			amdxdna_mgmt_buff_free(data_hdls[i]);
	}
	kfree(data_hdls);
free_list_hdl:
	amdxdna_mgmt_buff_free(list_hdl);
unlock_srcu:
	srcu_read_unlock(&ctx_client->ctx_srcu, idx);
	return ret;
}

static int aie2_aie_tile_read(struct amdxdna_client *client, struct amdxdna_drm_get_array *args)
{
	struct amdxdna_drm_aie_tile_access access = {};
	struct amdxdna_mgmt_dma_hdl *dma_hdl = NULL;
	struct amdxdna_client *ctx_client = NULL;
	struct amdxdna_client *tmp_client;
	struct amdxdna_ctx *hwctx = NULL;
	struct amdxdna_dev_hdl *ndev;
	struct amdxdna_dev *xdna;
	unsigned long hwctx_id;
	dma_addr_t dram_addr;
	int ret, idx = 0;
	void *cpu_addr;

	xdna = client->xdna;
	ndev = xdna->dev_handle;

	if (args->num_element != 1) {
		XDNA_ERR(xdna, "Invalid num_element %u, expected 1",
			 args->num_element);
		return -EINVAL;
	}

	if (!args->element_size ||
	    args->element_size > AMDXDNA_MAX_ELEMENT_SIZE) {
		XDNA_ERR(xdna, "Invalid element_size %u (max %u)",
			 args->element_size, AMDXDNA_MAX_ELEMENT_SIZE);
		return -EINVAL;
	}

	/* Access struct is at the beginning of the buffer */
	ret = amdxdna_drm_copy_array_from_user(args, &access, sizeof(access), 1);
	if (ret) {
		XDNA_ERR(xdna, "Failed to copy request from user");
		return ret;
	}

	XDNA_DBG(xdna, "AIE tile read: ctx %u pid %llu col %u row %u addr 0x%x size %u",
		 access.context_id, access.pid, access.col, access.row, access.addr, access.size);

	/* Find the hardware context and hold SRCU lock for the duration */
	mutex_lock(&xdna->dev_lock);
	list_for_each_entry(tmp_client, &xdna->client_list, node) {
		struct amdxdna_ctx *tmp_ctx;

		idx = srcu_read_lock(&tmp_client->ctx_srcu);
		amdxdna_for_each_ctx(tmp_client, hwctx_id, tmp_ctx) {
			if (access.context_id == hwctx_id && access.pid == tmp_ctx->client->pid) {
				hwctx = tmp_ctx;
				ctx_client = tmp_client;
				break;
			}
		}
		if (hwctx)
			break;
		srcu_read_unlock(&tmp_client->ctx_srcu, idx);
	}
	mutex_unlock(&xdna->dev_lock);

	if (!hwctx) {
		XDNA_ERR(xdna, "Context %u for pid %llu not found", access.context_id, access.pid);
		return -EINVAL;
	}

	/* Check if caller is root or owns the context */
	if (!amdxdna_ctx_access_allowed(hwctx, false)) {
		XDNA_ERR(xdna, "Permission denied for context %u", access.context_id);
		ret = -EPERM;
		goto unlock_srcu;
	}

	if (access.col >= hwctx->num_col) {
		XDNA_ERR(xdna, "Column %u is outside partition range [0, %u)",
			 access.col, hwctx->num_col);
		ret = -EINVAL;
		goto unlock_srcu;
	}

	if (access.row >= ndev->metadata.rows) {
		XDNA_ERR(xdna, "Row %u is outside range [0, %u)", access.row, ndev->metadata.rows);
		ret = -EINVAL;
		goto unlock_srcu;
	}

	/* Register read: size == 4 bytes */
	if (access.size == sizeof(u32)) {
		u32 reg_val = 0;

		mutex_lock(&ndev->aie2_lock);
		ret = aie2_rw_aie_reg(ndev, AIE2_ACCESS_TYPE_REG_READ, hwctx->priv->id,
				      access.row, access.col, access.addr, &reg_val);
		mutex_unlock(&ndev->aie2_lock);
		if (ret) {
			XDNA_ERR(xdna, "AIE register read failed, ret %d", ret);
			goto unlock_srcu;
		}

		ret = amdxdna_drm_copy_array_to_user(args, &reg_val, sizeof(reg_val), 1);
		if (ret)
			XDNA_ERR(xdna, "Failed to copy register data to user");

		goto unlock_srcu;
	}

	/* Memory read: size > 4 bytes, use DMA buffer */

	dma_hdl = amdxdna_mgmt_buff_alloc(xdna, max_t(u32, access.size, SZ_8K), DMA_FROM_DEVICE);
	if (IS_ERR(dma_hdl)) {
		ret = PTR_ERR(dma_hdl);
		XDNA_ERR(xdna, "Failed to allocate DMA buffer, ret %d", ret);
		goto unlock_srcu;
	}

	cpu_addr = amdxdna_mgmt_buff_get_cpu_addr(dma_hdl, 0);
	if (IS_ERR(cpu_addr)) {
		ret = PTR_ERR(cpu_addr);
		goto free_dma;
	}

	dram_addr = amdxdna_mgmt_buff_get_dma_addr(dma_hdl);
	if (!dram_addr) {
		XDNA_ERR(xdna, "Invalid DMA address");
		ret = -EINVAL;
		goto free_dma;
	}

	amdxdna_mgmt_buff_clflush(dma_hdl, 0, 0);

	mutex_lock(&ndev->aie2_lock);
	ret = aie2_rw_aie_mem(ndev, AIE2_ACCESS_TYPE_MEM_READ, hwctx->priv->id,
			      access.row, access.col, access.addr, dram_addr, access.size);
	mutex_unlock(&ndev->aie2_lock);
	if (ret) {
		XDNA_ERR(xdna, "AIE memory read failed, ret %d", ret);
		goto free_dma;
	}

	amdxdna_mgmt_buff_clflush(dma_hdl, 0, 0);

	ret = amdxdna_drm_copy_array_to_user(args, cpu_addr, access.size, 1);
	if (ret) {
		XDNA_ERR(xdna, "Failed to copy data to user");
		goto free_dma;
	}

free_dma:
	amdxdna_mgmt_buff_free(dma_hdl);
unlock_srcu:
	srcu_read_unlock(&ctx_client->ctx_srcu, idx);
	return ret;
}

static int aie2_aie_tile_write(struct amdxdna_client *client, struct amdxdna_drm_set_state *args)
{
	struct amdxdna_drm_aie_tile_access access = {};
	struct amdxdna_mgmt_dma_hdl *dma_hdl = NULL;
	struct amdxdna_client *ctx_client = NULL;
	struct amdxdna_client *tmp_client;
	struct amdxdna_ctx *hwctx = NULL;
	struct amdxdna_dev_hdl *ndev;
	struct amdxdna_dev *xdna;
	unsigned long hwctx_id;
	dma_addr_t dram_addr;
	int ret, idx = 0;
	void *cpu_addr;

	xdna = client->xdna;
	ndev = xdna->dev_handle;

	/* Access struct is at the beginning of the buffer, data follows after */
	if (copy_from_user(&access, u64_to_user_ptr(args->buffer), sizeof(access))) {
		XDNA_ERR(xdna, "Failed to copy request from user");
		return -EFAULT;
	}

	XDNA_DBG(xdna, "AIE tile write: ctx %u pid %llu col %u row %u addr 0x%x size %u",
		 access.context_id, access.pid, access.col, access.row, access.addr, access.size);

	/* Find the hardware context and hold SRCU lock for the duration */
	mutex_lock(&xdna->dev_lock);
	list_for_each_entry(tmp_client, &xdna->client_list, node) {
		struct amdxdna_ctx *tmp_ctx;

		idx = srcu_read_lock(&tmp_client->ctx_srcu);
		amdxdna_for_each_ctx(tmp_client, hwctx_id, tmp_ctx) {
			if (access.context_id == hwctx_id && access.pid == tmp_ctx->client->pid) {
				hwctx = tmp_ctx;
				ctx_client = tmp_client;
				break;
			}
		}
		if (hwctx)
			break;
		srcu_read_unlock(&tmp_client->ctx_srcu, idx);
	}
	mutex_unlock(&xdna->dev_lock);

	if (!hwctx) {
		XDNA_ERR(xdna, "Context %u for pid %llu not found", access.context_id, access.pid);
		return -EINVAL;
	}

	/* Check if caller is root or owns the context */
	if (!amdxdna_ctx_access_allowed(hwctx, false)) {
		XDNA_ERR(xdna, "Permission denied for context %u", access.context_id);
		ret = -EPERM;
		goto unlock_srcu;
	}

	if (access.col >= hwctx->num_col) {
		XDNA_ERR(xdna, "Column %u is outside partition range [0, %u)",
			 access.col, hwctx->num_col);
		ret = -EINVAL;
		goto unlock_srcu;
	}

	if (access.row >= ndev->metadata.rows) {
		XDNA_ERR(xdna, "Row %u is outside range [0, %u)",
			 access.row, ndev->metadata.rows);
		ret = -EINVAL;
		goto unlock_srcu;
	}

	/* Register write: size == 4 bytes */
	if (access.size == sizeof(u32)) {
		u32 reg_val;

		/* Data is after the access struct */
		if (copy_from_user(&reg_val,
				   u64_to_user_ptr(args->buffer) + sizeof(access),
				   sizeof(reg_val))) {
			XDNA_ERR(xdna, "Failed to copy register data from user");
			ret = -EFAULT;
			goto unlock_srcu;
		}

		mutex_lock(&ndev->aie2_lock);
		ret = aie2_rw_aie_reg(ndev, AIE2_ACCESS_TYPE_REG_WRITE, hwctx->priv->id,
				      access.row, access.col, access.addr, &reg_val);
		mutex_unlock(&ndev->aie2_lock);
		if (ret)
			XDNA_ERR(xdna, "AIE register write failed, ret %d", ret);

		goto unlock_srcu;
	}

	/* Memory write: size > 4 bytes, use DMA buffer */

	dma_hdl = amdxdna_mgmt_buff_alloc(xdna, max_t(u32, access.size, SZ_8K), DMA_TO_DEVICE);
	if (IS_ERR(dma_hdl)) {
		ret = PTR_ERR(dma_hdl);
		XDNA_ERR(xdna, "Failed to allocate DMA buffer, ret %d", ret);
		goto unlock_srcu;
	}

	cpu_addr = amdxdna_mgmt_buff_get_cpu_addr(dma_hdl, 0);
	if (IS_ERR(cpu_addr)) {
		ret = PTR_ERR(cpu_addr);
		goto free_dma;
	}

	dram_addr = amdxdna_mgmt_buff_get_dma_addr(dma_hdl);
	if (!dram_addr) {
		XDNA_ERR(xdna, "Invalid DMA address");
		ret = -EINVAL;
		goto free_dma;
	}

	/* Copy data from user space (data is after the access struct) */
	if (copy_from_user(cpu_addr, u64_to_user_ptr(args->buffer) + sizeof(access), access.size)) {
		XDNA_ERR(xdna, "Failed to copy data from user");
		ret = -EFAULT;
		goto free_dma;
	}

	amdxdna_mgmt_buff_clflush(dma_hdl, 0, 0);

	mutex_lock(&ndev->aie2_lock);
	ret = aie2_rw_aie_mem(ndev, AIE2_ACCESS_TYPE_MEM_WRITE, hwctx->priv->id,
			      access.row, access.col, access.addr, dram_addr, access.size);
	mutex_unlock(&ndev->aie2_lock);
	if (ret) {
		XDNA_ERR(xdna, "AIE memory write failed, ret %d", ret);
		goto free_dma;
	}

free_dma:
	amdxdna_mgmt_buff_free(dma_hdl);
unlock_srcu:
	srcu_read_unlock(&ctx_client->ctx_srcu, idx);
	return ret;
}

static int aie2_get_array_hwctx(struct amdxdna_client *client, struct amdxdna_drm_get_array *args)
{
	struct amdxdna_dev *xdna = client->xdna;
	struct amdxdna_drm_hwctx_entry input = {};
	struct amdxdna_drm_hwctx_entry *tmp;
	int ctx_limit, ctx_cnt, ret;
	size_t buf_size;

	if (!args->num_element ||
	    args->num_element > AMDXDNA_MAX_NUM_ELEMENT) {
		XDNA_ERR(xdna, "Invalid num_element %u (max %u)",
			 args->num_element, AMDXDNA_MAX_NUM_ELEMENT);
		return -EINVAL;
	}

	if (!args->element_size ||
	    args->element_size > AMDXDNA_MAX_ELEMENT_SIZE) {
		XDNA_ERR(xdna, "Invalid element_size %u (max %u)",
			 args->element_size, AMDXDNA_MAX_ELEMENT_SIZE);
		return -EINVAL;
	}

	buf_size = (size_t)args->num_element * args->element_size;

	tmp = kcalloc(args->num_element, sizeof(*tmp), GFP_KERNEL);
	if (!tmp)
		return -ENOMEM;

	mutex_lock(&xdna->dev_lock);

	switch (args->param) {
	case DRM_AMDXDNA_HW_CONTEXT_ALL:
		ctx_limit = aie2_rq_context_limit(&xdna->dev_handle->ctx_rq);
		WARN_ON(ctx_limit > AMDXDNA_MAX_NUM_ELEMENT);
		ctx_cnt = aie2_rq_active_context(&xdna->dev_handle->ctx_rq);

		if (args->num_element < ctx_cnt) {
			XDNA_ERR(xdna, "Not enough space. Total ctx %d, got %d",
				 ctx_cnt, args->num_element);
			args->num_element = ctx_cnt;
			ret = -ENOSPC;
			goto exit;
		}

		ret = aie2_query_ctx_status_array(client, tmp, 0, 0, args->num_element);
		if (ret) {
			if (ret == -ENOSPC) {
				ctx_cnt = aie2_rq_active_context(&xdna->dev_handle->ctx_rq);
				args->num_element = ctx_cnt;
			}
			goto exit;
		}

		break;
	case DRM_AMDXDNA_HW_CONTEXT_BY_ID:
		ctx_cnt = 1;

		ret = amdxdna_drm_copy_array_from_user(args, &input, sizeof(input), ctx_cnt);
		if (ret)
			goto exit;

		if (args->num_element != ctx_cnt || !input.context_id || !input.pid) {
			XDNA_ERR(xdna, "Invalid context ID %d, PID %lld or num_elements %d",
				 input.context_id, input.pid, args->num_element);
			args->num_element = ctx_cnt;
			ret = -EINVAL;
			goto exit;
		}

		ret = aie2_query_ctx_status_array(client, tmp, input.pid, input.context_id,
						  args->num_element);
		if (ret)
			goto exit;

		break;
	default:
		XDNA_ERR(xdna, "Not supported request parameter %u", args->param);
		ret = -EOPNOTSUPP;
		goto exit;
	}

	ret = amdxdna_drm_copy_array_to_user(args, tmp, sizeof(*tmp), ctx_cnt);
exit:
	mutex_unlock(&xdna->dev_lock);
	kfree(tmp);

	return ret;
}

static int aie2_get_array(struct amdxdna_client *client, struct amdxdna_drm_get_array *args)
{
	struct amdxdna_dev *xdna = client->xdna;
	int ret;

	ret = amdxdna_pm_resume_get(xdna);
	if (ret)
		return ret;

	switch (args->param) {
	case DRM_AMDXDNA_HW_LAST_ASYNC_ERR:
		ret = aie2_get_array_async_error(xdna, args);
		break;
	case DRM_AMDXDNA_FW_LOG:
		if (!amdxdna_admin_access_allowed(xdna)) {
			ret = -EPERM;
			break;
		}
		ret = amdxdna_get_fw_log(xdna, args);
		break;
	case DRM_AMDXDNA_FW_TRACE:
		if (!amdxdna_admin_access_allowed(xdna)) {
			ret = -EPERM;
			break;
		}
		ret = amdxdna_get_fw_trace(xdna, args);
		break;
	case DRM_AMDXDNA_FW_LOG_CONFIG:
		ret = amdxdna_get_fw_log_configs(xdna, args);
		break;
	case DRM_AMDXDNA_FW_TRACE_CONFIG:
		ret = amdxdna_get_fw_trace_configs(xdna, args);
		break;
	case DRM_AMDXDNA_AIE_COREDUMP:
		ret = aie2_get_coredump(client, args);
		break;
	case DRM_AMDXDNA_AIE_TILE_READ:
		ret = aie2_aie_tile_read(client, args);
		break;
	default:
		ret = aie2_get_array_hwctx(client, args);
		break;
	}

	amdxdna_pm_suspend_put(xdna);
	if (!ret)
		XDNA_DBG(xdna, "Got param %d", args->param);

	return ret;
}

static int aie2_set_power_mode(struct amdxdna_client *client, struct amdxdna_drm_set_state *args)
{
	struct amdxdna_drm_set_power_mode power_state = {};
	struct amdxdna_dev *xdna = client->xdna;
	int power_mode, min;

	if (!access_ok(u64_to_user_ptr(args->buffer), args->buffer_size)) {
		XDNA_ERR(xdna, "Failed to access buffer size %d", args->buffer_size);
		return -EFAULT;
	}

	min = min(args->buffer_size, sizeof(power_state));
	if (copy_from_user(&power_state, u64_to_user_ptr(args->buffer), min))
		return -EFAULT;

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
	struct amdxdna_drm_attribute_state force = {};
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

static int aie2_set_frame_boundary_preempt_state(struct amdxdna_client *client,
						 struct amdxdna_drm_set_state *args)
{
	struct amdxdna_dev_hdl *ndev = client->xdna->dev_handle;
	struct amdxdna_drm_attribute_state preempt = {};
	struct amdxdna_dev *xdna = client->xdna;
	int ret, min;

	if (args->buffer_size != sizeof(preempt)) {
		XDNA_ERR(xdna, "Invalid buffer size. Given: %u Need: %lu.",
			 args->buffer_size, sizeof(preempt));
		return -EINVAL;
	}

	min = min(args->buffer_size, sizeof(preempt));
	if (copy_from_user(&preempt, u64_to_user_ptr(args->buffer), sizeof(preempt)))
		return -EFAULT;

	if (preempt.state && preempt.state > 1) {
		XDNA_ERR(xdna, "Invalid state: %d", preempt.state);
		return -EINVAL;
	}

	ret = aie2_frame_boundary_preemption(ndev, preempt.state);
	if (ret) {
		XDNA_ERR(xdna, "Failed to %s frame boundary preemption",
			 preempt.state ? "enabled" : "disabled");
		return ret;
	}

	XDNA_DBG(xdna, "Frame boundary preemption %s",
		 ndev->frame_boundary_preempt ? "enabled" : "disabled");

	return 0;
}

static int aie2_set_state(struct amdxdna_client *client, struct amdxdna_drm_set_state *args)
{
	struct amdxdna_dev *xdna = client->xdna;
	int ret;

	ret = amdxdna_pm_resume_get(xdna);
	if (ret)
		return ret;

	switch (args->param) {
	case DRM_AMDXDNA_SET_POWER_MODE:
		mutex_lock(&xdna->dev_handle->aie2_lock);
		ret = aie2_set_power_mode(client, args);
		mutex_unlock(&xdna->dev_handle->aie2_lock);
		break;
	case DRM_AMDXDNA_SET_FORCE_PREEMPT:
		mutex_lock(&xdna->dev_handle->aie2_lock);
		ret = aie2_set_force_preempt_state(client, args);
		mutex_unlock(&xdna->dev_handle->aie2_lock);
		break;
	case DRM_AMDXDNA_SET_FRAME_BOUNDARY_PREEMPT:
		mutex_lock(&xdna->dev_handle->aie2_lock);
		ret = aie2_set_frame_boundary_preempt_state(client, args);
		mutex_unlock(&xdna->dev_handle->aie2_lock);
		break;
	case DRM_AMDXDNA_SET_FW_LOG_STATE:
		ret = amdxdna_set_fw_log_state(xdna, args);
		break;
	case DRM_AMDXDNA_SET_FW_TRACE_STATE:
		ret = amdxdna_set_fw_trace_state(xdna, args);
		break;
#ifdef AMDXDNA_AIE2_PRIV
	case DRM_AMDXDNA_WRITE_AIE_MEM:
		mutex_lock(&xdna->dev_handle->aie2_lock);
		ret = aie2_write_aie_mem(client, args);
		mutex_unlock(&xdna->dev_handle->aie2_lock);
		break;
	case DRM_AMDXDNA_WRITE_AIE_REG:
		mutex_lock(&xdna->dev_handle->aie2_lock);
		ret = aie2_write_aie_reg(client, args);
		mutex_unlock(&xdna->dev_handle->aie2_lock);
		break;
#endif
	case DRM_AMDXDNA_AIE_TILE_WRITE:
		ret = aie2_aie_tile_write(client, args);
		break;
	default:
		XDNA_ERR(xdna, "Not supported request parameter %u", args->param);
		ret = -EOPNOTSUPP;
	}

	amdxdna_pm_suspend_put(xdna);
	return ret;
}

static int aie2_get_dev_rev(struct amdxdna_dev *xdna, u32 *rev)
{
	struct amdxdna_dev_hdl *ndev = xdna->dev_handle;
	enum aie2_dev_revision aie2_rev;
	int ret;

	mutex_lock(&ndev->aie2_lock);
	ret = aie2_get_dev_revision(ndev, &aie2_rev);
	mutex_unlock(&ndev->aie2_lock);

	if (!ret)
		*rev = (u32)aie2_rev;

	return ret;
}

const struct amdxdna_dev_ops aie2_ops = {
	.mmap			= NULL,
	.init			= aie2_init,
	.fini			= aie2_fini,
	.get_dev_revision	= aie2_get_dev_rev,
	.tdr_start		= aie2_tdr_start,
	.tdr_stop		= aie2_tdr_stop,
	.resume			= aie2_hw_resume,
	.suspend		= aie2_hw_suspend,
	.reset_prepare		= aie2_reset_prepare,
	.reset_done		= aie2_reset_done,
	.debugfs		= aie2_debugfs_init,
	.fw_log_init		= aie2_fw_log_init,
	.fw_log_config		= aie2_fw_log_config,
	.fw_log_fini		= aie2_fw_log_fini,
	.fw_log_parse		= aie2_fw_log_parse,
	.fw_trace_init		= aie2_fw_trace_init,
	.fw_trace_config	= aie2_fw_trace_config,
	.fw_trace_fini		= aie2_fw_trace_fini,
	.fw_trace_parse		= aie2_fw_trace_parse,
	.get_aie_info		= aie2_get_info,
	.get_aie_array		= aie2_get_array,
	.set_aie_state		= aie2_set_state,
	.ctx_init		= aie2_ctx_init,
	.ctx_fini		= aie2_ctx_fini,
	.ctx_config		= aie2_ctx_config,
	.cmd_submit		= aie2_cmd_submit,
	.cmd_wait		= aie2_cmd_wait,
	.hmm_invalidate		= aie2_hmm_invalidate,
	.cmd_get_out_fence	= aie2_cmd_get_out_fence,
};

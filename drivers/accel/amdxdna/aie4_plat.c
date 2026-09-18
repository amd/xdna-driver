// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2026, Advanced Micro Devices, Inc.
 *
 * aie4 transport over a platform (non-PCI) device.
 *
 * This is the platform counterpart of aie4_pci.c: it provides the aie4
 * transport hooks (doorbell, cert-completion) and the device lifecycle ops
 * (aie4_plat_ops).  The transport-independent aie4 command/query/error core in
 * aie4.c/aie4_ctx.c is shared with the PCI path.
 *
 * The management channel and the doorbell run over the shmem+IPI mailbox in
 * amdxdna_mailbox_plat.c; cert completions arrive as a single shared IPI rather
 * than per-cert MSI-X vectors, so every completion wakes all cert waiters.  DPM
 * and performance counters have no platform backend yet (see below).
 */

#include <drm/drm_managed.h>

#include "aie.h"
#include "aie4.h"
#include "aie4_plat.h"
#include "amdxdna_ctx.h"
#include "amdxdna_dpt.h"
#include "amdxdna_drv.h"
#include "amdxdna_error.h"
#include "amdxdna_mailbox.h"
#include "amdxdna_mailbox_plat.h"
#include "amdxdna_pm.h"

/*
 * Transport hooks (mirror the aie4_pci.c definitions).  The shared aie4_ctx.c
 * reaches the doorbell and the cert completion only through these; on the
 * platform build aie4_pci.c is not compiled, so they are defined here.
 */

/*
 * The platform doorbell has no per-ctx MMIO kick target: the kick is a shmem
 * ring entry keyed by hw_ctx_id, which aie4_doorbell_ring() reads back from the
 * hwctx, so there is nothing to validate or store at setup time.  The
 * transport-neutral connected sentinel is owned by aie4_ctx.c.
 */
int aie4_doorbell_setup(struct amdxdna_hwctx *hwctx,
			const struct aie4_msg_create_hw_context_resp *resp)
{
	return 0;
}

void aie4_doorbell_ring(struct amdxdna_hwctx *hwctx)
{
	struct amdxdna_dev_hdl *ndev = hwctx->client->xdna->dev_handle;
	int ret;

	ret = amdxdna_mailbox_plat_ring_doorbell(ndev->mbox,
						 hwctx->priv->hw_ctx_id);
	if (ret)
		XDNA_ERR(ndev->aie.xdna, "Ring doorbell for hw_ctx %d failed, ret %d",
			 hwctx->priv->hw_ctx_id, ret);
}

/*
 * Completion notification on the platform arrives as a single IPI on a shared
 * RX path rather than a per-cert MSI-X vector, so there is no per-cert irq to
 * request or free.  What the transport does need is to know which completions
 * are live: every completion IPI wakes all registered cert_comp waiters (see
 * plat_mailbox_cert_notify()) and each re-checks its own condition.
 *
 * Unregistering here mirrors the free_irq() the PCI path does, and serves the
 * same purpose -- cert_comp_release() calls this before kfree(), and the
 * unregister cannot return while the IPI fan-out is still walking the entry.
 */
int aie4_request_notification(struct cert_comp *comp)
{
	return amdxdna_mailbox_plat_register_notify(comp->ndev->mbox,
						    comp->msix_idx, comp);
}

void aie4_free_notification(struct cert_comp *comp)
{
	amdxdna_mailbox_plat_unregister_notify(comp->ndev->mbox,
					       comp->msix_idx);
}

/* SR-IOV is PCI-only; a platform aie4 device is never a virtual function. */
bool aie4_is_vf(struct amdxdna_dev_hdl *ndev)
{
	return false;
}

/* TODO: platform DPM / performance counters (no PCI SMU hw_ops here). */
int aie4_set_dpm(struct amdxdna_dev_hdl *ndev, u32 dpm_level)
{
	return 0;
}

/*
 * TODO: platform performance counters.  Until firmware querying lands here,
 * npuclk_freq/hclk_freq and current-TOPS stay zero, so
 * DRM_AMDXDNA_QUERY_CLOCK_METADATA / QUERY_RESOURCE_INFO report stale values on
 * the platform -- part of the deferred bring-up (see the file header NOTE).
 */
void aie4_update_counters(struct amdxdna_dev_hdl *ndev)
{
}

/* Device lifecycle (platform variants of the aie4_classic_* lifecycle). */

/*
 * Bring up the shmem+IPI mailbox and its management channel.  This is the
 * platform counterpart of the PCI aie4_mailbox_init(): the ring buffers and IPI
 * come from the device tree (parsed in xdnam_mailbox_create()), so there are no
 * PCI ring resources or MSI-X irq to wire, and xdna_mailbox_start_channel() is a
 * no-op on this transport.  The mailbox itself is drm-managed (auto-freed);
 * aie4_mailbox_fini() only tears the channel back down.
 */
static int aie4_mailbox_init(struct amdxdna_dev_hdl *ndev)
{
	struct amdxdna_dev *xdna = ndev->aie.xdna;
	int ret;

	ndev->mbox = xdnam_mailbox_create(&xdna->ddev, NULL);
	if (IS_ERR(ndev->mbox)) {
		ret = PTR_ERR(ndev->mbox);
		ndev->mbox = NULL;
		XDNA_ERR(xdna, "failed to create mailbox device, ret %d", ret);
		return ret;
	}

	ndev->aie.mgmt_chann = xdna_mailbox_alloc_channel(ndev->mbox);
	if (!ndev->aie.mgmt_chann) {
		XDNA_ERR(xdna, "failed to alloc mailbox channel");
		return -ENODEV;
	}

	/* Firmware-initiated (async) messages arrive with mailbox id 0. */
	xdna_mailbox_set_async_cb(ndev->aie.mgmt_chann, ndev,
				  aie4_mgmt_async_event_handler);

	ret = xdna_mailbox_start_channel(ndev->aie.mgmt_chann, NULL, NULL, 0, 0);
	if (ret) {
		xdna_mailbox_free_channel(ndev->aie.mgmt_chann);
		ndev->aie.mgmt_chann = NULL;
	}
	return ret;
}

static void aie4_mailbox_fini(struct amdxdna_dev_hdl *ndev)
{
	if (!ndev->aie.mgmt_chann)
		return;

	xdna_mailbox_stop_channel(ndev->aie.mgmt_chann);
	xdna_mailbox_free_channel(ndev->aie.mgmt_chann);
	ndev->aie.mgmt_chann = NULL;
}

/*
 * Platform equivalent of the PCI aie4_config_fw(): calibrate the clock, attach
 * the DRAM work buffer and apply the context-switch hysteresis.  (The PCI-only
 * NPU3A iommu-bypass echo does not apply here.)
 */
static int aie4_plat_config_fw(struct amdxdna_dev_hdl *ndev)
{
	int ret;

	ret = aie4_calibrate_clock(ndev);
	if (ret)
		return ret;

	ret = aie4_attach_work_buffer(ndev, to_dma_addr(ndev->work_buf_hdl, 0),
				      to_buf_size(ndev->work_buf_hdl));
	if (ret)
		return ret;

	/* Best-effort tuning knob; failure warns internally, does not fail init. */
	aie4_set_ctx_hysteresis(ndev, ndev->ctx_switch_hysteresis_us);
	return 0;
}

static int aie4_plat_init(struct amdxdna_dev *xdna)
{
	struct amdxdna_dev_hdl *ndev;
	int ret;

	ndev = drmm_kzalloc(&xdna->ddev, sizeof(*ndev), GFP_KERNEL);
	if (!ndev)
		return -ENOMEM;

	ndev->aie.xdna = xdna;
	xdna->dev_handle = ndev;

	/* Per-cert completion routing state, mirroring the PCI aie4m_pcidev_init(). */
	xa_init_flags(&ndev->cert_comp_xa, XA_FLAGS_ALLOC);
	mutex_init(&ndev->cert_comp_lock);

	/*
	 * Kernel-mode submission: the driver fills the HSA queue and rings the
	 * doorbell (amdxdna_mailbox_plat_ring_doorbell), so the platform has no
	 * user-mmap'able doorbell.  Without this, user-mode submission hands a
	 * doorbell offset to the shim, whose mmap fails with -EOPNOTSUPP.
	 */
	ndev->kernel_submit = true;
	ndev->ctx_switch_hysteresis_us = AIE4_CTX_HYSTERESIS_US;

	/*
	 * Bring the device up the same way aie4_classic_hw_start() does, minus the
	 * PCI-only firmware load: the RPU self-boots its CERT firmware, so there is
	 * no aie_smu/aie_psp step.  Create the mailbox + management channel, then run
	 * the shared aie4 handshake -- query_fw negotiates the feature set (this is
	 * what turns on AIE4_HSA_COMMAND that aie4_hwctx_init() requires), config_fw
	 * calibrates the clock and attaches the work buffer, and setup_aie brings up
	 * the AIE partition.
	 */
	ret = aie4_alloc_work_buffer(ndev);
	if (ret)
		return ret;

	ret = aie4_mailbox_init(ndev);
	if (ret)
		goto free_work_buf;

	ret = aie4_query_fw(ndev);
	if (ret)
		goto mbox_fini;

	/*
	 * Apply the mgmt (fw) feature table.  The PCI path negotiates this from a
	 * mailbox-info register block (aie4_mailbox_info()); the platform mailbox has
	 * no such block, so negotiate from the IDENTIFY firmware version queried
	 * above (xdna->fw_ver) instead -- otherwise fw_feature_tbl (FW log/trace,
	 * app-health, RW access, coredump, calibrate-clock) stays clear even though
	 * the firmware supports it.  Must run before config_fw(), whose clock
	 * calibration is gated on AIE4_CALIBRATE_CLOCK.
	 */
	ret = aie_check_protocol(&ndev->aie, xdna->fw_ver.major, xdna->fw_ver.minor);
	if (ret)
		goto mbox_fini;

	ret = aie4_plat_config_fw(ndev);
	if (ret)
		goto mbox_fini;

	ret = aie4_setup_aie(ndev);
	if (ret)
		goto suspend_fw;

	/*
	 * Shared post-bring-up init, mirroring the PCI aie4_xdna_init(): msg_init
	 * installs the status/telemetry/health/coredump handlers and the hwctx
	 * limit, dpt_init brings up firmware-log/DPT services, pm_init enables
	 * runtime PM, and vbnv_init publishes the device VBNV. dpt_init is
	 * best-effort (the PCI path ignores its return too).
	 */
	aie4_msg_init(ndev);
	amdxdna_dpt_init(&ndev->aie);
	amdxdna_pm_init(xdna);
	amdxdna_vbnv_init(xdna);

	return 0;

suspend_fw:
	/*
	 * config_fw already attached the DRAM work buffer to CERT.  Suspend the
	 * firmware while the mailbox is still up so CERT releases that DMA pointer
	 * (AIE4_MSG_OP_SUSPEND is the only op that does; there is no detach) before
	 * aie4_free_work_buffer() frees it -- otherwise the self-booted CERT can
	 * access freed memory.  Mirrors the aie4_plat_fini() teardown.
	 */
	aie4_suspend_fw(ndev);
mbox_fini:
	aie4_mailbox_fini(ndev);
free_work_buf:
	aie4_free_work_buffer(ndev);
	return ret;
}

static void aie4_plat_fini(struct amdxdna_dev *xdna)
{
	struct amdxdna_dev_hdl *ndev = xdna->dev_handle;

	/* Mirror the PCI aie4_xdna_fini(); dpt_fini needs the mailbox still up. */
	amdxdna_pm_fini(xdna);
	amdxdna_dpt_fini(&ndev->aie);
	aie4_partition_fini(ndev);

	/*
	 * Suspend the firmware while the mailbox is still alive, mirroring the PCI
	 * aie4_teardown_fw(): AIE4_MSG_OP_SUSPEND is the only op that makes CERT
	 * release the attached DRAM work buffer (there is no detach op), so it must
	 * precede aie4_mailbox_fini()/aie4_free_work_buffer(). Otherwise the
	 * self-booted CERT keeps the work-buffer DMA pointer and can access it after
	 * the host has freed it during platform-device removal.
	 */
	aie4_suspend_fw(ndev);

	aie4_mailbox_fini(ndev);
	/*
	 * Free the async pool after the mailbox is torn down so channel teardown
	 * cannot fire the async callback on freed event slots (see aie4_vf_hw_stop).
	 */
	amdxdna_async_events_free(&ndev->aie);
	aie4_free_work_buffer(ndev);

	mutex_destroy(&ndev->cert_comp_lock);
	xa_destroy(&ndev->cert_comp_xa);
}

static int aie4_plat_suspend(struct amdxdna_dev *xdna)
{
	struct amdxdna_dev_hdl *ndev = xdna->dev_handle;

	drm_WARN_ON(&xdna->ddev, !mutex_is_locked(&xdna->dev_lock));

	/* Unlike aie4_classic_suspend, there is no hw_stop: the mailbox stays up. */
	aie4_hwctx_suspend_all(ndev, false);

	return 0;
}

static int aie4_plat_resume(struct amdxdna_dev *xdna)
{
	struct amdxdna_dev_hdl *ndev = xdna->dev_handle;
	int ret;

	drm_WARN_ON(&xdna->ddev, !mutex_is_locked(&xdna->dev_lock));

	/* Unlike aie4_classic_resume, there is no hw_start: the mailbox stayed up. */
	ret = aie4_hwctx_resume_all(ndev);
	if (ret) {
		XDNA_ERR(xdna, "hwctx resume failed, %d", ret);
		aie4_hwctx_suspend_all(ndev, true);
	}

	return ret;
}

const struct amdxdna_dev_ops aie4_plat_ops = {
	.init			= aie4_plat_init,
	.fini			= aie4_plat_fini,
	.debugfs_init		= aie4_debugfs_init,
	.hwctx_init		= aie4_hwctx_init,
	.hwctx_fini		= aie4_hwctx_fini,
	.hwctx_config		= aie4_hwctx_config,
	.cmd_submit		= aie4_cmd_submit,
	.cmd_wait		= aie4_cmd_wait,
	.get_aie_info		= aie4_get_info,
	.set_aie_state		= aie4_set_state,
	.get_array		= aie4_get_array,
	.resume			= aie4_plat_resume,
	.suspend		= aie4_plat_suspend,
	.runtime_resume		= aie4_plat_resume,
	.runtime_suspend	= aie4_plat_suspend,
	.register_async_event	= aie4_async_event_register,
	.handle_dev_async_event	= aie4_handle_dev_event,
};

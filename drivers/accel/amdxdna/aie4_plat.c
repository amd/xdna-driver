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
 * NOTE: transport scaffolding.  The management mailbox channel, cert-completion
 * routing and the full bring-up/suspend/resume sequences are TODO; the hooks are
 * stubbed so aie4_ctx.c links and the device probes.  A platform mailbox and the
 * device-info register wiring land in follow-up changes.
 */

#include <drm/drm_managed.h>

#include "aie.h"
#include "aie4.h"
#include "aie4_plat.h"
#include "amdxdna_ctx.h"
#include "amdxdna_drv.h"

/*
 * Transport hooks (mirror the aie4_pci.c definitions).  The shared aie4_ctx.c
 * reaches the doorbell and the cert completion only through these; on the
 * platform build aie4_pci.c is not compiled, so they are defined here.
 */

/*
 * The platform doorbell has no per-ctx MMIO kick target, so there is nothing to
 * validate or store at setup time.  The transport-neutral connected sentinel is
 * owned by aie4_ctx.c.  TODO: platform shmem-ring kick keyed by hw_ctx_id.
 */
int aie4_doorbell_setup(struct amdxdna_hwctx *hwctx,
			const struct aie4_msg_create_hw_context_resp *resp)
{
	return 0;
}

void aie4_doorbell_ring(struct amdxdna_hwctx *hwctx)
{
	/* TODO: platform shmem-ring doorbell kick. */
}

/*
 * Completion notification on the platform arrives on a shared RX path, not a
 * per-cert MSI-X vector, so there is no per-cert irq to request/free.
 * TODO: route platform completions to cert_comp->waitq.
 */
int aie4_request_notification(struct cert_comp *comp)
{
	return 0;
}

void aie4_free_notification(struct cert_comp *comp)
{
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

static int aie4_plat_init(struct amdxdna_dev *xdna)
{
	struct amdxdna_dev_hdl *ndev;

	ndev = drmm_kzalloc(&xdna->ddev, sizeof(*ndev), GFP_KERNEL);
	if (!ndev)
		return -ENOMEM;

	ndev->aie.xdna = xdna;
	xdna->dev_handle = ndev;

	/*
	 * TODO: create the platform mgmt mailbox and run the shared aie4
	 * bring-up (aie4_query_fw/aie4_setup_aie plus the common DRM/context
	 * init), mirroring aie4_classic_init().
	 */
	return 0;
}

static void aie4_plat_fini(struct amdxdna_dev *xdna)
{
	/* TODO: aie4_partition_fini() + tear down the platform mgmt mailbox. */
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
};

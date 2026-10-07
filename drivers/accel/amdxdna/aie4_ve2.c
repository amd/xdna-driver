// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2026, Advanced Micro Devices, Inc.
 *
 * VE2 device ops for the shared aie4 core.
 *
 * Probe runs the shared aie4 version and geometry queries. Those opcodes are
 * carried out through the Xilinx AIE driver by amdxdna_mailbox_ve2.c. The
 * npu12 DRAM work-buffer attach is not used: VE2 CERT has no such buffer, and
 * that opcode stays unimplemented.
 *
 * The doorbell is not a ring and not an IPI. aie4_doorbell_ring() writes the
 * CERT user-event register through the AIE driver. Completion is the AIE
 * user-event callback waking cert_comp, so there is no MSI-X and no IPI to
 * request.
 */

#include <drm/drm_drv.h>
#include <drm/drm_managed.h>
#include <linux/xarray.h>

#include "aie4.h"
#include "aie4_ve2.h"
#include "amdxdna_ctx.h"
#include "amdxdna_dpt.h"
#include "amdxdna_drv.h"
#include "amdxdna_mailbox.h"
#include "amdxdna_pm.h"

int aie4_doorbell_setup(struct amdxdna_hwctx *hwctx,
			const struct aie4_msg_create_hw_context_resp *resp)
{
	return ve2_cert_bind(hwctx);
}

void aie4_doorbell_ring(struct amdxdna_hwctx *hwctx)
{
	struct amdxdna_dev *xdna = hwctx->client->xdna;
	int ret;

	ret = ve2_cert_kick(hwctx);
	if (ret)
		XDNA_ERR(xdna, "VE2 CERT kick failed, ret %d", ret);
}

int aie4_request_notification(struct cert_comp *comp)
{
	/*
	 * No interrupt to allocate. CREATE_PARTITION already registered the
	 * AIE user-event callback, and that callback wakes every cert_comp
	 * on the device. This runs before the comp is stored in the xarray,
	 * which is fine: the callback walks whatever is registered at event
	 * time.
	 */
	return 0;
}

void aie4_free_notification(struct cert_comp *comp)
{
}

bool aie4_is_vf(struct amdxdna_dev_hdl *ndev)
{
	return false;
}

int aie4_set_dpm(struct amdxdna_dev_hdl *ndev, u32 dpm_level)
{
	return 0;
}

void aie4_update_counters(struct amdxdna_dev_hdl *ndev)
{
}

static int ve2_mailbox_init(struct amdxdna_dev_hdl *ndev)
{
	struct amdxdna_dev *xdna = ndev->aie.xdna;
	int ret;

	ndev->mbox = xdnam_mailbox_create(&xdna->ddev, NULL);
	if (IS_ERR(ndev->mbox)) {
		ret = PTR_ERR(ndev->mbox);
		ndev->mbox = NULL;
		XDNA_ERR(xdna, "failed to create VE2 mailbox, ret %d", ret);
		return ret;
	}

	ndev->aie.mgmt_chann = xdna_mailbox_alloc_channel(ndev->mbox);
	if (!ndev->aie.mgmt_chann) {
		XDNA_ERR(xdna, "failed to alloc mailbox channel");
		return -ENODEV;
	}

	xdna_mailbox_set_async_cb(ndev->aie.mgmt_chann, ndev,
				  aie4_mgmt_async_event_handler);

	ret = xdna_mailbox_start_channel(ndev->aie.mgmt_chann, NULL, NULL, 0, 0, 0);
	if (ret) {
		xdna_mailbox_free_channel(ndev->aie.mgmt_chann);
		ndev->aie.mgmt_chann = NULL;
	}
	return ret;
}

static void ve2_mailbox_fini(struct amdxdna_dev_hdl *ndev)
{
	if (!ndev->aie.mgmt_chann)
		return;

	xdna_mailbox_stop_channel(ndev->aie.mgmt_chann);
	xdna_mailbox_free_channel(ndev->aie.mgmt_chann);
	ndev->aie.mgmt_chann = NULL;
}

static int aie4_ve2_init(struct amdxdna_dev *xdna)
{
	struct amdxdna_dev_hdl *ndev;
	int ret;

	ndev = drmm_kzalloc(&xdna->ddev, sizeof(*ndev), GFP_KERNEL);
	if (!ndev)
		return -ENOMEM;

	ndev->aie.xdna = xdna;
	xdna->dev_handle = ndev;
	ndev->kernel_submit = true;

	xa_init_flags(&ndev->cert_comp_xa, XA_FLAGS_ALLOC);
	mutex_init(&ndev->cert_comp_lock);

	ret = ve2_mailbox_init(ndev);
	if (ret)
		goto xa_fini;

	/*
	 * Same feature negotiation as the platform path: IDENTIFY plus the
	 * CERT version turn on AIE4_HSA_COMMAND, which aie4_hwctx_init()
	 * requires. Skip the platform work-buffer attach; that opcode is not
	 * implemented here and VE2 CERT does not use the buffer.
	 */
	ret = aie4_query_fw(ndev);
	if (ret)
		goto mbox_fini;

	ret = aie_check_protocol(&ndev->aie, xdna->fw_ver.major, xdna->fw_ver.minor);
	if (ret) {
		XDNA_ERR(xdna, "firmware %u.%u is not supported",
			 xdna->fw_ver.major, xdna->fw_ver.minor);
		goto mbox_fini;
	}

	ret = aie4_setup_aie(ndev);
	if (ret)
		goto mbox_fini;

	aie4_msg_init(ndev);
	amdxdna_dpt_init(&ndev->aie);
	amdxdna_pm_init(xdna);
	amdxdna_vbnv_init(xdna);
	return 0;

mbox_fini:
	ve2_mailbox_fini(ndev);
xa_fini:
	mutex_destroy(&ndev->cert_comp_lock);
	xa_destroy(&ndev->cert_comp_xa);
	return ret;
}

static void aie4_ve2_fini(struct amdxdna_dev *xdna)
{
	struct amdxdna_dev_hdl *ndev = xdna->dev_handle;

	if (!ndev)
		return;

	amdxdna_pm_fini(xdna);
	amdxdna_dpt_fini(&ndev->aie);
	ve2_mailbox_fini(ndev);
	ve2_mbox_release(ndev->mbox);
	amdxdna_async_events_free(&ndev->aie);
	mutex_destroy(&ndev->cert_comp_lock);
	xa_destroy(&ndev->cert_comp_xa);
}

static int aie4_ve2_suspend(struct amdxdna_dev *xdna)
{
	drm_WARN_ON(&xdna->ddev, !mutex_is_locked(&xdna->dev_lock));
	aie4_hwctx_suspend_all(xdna->dev_handle, false);
	return 0;
}

static int aie4_ve2_resume(struct amdxdna_dev *xdna)
{
	struct amdxdna_dev_hdl *ndev = xdna->dev_handle;
	int ret;

	drm_WARN_ON(&xdna->ddev, !mutex_is_locked(&xdna->dev_lock));

	ret = aie4_hwctx_resume_all(ndev);
	if (ret) {
		XDNA_ERR(xdna, "hwctx resume failed, %d", ret);
		aie4_hwctx_suspend_all(ndev, true);
	}
	return ret;
}

const struct amdxdna_dev_ops aie4_ve2_ops = {
	.init			= aie4_ve2_init,
	.fini			= aie4_ve2_fini,
	.debugfs_init		= aie4_debugfs_init,
	.hwctx_init		= aie4_hwctx_init,
	.hwctx_fini		= aie4_hwctx_fini,
	.hwctx_config		= aie4_hwctx_config,
	.cmd_submit		= aie4_cmd_submit,
	.cmd_wait		= aie4_cmd_wait,
	.get_aie_info		= aie4_get_info,
	.set_aie_state		= aie4_set_state,
	.get_array		= aie4_get_array,
	.resume			= aie4_ve2_resume,
	.suspend		= aie4_ve2_suspend,
	.runtime_resume		= aie4_ve2_resume,
	.runtime_suspend	= aie4_ve2_suspend,
};

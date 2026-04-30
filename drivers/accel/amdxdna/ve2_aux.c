// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2026, Advanced Micro Devices, Inc.
 *
 * VE2 auxiliary entry: `amdxdna_dev_info` / `ve2_ops`.  Firmware and AIE
 * partition bring-up live in ve2_hw.c.
 */

#include <linux/errno.h>
#include <linux/string.h>

#include "amdxdna_aux_drv.h"
#include "amdxdna_ctx.h"
#include "ve2_aux.h"
#include "ve2_ctx.h"
#include "ve2_hw.h"

const struct amdxdna_dev_priv ve2_aux_priv = {
	.fw_path	= "amdnpu/release_cert_ve2.elf",
};

const struct amdxdna_dev_info dev_ve2_info = {
	.device_type	= AMDXDNA_DEV_TYPE_KMQ,
	.dev_priv	= &ve2_aux_priv,
	.ops		= &ve2_ops,
};

static int ve2_init(struct amdxdna_dev *xdna)
{
	struct device *dev = xdna->ddev.dev;
	struct amdxdna_dev_hdl *xdna_hdl;
	int ret;

	XDNA_DBG(xdna, "Initializing VE2 device");

	xdna_hdl = devm_kzalloc(dev, sizeof(*xdna_hdl), GFP_KERNEL);
	if (!xdna_hdl)
		return -ENOMEM;

	xdna_hdl->xdna = xdna;
	xdna_hdl->ve2_priv = &ve2_aux_priv;
	xdna->dev_handle = xdna_hdl;

	ret = aie_get_device_info(&xdna_hdl->aie_dev_info);
	if (ret) {
		if (ret == -ENODEV) {
			XDNA_INFO(xdna, "AIE device not ready yet, deferring probe");
			return -EPROBE_DEFER;
		}
		XDNA_ERR(xdna, "Failed to get AIE device info, ret %d", ret);
		return ret;
	}
	XDNA_INFO(xdna, "AIE device: %d columns, %d rows",
		  xdna_hdl->aie_dev_info.cols, xdna_hdl->aie_dev_info.rows);

	ret = ve2_hw_load_cert_firmware(xdna_hdl);
	if (ret) {
		XDNA_ERR(xdna, "aie load %s failed with err %d", xdna_hdl->ve2_priv->fw_path, ret);
		return ret;
	}
	XDNA_DBG(xdna, "aie fw load %s completed", xdna_hdl->ve2_priv->fw_path);

	ret = ve2_hw_init_fw_status_slots(xdna, xdna_hdl);
	if (ret)
		return ret;

	return 0;
}

static void ve2_fini(struct amdxdna_dev *xdna)
{
	struct amdxdna_dev_hdl *hdl = ve2_dev_hdl(xdna);

	if (!hdl)
		return;

	XDNA_DBG(xdna, "VE2 device cleanup");
}

static int ve2_get_aie_info(struct amdxdna_client *client, struct amdxdna_drm_get_info *args)
{
	return -EOPNOTSUPP;
}

static int ve2_set_aie_state(struct amdxdna_client *client, struct amdxdna_drm_set_state *args)
{
	return -EOPNOTSUPP;
}

static int ve2_hwctx_sync_debug_bo(struct amdxdna_hwctx *hwctx, u32 debug_bo_hdl)
{
	return -EOPNOTSUPP;
}

static void ve2_hmm_invalidate(struct amdxdna_gem_obj *abo, unsigned long cur_seq)
{
}

static int ve2_cmd_submit(struct amdxdna_hwctx *hwctx, struct amdxdna_sched_job *job, u64 *seq)
{
	return ve2_hw_get_ops()->cmd_submit(hwctx, job, seq);
}

static int ve2_cmd_wait(struct amdxdna_hwctx *hwctx, u64 seq, u32 timeout_ms)
{
	return ve2_hw_get_ops()->cmd_wait(hwctx, seq, timeout_ms);
}

static int ve2_get_array(struct amdxdna_client *client, struct amdxdna_drm_get_array *args)
{
	return -EOPNOTSUPP;
}

const struct amdxdna_dev_ops ve2_ops = {
	.init			= ve2_init,
	.fini			= ve2_fini,
	.get_aie_info		= ve2_get_aie_info,
	.set_aie_state		= ve2_set_aie_state,
	.hwctx_init		= ve2_hwctx_init,
	.hwctx_fini		= ve2_hwctx_fini,
	.hwctx_config		= ve2_hwctx_config,
	.hwctx_sync_debug_bo	= ve2_hwctx_sync_debug_bo,
	.hmm_invalidate		= ve2_hmm_invalidate,
	.cmd_submit		= ve2_cmd_submit,
	.cmd_wait		= ve2_cmd_wait,
	.get_array		= ve2_get_array,
};

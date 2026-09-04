// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2026, Advanced Micro Devices, Inc.
 */

#include <drm/drm_drv.h>
#include <linux/cleanup.h>
#include <linux/debugfs.h>
#include <linux/limits.h>
#include <linux/mutex.h>

#include "aie.h"
#include "aie4.h"
#include "amdxdna_pci_drv.h"
#include "amdxdna_pm.h"

static int aie4_ctx_hysteresis_get(void *data, u64 *val)
{
	struct amdxdna_dev_hdl *ndev = data;
	struct amdxdna_dev *xdna = ndev->aie.xdna;

	guard(mutex)(&xdna->dev_lock);
	*val = ndev->ctx_switch_hysteresis_us;

	return 0;
}

static int aie4_ctx_hysteresis_set(void *data, u64 val)
{
	struct amdxdna_dev_hdl *ndev = data;
	struct amdxdna_dev *xdna = ndev->aie.xdna;
	int ret, idx;

	if (val > U32_MAX)
		return -EINVAL;

	if (!drm_dev_enter(&xdna->ddev, &idx))
		return -ENODEV;

	mutex_lock(&xdna->dev_lock);

	ret = amdxdna_pm_resume_get_locked(xdna);
	if (ret)
		goto unlock;

	ret = aie4_set_ctx_hysteresis(ndev, (u32)val);
	if (!ret)
		ndev->ctx_switch_hysteresis_us = (u32)val;

	amdxdna_pm_suspend_put(xdna);

unlock:
	mutex_unlock(&xdna->dev_lock);
	drm_dev_exit(idx);

	return ret;
}

/* Context switch hysteresis timeout in microseconds; 0 disables hysteresis. */
DEFINE_DEBUGFS_ATTRIBUTE(aie4_ctx_hysteresis_fops, aie4_ctx_hysteresis_get,
			 aie4_ctx_hysteresis_set, "%llu\n");

void aie4_debugfs_init(struct amdxdna_dev *xdna)
{
	struct amdxdna_dev_hdl *ndev = xdna->dev_handle;

	/*
	 * The platform transport has no SR-IOV PF/VF split: it always runs hw
	 * contexts and always programs the context switch hysteresis, so expose
	 * both knobs unconditionally.
	 * kernel_mode_submission: 0 - submit by user space, 1 - submit by driver.
	 */
	debugfs_create_bool("kernel_mode_submission", 0600,
			    xdna->ddev.accel->debugfs_root, &ndev->kernel_submit);

	debugfs_create_file_unsafe("ctx_switch_hysteresis_us", 0600,
				   xdna->ddev.accel->debugfs_root, ndev,
				   &aie4_ctx_hysteresis_fops);
}

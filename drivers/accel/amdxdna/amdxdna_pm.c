// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2025, Advanced Micro Devices, Inc.
 */

#include "drm/amdxdna_accel.h"
#include <drm/drm_drv.h>
#include <linux/pm_runtime.h>

#include "amdxdna_dpt.h"
#include "amdxdna_pm.h"

#define AMDXDNA_AUTOSUSPEND_DELAY	5000 /* milliseconds */

int amdxdna_pm_suspend(struct device *dev)
{
	struct amdxdna_dev *xdna = to_xdna_dev(dev_get_drvdata(dev));
	int ret = -EOPNOTSUPP;

	guard(mutex)(&xdna->dev_lock);
	if (xdna->dev_info->ops->suspend)
		ret = xdna->dev_info->ops->suspend(xdna);

	/*
	 * Drain and pause firmware DPT (log/trace) after the device has
	 * quiesced. Common to every generation/config; a safe no-op when no
	 * DPT kind is active. A drain/pause failure must not change the
	 * device suspend result (logging/tracing is auxiliary), but surface
	 * it so it is visible rather than silently swallowed.
	 */
#ifndef AMDXDNA_AUX
	if (!ret) {
		int dpt_ret = amdxdna_dpt_suspend(xdna);

		if (dpt_ret)
			XDNA_WARN(xdna, "DPT drain/pause on suspend failed: %d", dpt_ret);
	}
#endif

	XDNA_DBG(xdna, "Suspend done ret %d", ret);
	return ret;
}

int amdxdna_pm_resume(struct device *dev)
{
	struct amdxdna_dev *xdna = to_xdna_dev(dev_get_drvdata(dev));
	int ret = -EOPNOTSUPP;

	guard(mutex)(&xdna->dev_lock);
	if (xdna->dev_info->ops->resume)
		ret = xdna->dev_info->ops->resume(xdna);

	/*
	 * Re-arm firmware DPT only after a successful device resume. A DPT
	 * re-arm failure must not fail the device resume (logging/tracing is
	 * auxiliary), but surface it so it is visible in the resume logs
	 * rather than silently leaving DPT paused.
	 */
#ifndef AMDXDNA_AUX
	if (!ret) {
		int dpt_ret = amdxdna_dpt_resume(xdna);

		if (dpt_ret)
			XDNA_WARN(xdna, "DPT re-arm on resume failed: %d", dpt_ret);
	}
#endif

	XDNA_DBG(xdna, "Resume done ret %d", ret);
	return ret;
}

int amdxdna_pm_resume_get(struct amdxdna_dev *xdna)
{
	struct device *dev = xdna->ddev.dev;
	int ret;

	if (!pm_runtime_enabled(dev))
		return 0;

	ret = pm_runtime_resume_and_get(dev);
	if (ret) {
		XDNA_ERR(xdna, "Resume failed: %d", ret);
		pm_runtime_set_suspended(dev);
	}

	return ret;
}

void amdxdna_pm_suspend_put(struct amdxdna_dev *xdna)
{
	struct device *dev = xdna->ddev.dev;

	if (!pm_runtime_enabled(dev))
		return;

	pm_runtime_mark_last_busy(dev);
	pm_runtime_put_autosuspend(dev);
}

void amdxdna_pm_init(struct amdxdna_dev *xdna)
{
	struct device *dev = xdna->ddev.dev;

	pm_runtime_set_active(dev);
	pm_runtime_set_autosuspend_delay(dev, AMDXDNA_AUTOSUSPEND_DELAY);
	pm_runtime_use_autosuspend(dev);
	pm_runtime_allow(dev);
	pm_runtime_mark_last_busy(dev);
	pm_runtime_put_autosuspend(dev);
}

void amdxdna_pm_fini(struct amdxdna_dev *xdna)
{
	struct device *dev = xdna->ddev.dev;

	pm_runtime_get_noresume(dev);
	pm_runtime_forbid(dev);
}

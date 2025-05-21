// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2025, Advanced Micro Devices, Inc.
 */

#include <linux/pm_runtime.h>

#include "amdxdna_drm.h"
#include "amdxdna_pm.h"

int autosuspend_ms = 5000;
module_param(autosuspend_ms, int, 0644);
MODULE_PARM_DESC(autosuspend_ms, "runtime suspend delay in miliseconds. < 0: prevent it");

static int amdxdna_pmops_suspend(struct device *dev)
{
	struct amdxdna_dev *xdna = to_xdna_dev(dev_get_drvdata(dev));

	if (xdna->dev_info->ops->suspend)
		xdna->dev_info->ops->suspend(xdna);

	return 0;
}

static int amdxdna_pmops_resume(struct device *dev)
{
	struct amdxdna_dev *xdna = to_xdna_dev(dev_get_drvdata(dev));
	int ret = 0;

	if (xdna->dev_info->ops->resume)
		ret = xdna->dev_info->ops->resume(xdna);

	XDNA_DBG(xdna, "Resume done ret: %d", ret);
	return ret;
}

static int amdxdna_rpmops_suspend(struct device *dev)
{
	struct amdxdna_dev *xdna = to_xdna_dev(dev_get_drvdata(dev));

	if (xdna->dev_info->ops->suspend)
		xdna->dev_info->ops->suspend(xdna);

	XDNA_DBG(xdna, "Runtime suspend done");
	return 0;
}

static int amdxdna_rpmops_resume(struct device *dev)
{
	struct amdxdna_dev *xdna = to_xdna_dev(dev_get_drvdata(dev));
	int ret = 0;

	if (xdna->dev_info->ops->resume)
		ret = xdna->dev_info->ops->resume(xdna);

	XDNA_DBG(xdna, "Runtime resume done ret: %d", ret);
	return ret;
}

int amdxdna_pm_resume_get(struct device *dev)
{
#ifdef AMDXDNA_OF
	return 0;
#else
	return pm_runtime_resume_and_get(dev);
#endif
}

void amdxdna_pm_suspend_put(struct device *dev)
{
#ifndef AMDXDNA_OF
	pm_runtime_mark_last_busy(dev);
	pm_runtime_put_autosuspend(dev);
#endif
}

void amdxdna_pm_init(struct device *dev)
{
	pm_runtime_set_autosuspend_delay(dev, autosuspend_ms);
	pm_runtime_use_autosuspend(dev);
	pm_runtime_allow(dev);
	pm_runtime_mark_last_busy(dev);
	pm_runtime_put_autosuspend(dev);
}

void amdxdna_pm_fini(struct device *dev)
{
	pm_runtime_get_noresume(dev);
	pm_runtime_forbid(dev);
}

const struct dev_pm_ops amdxdna_pm_ops = {
	SET_SYSTEM_SLEEP_PM_OPS(amdxdna_pmops_suspend, amdxdna_pmops_resume)
	SET_RUNTIME_PM_OPS(amdxdna_rpmops_suspend, amdxdna_rpmops_resume, NULL)
};

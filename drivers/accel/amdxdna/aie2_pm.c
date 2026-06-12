// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2024-2026, Advanced Micro Devices, Inc.
 */

#include "drm/amdxdna_accel.h"
#include <drm/drm_device.h>
#include <drm/drm_print.h>
#include <drm/gpu_scheduler.h>
#include <linux/iopoll.h>

#include "aie2_pci.h"
#include "amdxdna_pci_drv.h"
#include "amdxdna_pm.h"
#include "amdxdna_sensors.h"

#define AIE2_CLK_GATING_ENABLE	1
#define AIE2_CLK_GATING_DISABLE	0

/* Allow the NPU clock to ramp to a power-override DPM level before returning. */
#define AIE2_DPM_SETTLE_TIMEOUT_US	2000000
#define AIE2_DPM_SETTLE_INTERVAL_US	1000

/*
 * Setting a DPM level via the SMU only defines the allowed clock range; the
 * actual NPU clock is demand-driven and ramps to the requested level over
 * time. For an explicit power-mode override the caller expects the requested
 * performance to be in effect on return, so poll until PMF telemetry reports
 * the MP-NPU clock has reached the target.
 *
 * Only the ramp-up direction is waited on: a downclocking override (e.g. to
 * LOW) is an explicit request for lower performance and has nothing to settle.
 *
 * PMF NPU telemetry is only available on kernels with amd-pmf support (>= 7.0);
 * amdxdna_get_sensors() returns an error otherwise, in which case the wait is
 * skipped. The wait is bounded by a timeout.
 */
static void aie2_pm_wait_for_dpm(struct amdxdna_dev_hdl *ndev, u32 dpm_level)
{
	struct amdxdna_sensors npu_metrics;
	int err, ret;
	u32 target;

	/* Telemetry can plateau just below the table value; accept within ~5%. */
	target = ndev->priv->dpm_clk_tbl[dpm_level].npuclk;
	target -= target / 20;

	ret = read_poll_timeout(amdxdna_get_sensors, err,
				err || npu_metrics.mpnpuclk_freq >= target,
				AIE2_DPM_SETTLE_INTERVAL_US,
				AIE2_DPM_SETTLE_TIMEOUT_US, false, &npu_metrics);

	if (err) {
		if (err != -EOPNOTSUPP)
			XDNA_DBG(ndev->aie.xdna, "PMF sensor read failed (%d), skip DPM wait", err);
		return;
	}

	if (ret)
		XDNA_WARN(ndev->aie.xdna,
			  "Timed out waiting for MP-NPU clock %u, got %u",
			  target, npu_metrics.mpnpuclk_freq);
}

static int aie2_pm_set_clk_gating(struct amdxdna_dev_hdl *ndev, u32 val)
{
	int ret;

	ret = aie2_runtime_cfg(ndev, AIE2_RT_CFG_CLK_GATING, &val);
	if (ret)
		return ret;

	ndev->aie.clk_gating = val;
	return 0;
}

int aie2_pm_set_dpm(struct amdxdna_dev_hdl *ndev, u32 dpm_level)
{
	int ret;

	ret = amdxdna_pm_resume_get_locked(ndev->aie.xdna);
	if (ret)
		return ret;

	ret = ndev->priv->hw_ops->set_dpm(&ndev->aie, dpm_level);
	if (!ret)
		ndev->dpm_level = dpm_level;
	amdxdna_pm_suspend_put(ndev->aie.xdna);

	return ret;
}

int aie2_pm_start(struct amdxdna_dev_hdl *ndev)
{
	int ret;

	if (ndev->dev_status != AIE2_DEV_UNINIT) {
		/* Resume device */
		ret = ndev->priv->hw_ops->set_dpm(&ndev->aie, ndev->dpm_level);
		if (ret)
			return ret;

		ret = aie2_pm_set_clk_gating(ndev, ndev->aie.clk_gating);
		if (ret)
			return ret;

		return 0;
	}

	while (ndev->priv->dpm_clk_tbl[ndev->max_dpm_level].hclk)
		ndev->max_dpm_level++;
	ndev->max_dpm_level--;

	/* Boot at the lowest DPM level. The first context raises it. */
	ret = ndev->priv->hw_ops->set_dpm(&ndev->aie, 0);
	if (ret)
		return ret;
	ndev->dpm_level = 0;

	ret = aie2_pm_set_clk_gating(ndev, AIE2_CLK_GATING_ENABLE);
	if (ret)
		return ret;

	ndev->pw_mode = POWER_MODE_DEFAULT;
	ndev->dft_dpm_level = 0;

	return 0;
}

int aie2_pm_set_mode(struct amdxdna_dev_hdl *ndev, enum amdxdna_power_mode_type target)
{
	struct amdxdna_dev *xdna = ndev->aie.xdna;
	u32 clk_gating, dpm_level;
	int ret;

	drm_WARN_ON(&xdna->ddev, !mutex_is_locked(&xdna->dev_lock));

	if (ndev->pw_mode == target)
		return 0;

	switch (target) {
	case POWER_MODE_TURBO:
		clk_gating = AIE2_CLK_GATING_DISABLE;
		dpm_level = ndev->max_dpm_level;
		break;
	case POWER_MODE_HIGH:
		clk_gating = AIE2_CLK_GATING_ENABLE;
		dpm_level = ndev->max_dpm_level;
		break;
	case POWER_MODE_DEFAULT:
		clk_gating = AIE2_CLK_GATING_ENABLE;
		dpm_level = ndev->dft_dpm_level;
		break;
	case POWER_MODE_LOW:
		clk_gating = AIE2_CLK_GATING_ENABLE;
		dpm_level = 0;
		break;
	case POWER_MODE_MEDIUM:
		clk_gating = AIE2_CLK_GATING_ENABLE;
		dpm_level = ndev->max_dpm_level / 2;
		break;
	default:
		return -EOPNOTSUPP;
	}

	ret = aie2_pm_set_dpm(ndev, dpm_level);
	if (ret)
		return ret;

	/*
	 * For an explicit power override, wait for the clock to actually reach
	 * the requested level so the next workload runs at the intended
	 * frequency instead of during the ramp.
	 */
	if (target != POWER_MODE_DEFAULT)
		aie2_pm_wait_for_dpm(ndev, dpm_level);

	ret = aie2_pm_set_clk_gating(ndev, clk_gating);
	if (ret)
		return ret;

	ndev->pw_mode = target;

	return 0;
}

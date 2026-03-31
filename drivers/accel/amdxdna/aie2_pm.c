// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2024-2026, Advanced Micro Devices, Inc.
 */

#include "drm/amdxdna_accel.h"
#include <drm/drm_device.h>
#include <drm/drm_managed.h>
#include <drm/drm_print.h>
#include <drm/gpu_scheduler.h>

#include "aie2_pci.h"
#include "aie2_solver.h"
#include "amdxdna_pci_drv.h"
#include "amdxdna_pm.h"

#define AIE2_CLK_GATING_ENABLE	1
#define AIE2_CLK_GATING_DISABLE	0

static int aie2_pm_set_clk_gating(struct amdxdna_dev_hdl *ndev, u32 val)
{
	int ret;

	ret = aie2_runtime_cfg(ndev, AIE2_RT_CFG_CLK_GATING, &val);
	if (ret)
		return ret;

	ndev->clk_gating = val;
	return 0;
}

int aie2_pm_set_dpm(struct amdxdna_dev_hdl *ndev, u32 dpm_level)
{
	int ret;

	ret = amdxdna_pm_resume_get_locked(ndev->aie.xdna);
	if (ret)
		return ret;

	ret = ndev->priv->hw_ops->set_dpm(ndev, dpm_level);
	if (!ret)
		ndev->dpm_level = dpm_level;
	amdxdna_pm_suspend_put(ndev->aie.xdna);

	return ret;
}

void aie2_pm_update_dpm_ref(struct amdxdna_dev_hdl *ndev, u32 level, bool add)
{
	struct amdxdna_dev *xdna = ndev->aie.xdna;
	int i;

	drm_WARN_ON(&xdna->ddev, !mutex_is_locked(&xdna->dev_lock));

	if (drm_WARN_ON(&xdna->ddev, level > ndev->max_dpm_level))
		level = ndev->max_dpm_level;

	if (add) {
		ndev->dpm_refcnt[level]++;
	} else {
		if (drm_WARN_ON(&xdna->ddev, !ndev->dpm_refcnt[level]))
			return;
		ndev->dpm_refcnt[level]--;
	}

	/* Find highest DPM level in use */
	level = 0;
	for (i = ndev->max_dpm_level; i >= 0; i--) {
		if (ndev->dpm_refcnt[i]) {
			level = i;
			break;
		}
	}

	ndev->dft_dpm_level = level;

	if (ndev->pw_mode != POWER_MODE_DEFAULT || ndev->dev_status != AIE2_DEV_START)
		return;

	if (ndev->priv->hw_ops->set_dpm(ndev, level))
		XDNA_ERR(xdna, "Set DPM level %d failed", level);
	else
		ndev->dpm_level = level;
}

u32 aie2_pm_calc_dpm_level(struct amdxdna_dev_hdl *ndev, u32 opc,
			   struct amdxdna_qos_info *qos)
{
	struct aie_qos rqos = { .gops = qos->gops, .fps = qos->fps,
				.latency = qos->latency };
	u32 req_gops, level;

	if (!xrs_is_valid_dpm_qos(&rqos))
		return ndev->max_dpm_level;

	req_gops = xrs_calculate_gops(&rqos);
	if (!req_gops)
		return ndev->max_dpm_level;

	for (level = 0; level <= ndev->max_dpm_level; level++) {
		if (req_gops <= opc * ndev->priv->dpm_clk_tbl[level].hclk / 1000)
			return level;
	}

	return ndev->max_dpm_level;
}

int aie2_pm_init(struct amdxdna_dev_hdl *ndev)
{
	int ret;

	if (ndev->dev_status != AIE2_DEV_UNINIT) {
		/* Resume device */
		ret = ndev->priv->hw_ops->set_dpm(ndev, ndev->dpm_level);
		if (ret)
			return ret;

		ret = aie2_pm_set_clk_gating(ndev, ndev->clk_gating);
		if (ret)
			return ret;

		return 0;
	}

	while (ndev->priv->dpm_clk_tbl[ndev->max_dpm_level].hclk)
		ndev->max_dpm_level++;

	ndev->dpm_refcnt = drmm_kcalloc(&ndev->aie.xdna->ddev,
					ndev->max_dpm_level, sizeof(u32),
					GFP_KERNEL);
	if (!ndev->dpm_refcnt)
		return -ENOMEM;

	ndev->max_dpm_level--;

	ret = ndev->priv->hw_ops->set_dpm(ndev, ndev->max_dpm_level);
	if (ret)
		return ret;
	ndev->dpm_level = ndev->max_dpm_level;

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

	ret = aie2_pm_set_clk_gating(ndev, clk_gating);
	if (ret)
		return ret;

	ndev->pw_mode = target;

	return 0;
}

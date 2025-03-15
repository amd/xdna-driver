// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2024-2025, Advanced Micro Devices, Inc.
 */

#include "aie2_pci.h"

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

int aie2_pm_init(struct amdxdna_dev_hdl *ndev)
{
	struct amdxdna_dev *xdna = ndev->xdna;
	int ret;

	drm_WARN_ON(&xdna->ddev, !mutex_is_locked(&ndev->aie2_lock));
	if (ndev->dev_status != AIE2_DEV_UNINIT) {
		/* Resume device */
		ret = ndev->priv->hw_ops.set_dpm(ndev, ndev->dpm_level);
		if (ret)
			return ret;

		ret = aie2_pm_set_clk_gating(ndev, ndev->clk_gating);
		if (ret)
			return ret;

		return 0;
	}

	while (ndev->priv->dpm_clk_tbl[ndev->max_dpm_level].hclk)
		ndev->max_dpm_level++;
	ndev->max_dpm_level--;

	ret = ndev->priv->hw_ops.set_dpm(ndev, ndev->max_dpm_level);
	if (ret)
		return ret;

	ret = aie2_pm_set_clk_gating(ndev, AIE2_CLK_GATING_ENABLE);
	if (ret)
		return ret;

	ndev->pw_mode = POWER_MODE_DEFAULT;
	ndev->dft_dpm_level = ndev->max_dpm_level;

	return 0;
}

void aie2_pm_fini(struct amdxdna_dev_hdl *ndev)
{
	drm_WARN_ON(&xdna->ddev, !mutex_is_locked(&ndev->aie2_lock));

	if(aie2_pm_set_mode(ndev, POWER_MODE_LOW))
		XDNA_ERR(ndev->xdna, "Can not set to lowest power mode");
}

int aie2_pm_set_mode(struct amdxdna_dev_hdl *ndev, int target)
{
	struct amdxdna_dev *xdna = ndev->xdna;
	u32 clk_gating, dpm_level;
	int ret;

	drm_WARN_ON(&xdna->ddev, !mutex_is_locked(&ndev->aie2_lock));

	if (ndev->pw_mode == target)
		return 0;

	switch (target) {
	case POWER_MODE_TURBO:
		if (ndev->hwctx_cnt) {
			XDNA_ERR(xdna, "Can not set turbo when there is active ctx");
			return -EINVAL;
		}

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
	case POWER_MODE_MEDIUM:
		clk_gating = AIE2_CLK_GATING_ENABLE;
		dpm_level = min(ndev->max_dpm_level, 5);
		break;
	case POWER_MODE_LOW:
		clk_gating = AIE2_CLK_GATING_ENABLE;
		dpm_level = 0;
		break;
	default:
		return -EOPNOTSUPP;
	}

	ret = ndev->priv->hw_ops.set_dpm(ndev, dpm_level);
	if (ret)
		return ret;

	ret = aie2_pm_set_clk_gating(ndev, clk_gating);
	if (ret)
		return ret;

	ndev->pw_mode = target;

	return 0;
}

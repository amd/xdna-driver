// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2024-2025, Advanced Micro Devices, Inc.
 */

#include <drm/drm_managed.h>
#include "aie2_pci.h"

#define DEFAULT_SYS_EFF_FACTOR 2
uint sys_eff_factor = DEFAULT_SYS_EFF_FACTOR;
module_param(sys_eff_factor, int, 0444);
MODULE_PARM_DESC(sys_eff_factor, "System efficiency factor, default 2");

#define AIE2_CLK_GATING_ENABLE	1
#define AIE2_CLK_GATING_DISABLE	0

static int pm_set_clk_gating(struct amdxdna_dev_hdl *ndev, u32 val)
{
	int ret;

	ret = aie2_runtime_cfg(ndev, AIE2_RT_CFG_CLK_GATING, &val);
	if (ret)
		return ret;

	ndev->clk_gating = val;
	return 0;
}

static int pm_set_mode(struct amdxdna_dev_hdl *ndev, int target, bool cache_pw_mode)
{
	struct amdxdna_dev *xdna = ndev->xdna;
	u32 clk_gating, dpm_level;
	int ret;

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
		dpm_level = min(ndev->max_dpm_level, 3);
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

	ret = pm_set_clk_gating(ndev, clk_gating);
	if (ret)
		return ret;

	if (cache_pw_mode)
		ndev->pw_mode = target;

	return 0;
}

int aie2_pm_set_mode(struct amdxdna_dev_hdl *ndev, int target)
{
	struct amdxdna_dev *xdna = ndev->xdna;

	drm_WARN_ON(&xdna->ddev, !mutex_is_locked(&ndev->aie2_lock));

	if (ndev->pw_mode == target)
		return 0;

	return pm_set_mode(ndev, target, true);
}

void aie2_pm_set_dft_dpm_level(struct amdxdna_dev_hdl *ndev, u32 level, bool add)
{
	struct amdxdna_dev *xdna = ndev->xdna;

	XDNA_DBG(xdna, "Default DPM %d, %s level %d", ndev->dft_dpm_level,
		 add ? "add" : "delete", level);

	mutex_lock(&ndev->aie2_lock);
	if (unlikely(level > ndev->max_dpm_level)) {
		level = ndev->max_dpm_level;
		WARN_ON(1);
	}

	if (add) {
		/* Add DPM level count */
		ndev->dpm_cnt[level]++;
	} else {
		/* Delete DPM level count */
		WARN_ON(level > ndev->dft_dpm_level);
		WARN_ON(!ndev->dpm_cnt[level]);
		ndev->dpm_cnt[level]--;
	}

	for (level = ndev->max_dpm_level; level > 0; level--)
		if (ndev->dpm_cnt[level])
			break;

	XDNA_DBG(xdna, "Set default DPM to %d", level);
	if (ndev->pw_mode == POWER_MODE_DEFAULT && ndev->dev_status == AIE2_DEV_START)
		ndev->priv->hw_ops.set_dpm(ndev, level);
	ndev->dft_dpm_level = level;

	mutex_unlock(&ndev->aie2_lock);
}

int aie2_pm_init(struct amdxdna_dev_hdl *ndev)
{
	struct amdxdna_dev *xdna = ndev->xdna;
	int ret;

	drm_WARN_ON(&xdna->ddev, !mutex_is_locked(&ndev->aie2_lock));
	if (ndev->dev_status != AIE2_DEV_UNINIT) {
		/* Resume device */
		ret = pm_set_mode(ndev, ndev->pw_mode, true);
		if (ret)
			return ret;

		return 0;
	}

	while (ndev->priv->dpm_clk_tbl[ndev->max_dpm_level].hclk)
		ndev->max_dpm_level++;
	ndev->dpm_cnt = drmm_kzalloc(&xdna->ddev, ndev->max_dpm_level * sizeof(u32), GFP_KERNEL);
	if (!ndev->dpm_cnt)
		return -ENOMEM;
	ndev->max_dpm_level--;

	ret = ndev->priv->hw_ops.set_dpm(ndev, ndev->max_dpm_level);
	if (ret)
		return ret;

	ret = pm_set_clk_gating(ndev, AIE2_CLK_GATING_ENABLE);
	if (ret)
		return ret;

	ndev->pw_mode = POWER_MODE_DEFAULT;
	ndev->dft_dpm_level = 0; // Start with lowest DPM level
	ndev->sys_eff_factor = sys_eff_factor;
	if (!ndev->sys_eff_factor)
		ndev->sys_eff_factor = DEFAULT_SYS_EFF_FACTOR;

	return 0;
}

void aie2_pm_fini(struct amdxdna_dev_hdl *ndev)
{
	struct amdxdna_dev *xdna = ndev->xdna;

	drm_WARN_ON(&xdna->ddev, !mutex_is_locked(&ndev->aie2_lock));

	if (pm_set_mode(ndev, POWER_MODE_DEFAULT, false))
		XDNA_ERR(ndev->xdna, "Can not set to default power mode");
}

int npu1_get_tops(struct amdxdna_dev_hdl *ndev, u64 *max, u64 *curr)
{
	u64 total_col, hclk_freq;

	total_col = ndev->total_col;
	hclk_freq = ndev->hclk_freq;
	*max = 2 * total_col;
	*curr = (*max * hclk_freq) / 1028;

	return 0;
}

int npu4_get_tops(struct amdxdna_dev_hdl *ndev, u64 *max, u64 *curr)
{
	const struct amdxdna_dev_priv *priv = ndev->priv;
	u64 total_col, hclk_freq, topc;

	total_col = ndev->total_col;
	hclk_freq = ndev->hclk_freq;
	topc = 4096 * total_col;
	*max = (topc * priv->dpm_clk_tbl[ndev->max_dpm_level].hclk) / 1000000;
	*curr = (topc * hclk_freq) / 1000000;

	return 0;
}

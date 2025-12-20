// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2024-2025, Advanced Micro Devices, Inc.
 */

#include "aie4_pci.h"

static int aie4_pm_set_clock_gating(struct amdxdna_dev_hdl *ndev, bool enable)
{
	const struct rt_config_clk_gating *config;
	u32 value;
	int ret;

	if (enable == ndev->clk_gate_enabled)
		return 0;

	config = &ndev->priv->clk_gating;
	if (enable)
		value = config->value_enable;
	else
		value = config->value_disable;

	XDNA_DBG(ndev->xdna, "%s clock gating, %d type(s)",
		 (enable) ? "Enable" : "Disable", config->num_types);

	/* TODO: clock gating operations on par with aie2 */
	if (!ret)
		ndev->clk_gate_enabled = enable;

	return ret;
}

bool aie4_pm_is_turbo(struct amdxdna_dev_hdl *ndev)
{
	return ndev->pw_mode == POWER_MODE_TURBO;
}

static int aie4_pm_check_turbo(struct amdxdna_dev_hdl *ndev,
			       int prev, int next)
{
	struct amdxdna_dev *xdna = ndev->xdna;
	struct amdxdna_client *client;

	if (prev != POWER_MODE_TURBO && next != POWER_MODE_TURBO)
		return 0;

	drm_WARN_ON(&xdna->ddev, !mutex_is_locked(&xdna->dev_lock));
	list_for_each_entry(client, &xdna->client_list, node) {
		bool empty;

		empty = amdxdna_no_ctx(client);
		if (!empty)
			return -EBUSY;
	}
	return 0;
}

int aie4_pm_set_mode(struct amdxdna_dev_hdl *ndev, int target)
{
	struct amdxdna_dev *xdna = ndev->xdna;
	int ret = 0;

	if (ndev->pw_mode == target)
		return 0;

	XDNA_DBG(xdna, "Changing power mode from %d to %d", ndev->pw_mode, target);

	switch (target) {
	case POWER_MODE_TURBO: // Turbo mode
		ret = aie4_pm_check_turbo(ndev, ndev->pw_mode, target);
		if (ret)
			break;
		ret = aie4_pm_set_clock_gating(ndev, false);
		break;
	case POWER_MODE_HIGH: // Performance mode
		ret = aie4_pm_set_clock_gating(ndev, true);
		break;
	case POWER_MODE_DEFAULT: // Default mode
		ret = aie4_pm_set_clock_gating(ndev, true);
		// Revert back to default level, let resolver decide level
		break;
	case POWER_MODE_MEDIUM: // Balanced mode
		ret = aie4_pm_set_clock_gating(ndev, true);
		break;
	case POWER_MODE_LOW: // Powersaver mode
		ret = aie4_pm_set_clock_gating(ndev, true);
		break;
	default:
		ret = -EOPNOTSUPP;
		break;
	}
	if (ret) {
		/* Either nothing was done or messed up, can't recover. */
		XDNA_ERR(xdna, "Failed to set power mode: %d, ret %d", target, ret);
		return ret;
	}

	ret = aie4_set_pm_msg(ndev, target);
	if (ret) {
		/* FW pmode set error */
		XDNA_ERR(xdna, "Set power mode msg failed, status %d", ret);
		return ret;
	}

	ndev->pw_mode = target;
	XDNA_INFO(xdna, "Power mode changed to %d", ndev->pw_mode);
	return 0;
}

int aie4_pm_init(struct amdxdna_dev_hdl *ndev)
{
	return aie4_pm_set_mode(ndev, ndev->pw_mode);
}

void aie4_pm_fini(struct amdxdna_dev_hdl *ndev)
{
	struct amdxdna_dev *xdna = ndev->xdna;

	drm_WARN_ON(&xdna->ddev, !mutex_is_locked(&ndev->aie4_lock));

	aie4_pm_set_mode(ndev, POWER_MODE_DEFAULT);
}

int aie4_get_tops(struct amdxdna_dev_hdl *ndev, u64 *max, u64 *curr)
{
	u64 total_col, hclk_freq;

	total_col = ndev->total_col;
	hclk_freq = ndev->h_clock.freq_mhz;
	*max = 2 * total_col;
	*curr = (*max * hclk_freq) / 1028;

	return 0;
}

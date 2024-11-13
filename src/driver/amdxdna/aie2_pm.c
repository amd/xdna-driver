// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2024, Advanced Micro Devices, Inc.
 */

#include "aie2_pci.h"

static int aie2_pm_set_clock_gating(struct amdxdna_dev_hdl *ndev, bool enable)
{
	const struct rt_config_clk_gating *config;
	u32 value;
	int ret;
	int i;

	if (enable == ndev->clk_gate_enabled)
		return 0;

	config = &ndev->priv->clk_gating;
	if (enable)
		value = config->value_enable;
	else
		value = config->value_disable;

	XDNA_DBG(ndev->xdna, "%s clock gating, %d type(s)",
		 (enable) ? "Enable" : "Disable", config->num_types);

	for (i = 0; i < config->num_types; i++) {
		ret = aie2_set_runtime_cfg(ndev, config->types[i], value);
		if (ret) {
			XDNA_ERR(ndev->xdna, "Config type %d, value %d",
				 config->types[i], value);
			break;
		}
	}

	if (!ret)
		ndev->clk_gate_enabled = enable;

	return ret;
}

bool aie2_pm_is_turbo(struct amdxdna_dev_hdl *ndev)
{
	return ndev->pw_mode == POWER_MODE_TURBO;
}

static int aie2_pm_check_turbo(struct amdxdna_dev_hdl *ndev,
			       enum amdxdna_power_mode_type prev,
			       enum amdxdna_power_mode_type next)
{
	struct amdxdna_dev *xdna = ndev->xdna;
	struct amdxdna_client *client;

	if (prev != POWER_MODE_TURBO && next != POWER_MODE_TURBO)
		return 0;

	drm_WARN_ON(&xdna->ddev, !mutex_is_locked(&xdna->dev_lock));
	list_for_each_entry(client, &xdna->client_list, node) {
		bool empty;

		mutex_lock(&client->hwctx_lock);
		empty = amdxdna_no_hwctx(client);
		mutex_unlock(&client->hwctx_lock);
		if (!empty)
			return -EBUSY;
	}
	return 0;
}

int aie2_pm_set_mode(struct amdxdna_dev_hdl *ndev, enum amdxdna_power_mode_type target)
{
	struct amdxdna_dev *xdna = ndev->xdna;
	int ret = 0;

	if (ndev->pw_mode == target)
		return 0;

	XDNA_DBG(xdna, "Changing power mode from %d to %d", ndev->pw_mode, target);

	switch (target) {
	case POWER_MODE_TURBO: // Turbo mode
		ret = aie2_pm_check_turbo(ndev, ndev->pw_mode, target);
		if (ret)
			break;
		ret = aie2_pm_set_clock_gating(ndev, false);
		if (ret)
			break;
		ret = aie2_smu_set_fixed_dpm_level(ndev, SMU_DPM_MAX(ndev));
		break;
	case POWER_MODE_HIGH: // Performance mode
		ret = aie2_pm_set_clock_gating(ndev, true);
		if (ret)
			break;
		ret = aie2_smu_set_fixed_dpm_level(ndev, SMU_DPM_MAX(ndev));
		break;
	case POWER_MODE_DEFAULT: // Default mode
		ret = aie2_pm_set_clock_gating(ndev, true);
		if (ret)
			break;
		// Revert back to default level, let resolver decide level
		ret = aie2_smu_set_fixed_dpm_level(ndev, SMU_DPM_INVALID);
		break;
	default:
		// POWER_MODE_LOW and POWER_MODE_MEDIUM
		ret = -EOPNOTSUPP;
		break;
	}
	if (ret) {
		/* Either nothing was done or messed up, can't recover. */
		XDNA_ERR(xdna, "Failed to set power mode: %d, ret %d", target, ret);
		return ret;
	}

	ndev->pw_mode = target;
	XDNA_INFO(xdna, "Power mode changed to %d", ndev->pw_mode);
	return 0;
}

int aie2_pm_start(struct amdxdna_dev_hdl *ndev)
{
	return aie2_pm_set_mode(ndev, ndev->pw_mode);
}

void aie2_pm_stop(struct amdxdna_dev_hdl *ndev)
{
	aie2_pm_set_mode(ndev, POWER_MODE_DEFAULT);
}

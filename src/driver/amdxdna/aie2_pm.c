// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2024, Advanced Micro Devices, Inc.
 */

#include "aie2_pci.h"

static int aie2_pm_clock_gating(struct amdxdna_dev_hdl *ndev, bool enable)
{
	const struct rt_config_clk_gating *config;
	u32 value;
	int ret;
	int i;

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

	return ret;
}

bool aie2_pm_is_turbo(struct amdxdna_dev_hdl *ndev)
{
	return ndev->pw_mode == POWER_MODE_TURBO;
}

static int aie2_pm_turbo(struct amdxdna_dev_hdl *ndev, bool enable)
{
	struct amdxdna_dev *xdna = ndev->xdna;
	struct amdxdna_client *client;
	bool clk_gate_on;

	drm_WARN_ON(&xdna->ddev, !mutex_is_locked(&xdna->dev_lock));
	list_for_each_entry(client, &xdna->client_list, node) {
		bool empty;

		mutex_lock(&client->hwctx_lock);
		empty = idr_is_empty(&client->hwctx_idr);
		mutex_unlock(&client->hwctx_lock);
		if (!empty)
			return -EBUSY;
	}

	clk_gate_on = !enable;
	return aie2_pm_clock_gating(ndev, clk_gate_on);
}

int aie2_pm_set_mode(struct amdxdna_dev_hdl *ndev, enum amdxdna_power_mode_type target)
{
	struct amdxdna_dev *xdna = ndev->xdna;
	int ret = 0;

	if (ndev->pw_mode == target)
		return 0;

	if (target != POWER_MODE_DEFAULT && target != POWER_MODE_TURBO)
		return -EOPNOTSUPP;

	XDNA_DBG(xdna, "Changing power mode from %d to %d", ndev->pw_mode, target);
	/* Set resource solver power property to the user choice */

	/* Set power level within the device */

	/*
	 * Other mode -> POWER_MODE_TURBO: Turn off turbo mode
	 * POWER_MODE_TURBO -> Other mode: Turn on turbo mode
	 * Otherwise, no change
	 */
	if (target == POWER_MODE_TURBO)
		ret = aie2_pm_turbo(ndev, true);
	else if (ndev->pw_mode == POWER_MODE_TURBO)
		ret = aie2_pm_turbo(ndev, false);
	if (ret) {
		XDNA_ERR(xdna, "Failed to config clock gating");
		return ret;
	}

	ndev->pw_mode = target;
	XDNA_INFO(xdna, "Power mode changed into %d", ndev->pw_mode);
	return 0;
}

int aie2_pm_start(struct amdxdna_dev_hdl *ndev)
{
	/*
	 * TODO: should only skip POWER_MODE_DEFAULT.
	 * Let's make it right after full DPM support is ready
	 */
	if (ndev->pw_mode != POWER_MODE_TURBO)
		return 0;

	return aie2_pm_clock_gating(ndev, false);
}

void aie2_pm_stop(struct amdxdna_dev_hdl *ndev)
{
	if (ndev->pw_mode != POWER_MODE_TURBO)
		return;

	/* Clock gating must be turned ON before suspend firmware */
	aie2_pm_clock_gating(ndev, true);
}

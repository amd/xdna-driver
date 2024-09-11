// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2024, Advanced Micro Devices, Inc.
 */

#include "aie2_pci.h"

static int aie2_pm_clock_gating(struct amdxdna_dev_hdl *ndev,
				enum amdxdna_power_mode_type target)
{
	const struct rt_config_clk_gating *config;
	bool enable;
	u32 value;
	int ret;
	int i;

	enable = (target != POWER_MODE_TURBO && target != POWER_MODE_HIGH);
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
		empty = idr_is_empty(&client->hwctx_idr);
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

	if (target == POWER_MODE_LOW || target == POWER_MODE_MEDIUM)
		return -EOPNOTSUPP;

	ret = aie2_pm_check_turbo(ndev, ndev->pw_mode, target);
	if (ret) {
		XDNA_WARN(xdna, "Change Turbo mode failed");
		return ret;
	}

	XDNA_DBG(xdna, "Changing power mode from %d to %d", ndev->pw_mode, target);

	/* TODO:
	 *switch (ndev->pw_mode) {
	 *case POWER_MODE_LOW:
	 *	Set to low DPM level
	 *case POWER_MODE_MEDIUM:
	 *	Set to medium DPM level
	 *case POWER_MODE_HIGH:
	 *case POWER_MODE_TURBO:
	 *	Set to highest DPM level
	 *default:
	 *	Let driver decides DPM level
	 *}
	 */

	ret = aie2_pm_clock_gating(ndev, target);
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
	return aie2_pm_clock_gating(ndev, ndev->pw_mode);
}

void aie2_pm_stop(struct amdxdna_dev_hdl *ndev)
{
	aie2_pm_clock_gating(ndev, POWER_MODE_DEFAULT);
}

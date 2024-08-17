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

int aie2_pm_set_mode(struct amdxdna_dev_hdl *ndev, enum amdxdna_power_mode_type target)
{
	struct amdxdna_dev *xdna = ndev->xdna;
	int ret = 0;

	if (ndev->pw_mode == target)
		return 0;

	if (target == POWER_MODE_LOW || target == POWER_MODE_MEDIUM)
		return -EOPNOTSUPP;

	XDNA_DBG(xdna, "Changing power mode from %d to %d", ndev->pw_mode, target);
	/* Set resource solver power property to the user choice */

	/* Set power level within the device */

	/*
	 * Other mode -> POWER_MODE_HIGH: Turn off clock gating
	 * POWER_MODE_HIGH -> Other mode: Turn on clock gating
	 * Otherwise, no change
	 */
	if (target == POWER_MODE_HIGH) {
		XDNA_DBG(xdna, "Clock gating turning off");
		ret = aie2_pm_clock_gating(ndev, false);
	} else if (ndev->pw_mode == POWER_MODE_HIGH) {
		XDNA_DBG(xdna, "Clock gating turning on");
		ret = aie2_pm_clock_gating(ndev, true);
	}
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
	if (ndev->pw_mode != POWER_MODE_HIGH)
		return 0;

	return aie2_pm_clock_gating(ndev, false);
}

void aie2_pm_stop(struct amdxdna_dev_hdl *ndev)
{
	if (ndev->pw_mode != POWER_MODE_HIGH)
		return;

	/* Clock gating must be turned ON before suspend firmware */
	aie2_pm_clock_gating(ndev, true);
}

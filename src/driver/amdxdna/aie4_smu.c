// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2025, Advanced Micro Devices, Inc.
 */

#include "aie4_pci.h"

#define SMU_RESULT_OK		1

/* SMU commands */
#define AIE4_SMU_POWER_ON		0x3
#define AIE4_SMU_POWER_OFF		0x4
/* For SMU v0 */
#define AIE4_SMU_SET_MPNPUCLK_FREQ	0x5
#define AIE4_SMU_SET_HCLK_FREQ		0x6
/* For SMU v1 */
#define AIE4_SMU_SET_SOFT_DPMLEVEL	0x7
#define AIE4_SMU_SET_HARD_DPMLEVEL	0x8

static int aie4_smu_exec(struct amdxdna_dev_hdl *ndev, u32 reg_cmd,
			 u32 reg_arg, u32 *out)
{
	u32 resp;
	int ret;

	writel(0, SMU_REG(ndev, SMU_RESP_REG));
	writel(reg_arg, SMU_REG(ndev, SMU_ARG_REG));
	writel(reg_cmd, SMU_REG(ndev, SMU_CMD_REG));

	/* Clear and set SMU_INTR_REG to kick off */
	writel(0, SMU_REG(ndev, SMU_INTR_REG));
	writel(1, SMU_REG(ndev, SMU_INTR_REG));

	XDNA_DBG(ndev->xdna, "smu exec timeout %d ns", AIE4_TIMEOUT);

	ret = readx_poll_timeout(readl, SMU_REG(ndev, SMU_RESP_REG), resp,
				 resp, AIE4_INTERVAL, AIE4_TIMEOUT);
	if (ret) {
		XDNA_ERR(ndev->xdna, "SMU cmd %d timed out", reg_cmd);
		return ret;
	}

	if (out)
		*out = readl(SMU_REG(ndev, SMU_OUT_REG));

	if (resp != SMU_RESULT_OK) {
		XDNA_ERR(ndev->xdna, "SMU cmd %d failed, 0x%x", reg_cmd, resp);
		return -EINVAL;
	}

	return 0;
}

int aie4_set_dpm(struct amdxdna_dev_hdl *ndev, u32 dpm_level)
{
	int ret;

	ret = aie4_smu_exec(ndev, AIE4_SMU_SET_HARD_DPMLEVEL, dpm_level, NULL);
	if (ret) {
		XDNA_ERR(ndev->xdna, "Set hard dpm level %d failed, ret %d ",
			 dpm_level, ret);
		return ret;
	}

	ret = aie4_smu_exec(ndev, AIE4_SMU_SET_SOFT_DPMLEVEL, dpm_level, NULL);
	if (ret) {
		XDNA_ERR(ndev->xdna, "Set soft dpm level %d failed, ret %d",
			 dpm_level, ret);
		return ret;
	}

	ndev->mp_npu_clock.freq_mhz = ndev->priv->dpm_clk_tbl[dpm_level].npuclk;
	ndev->h_clock.freq_mhz = ndev->priv->dpm_clk_tbl[dpm_level].hclk;
	ndev->dpm_level = dpm_level;

	XDNA_DBG(ndev->xdna, "MP-NPU clock %d, H clock %d\n",
		 ndev->mp_npu_clock.freq_mhz, ndev->h_clock.freq_mhz);

	return 0;
}

int aie4_smu_set_power_on(struct amdxdna_dev_hdl *ndev)
{
	int ret;

	ret = aie4_smu_exec(ndev, AIE4_SMU_POWER_ON, 0, NULL);
	if (ret)
		return ret;
	ndev->power_state = SMU_POWER_ON;

	return 0;
}

int aie4_smu_set_power_off(struct amdxdna_dev_hdl *ndev)
{
	int ret;

	ret = aie4_smu_exec(ndev, AIE4_SMU_POWER_OFF, 0, NULL);
	if (ret)
		return ret;
	ndev->power_state = SMU_POWER_OFF;
	XDNA_DBG(ndev->xdna, "Power off successful");

	return 0;
}

int aie4_smu_get_power_state(struct amdxdna_dev_hdl *ndev)
{
	return ndev->power_state;
}

int aie4_smu_start(struct amdxdna_dev_hdl *ndev)
{
	int ret;

	ret = aie4_smu_set_power_on(ndev);
	if (ret) {
		XDNA_ERR(ndev->xdna, "Power on failed, ret %d", ret);
		return ret;
	}

	return 0;
}

void aie4_smu_stop(struct amdxdna_dev_hdl *ndev)
{
	int ret;

	/* Minimize clocks/dpm level prior to power off */
	/* aie4 dpm controlled by FW */
	//ndev->priv->hw_ops.set_dpm(ndev, 0);

	ret = aie4_smu_set_power_off(ndev);
	if (ret)
		XDNA_WARN(ndev->xdna, "Power off failed, ret %d", ret);
}

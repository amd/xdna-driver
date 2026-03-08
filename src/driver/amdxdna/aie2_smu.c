// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2022-2025, Advanced Micro Devices, Inc.
 */

#include "aie2_pci.h"

#define SMU_RESULT_OK		1

/* SMU commands */
#define AIE2_SMU_POWER_ON		0x3
#define AIE2_SMU_POWER_OFF		0x4
/* For SMU v0 */
#define AIE2_SMU_SET_MPNPUCLK_FREQ	0x5
#define AIE2_SMU_SET_HCLK_FREQ		0x6
/* For SMU v1 */
#define AIE2_SMU_SET_SOFT_DPMLEVEL	0x7
#define AIE2_SMU_SET_HARD_DPMLEVEL	0x8

#define NPU4_DPM_TOPS(ndev, dpm_level) \
({ \
	typeof(ndev) _ndev = ndev; \
	(4096 * (_ndev)->total_col * \
	 (_ndev)->priv->dpm_clk_tbl[dpm_level].hclk / 1000000); \
})

static int aie2_smu_exec(struct amdxdna_dev_hdl *ndev, u32 reg_cmd,
			 u32 reg_arg, u32 *out)
{
	u32 resp;
	int ret;

	WARN_ON(!mutex_is_locked(&ndev->aie2_lock));

	writel(0, SMU_REG(ndev, SMU_RESP_REG));
	writel(reg_arg, SMU_REG(ndev, SMU_ARG_REG));
	writel(reg_cmd, SMU_REG(ndev, SMU_CMD_REG));

	/* Clear and set SMU_INTR_REG to kick off */
	writel(0, SMU_REG(ndev, SMU_INTR_REG));
	writel(1, SMU_REG(ndev, SMU_INTR_REG));

	ret = readx_poll_timeout(readl, SMU_REG(ndev, SMU_RESP_REG), resp,
				 resp, AIE2_INTERVAL, AIE2_TIMEOUT);
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

int npu1_set_dpm(struct amdxdna_dev_hdl *ndev, u32 dpm_level)
{
	u32 freq;
	int ret;

	ret = aie2_smu_exec(ndev, AIE2_SMU_SET_MPNPUCLK_FREQ,
			    ndev->priv->dpm_clk_tbl[dpm_level].npuclk, &freq);
	if (ret) {
		XDNA_ERR(ndev->xdna, "Set npu clock to %d failed, ret %d\n",
			 ndev->priv->dpm_clk_tbl[dpm_level].npuclk, ret);
	}
	ndev->npuclk_freq = freq;

	ret = aie2_smu_exec(ndev, AIE2_SMU_SET_HCLK_FREQ,
			    ndev->priv->dpm_clk_tbl[dpm_level].hclk, &freq);
	if (ret) {
		XDNA_ERR(ndev->xdna, "Set h clock to %d failed, ret %d\n",
			 ndev->priv->dpm_clk_tbl[dpm_level].hclk, ret);
	}
	ndev->hclk_freq = freq;
	ndev->dpm_level = dpm_level;
	ndev->max_tops = 2 * ndev->total_col;
	ndev->curr_tops = ndev->max_tops * freq / 1028;

	XDNA_DBG(ndev->xdna, "MP-NPU clock %d, H clock %d\n",
		 ndev->npuclk_freq, ndev->hclk_freq);

	return 0;
}

int npu4_set_dpm(struct amdxdna_dev_hdl *ndev, u32 dpm_level)
{
	int ret;

	ret = aie2_smu_exec(ndev, AIE2_SMU_SET_HARD_DPMLEVEL, dpm_level, NULL);
	if (ret) {
		XDNA_ERR(ndev->xdna, "Set hard dpm level %d failed, ret %d ",
			 dpm_level, ret);
		return ret;
	}

	ret = aie2_smu_exec(ndev, AIE2_SMU_SET_SOFT_DPMLEVEL, dpm_level, NULL);
	if (ret) {
		XDNA_ERR(ndev->xdna, "Set soft dpm level %d failed, ret %d",
			 dpm_level, ret);
		return ret;
	}

	ndev->npuclk_freq = ndev->priv->dpm_clk_tbl[dpm_level].npuclk;
	ndev->hclk_freq = ndev->priv->dpm_clk_tbl[dpm_level].hclk;
	ndev->dpm_level = dpm_level;
	ndev->max_tops = NPU4_DPM_TOPS(ndev, ndev->max_dpm_level);
	ndev->curr_tops = NPU4_DPM_TOPS(ndev, dpm_level);

	XDNA_DBG(ndev->xdna, "MP-NPU clock %d, H clock %d\n",
		 ndev->npuclk_freq, ndev->hclk_freq);

	return 0;
}

int aie2_smu_get_mpnpu_clock_freq(struct amdxdna_dev_hdl *ndev)
{
	return ndev->npuclk_freq;
}

int aie2_smu_get_hclock_freq(struct amdxdna_dev_hdl *ndev)
{
	return ndev->hclk_freq;
}

int aie2_smu_set_power_on(struct amdxdna_dev_hdl *ndev)
{
	int ret;

	ret = aie2_smu_exec(ndev, AIE2_SMU_POWER_ON, 0, NULL);
	if (ret)
		return ret;
	ndev->power_state = SMU_POWER_ON;

	return 0;
}

int aie2_smu_set_power_off(struct amdxdna_dev_hdl *ndev)
{
	int ret;

	ret = aie2_smu_exec(ndev, AIE2_SMU_POWER_OFF, 0, NULL);
	if (ret)
		return ret;
	ndev->power_state = SMU_POWER_OFF;

	return 0;
}

int aie2_smu_get_power_state(struct amdxdna_dev_hdl *ndev)
{
	return ndev->power_state;
}

int aie2_smu_start(struct amdxdna_dev_hdl *ndev)
{
	int ret;

	/*
	 * If the hardware was not powered off properly, try to set
	 * power off. Failing to power off indicates an unrecoverable
	 * issue, return failure.
	 */
	ret = aie2_smu_set_power_off(ndev);
	if (ret) {
		XDNA_ERR(ndev->xdna, "Access power failed, ret %d", ret);
		return ret;
	}

	ret = aie2_smu_set_power_on(ndev);
	if (ret) {
		XDNA_ERR(ndev->xdna, "Power on failed, ret %d", ret);
		return ret;
	}

	return 0;
}

void aie2_smu_stop(struct amdxdna_dev_hdl *ndev)
{
	int ret;

	/* Minimize clocks/dpm level prior to power off */
	ndev->priv->hw_ops.set_dpm(ndev, 0);

	ret = aie2_smu_set_power_off(ndev);
	if (ret)
		XDNA_WARN(ndev->xdna, "Power off failed, ret %d", ret);
}

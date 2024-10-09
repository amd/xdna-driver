// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2022-2024, Advanced Micro Devices, Inc.
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

/* This is a hack for NPU1 device */
const struct dpm_clk npu1_hack_dpm_clk_table[] = {
	{400, 800},
	{600, 1024},
};

static int aie2_smu_exec(struct amdxdna_dev_hdl *ndev, u32 reg_cmd,
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

/*
 * Depending on the current running frequency and debugfs setting,
 * aie2_smu_set_clock_freq() might or might not update freqency.
 */
static int aie2_smu_set_clock_freq(struct amdxdna_dev_hdl *ndev,
				   struct clock *clock, u32 freq_mhz)
{
	u32 smu_cmd;
	int ret;

	if (!freq_mhz || freq_mhz > clock->max_freq_mhz) {
		XDNA_ERR(ndev->xdna, "Invalid %s freq %d", clock->name, freq_mhz);
		return -EINVAL;
	}

	if (clock == &ndev->smu.mp_npu_clock)
		smu_cmd = AIE2_SMU_SET_MPNPUCLK_FREQ;
	else if (clock == &ndev->smu.h_clock)
		smu_cmd = AIE2_SMU_SET_HCLK_FREQ;
	else
		return -EINVAL; /* Buggy */

	if (freq_mhz == clock->freq_mhz)
		return 0;

	ret = aie2_smu_exec(ndev, smu_cmd, freq_mhz, NULL);
	if (ret)
		return ret;

	clock->freq_mhz = freq_mhz;
	XDNA_DBG(ndev->xdna, "Set %s = %d mhz", clock->name, clock->freq_mhz);
	return 0;
}

int aie2_smu_get_mpnpu_clock_freq(struct amdxdna_dev_hdl *ndev)
{
	return ndev->smu.mp_npu_clock.freq_mhz;
}

char *aie2_smu_get_mpnpu_clock_name(struct amdxdna_dev_hdl *ndev)
{
	return ndev->smu.mp_npu_clock.name;
}

int aie2_smu_get_hclock_freq(struct amdxdna_dev_hdl *ndev)
{
	return ndev->smu.h_clock.freq_mhz;
}

char *aie2_smu_get_hclock_name(struct amdxdna_dev_hdl *ndev)
{
	return ndev->smu.h_clock.name;
}

static int aie2_smu_set_dpm_level_v0(struct amdxdna_dev_hdl *ndev, u32 dpm_level)
{
	const struct dpm_clk *dpm_entry = SMU_DPM_TABLE_ENTRY(ndev, dpm_level);
	struct clock *clk;
	int ret;

	clk = &ndev->smu.mp_npu_clock;
	ret = aie2_smu_set_clock_freq(ndev, clk, dpm_entry->npuclk);
	if (ret) {
		XDNA_ERR(ndev->xdna, "setting npu clk failed for dpm level %d, ret: %d",
			 dpm_level, ret);
		return ret;
	}

	clk = &ndev->smu.h_clock;
	ret = aie2_smu_set_clock_freq(ndev, clk, dpm_entry->hclk);
	if (ret) {
		XDNA_ERR(ndev->xdna, "setting hclk failed for dpm level %d, ret: %d",
			 dpm_level, ret);
		return ret;
	}

	return ret;
}

static int aie2_smu_set_dpm_level_v1(struct amdxdna_dev_hdl *ndev, u32 dpm_level)
{
	int ret;

	ret = aie2_smu_exec(ndev, AIE2_SMU_SET_HARD_DPMLEVEL, dpm_level, NULL);
	if (!ret)
		XDNA_INFO_ONCE(ndev->xdna, "Set hard dpm level = %d", dpm_level);
	else
		return ret;

	ret = aie2_smu_exec(ndev, AIE2_SMU_SET_SOFT_DPMLEVEL, dpm_level, NULL);
	if (!ret)
		XDNA_INFO_ONCE(ndev->xdna, "Set soft dpm level = %d", dpm_level);

	ndev->smu.mp_npu_clock.freq_mhz = SMU_DPM_TABLE_ENTRY(ndev, dpm_level)->npuclk;
	ndev->smu.h_clock.freq_mhz = SMU_DPM_TABLE_ENTRY(ndev, dpm_level)->hclk;

	return ret;
}

// Find out the target level to set, fixed level always gets priority
static u32 aie2_smu_get_tgt_dpm_level(struct amdxdna_dev_hdl *ndev)
{
	return ndev->smu.fixed_dpm_level != SMU_DPM_INVALID ?
		ndev->smu.fixed_dpm_level : ndev->smu.dft_dpm_level;
}

// Find out what current level is set to
u32 aie2_smu_get_dpm_level(struct amdxdna_dev_hdl *ndev)
{
	return ndev->smu.curr_dpm_level;
}

static int aie2_smu_set_dpm_level(struct amdxdna_dev_hdl *ndev, u32 dpm_level)
{
	int ret;

	if (aie2_control_flags & BIT(AIE2_BIT_BYPASS_SET_FREQ)) {
		XDNA_DBG(ndev->xdna, "Bypassed set dpm level");
		return 0;
	}

	if (dpm_level > SMU_DPM_MAX(ndev))
		return -EINVAL;
	if (dpm_level == ndev->smu.curr_dpm_level)
		return 0;

	if (!ndev->priv->smu_rev)
		ret = aie2_smu_set_dpm_level_v0(ndev, dpm_level);
	else
		ret = aie2_smu_set_dpm_level_v1(ndev, dpm_level);
	if (!ret) {
		ndev->smu.curr_dpm_level = dpm_level;
		XDNA_DBG(ndev->xdna, "The current dpm level is set to %d", dpm_level);
	}

	return ret;
}

int aie2_smu_set_fixed_dpm_level(struct amdxdna_dev_hdl *ndev, u32 dpm_level)
{
	ndev->smu.fixed_dpm_level = dpm_level;
	XDNA_DBG(ndev->xdna, "The fixed dpm level is %d", dpm_level);
	return aie2_smu_set_dpm_level(ndev, aie2_smu_get_tgt_dpm_level(ndev));
}

int aie2_smu_set_dft_dpm_level(struct amdxdna_dev_hdl *ndev, u32 dpm_level)
{
	ndev->smu.dft_dpm_level = dpm_level;
	XDNA_DBG(ndev->xdna, "The default dpm level is %d", dpm_level);
	return aie2_smu_set_dpm_level(ndev, aie2_smu_get_tgt_dpm_level(ndev));
}

int aie2_smu_set_power_on(struct amdxdna_dev_hdl *ndev)
{
	int ret;

	ret = aie2_smu_exec(ndev, AIE2_SMU_POWER_ON, 0, NULL);
	if (ret)
		return ret;

	ndev->smu.power_state = SMU_POWER_ON;
	return 0;
}

int aie2_smu_set_power_off(struct amdxdna_dev_hdl *ndev)
{
	int ret;

	ret = aie2_smu_exec(ndev, AIE2_SMU_POWER_OFF, 0, NULL);
	if (ret)
		return ret;

	ndev->smu.power_state = SMU_POWER_OFF;
	return 0;
}

int aie2_smu_get_power_state(struct amdxdna_dev_hdl *ndev)
{
	return ndev->smu.power_state;
}

int aie2_smu_start(struct amdxdna_dev_hdl *ndev)
{
	int ret;

	ret = aie2_smu_set_power_on(ndev);
	if (ret) {
		XDNA_ERR(ndev->xdna, "Power on failed, ret %d", ret);
		return ret;
	}

	// Restore DPM level to what we set before 
	ret = aie2_smu_set_dpm_level(ndev, aie2_smu_get_tgt_dpm_level(ndev));
	if (ret) {
		XDNA_ERR(ndev->xdna, "Restore dpm level failed, ret %d", ret);
		return ret;
	}

	return 0;
}

void aie2_smu_stop(struct amdxdna_dev_hdl *ndev)
{
	int ret;

	/* Minimize clocks/dpm level prior to power off */
	ret = aie2_smu_set_dpm_level(ndev, 0);
	if (ret)
		XDNA_WARN(ndev->xdna, "Set dpm level 0 failed, ret %d", ret);

	ret = aie2_smu_set_power_off(ndev);
	if (ret)
		XDNA_WARN(ndev->xdna, "Power off failed, ret %d", ret);
}

void aie2_smu_setup(struct amdxdna_dev_hdl *ndev)
{
	struct smu *smu = &ndev->smu;

	snprintf(smu->mp_npu_clock.name, sizeof(smu->mp_npu_clock.name), "MP-NPU Clock");
	snprintf(smu->h_clock.name, sizeof(smu->h_clock.name), "H Clock");

	smu->dpm_table = ndev->priv->smu_npu_dpm_clk_table;
	smu->num_dpm_levels = ndev->priv->smu_npu_dpm_levels;
	if (!ndev->priv->smu_rev) {
		u32 npuclk_freq;
		u32 out;

		/* This is a hack for special NPU1 device */
		npuclk_freq = SMU_DPM_TABLE_ENTRY(ndev, SMU_DPM_MAX(ndev))->npuclk;
		aie2_smu_exec(ndev, AIE2_SMU_SET_MPNPUCLK_FREQ, npuclk_freq, &out);
		if (npuclk_freq != out) {
			XDNA_DBG(ndev->xdna, "Use small DPM table");
			smu->dpm_table = npu1_hack_dpm_clk_table;
			smu->num_dpm_levels = ARRAY_SIZE(npu1_hack_dpm_clk_table);
		}
	}
	smu->dft_dpm_level = SMU_DPM_MAX(ndev);
	smu->fixed_dpm_level = SMU_DPM_INVALID;
	smu->curr_dpm_level = SMU_DPM_INVALID;

	smu->mp_npu_clock.max_freq_mhz = SMU_DPM_TABLE_ENTRY(ndev, SMU_DPM_MAX(ndev))->npuclk;
	smu->h_clock.max_freq_mhz = SMU_DPM_TABLE_ENTRY(ndev, SMU_DPM_MAX(ndev))->hclk;
}

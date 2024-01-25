// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright 2022-2024 Advanced Micro Devices, Inc.
 */

#include "ipu_common.h"

#define SMU_RESULT_OK		1

/* SMU commands */
#define IPU_SMU_POWER_ON		0x3
#define IPU_SMU_POWER_OFF		0x4
#define IPU_SMU_SET_MPIPUCLK_FREQ	0x5
#define IPU_SMU_SET_HCLK_FREQ		0x6

#define SMU_MPIPUCLK_FREQ_MAX		600
#define SMU_HCLK_FREQ_MAX		1024

static int ipu_smu_exec(struct ipu_device *idev, u32 reg_cmd, u32 reg_arg)
{
	u32 resp;
	int ret;

	writel(0, SMU_REG(idev, SMU_RESP_REG));
	writel(reg_arg, SMU_REG(idev, SMU_ARG_REG));
	writel(reg_cmd, SMU_REG(idev, SMU_CMD_REG));

	/* Clear and set SMU_INTR_REG to kick off */
	writel(0, SMU_REG(idev, SMU_INTR_REG));
	writel(1, SMU_REG(idev, SMU_INTR_REG));

	ret = readx_poll_timeout(readl, SMU_REG(idev, SMU_RESP_REG), resp,
				 resp, IPU_INTERVAL, IPU_TIMEOUT);
	if (ret) {
		XDNA_ERR(idev->xdna, "smu cmd %d timed out", reg_cmd);
		return ret;
	}

	if (resp != SMU_RESULT_OK) {
		XDNA_ERR(idev->xdna, "smu cmd %d failed, 0x%x", reg_cmd, resp);
		return -EINVAL;
	}

	return 0;
}

int ipu_smu_set_mpipu_clock_freq(struct ipu_device *idev, u32 freq_mhz)
{
	if (!freq_mhz || freq_mhz > SMU_MPIPUCLK_FREQ_MAX) {
		XDNA_ERR(idev->xdna, "invalid mpipu clock freq %d", freq_mhz);
		return -EINVAL;
	}

	idev->mp_ipu_clock.freq_mhz = freq_mhz;
	return ipu_smu_exec(idev, IPU_SMU_SET_MPIPUCLK_FREQ, freq_mhz);
}

int ipu_smu_set_hclock_freq(struct ipu_device *idev, u32 freq_mhz)
{
	if (!freq_mhz || freq_mhz > SMU_HCLK_FREQ_MAX) {
		XDNA_ERR(idev->xdna, "invalid hclock freq %d", freq_mhz);
		return -EINVAL;
	}

	idev->h_clock.freq_mhz = freq_mhz;
	return ipu_smu_exec(idev, IPU_SMU_SET_HCLK_FREQ, freq_mhz);
}

int ipu_smu_set_power_on(struct ipu_device *idev)
{
	return ipu_smu_exec(idev, IPU_SMU_POWER_ON, 0);
}

int ipu_smu_set_power_off(struct ipu_device *idev)
{
	return ipu_smu_exec(idev, IPU_SMU_POWER_OFF, 0);
}

int ipu_smu_init(struct ipu_device *idev)
{
	int ret;

	ret = ipu_smu_set_power_on(idev);
	if (ret) {
		XDNA_ERR(idev->xdna, "Power on failed, ret %d", ret);
		return ret;
	}

	ret = ipu_smu_set_mpipu_clock_freq(idev, SMU_MPIPUCLK_FREQ_MAX);
	if (ret) {
		XDNA_ERR(idev->xdna, "Set mpipu clk freq failed, ret %d", ret);
		return ret;
	}
	snprintf(idev->mp_ipu_clock.name, sizeof(idev->mp_ipu_clock.name), "MP-IPU Clock");

	ret = ipu_smu_set_hclock_freq(idev, SMU_HCLK_FREQ_MAX);
	if (ret) {
		XDNA_ERR(idev->xdna, "Set hclk freq failed, ret %d", ret);
		return ret;
	}
	snprintf(idev->h_clock.name, sizeof(idev->h_clock.name), "H Clock");


	return 0;
}

void ipu_smu_fini(struct ipu_device *idev)
{
	int ret;

	ret = ipu_smu_set_power_off(idev);
	if (ret)
		XDNA_WARN(idev->xdna, "Power off failed, ret %d", ret);
}

/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2025-2026, Advanced Micro Devices, Inc.
 */

#ifndef _AIE_COMMON_H_
#define _AIE_COMMON_H_

#define AIE_INTERVAL	20000	/* us */
#define AIE_TIMEOUT	1000000	/* us */

#define SMU_RESULT_OK	1

/* SMU commands */
#define AIE_SMU_POWER_ON		0x3
#define AIE_SMU_POWER_OFF		0x4
/* For SMU v0 */
#define AIE_SMU_SET_MPNPUCLK_FREQ	0x5
#define AIE_SMU_SET_HCLK_FREQ		0x6
/* For SMU v1 */
#define AIE_SMU_SET_SOFT_DPMLEVEL	0x7
#define AIE_SMU_SET_HARD_DPMLEVEL	0x8

#define SMU_REG_BAR(ndev, idx) ((ndev)->priv->smu_regs_off[(idx)].bar_idx)
#define SMU_REG_OFF(ndev, idx) ((ndev)->priv->smu_regs_off[(idx)].offset)

enum aie_smu_reg_idx {
	SMU_CMD_REG = 0,
	SMU_ARG_REG,
	SMU_INTR_REG,
	SMU_RESP_REG,
	SMU_OUT_REG,
	SMU_MAX_REGS /* Keep this at the end */
};

enum aie_smu_rev {
	SMU_REVISION_NONE = 0,
	SMU_REVISION_NPU1,
	SMU_REVISION_NPU4,
	SMU_REVISION_MAX
};

struct smu_config {
	void __iomem	*smu_regs[SMU_MAX_REGS];
};

struct drm_device;
struct smu_device;
struct smu_device *aiem_smu_create(struct drm_device *ddev, struct smu_config *conf);
int aie_smu_exec(struct smu_device *smu, u32 reg_cmd, u32 reg_arg, u32 *out);

#endif /* _AIE_COMMON_H_ */

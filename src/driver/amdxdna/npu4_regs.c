// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2023-2025, Advanced Micro Devices, Inc.
 */

#include "npu4_family.h"

const struct rt_config npu4_default_rt_cfg[] = {
	/* PDI APP LOAD MODE */
	{ 5, 1, AIE2_RT_CFG_INIT },
	/* Large Debug BO */
	{ 10, 1, AIE2_RT_CFG_INIT },
	/* Clock gating on */
	{ 1, 1, AIE2_RT_CFG_CLK_GATING },
	/* H-Clock gating on */
	{ 2, 1, AIE2_RT_CFG_CLK_GATING },
	/* Power gating on */
	{ 3, 1, AIE2_RT_CFG_CLK_GATING },
	/* L1 power gating on */
	{ 4, 1, AIE2_RT_CFG_CLK_GATING },
	/* Fine grain preemption enabled */
	{ 12, 1, AIE2_RT_CFG_FINE_PREEMPTION },
	/* Force preemption disabled */
	{ 13, 0, AIE2_RT_CFG_FORCE_PREEMPTION },
	/* Frame boundary preemption enabled */
	{ 14, 1, AIE2_RT_CFG_FRAME_BOUNDARY_PREEMPT },
	{ 0 },
};

const struct dpm_clk_freq npu4_dpm_clk_table[] = {
	{396, 792},
	{600, 1056},
	{792, 1152},
	{975, 1267},
	{975, 1267},
	{1056, 1408},
	{1152, 1584},
	{1267, 1800},
	{ 0 }
};

const struct amdxdna_dev_priv npu4_dev_priv = {
	.fw_path        = "amdnpu/17f0_10/npu.dev.sbin",
	.protocol_major = 0x6,
	.protocol_minor = 0x6,
	NPU4_COMMON_DEV_PRIV,
};

const struct amdxdna_dev_info dev_npu4_info = {
	.vbnv              = "NPU Strix",
	.dev_priv          = &npu4_dev_priv,
	NPU4_COMMON_DEV_INFO,
};

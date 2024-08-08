// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2023-2024, Advanced Micro Devices, Inc.
 */

#include "npu4_family.h"

const struct rt_config npu4_default_rt_cfg[] = {
	{ 5, 1, AIE2_RT_CFG_INIT }, /* PDI APP LOAD MODE */
	{ 10, 1, AIE2_RT_CFG_INIT }, /* Large Debug BO */
	{ 1, 1, AIE2_RT_CFG_CLK_GATING }, /* Clock gating on */
	{ 2, 1, AIE2_RT_CFG_CLK_GATING }, /* Clock gating on */
	{ 3, 1, AIE2_RT_CFG_CLK_GATING }, /* Clock gating on */
	{ 4, 1, AIE2_RT_CFG_CLK_GATING }, /* Clock gating on */
	{ 12, 1, AIE2_RT_CFG_FINE_PREEMPTION }, /* Fine grain preemption control */
	{ 13, 0, AIE2_RT_CFG_FORCE_PREEMPTION }, /* Force preemption control */
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
	.fw_path        = "amdnpu/17f0_10/npu.sbin",
	.protocol_major = 0x6,
	.protocol_minor = 0x6,
	NPU4_COMMON_DEV_PRIV,
};

const struct amdxdna_dev_info dev_npu4_info = {
	.vbnv              = "RyzenAI-npu4",
	.dev_priv          = &npu4_dev_priv,
	NPU4_COMMON_DEV_INFO,
};

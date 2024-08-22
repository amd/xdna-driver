// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2023-2024, Advanced Micro Devices, Inc.
 */

#include "npu4_family.h"

const struct dpm_clk npu4_dpm_clk_table[DPM_LEVEL_MAX] = {
	{396, 792},
	{600, 1056},
	{792, 1152},
	{975, 1267},
	{975, 1267},
	{1056, 1408},
	{1152, 1584},
	{1267, 1800}
};

const struct rt_config npu4_rt_cfg[NPU4_INIT_RT_CFG_NUM] = {
	{NPU4_RT_CFG_TYPE_PDI_LOAD, NPU4_RT_CFG_VAL_PDI_LOAD_APP},
	{NPU4_RT_CFG_TYPE_DEBUG_BO, NPU4_RT_CFG_VAL_DEBUG_BO_LARGE},
};

const u32 npu4_clk_gating_types[NPU4_CLK_GATING_CFG_NUM] = {
	NPU4_RT_CFG_TYPE_CLK_GATING,
	NPU4_RT_CFG_TYPE_HCLK_GATING,
	NPU4_RT_CFG_TYPE_PWR_GATING,
	NPU4_RT_CFG_TYPE_L1IMU_GATING,
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

// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2023-2025, Advanced Micro Devices, Inc.
 */

#include "npu4_family.h"

const struct rt_config npu4_default_rt_cfg[] = {
	{ 5,  1, AIE2_RT_CFG_INIT }, /* PDI APP LOAD MODE */
	{ 10, 1, AIE2_RT_CFG_INIT }, /* Large Debug BO */
	{ 14, 0, AIE2_RT_CFG_INIT }, /* Frame boundary preemption on */
	{ 1,  1, AIE2_RT_CFG_CLK_GATING }, /* Clock gating on */
	{ 2,  1, AIE2_RT_CFG_CLK_GATING }, /* H-Clock gating on */
	{ 3,  1, AIE2_RT_CFG_CLK_GATING }, /* Power gating on */
	{ 4,  1, AIE2_RT_CFG_CLK_GATING }, /* L1 power gating on */
	{ 0 },
};

const struct rt_cfg_ver npu4_rt_cfg_tbl[] = {
	{ 12, 12 }, /* Fine grain preemption */
	{ 12, 13 }, /* Force preemption */
	{ 12, 14 }, /* Frame boundary preemption */
	{ 0 },
};

const struct msg_op_ver npu4_msg_op_tbl[] = {
	{ 15, MSG_OP_UPDATE_PROPERTY },
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
	.protocol_minor = 0x12,
	NPU4_COMMON_DEV_PRIV,
};

const struct amdxdna_dev_info dev_npu4_info = {
	.vbnv              = "NPU Strix",
	.dev_priv          = &npu4_dev_priv,
	NPU4_COMMON_DEV_INFO,
};

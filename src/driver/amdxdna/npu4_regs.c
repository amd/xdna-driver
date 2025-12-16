// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2023-2025, Advanced Micro Devices, Inc.
 */

#include "npu4_family.h"

const struct rt_config npu4_default_rt_cfg[] = {
	{ NPU4_RT_TYPE_PDI_LOADING_MODE,	  1 /* APP */,	    AIE2_RT_CFG_INIT },
	{ NPU4_RT_TYPE_DEBUG_BUF,		  1 /* Large BO */, AIE2_RT_CFG_INIT },
	{ NPU4_RT_TYPE_FRAME_BOUNDARY_PREEMPTION, 0 /* Enable */,   AIE2_RT_CFG_INIT },
	{ NPU4_RT_TYPE_CLOCK_GATING,		  1 /* On */,	    AIE2_RT_CFG_CLK_GATING },
	{ NPU4_RT_TYPE_H_CLOCK_GATING,		  1 /* On */,	    AIE2_RT_CFG_CLK_GATING },
	{ NPU4_RT_TYPE_POWER_GATING,		  1 /* On */,	    AIE2_RT_CFG_CLK_GATING },
	{ NPU4_RT_TYPE_L1_POWER_GATING,		  1 /* On */,	    AIE2_RT_CFG_CLK_GATING },
	{ 0 },
};

const struct rt_cfg_ver npu4_rt_cfg_tbl[] = {
	{ AIE2_FW_VERSION(6, 12), NPU4_RT_TYPE_FINE_PREEMPTION },
	{ AIE2_FW_VERSION(6, 12), NPU4_RT_TYPE_FORCE_PREEMPTION },
	{ AIE2_FW_VERSION(6, 12), NPU4_RT_TYPE_FRAME_BOUNDARY_PREEMPTION },
	{ AIE2_FW_VERSION(6, 19), NPU4_RT_TYPE_LOG_LEVEL },
	{ AIE2_FW_VERSION(6, 19), NPU4_RT_TYPE_LOG_FORMAT },
	{ AIE2_FW_VERSION(6, 19), NPU4_RT_TYPE_LOG_DESTINATION },
	{ 0 },
};

const struct msg_op_ver npu4_msg_op_tbl[] = {
	{ AIE2_FW_VERSION(6, 15), MSG_OP_CHAIN_EXEC_NPU },
	{ AIE2_FW_VERSION(6, 15), MSG_OP_UPDATE_PROPERTY },
	{ AIE2_FW_VERSION(6, 18), MSG_OP_GET_APP_HEALTH },
	{ AIE2_FW_VERSION(6, 19), MSG_OP_CONFIG_FW_LOG },
	{ AIE2_FW_VERSION(6, 19), MSG_OP_START_FW_TRACE },
	{ AIE2_FW_VERSION(6, 19), MSG_OP_STOP_FW_TRACE },
	{ AIE2_FW_VERSION(6, 19), MSG_OP_SET_FW_TRACE_CATEGORIES },
	{ AIE2_FW_VERSION(6, 24), MSG_OP_GET_COREDUMP },
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

const struct aie2_fw_feature_tbl npu4_fw_feature_table[] = {
	{ .feature = AIE2_NPU_COMMAND, .min_fw_version = AIE2_FW_VERSION(6, 15) },
	{ .feature = AIE2_PREEMPT, .min_fw_version = AIE2_FW_VERSION(6, 12) },
	{ 0 }
};

const struct amdxdna_dev_priv npu4_dev_priv = {
	.fw_path	= "amdnpu/17f0_10/npu.dev.sbin",
	.min_fw_version	= AIE2_FW_VERSION(6, 12),
	NPU4_COMMON_DEV_PRIV,
};

const struct amdxdna_dev_info dev_npu4_info = {
	.vbnv              = "NPU Strix",
	.dev_priv          = &npu4_dev_priv,
	NPU4_COMMON_DEV_INFO,
};

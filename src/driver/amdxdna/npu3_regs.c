// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2023-2026, Advanced Micro Devices, Inc.
 */

#include "drm_local/amdxdna_accel.h"
#include "aie4_pci.h"
#include "npu3_family.h"

const struct amdxdna_dev_priv npu3_dev_priv = {
	NPU3_COMMON_DEV_PRIV,
	.smu_regs_off   = {
		DEFINE_BAR_OFFSET(SMU_CMD_REG,  NPU3_SMU, MP1_C2PMSG_59_ALT_1),
		DEFINE_BAR_OFFSET(SMU_ARG_REG,  NPU3_SMU, MP1_C2PMSG_61_ALT_1),
		DEFINE_BAR_OFFSET(SMU_INTR_REG, NPU3_SMU, MMNPU_APERTURE4_BASE),
		DEFINE_BAR_OFFSET(SMU_RESP_REG, NPU3_SMU, MP1_C2PMSG_60_ALT_1),
		DEFINE_BAR_OFFSET(SMU_OUT_REG,  NPU3_SMU, MP1_C2PMSG_61_ALT_1),
	},
};

const struct amdxdna_dev_info dev_npu3_info = {
	.default_vbnv		= "RyzenAI-npu3",
	.device_type		= AMDXDNA_DEV_TYPE_UMQ,
	.dev_priv		= &npu3_dev_priv,
	NPU3_COMMON_DEV_INFO,
};

const struct amdxdna_dev_info dev_npu3_pf_info = {
	.default_vbnv		= "RyzenAI-npu3-pf",
	.device_type		= AMDXDNA_DEV_TYPE_PF,
	.dev_priv		= &npu3_dev_priv,
	NPU3_COMMON_DEV_INFO,
};

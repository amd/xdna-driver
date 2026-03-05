// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2023-2026, Advanced Micro Devices, Inc.
 */

#include "drm_local/amdxdna_accel.h"
#include "aie4_pci.h"
#include "npu3_family.h"

#define NPU3_PSP_BAR_INDEX      4

#define MMNPU_APERTURE3_BASE    0x3810000
#define NPU3_PSP_BAR_BASE       MMNPU_APERTURE3_BASE

#define MPASP_C2PMSG_123_ALT_1  0x3810AEC
#define MPASP_C2PMSG_156_ALT_1  0x3810B70
#define MPASP_C2PMSG_157_ALT_1  0x3810B74
#define MPASP_C2PMSG_73_ALT_1   0x3810A24

const struct amdxdna_dev_priv npu3_dev_priv = {
	.npufw_path    = "npu.dev.sbin",
	.certfw_path    = "cert.dev.sbin",
	NPU3_COMMON_DEV_PRIV,
	.psp_regs_off   = {
		DEFINE_BAR_OFFSET(PSP_CMD_REG,    NPU3_PSP, MPASP_C2PMSG_123_ALT_1),
		DEFINE_BAR_OFFSET(PSP_ARG0_REG,   NPU3_PSP, MPASP_C2PMSG_156_ALT_1),
		DEFINE_BAR_OFFSET(PSP_ARG1_REG,   NPU3_PSP, MPASP_C2PMSG_157_ALT_1),
		DEFINE_BAR_OFFSET(PSP_ARG2_REG,   NPU3_PSP, MPASP_C2PMSG_123_ALT_1),
		DEFINE_BAR_OFFSET(PSP_INTR_REG,   NPU3_PSP, MPASP_C2PMSG_73_ALT_1),
		DEFINE_BAR_OFFSET(PSP_STATUS_REG, NPU3_PSP, MPASP_C2PMSG_123_ALT_1),
		DEFINE_BAR_OFFSET(PSP_RESP_REG,   NPU3_PSP, MPASP_C2PMSG_156_ALT_1),
		/* npu3 doesn't use 8th pwaitmode register */
	},
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
	.psp_bar       = NPU3_PSP_BAR_INDEX,
	.default_vbnv		= "RyzenAI-npu3-pf",
	.device_type		= AMDXDNA_DEV_TYPE_PF,
	.dev_priv		= &npu3_dev_priv,
	NPU3_COMMON_DEV_INFO,
};

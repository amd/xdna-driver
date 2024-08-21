// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2023-2024, Advanced Micro Devices, Inc.
 */

#include "drm_local/amdxdna_accel.h"
#include "aie2_pci.h"

/* Address definition from NPU1 docs */
#define MPNPU_PUB_SEC_INTR		0x3010090
#define MPNPU_PUB_PWRMGMT_INTR		0x3010094
#define MPNPU_PUB_SCRATCH2		0x30100A0
#define MPNPU_PUB_SCRATCH3		0x30100A4
#define MPNPU_PUB_SCRATCH4		0x30100A8
#define MPNPU_PUB_SCRATCH5		0x30100AC
#define MPNPU_PUB_SCRATCH6		0x30100B0
#define MPNPU_PUB_SCRATCH7		0x30100B4
#define MPNPU_PUB_SCRATCH9		0x30100BC

#define MPNPU_SRAM_X2I_MAILBOX_0	0x30A0000
#define MPNPU_SRAM_X2I_MAILBOX_1	0x30A2000
#define MPNPU_SRAM_I2X_MAILBOX_15	0x30BF000

#define MPNPU_APERTURE0_BASE		0x3000000
#define MPNPU_APERTURE1_BASE		0x3080000
#define MPNPU_APERTURE2_BASE		0x30C0000

/* PCIe BAR Index for NPU1 */
#define NPU1_REG_BAR_INDEX  0
#define NPU1_MBOX_BAR_INDEX 4
#define NPU1_PSP_BAR_INDEX  0
#define NPU1_SMU_BAR_INDEX  0
#define NPU1_SRAM_BAR_INDEX 2
/* Associated BARs and Apertures */
#define NPU1_REG_BAR_BASE  MPNPU_APERTURE0_BASE
#define NPU1_MBOX_BAR_BASE MPNPU_APERTURE2_BASE
#define NPU1_PSP_BAR_BASE  MPNPU_APERTURE0_BASE
#define NPU1_SMU_BAR_BASE  MPNPU_APERTURE0_BASE
#define NPU1_SRAM_BAR_BASE MPNPU_APERTURE1_BASE

#define NPU1_RT_CFG_TYPE_CLK_GATING 1
#define NPU1_RT_CFG_TYPE_PDI_LOAD 2
#define NPU1_RT_CFG_TYPE_DEBUG_BO 4

#define NPU1_RT_CFG_VAL_CLK_GATING_OFF 0
#define NPU1_RT_CFG_VAL_CLK_GATING_ON 1

#define NPU1_RT_CFG_VAL_PDI_LOAD_MGMT 0
#define NPU1_RT_CFG_VAL_PDI_LOAD_APP 1

#define NPU1_RT_CFG_VAL_DEBUG_BO_DEFAULT 0
#define NPU1_RT_CFG_VAL_DEBUG_BO_LARGE   1

#define NPU1_MPNPUCLK_FREQ_MAX  847
#define NPU1_HCLK_FREQ_MAX      1600

/*fill in the dpm clock frequencies */
const struct dpm_clk npu1_dpm_clk_table[] = {
	{400, 800},
	{600, 1024},
	{600, 1024},
	{600, 1024},
	{600, 1024},
	{720, 1309},
	{720, 1309},
	{847, 1600},
};

const struct rt_config npu1_rt_cfg[] = {
	{NPU1_RT_CFG_TYPE_PDI_LOAD, NPU1_RT_CFG_VAL_PDI_LOAD_APP},
	{NPU1_RT_CFG_TYPE_DEBUG_BO, NPU1_RT_CFG_VAL_DEBUG_BO_LARGE},
};

const u32 npu1_clk_gating_types[] = {NPU1_RT_CFG_TYPE_CLK_GATING};

const struct amdxdna_dev_priv npu1_dev_priv = {
	.fw_path        = "amdnpu/1502_00/npu.sbin",
	.protocol_major = 0x5,
	.protocol_minor = 0x5,
	.rt_config	= npu1_rt_cfg,
	.num_rt_cfg	= ARRAY_SIZE(npu1_rt_cfg),
	.col_align	= COL_ALIGN_NONE,
	.mbox_dev_addr  = NPU1_MBOX_BAR_BASE,
	.mbox_size      = 0, /* Use BAR size */
	.sram_dev_addr  = NPU1_SRAM_BAR_BASE,
	.sram_offs      = {
		DEFINE_BAR_OFFSET(MBOX_CHANN_OFF, NPU1_SRAM, MPNPU_SRAM_X2I_MAILBOX_0),
		DEFINE_BAR_OFFSET(FW_ALIVE_OFF,   NPU1_SRAM, MPNPU_SRAM_I2X_MAILBOX_15),
	},
	.psp_regs_off   = {
		DEFINE_BAR_OFFSET(PSP_CMD_REG,    NPU1_PSP, MPNPU_PUB_SCRATCH2),
		DEFINE_BAR_OFFSET(PSP_ARG0_REG,   NPU1_PSP, MPNPU_PUB_SCRATCH3),
		DEFINE_BAR_OFFSET(PSP_ARG1_REG,   NPU1_PSP, MPNPU_PUB_SCRATCH4),
		DEFINE_BAR_OFFSET(PSP_ARG2_REG,   NPU1_PSP, MPNPU_PUB_SCRATCH9),
		DEFINE_BAR_OFFSET(PSP_INTR_REG,   NPU1_PSP, MPNPU_PUB_SEC_INTR),
		DEFINE_BAR_OFFSET(PSP_STATUS_REG, NPU1_PSP, MPNPU_PUB_SCRATCH2),
		DEFINE_BAR_OFFSET(PSP_RESP_REG,   NPU1_PSP, MPNPU_PUB_SCRATCH3),
	},
	.smu_regs_off   = {
		DEFINE_BAR_OFFSET(SMU_CMD_REG,  NPU1_SMU, MPNPU_PUB_SCRATCH5),
		DEFINE_BAR_OFFSET(SMU_ARG_REG,  NPU1_SMU, MPNPU_PUB_SCRATCH7),
		DEFINE_BAR_OFFSET(SMU_INTR_REG, NPU1_SMU, MPNPU_PUB_PWRMGMT_INTR),
		DEFINE_BAR_OFFSET(SMU_RESP_REG, NPU1_SMU, MPNPU_PUB_SCRATCH6),
		DEFINE_BAR_OFFSET(SMU_OUT_REG,  NPU1_SMU, MPNPU_PUB_SCRATCH7),
	},
	.clk_gating = {
		.types = npu1_clk_gating_types,
		.num_types = ARRAY_SIZE(npu1_clk_gating_types),
		.value_enable = NPU1_RT_CFG_VAL_CLK_GATING_ON,
		.value_disable = NPU1_RT_CFG_VAL_CLK_GATING_OFF,
	},
	.smu_mpnpuclk_freq_max = NPU1_MPNPUCLK_FREQ_MAX,
	.smu_hclk_freq_max     = NPU1_HCLK_FREQ_MAX,
	.smu_dpm_max           = 7,
	.smu_rev = SMU_REVISION_V0,
	.smu_npu_dpm_clk_table = npu1_dpm_clk_table,
	.smu_npu_dpm_levels = ARRAY_SIZE(npu1_dpm_clk_table),
#ifdef AMDXDNA_DEVEL
	.priv_load_cfg	= {NPU1_RT_CFG_TYPE_PDI_LOAD, NPU1_RT_CFG_VAL_PDI_LOAD_MGMT},
#endif
};

const struct amdxdna_dev_info dev_npu1_info = {
	.reg_bar           = NPU1_REG_BAR_INDEX,
	.mbox_bar          = NPU1_MBOX_BAR_INDEX,
	.sram_bar          = NPU1_SRAM_BAR_INDEX,
	.psp_bar           = NPU1_PSP_BAR_INDEX,
	.smu_bar           = NPU1_SMU_BAR_INDEX,
	.first_col         = 1,
	.dev_mem_buf_shift = 15, /* 32 KiB aligned */
	.dev_mem_base      = AIE2_DEVM_BASE,
	.dev_mem_size      = AIE2_DEVM_SIZE,
	.vbnv              = "RyzenAI-npu1",
	.device_type       = AMDXDNA_DEV_TYPE_KMQ,
	.dev_priv          = &npu1_dev_priv,
	.ops               = &aie2_ops,
};

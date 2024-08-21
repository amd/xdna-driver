// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2024, Advanced Micro Devices, Inc.
 */

#include "drm_local/amdxdna_accel.h"
#include "aie2_pci.h"

/* NPU Public Registers on MpNPUAxiXbar (refer to Diag npu_registers.h) */
#define MPNPU_PUB_SEC_INTR             0x3010060
#define MPNPU_PUB_PWRMGMT_INTR         0x3010064
#define MPNPU_PUB_SCRATCH0             0x301006C
#define MPNPU_PUB_SCRATCH1             0x3010070
#define MPNPU_PUB_SCRATCH2             0x3010074
#define MPNPU_PUB_SCRATCH3             0x3010078
#define MPNPU_PUB_SCRATCH4             0x301007C
#define MPNPU_PUB_SCRATCH5             0x3010080
#define MPNPU_PUB_SCRATCH6             0x3010084
#define MPNPU_PUB_SCRATCH7             0x3010088
#define MPNPU_PUB_SCRATCH8             0x301008C
#define MPNPU_PUB_SCRATCH9             0x3010090
#define MPNPU_PUB_SCRATCH10            0x3010094
#define MPNPU_PUB_SCRATCH11            0x3010098
#define MPNPU_PUB_SCRATCH12            0x301009C
#define MPNPU_PUB_SCRATCH13            0x30100A0
#define MPNPU_PUB_SCRATCH14            0x30100A4
#define MPNPU_PUB_SCRATCH15            0x30100A8
#define MP0_C2PMSG_73                  0x3810A24
#define MP0_C2PMSG_123                 0x3810AEC

#define MP1_C2PMSG_0                   0x3B10900
#define MP1_C2PMSG_60                  0x3B109F0
#define MP1_C2PMSG_61                  0x3B109F4

#define MPNPU_SRAM_X2I_MAILBOX_0       0x3600000
#define MPNPU_SRAM_X2I_MAILBOX_15      0x361E000
#define MPNPU_SRAM_X2I_MAILBOX_31      0x363E000
#define MPNPU_SRAM_I2X_MAILBOX_31      0x363F000

#define MMNPU_APERTURE0_BASE           0x3000000
#define MMNPU_APERTURE1_BASE           0x3600000
#define MMNPU_APERTURE3_BASE           0x3810000
#define MMNPU_APERTURE4_BASE           0x3B10000

/* PCIe BAR Index for NPU6 */
#define NPU6_REG_BAR_INDEX	0
#define NPU6_MBOX_BAR_INDEX	0
#define NPU6_PSP_BAR_INDEX	4
#define NPU6_SMU_BAR_INDEX	5
#define NPU6_SRAM_BAR_INDEX	2
/* Associated BARs and Apertures */
#define NPU6_REG_BAR_BASE	MMNPU_APERTURE0_BASE
#define NPU6_MBOX_BAR_BASE	MMNPU_APERTURE0_BASE
#define NPU6_PSP_BAR_BASE	MMNPU_APERTURE3_BASE
#define NPU6_SMU_BAR_BASE	MMNPU_APERTURE4_BASE
#define NPU6_SRAM_BAR_BASE	MMNPU_APERTURE1_BASE

#define NPU6_RT_CFG_TYPE_CLK_GATING   1
#define NPU6_RT_CFG_TYPE_HCLK_GATING  2
#define NPU6_RT_CFG_TYPE_PWR_GATING   3
#define NPU6_RT_CFG_TYPE_L1IMU_GATING 4
#define NPU6_RT_CFG_TYPE_PDI_LOAD     5
#define NPU6_RT_CFG_TYPE_DEBUG_BO     10

#define NPU6_RT_CFG_VAL_CLK_GATING_OFF 0
#define NPU6_RT_CFG_VAL_CLK_GATING_ON 1

#define NPU6_RT_CFG_VAL_PDI_LOAD_MGMT 0
#define NPU6_RT_CFG_VAL_PDI_LOAD_APP 1

#define NPU6_RT_CFG_VAL_DEBUG_BO_DEFAULT 0
#define NPU6_RT_CFG_VAL_DEBUG_BO_LARGE   1

#define NPU6_MPNPUCLK_FREQ_MAX  1267
#define NPU6_HCLK_FREQ_MAX      1800

const struct dpm_clk npu6_dpm_clk_table[DPM_LEVEL_MAX] = {
	{396, 792},
	{600, 1056},
	{792, 1152},
	{975, 1267},
	{975, 1267},
	{1056, 1408},
	{1152, 1584},
	{1267, 1800}
};

const struct rt_config npu6_rt_cfg[] = {
	{NPU6_RT_CFG_TYPE_PDI_LOAD, NPU6_RT_CFG_VAL_PDI_LOAD_APP},
	{NPU6_RT_CFG_TYPE_DEBUG_BO, NPU6_RT_CFG_VAL_DEBUG_BO_LARGE},
};

const u32 npu6_clk_gating_types[] = {
	NPU6_RT_CFG_TYPE_CLK_GATING,
	NPU6_RT_CFG_TYPE_HCLK_GATING,
	NPU6_RT_CFG_TYPE_PWR_GATING,
	NPU6_RT_CFG_TYPE_L1IMU_GATING,
};

const struct amdxdna_dev_priv npu6_dev_priv = {
	.fw_path        = "amdnpu/17f0_20/npu.sbin",
	.protocol_major = 0x6,
	.protocol_minor = 0x6,
	.rt_config	= npu6_rt_cfg,
	.num_rt_cfg	= ARRAY_SIZE(npu6_rt_cfg),
	.col_align	= COL_ALIGN_NATURE,
	.mbox_dev_addr  = NPU6_MBOX_BAR_BASE,
	.mbox_size      = 0, /* Use BAR size */
	.sram_dev_addr  = NPU6_SRAM_BAR_BASE,
	.sram_offs      = {
		DEFINE_BAR_OFFSET(MBOX_CHANN_OFF, NPU6_SRAM, MPNPU_SRAM_X2I_MAILBOX_0),
		DEFINE_BAR_OFFSET(FW_ALIVE_OFF,   NPU6_SRAM, MPNPU_SRAM_X2I_MAILBOX_15),
	},
	.psp_regs_off   = {
		DEFINE_BAR_OFFSET(PSP_CMD_REG,    NPU6_PSP, MP0_C2PMSG_123),
		DEFINE_BAR_OFFSET(PSP_ARG0_REG,   NPU6_REG, MPNPU_PUB_SCRATCH3),
		DEFINE_BAR_OFFSET(PSP_ARG1_REG,   NPU6_REG, MPNPU_PUB_SCRATCH4),
		DEFINE_BAR_OFFSET(PSP_ARG2_REG,   NPU6_REG, MPNPU_PUB_SCRATCH9),
		DEFINE_BAR_OFFSET(PSP_INTR_REG,   NPU6_PSP, MP0_C2PMSG_73),
		DEFINE_BAR_OFFSET(PSP_STATUS_REG, NPU6_PSP, MP0_C2PMSG_123),
		DEFINE_BAR_OFFSET(PSP_RESP_REG,   NPU6_REG, MPNPU_PUB_SCRATCH3),
	},
	.smu_regs_off   = {
		DEFINE_BAR_OFFSET(SMU_CMD_REG,  NPU6_SMU, MP1_C2PMSG_0),
		DEFINE_BAR_OFFSET(SMU_ARG_REG,  NPU6_SMU, MP1_C2PMSG_60),
		DEFINE_BAR_OFFSET(SMU_INTR_REG, NPU6_SMU, MMNPU_APERTURE4_BASE),
		DEFINE_BAR_OFFSET(SMU_RESP_REG, NPU6_SMU, MP1_C2PMSG_61),
		DEFINE_BAR_OFFSET(SMU_OUT_REG,  NPU6_SMU, MP1_C2PMSG_60),
	},
	.clk_gating = {
		.types = npu6_clk_gating_types,
		.num_types = ARRAY_SIZE(npu6_clk_gating_types),
		.value_enable = NPU6_RT_CFG_VAL_CLK_GATING_ON,
		.value_disable = NPU6_RT_CFG_VAL_CLK_GATING_OFF,
	},
	.smu_mpnpuclk_freq_max = NPU6_MPNPUCLK_FREQ_MAX,
	.smu_hclk_freq_max     = NPU6_HCLK_FREQ_MAX,
	.smu_dpm_max           = 7,
	.smu_rev = SMU_REVISION_V1,
	.smu_npu_dpm_clk_table = npu6_dpm_clk_table,
	.smu_npu_dpm_levels = ARRAY_SIZE(npu6_dpm_clk_table),
#ifdef AMDXDNA_DEVEL
	.priv_load_cfg = {NPU6_RT_CFG_TYPE_PDI_LOAD, NPU6_RT_CFG_VAL_PDI_LOAD_MGMT},
#endif
};

const struct amdxdna_dev_info dev_npu6_info = {
	.reg_bar           = NPU6_REG_BAR_INDEX,
	.mbox_bar          = NPU6_MBOX_BAR_INDEX,
	.sram_bar          = NPU6_SRAM_BAR_INDEX,
	.psp_bar           = NPU6_PSP_BAR_INDEX,
	.smu_bar           = NPU6_SMU_BAR_INDEX,
	.first_col         = 0,
	.dev_mem_buf_shift = 15, /* 32 KiB aligned */
	.dev_mem_base      = AIE2_DEVM_BASE,
	.dev_mem_size      = AIE2_DEVM_SIZE,
	.vbnv              = "RyzenAI-npu6",
	.device_type       = AMDXDNA_DEV_TYPE_KMQ,
	.dev_priv          = &npu6_dev_priv,
	.ops               = &aie2_ops,
};

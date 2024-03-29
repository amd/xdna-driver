// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2023-2024, Advanced Micro Devices, Inc.
 */

#include "npu_common.h"

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
#define MP0_C2PMSG_73                       0x3810A24
#define MP0_C2PMSG_123                     0x3810AEC

#define MP1_C2PMSG_0                        0x3B10900
#define MP1_C2PMSG_60                       0x3B109F0
#define MP1_C2PMSG_61                       0x3B109F4

#define MPNPU_SRAM_X2I_MAILBOX_0       0x3600000
#define MPNPU_SRAM_X2I_MAILBOX_15      0x361E000
#define MPNPU_SRAM_X2I_MAILBOX_31      0x363E000
#define MPNPU_SRAM_I2X_MAILBOX_31      0x363F000

#define MMNPU_APERTURE0_BASE            0x3000000
#define MMNPU_APERTURE1_BASE            0x3600000
#define MMNPU_APERTURE3_BASE            0x3810000
#define MMNPU_APERTURE4_BASE            0x3B10000

/* <device name>_<bar>_<enum name>_ADDR, see enum psp_reg_idx */
#define NPU2_PSP_PSP_CMD_REG_ADDR	MP0_C2PMSG_123
#define NPU2_REG_PSP_ARG0_REG_ADDR	MPNPU_PUB_SCRATCH3
#define NPU2_REG_PSP_ARG1_REG_ADDR	MPNPU_PUB_SCRATCH4
#define NPU2_REG_PSP_ARG2_REG_ADDR	MPNPU_PUB_SCRATCH9
#define NPU2_PSP_PSP_INTR_REG_ADDR	MP0_C2PMSG_73
#define NPU2_PSP_PSP_STATUS_REG_ADDR	MP0_C2PMSG_123
#define NPU2_REG_PSP_RESP_REG_ADDR	MPNPU_PUB_SCRATCH3
/* <device name>_<bar>_<enum name>_ADDR, see enum npu_smu_reg_idx */
#define NPU2_SMU_SMU_CMD_REG_ADDR	MP1_C2PMSG_0
#define NPU2_SMU_SMU_ARG_REG_ADDR	MP1_C2PMSG_60
#define NPU2_SMU_SMU_INTR_REG_ADDR	MMNPU_APERTURE4_BASE
#define NPU2_SMU_SMU_RESP_REG_ADDR	MP1_C2PMSG_61
#define NPU2_SMU_SMU_OUT_REG_ADDR	MP1_C2PMSG_60
/* <device name>_<bar>_<enum name>_ADDR, see enum npu_sram_reg_idx */
#define NPU2_SRAM_MBOX_CHANN_OFF_ADDR	MPNPU_SRAM_X2I_MAILBOX_0
#define NPU2_SRAM_FW_ALIVE_OFF_ADDR	MPNPU_SRAM_X2I_MAILBOX_15

/* PCIe BAR Index for NPU2 */
#define NPU2_REG_BAR_INDEX	0
#define NPU2_MBOX_BAR_INDEX	0
#define NPU2_PSP_BAR_INDEX	4
#define NPU2_SMU_BAR_INDEX	5
#define NPU2_SRAM_BAR_INDEX	2
/* Associated BARs and Apertures */
#define NPU2_REG_BAR_BASE	MMNPU_APERTURE0_BASE
#define NPU2_MBOX_BAR_BASE	MMNPU_APERTURE0_BASE
#define NPU2_PSP_BAR_BASE	MMNPU_APERTURE3_BASE
#define NPU2_SMU_BAR_BASE	MMNPU_APERTURE4_BASE
#define NPU2_SRAM_BAR_BASE	MMNPU_APERTURE1_BASE

#define NPU2_PSP_OFFSETS(_dev) \
{ \
	BAR_OFFSET_PAIR(_dev##PSP, PSP_CMD_REG), \
	BAR_OFFSET_PAIR(_dev##REG, PSP_ARG0_REG), \
	BAR_OFFSET_PAIR(_dev##REG, PSP_ARG1_REG), \
	BAR_OFFSET_PAIR(_dev##REG, PSP_ARG2_REG), \
	BAR_OFFSET_PAIR(_dev##PSP, PSP_INTR_REG), \
	BAR_OFFSET_PAIR(_dev##PSP, PSP_STATUS_REG), \
	BAR_OFFSET_PAIR(_dev##REG, PSP_RESP_REG), \
}

#define PROTOCOL_MAJOR                  0x3
#define PROTOCOL_MINOR                  0x2

const NPU_DEFINE_DEV_INFO_PSP(NPU2, "RyzenAI-npu2", NPU2_PSP_OFFSETS,
			      "amdnpu/17f0_00/npu.sbin", PROTOCOL_MAJOR, PROTOCOL_MINOR);

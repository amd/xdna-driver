/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2026, Advanced Micro Devices, Inc.
 */

#ifndef _NPU3_FAMILY_H_
#define _NPU3_FAMILY_H_

#include "drm_local/amdxdna_accel.h"
#include "aie4_pci.h"

extern const struct amdxdna_dev_priv npu3_dev_priv;

#define NPU3_MBOX_BAR		0

#define NPU3_MBOX_BUFFER_BAR	2
#define NPU3_MBOX_INFO_OFF	0x0

#define NPU3_DOORBELL_BAR	2
#define NPU3_DOORBELL_OFF	0

#define MMNPU_APERTURE0_BASE	0x3000000
#define MMNPU_APERTURE3_BASE	0x3810000
#define MMNPU_APERTURE4_BASE	0x3B10000

/* PCIe BAR Index for NPU3 */
#define NPU3_REG_BAR_INDEX	0
#define NPU3_PSP_BAR_INDEX	4
#define NPU3_SMU_BAR_INDEX	5

/* Associated BARs and Apertures */
#define NPU3_REG_BAR_BASE	MMNPU_APERTURE0_BASE
#define NPU3_PSP_BAR_BASE	MMNPU_APERTURE3_BASE
#define NPU3_SMU_BAR_BASE	MMNPU_APERTURE4_BASE

#define MPASP_C2PMSG_123_ALT_1	0x3810AEC
#define MPASP_C2PMSG_156_ALT_1	0x3810B70
#define MPASP_C2PMSG_157_ALT_1	0x3810B74
#define MPASP_C2PMSG_73_ALT_1	0x3810A24

#define MP1_C2PMSG_24_ALT_1	0x3B10960
#define MP1_C2PMSG_25_ALT_1	0x3B10964
#define MP1_C2PMSG_26_ALT_1	0x3B10968
#define MP1_C2PMSG_59_ALT_1	0x3B109EC
#define MP1_C2PMSG_60_ALT_1	0x3B109F0
#define MP1_C2PMSG_61_ALT_1	0x3B109F4

#define NPU3_COMMON_DEV_PRIV						\
	.npufw_path		= "npu.dev.sbin",				\
	.certfw_path		= "cert.dev.sbin",				\
	.mbox_info_off		= NPU3_MBOX_INFO_OFF,				\
	.doorbell_off		= NPU3_DOORBELL_OFF,				\
	.psp_regs_off   = {						\
		DEFINE_BAR_OFFSET(PSP_CMD_REG,    NPU3_PSP, MPASP_C2PMSG_123_ALT_1),	\
		DEFINE_BAR_OFFSET(PSP_ARG0_REG,   NPU3_PSP, MPASP_C2PMSG_156_ALT_1),	\
		DEFINE_BAR_OFFSET(PSP_ARG1_REG,   NPU3_PSP, MPASP_C2PMSG_157_ALT_1),	\
		DEFINE_BAR_OFFSET(PSP_ARG2_REG,   NPU3_PSP, MPASP_C2PMSG_123_ALT_1),	\
		DEFINE_BAR_OFFSET(PSP_INTR_REG,   NPU3_PSP, MPASP_C2PMSG_73_ALT_1),	\
		DEFINE_BAR_OFFSET(PSP_STATUS_REG, NPU3_PSP, MPASP_C2PMSG_123_ALT_1),	\
		DEFINE_BAR_OFFSET(PSP_RESP_REG,   NPU3_PSP, MPASP_C2PMSG_156_ALT_1),	\
	},								\
	.hw_ops		= {						\
		.set_dpm = aie4_set_dpm,				\
		.get_tops = aie4_get_tops,				\
	}

#define NPU3_COMMON_DEV_INFO	\
	.mbox_bar		= NPU3_MBOX_BAR,				\
	.sram_bar		= NPU3_MBOX_BUFFER_BAR,		\
	.psp_bar		= NPU3_PSP_BAR_INDEX,		\
	.smu_bar		= NPU3_SMU_BAR_INDEX,		\
	.doorbell_bar		= NPU3_DOORBELL_BAR,		\
	.ops			= &aie4_ops

#endif /* _NPU3_FAMILY_H_ */

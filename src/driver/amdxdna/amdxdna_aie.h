/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2025, Advanced Micro Devices, Inc.
 */

#ifndef _AMDXDNA_AIE_H_
#define _AMDXDNA_AIE_H_

#define PSP_REG_BAR(ndev, idx) ((ndev)->priv->psp_regs_off[(idx)].bar_idx)
#define PSP_REG_OFF(ndev, idx) ((ndev)->priv->psp_regs_off[(idx)].offset)
#define SRAM_REG_OFF(ndev, idx) ((ndev)->priv->sram_offs[(idx)].offset)

#define SMU_REG(ndev, idx) \
({ \
	typeof(ndev) _ndev = ndev; \
	((_ndev)->smu_base + (_ndev)->priv->smu_regs_off[(idx)].offset); \
})

#define DEFINE_BAR_OFFSET(reg_name, bar, reg_addr) \
	[reg_name] = {bar##_BAR_INDEX, (reg_addr) - bar##_BAR_BASE}

enum aie_smu_reg_idx {
	SMU_CMD_REG = 0,
	SMU_ARG_REG,
	SMU_INTR_REG,
	SMU_RESP_REG,
	SMU_OUT_REG,
	SMU_MAX_REGS /* Keep this at the end */
};

enum aie_smu_rev {
	SMU_REVISION_NONE = 0,
	SMU_REVISION_NPU1,
	SMU_REVISION_NPU4,
	SMU_REVISION_MAX
};

enum psp_reg_idx {
	PSP_CMD_REG = 0,
	PSP_ARG0_REG,
	PSP_ARG1_REG,
	PSP_ARG2_REG,
	PSP_NUM_IN_REGS, /* number of input registers */
	PSP_INTR_REG = PSP_NUM_IN_REGS,
	PSP_STATUS_REG,
	PSP_RESP_REG,
	PSP_PWAITMODE_REG,
	PSP_MAX_REGS /* Keep this at the end */
};

struct psp_config {
	const void	*fw_buf;
	u32		fw_size;
	void __iomem	*psp_regs[PSP_MAX_REGS];
};

struct aie4_psp_config {
	const void      *fw_buf;
	u32             fw_size;
	const void      *certfw_buf;
	u32             certfw_size;
	void __iomem    *psp_regs[PSP_MAX_REGS];
};

enum dpm_level {
	DPM_LEVEL_0 = 0,
	DPM_LEVEL_1,
	DPM_LEVEL_2,
	DPM_LEVEL_3,
	DPM_LEVEL_4,
	DPM_LEVEL_5,
	DPM_LEVEL_6,
	DPM_LEVEL_7,
	DPM_LEVEL_MAX,
};

struct dpm_clk {
	u32 npuclk;
	u32 hclk;
};

struct aie_version {
	u32 major;
	u32 minor;
};

struct aie_tile_metadata {
	u16 row_count;
	u16 row_start;
	u16 dma_channel_count;
	u16 lock_count;
	u16 event_reg_count;
};

struct aie_metadata {
	u32 size;
	u16 cols;
	u16 rows;
	struct aie_version version;
	struct aie_tile_metadata core;
	struct aie_tile_metadata mem;
	struct aie_tile_metadata shim;
};

struct dpm_clk_freq {
	u32	npuclk;
	u32	hclk;
};

enum aie_power_state {
	SMU_POWER_OFF,
	SMU_POWER_ON,
};

struct aie_bar_off_pair {
	int	bar_idx;
	u32	offset;
};

struct amdxdna_dev_hdl;
struct aie_hw_ops {
	int (*set_dpm)(struct amdxdna_dev_hdl *ndev, u32 dpm_level);
	int (*get_tops)(struct amdxdna_dev_hdl *ndev, u64 *max, u64 *curr);
};

#endif /* _AMDXDNA_AIE_H_ */

/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2025-2026, Advanced Micro Devices, Inc.
 */

#ifndef _AMDXDNA_AIE_H_
#define _AMDXDNA_AIE_H_

#include "aie_common.h"

#define DEFINE_BAR_OFFSET(reg_name, bar, reg_addr) \
	[reg_name] = {bar##_BAR_INDEX, (reg_addr) - bar##_BAR_BASE}
#define SRAM_REG_OFF(ndev, idx) ((ndev)->priv->sram_offs[(idx)].offset)

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

struct amdxdna_dev_hdl;
struct aie_hw_ops {
	int (*set_dpm)(struct amdxdna_dev_hdl *ndev, u32 dpm_level);
	int (*update_counters)(struct amdxdna_dev_hdl *ndev);
	int (*get_tops)(struct amdxdna_dev_hdl *ndev, u64 *max, u64 *curr);
};

#endif /* _AMDXDNA_AIE_H_ */

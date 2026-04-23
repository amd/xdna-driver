/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2022-2026, Advanced Micro Devices, Inc.
 */

#ifndef _AMDXDNA_AUX_DRV_H_
#define _AMDXDNA_AUX_DRV_H_

#include "amdxdna_drv.h"
#include "drm/amdxdna_accel.h"

/*
 * struct amdxdna_dev_info - Device hardware information
 * Record device static information, like reg, mbox, PSP, SMU bar index
 */
struct amdxdna_dev_info {
	int				reg_bar;
	int				mbox_bar;
	int				sram_bar;
	int				psp_bar;
	int				smu_bar;
	int				doorbell_bar;
	int				device_type;
	int				first_col;
	u32				dev_mem_buf_shift;
	u64				dev_mem_base;
	size_t				dev_mem_size;
	const char			*default_vbnv;
	const struct amdxdna_rev_vbnv	*rev_vbnv_tbl;
	const struct amdxdna_dev_priv	*dev_priv;
	const struct amdxdna_dev_ops	*ops;
};

/* Add device info below */
extern const struct amdxdna_dev_info dev_ve2_info;

#endif /* _AMDXDNA_AUX_DRV_H_ */

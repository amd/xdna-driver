/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2022-2026, Advanced Micro Devices, Inc.
 */

#ifndef _AMDXDNA_PCI_DRV_H_
#define _AMDXDNA_PCI_DRV_H_

#include "amdxdna_drv.h"

struct amdxdna_fw_feature_tbl {
	u64 features;
	u32 major;
	u32 max_minor;
	u32 min_minor;
};

/* PCI-specific dev_info extensions */
struct amdxdna_dev_info {
	int				reg_bar;
	int				mbox_bar;
	int				sram_bar;
	int				psp_bar;
	int				smu_bar;
	int				device_type;
	int				first_col;
	u32				dev_mem_buf_shift;
	u64				dev_mem_base;
	size_t				dev_mem_size;
	char				*vbnv;
	const struct amdxdna_dev_priv	*dev_priv;
	const struct amdxdna_fw_feature_tbl *fw_feature_tbl;
	const struct amdxdna_dev_ops	*ops;
};

/* Add device info below */
extern const struct amdxdna_dev_info dev_npu1_info;
extern const struct amdxdna_dev_info dev_npu3_pf_info;
extern const struct amdxdna_dev_info dev_npu4_info;
extern const struct amdxdna_dev_info dev_npu5_info;
extern const struct amdxdna_dev_info dev_npu6_info;

#endif /* _AMDXDNA_PCI_DRV_H_ */

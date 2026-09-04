/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2022-2026, Advanced Micro Devices, Inc.
 *
 * PCI-only declarations for amdxdna: the (device, revision) -> dev_info match
 * table and the PCI device_info instances.  Only the PCI driver and the PCI
 * device-info tables (npu{1,3,4,5,6}_regs.c) include this; everything else uses
 * the common amdxdna_drv.h.
 */

#ifndef _AMDXDNA_PCI_DRV_H_
#define _AMDXDNA_PCI_DRV_H_

#include "amdxdna_drv.h"

/*
 * struct amdxdna_device_id - PCI (device, revision) to dev_info mapping
 */
struct amdxdna_device_id {
	unsigned short device;
	u8 revision;
	const struct amdxdna_dev_info *dev_info;
};

/* Add device info below */
extern const struct amdxdna_dev_info dev_npu1_info;
extern const struct amdxdna_dev_info dev_npu3_classic_info;
extern const struct amdxdna_dev_info dev_npu3_pf_info;
extern const struct amdxdna_dev_info dev_npu3_vf_info;
extern const struct amdxdna_dev_info dev_npu4_info;
extern const struct amdxdna_dev_info dev_npu5_info;
extern const struct amdxdna_dev_info dev_npu6_info;
extern const struct amdxdna_dev_info dev_npu9_classic_info;
extern const struct amdxdna_dev_info dev_npu9_pf_info;
extern const struct amdxdna_dev_info dev_npu9_vf_info;
extern const struct amdxdna_dev_info dev_npu10_classic_info;
extern const struct amdxdna_dev_info dev_npu10_pf_info;
extern const struct amdxdna_dev_info dev_npu10_vf_info;
extern const struct amdxdna_dev_info dev_npu11_classic_info;
extern const struct amdxdna_dev_info dev_npu11_pf_info;
extern const struct amdxdna_dev_info dev_npu11_vf_info;

#endif /* _AMDXDNA_PCI_DRV_H_ */

/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2022-2024, Advanced Micro Devices, Inc.
 */

#ifndef _AMDXDNA_PCI_DRV_H_
#define _AMDXDNA_PCI_DRV_H_

#include <linux/pci.h>

#include "amdxdna_drm.h"

#define AMDXDNA_DRIVER_NAME "amdxdna"

/*
 * struct amdxdna_device_id - PCI device info
 *
 * @device: PCI device id
 * @revision: PCI revision id
 * @dev_info: device hardware information
 */
struct amdxdna_device_id {
	unsigned short device;
	u8 revision;
	const struct amdxdna_dev_info *dev_info;
};

/* Add device info below */
extern const struct amdxdna_dev_info dev_npu1_info;
extern const struct amdxdna_dev_info dev_npu2_info;
extern const struct amdxdna_dev_info dev_npu3_info;
extern const struct amdxdna_dev_info dev_npu4_info;
extern const struct amdxdna_dev_info dev_npu5_info;
extern const struct amdxdna_dev_info dev_npu6_info;

#endif /* _AMDXDNA_PCI_DRV_H_ */

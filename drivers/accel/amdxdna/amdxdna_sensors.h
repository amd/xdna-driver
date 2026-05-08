/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2026, Advanced Micro Devices, Inc.
 */
#ifndef _AMDXDNA_SENSORS_H_
#define _AMDXDNA_SENSORS_H_

#include "amdxdna_pci_drv.h"
#include "drm/amdxdna_accel.h"
#include <linux/errno.h>
#include <linux/kconfig.h>
#include <linux/types.h>

#define AMDXDNA_INVALID_TEMPERATURE	0xffff
#define AMDXDNA_NPU_MAX_PMF_COLUMNS	0x8

/*
 * For now, only supports global set of NPU sensors retrieved through PMF.
 * Different subset of these sensors are supported on different platforms.
 */
struct amdxdna_sensors {
	u16 npuclk_freq;
	u16 npu_busy[AMDXDNA_NPU_MAX_PMF_COLUMNS];
	u16 npu_power;
	u16 mpnpuclk_freq;
	u16 npu_temp;
};

int amdxdna_get_sensors(struct amdxdna_sensors *sensors);
int amdxdna_query_sensors(struct amdxdna_drm_get_info *args, u32 total_col);
void amdxdna_hwmon_init(struct amdxdna_dev *xdna);

#endif

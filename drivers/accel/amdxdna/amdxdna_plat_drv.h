/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2026, Advanced Micro Devices, Inc.
 *
 * Platform-only declarations for amdxdna: the platform (non-PCI) device_info
 * externs consumed by the platform driver's OF match table.  Only the platform
 * driver (amdxdna_plat_drv.c) and the platform device-info tables include this;
 * everything else uses the common amdxdna_drv.h.
 */

#ifndef _AMDXDNA_PLAT_DRV_H_
#define _AMDXDNA_PLAT_DRV_H_

#include "amdxdna_drv.h"

/* Add platform device info below */
extern const struct amdxdna_dev_info dev_npu12_info;

#endif /* _AMDXDNA_PLAT_DRV_H_ */

/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2025, Advanced Micro Devices, Inc.
 */

#ifndef _AMDXDNA_VE2_DRV_H_
#define _AMDXDNA_VE2_DRV_H_

#include <linux/platform_device.h>
#include <linux/of.h>
#include <linux/xlnx-ai-engine.h>

#include "amdxdna_drm.h"
#include "ve2_res_solver.h"

#define AMDXDNA_DRIVER_NAME "amdxdna_of"
#define AMDXDNA_VE2_AUTOSUSPEND_DELAY       5000 /* miliseconds */

/* Add device info below */
extern const struct amdxdna_dev_info dev_ve2_info;
extern int max_col;
extern int start_col;

#endif /* _AMDXDNA_VE2_DRV_H_ */

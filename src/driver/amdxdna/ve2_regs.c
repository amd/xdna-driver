// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2025, Advanced Micro Devices, Inc.
 */

#include "drm_local/amdxdna_accel.h"
#include "ve2_of.h"

const struct amdxdna_dev_info dev_ve2_info = {
	.device_type		= AMDXDNA_DEV_TYPE_VE,
	.ops			= &ve2_ops,
};

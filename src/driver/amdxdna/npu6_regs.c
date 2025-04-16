// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2024-2025, Advanced Micro Devices, Inc.
 */

#include "npu4_family.h"

const struct amdxdna_dev_info dev_npu6_info = {
	.vbnv              = "NPU Krackan",
	.dev_priv          = &npu4_dev_priv,
	NPU4_COMMON_DEV_INFO,
};

// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2024-2025, Advanced Micro Devices, Inc.
 */

#include "npu4_family.h"

const struct amdxdna_dev_priv npu5_dev_priv = {
	.fw_path	= "amdnpu/17f0_11/npu.dev.sbin",
	.min_fw_version	= AIE2_FW_VERSION(6, 12),
	NPU4_COMMON_DEV_PRIV,
};

const struct amdxdna_dev_info dev_npu5_info = {
	.default_vbnv      = "NPU Strix Halo",
	.dev_priv          = &npu5_dev_priv,
	NPU4_COMMON_DEV_INFO,
};

// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2024-2025, Advanced Micro Devices, Inc.
 */

#include "npu4_family.h"

static const struct aie2_supported_fw_ver npu5_supported_fw_vers[] = {
	{ .major = 6, .min_fw_version = AIE2_FW_VERSION(6, 12) },
};

const struct amdxdna_dev_priv npu5_dev_priv = {
	.fw_path              = "amdnpu/17f0_11/npu.dev.sbin",
	.supported_fw_vers    = npu5_supported_fw_vers,
	.num_supported_fw_vers = ARRAY_SIZE(npu5_supported_fw_vers),
	NPU4_COMMON_DEV_PRIV,
};

const struct amdxdna_dev_info dev_npu5_info = {
	.vbnv              = "NPU Strix Halo",
	.dev_priv          = &npu5_dev_priv,
	NPU4_COMMON_DEV_INFO,
};

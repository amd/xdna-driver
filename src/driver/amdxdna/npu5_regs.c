// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2024, Advanced Micro Devices, Inc.
 */

#include "npu4_family.h"

const struct amdxdna_dev_priv npu5_dev_priv = {
	.fw_path        = "amdnpu/17f0_11/npu.sbin",
	.protocol_major = 0x6,
	.protocol_minor = 0x6,
	NPU4_COMMON_DEV_PRIV,
};

const struct amdxdna_dev_info dev_npu5_info = {
	.vbnv              = "RyzenAI-npu5",
	.dev_priv          = &npu5_dev_priv,
	NPU4_COMMON_DEV_INFO,
};

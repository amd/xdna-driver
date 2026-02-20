// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2026, Advanced Micro Devices, Inc.
 */

#include "npu3_family.h"

const struct amdxdna_dev_info dev_npu8_info = {
	.default_vbnv		= "RyzenAI-npu8",
	.device_type		= AMDXDNA_DEV_TYPE_UMQ,
	.dev_priv		= &npu3_dev_priv,
	NPU3_COMMON_DEV_INFO,
};

const struct amdxdna_dev_info dev_npu8_pf_info = {
	.default_vbnv		= "RyzenAI-npu8-pf",
	.device_type		= AMDXDNA_DEV_TYPE_PF,
	.dev_priv		= &npu3_dev_priv,
	NPU3_COMMON_DEV_INFO,
};

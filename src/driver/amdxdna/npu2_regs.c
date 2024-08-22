// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2023-2024, Advanced Micro Devices, Inc.
 */

#include "npu4_family.h"

/* NPU2 is the prototype of NPU4. It will be obsoleted in near future. */

const struct amdxdna_dev_priv npu2_dev_priv = {
	.fw_path        = "amdnpu/17f0_00/npu.sbin",
	.protocol_major = 0x6,
	.protocol_minor = 0x6,
	NPU4_COMMON_DEV_PRIV,
};

const struct amdxdna_dev_info dev_npu2_info = {
	.vbnv              = "RyzenAI-npu2",
	.dev_priv          = &npu2_dev_priv,
	NPU4_COMMON_DEV_INFO,
};

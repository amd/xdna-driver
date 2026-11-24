// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2026, Advanced Micro Devices, Inc.
 */

#include "drm/amdxdna_accel.h"
#include <linux/bits.h>

#include "aie4.h"
#include "ve2.h"
#include "amdxdna_drv.h"
#include "amdxdna_ve2_drv.h"

/*
 * VE2 (Versal AIE2). The part has no mailbox IP, so this is not the npu12
 * shared-memory and IPI transport. dev_ve2_info still uses the shared aie4
 * context, command, and query ops.
 *
 * VE2 is a UMQ-format device that always submits from the kernel, like the
 * npu12 platform: user space allocates the queue BO and the shim sends command
 * buffers to the driver, which fills the queue (aie4 kernel_submit). With no
 * PASID the driver uses a private queue buffer. CERT takes two-level
 * indirect packets.
 *
 * xrt-smi examine prints this VBNV as the device name. This is the
 * Versal 2VE/2VM part, not a RyzenAI NPU.
 */

static const struct amdxdna_fw_feature_tbl ve2_fw_feature_table[] = {
	{ .major = 1, .min_minor = 0 },
	{ .features = BIT_U64(AIE4_GET_COREDUMP), .major = 1, .min_minor = 0 },
	{ .features = BIT_U64(AIE4_RW_ACCESS), .major = 1, .min_minor = 0 },
	{ .features = BIT_U64(AIE4_FW_LOG), .major = 1, .min_minor = 0 },
	{ .features = BIT_U64(AIE4_FW_TRACE), .major = 1, .min_minor = 0 },
	{ 0 }
};

static const struct amdxdna_fw_feature_tbl ve2_cert_feature_table[] = {
	{ .major = 1, .min_minor = 0 },
	{ .features = BIT_U64(AIE4_HSA_COMMAND), .major = 1, .min_minor = 0 },
	{ 0 }
};

const struct amdxdna_dev_info dev_ve2_info = {
	.default_vbnv		= "Versal-2VE-2VM",
	.device_type		= AMDXDNA_DEV_TYPE_UMQ,
	.ops			= &ve2_ops,
	.partition_per_hwctx	= true,
	.hsa_level2_indirect	= true,
	.fw_feature_tbl		= ve2_fw_feature_table,
	.cert_feature_tbl	= ve2_cert_feature_table,
	.async_error		= &aie4_async_error_desc,
};

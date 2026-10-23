// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2026, Advanced Micro Devices, Inc.
 */

#include "drm/amdxdna_accel.h"
#include <linux/bits.h>

#include "aie4.h"
#include "aie4_msg_priv.h"
#include "ve2.h"
#include "amdxdna_drv.h"
#include "amdxdna_ve2_drv.h"

/*
 * VE2 (Versal AIE2). The part has no mailbox IP, so this is not the npu12
 * shared-memory and IPI transport. dev_ve2_info still uses the shared aie4
 * context, command, and query ops. This commit answers the version and
 * geometry queries xrt-smi examine uses. Partition, hardware-context, and
 * command opcodes return -EOPNOTSUPP until a later patch.
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
	.device_type		= AMDXDNA_DEV_TYPE_KMQ,
	.ops			= &ve2_ops,
	.partition_per_hwctx	= true,
	.fw_feature_tbl		= ve2_fw_feature_table,
	.cert_feature_tbl	= ve2_cert_feature_table,
	.luts			= &aie4_error_luts,
	.async_max_status_code	= MAX_AIE4_MSG_STATUS_CODE,
};

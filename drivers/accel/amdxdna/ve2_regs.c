// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2026, Advanced Micro Devices, Inc.
 */

#include "drm/amdxdna_accel.h"
#include <linux/bits.h>

#include "aie4.h"
#include "aie4_msg_priv.h"
#include "aie4_ve2.h"
#include "amdxdna_drv.h"
#include "amdxdna_ve2_drv.h"

/*
 * VE2 (Versal AIE2). The part has no mailbox IP, so this is not the npu12
 * shared-memory and IPI transport. dev_ve2_info still uses the shared aie4
 * context, command, and query ops. Those ops send the same opcodes as npu12;
 * amdxdna_mailbox_ve2.c carries an opcode out through the Xilinx AIE driver,
 * or returns -EOPNOTSUPP when it cannot.
 *
 * partition_per_hwctx selects the per-context CREATE_PARTITION path from the
 * npu12 work. The VBNV is the one XRT uses to dispatch VE2 ELFs.
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
	.default_vbnv		= "RyzenAI-npu12-aie2ps",
	.device_type		= AMDXDNA_DEV_TYPE_UMQ,
	.ops			= &aie4_ve2_ops,
	.partition_per_hwctx	= true,
	.fw_feature_tbl		= ve2_fw_feature_table,
	.cert_feature_tbl	= ve2_cert_feature_table,
	.luts			= &aie4_error_luts,
	.async_max_status_code	= MAX_AIE4_MSG_STATUS_CODE,
};

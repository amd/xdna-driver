// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2026, Advanced Micro Devices, Inc.
 */

#include "drm/amdxdna_accel.h"

#include "aie4.h"
#include "aie4_msg_priv.h"
#include "aie4_plat.h"
#include "amdxdna_drv.h"
#include "amdxdna_plat_drv.h"

/*
 * aie2ps ("npu12") SoC variant: aie4 firmware over the platform (non-PCI)
 * transport. Functionally it speaks the aie4 message protocol like the PCI
 * npu3/aie4 parts, but it is not a PCI device -- it is described in the device
 * tree ("amd,xdna") and reaches firmware through shared memory. The
 * underlying AIE silicon matches Versal AIE2 (ve2).
 *
 * A distinct vbnv ("RyzenAI-npu12-aie2ps") lets XRT dispatch to the npu12_aie2ps
 * hardware type (ve2 ELFs) instead of treating this as a regular PCI npu3
 * device. The PCI-only fields (bars) are left unset; the platform driver drives
 * this device through aie4_plat_ops.
 */

/*
 * Firmware/CERT protocol version negotiation: advertise only the base
 * major/minimum-minor npu12 speaks. No optional feature bits are claimed.
 */
static const struct amdxdna_fw_feature_tbl npu12_fw_feature_table[] = {
	{ .major = 6, .min_minor = 0 },
	{ 0 }
};

static const struct amdxdna_fw_feature_tbl npu12_cert_feature_table[] = {
	{ .major = 1, .min_minor = 6 },
	{ 0 }
};

const struct amdxdna_dev_info dev_npu12_info = {
	.default_vbnv	= "RyzenAI-npu12-aie2ps",
	.device_type	= AMDXDNA_DEV_TYPE_UMQ,
	.ops		= &aie4_plat_ops,
	.fw_feature_tbl	= npu12_fw_feature_table,
	.cert_feature_tbl = npu12_cert_feature_table,
	.luts			= &aie4_error_luts,
	.async_max_status_code	= MAX_AIE4_MSG_STATUS_CODE,
};

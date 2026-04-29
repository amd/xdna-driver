// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2026, Advanced Micro Devices, Inc.
 */

#include "npu3_family.h"

/*
 * T20 SoC variant: npu3 firmware over rpmsg (or shmem mailbox) + aie2ps
 * ("ve2") hardware.  Functionally it speaks the npu3/aie4 message
 * protocol like the other npu3 parts, but the underlying AIE silicon
 * and ELFs match Versal AIE2 (ve2).
 *
 * A distinct vbnv ("RyzenAI-npu3-aie2ps") lets XRT dispatch to the
 * npu3_aie2ps hardware_type (xrt_smi_ve2.a archive + ve2-style validate
 * test list) instead of treating this as a regular PCI npu3 device.
 *
 * SMU/PSP/DPM tables are inherited from npu3 (see npu3_regs.c) since the
 * uC firmware interface is identical; only the AIE-side artifacts (ELFs,
 * xclbins) differ.  If T20 ever needs a custom dev_priv, fork it here
 * rather than overloading npu3_dev_priv.
 */
const struct amdxdna_dev_info dev_npu3_aie2ps_info = {
	.default_vbnv		= "RyzenAI-npu3-aie2ps",
	.device_type		= AMDXDNA_DEV_TYPE_UMQ,
	.dev_priv		= &npu3_dev_priv,
	NPU3_COMMON_DEV_INFO,
};

/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2026, Advanced Micro Devices, Inc.
 *
 * aie4-over-platform device ops.
 *
 * The aie4 message protocol runs over a platform (non-PCI) transport on
 * aie2ps-class SoC parts.  It reuses the same struct amdxdna_dev_hdl as the PCI
 * path, so the shared aie4 command/query/error flows in aie4.c/aie4_ctx.c work
 * unchanged; only hardware bring-up differs.  This file provides the aie4
 * transport hooks (doorbell/cert notification) and the platform device
 * lifecycle ops (aie4_plat_ops).
 */

#ifndef _AIE4_PLAT_H_
#define _AIE4_PLAT_H_

struct amdxdna_dev_ops;

extern const struct amdxdna_dev_ops aie4_plat_ops;

#endif /* _AIE4_PLAT_H_ */

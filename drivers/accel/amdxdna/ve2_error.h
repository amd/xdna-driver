/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2026, Advanced Micro Devices, Inc.
 *
 * VE2 (aux) async-error helpers. Kept separate from the shared amdxdna_error.h
 * (which is part of the aie2/aie4 PCI async-error framework and redefines
 * enum aie_module_type, clashing with the kernel AIE header the VE2 backend
 * includes). This header only provides the small pieces the VE2 backend needs.
 */

#ifndef _VE2_ERROR_H_
#define _VE2_ERROR_H_

#include <linux/bitfield.h>
#include <linux/bits.h>
#include <linux/mutex.h>

#include "drm/amdxdna_accel.h"

/* Cache for the last async error so it can be queried from userspace. */
struct amdxdna_async_err_cache {
	struct amdxdna_async_error	err; /* last async error */
	struct mutex			lock; /* protects access to the error cache */
};

#define AMDXDNA_ERR_DRV_AIE		4
#define AMDXDNA_ERR_SEV_CRITICAL	3
#define AMDXDNA_ERR_CLASS_AIE		2

#define AMDXDNA_ERR_NUM_MASK		GENMASK_U64(15, 0)
#define AMDXDNA_ERR_DRV_MASK		GENMASK_U64(23, 16)
#define AMDXDNA_ERR_SEV_MASK		GENMASK_U64(31, 24)
#define AMDXDNA_ERR_MOD_MASK		GENMASK_U64(39, 32)
#define AMDXDNA_ERR_CLASS_MASK		GENMASK_U64(47, 40)

enum amdxdna_error_num {
	AMDXDNA_ERROR_NUM_AIE_SATURATION = 3,
	AMDXDNA_ERROR_NUM_AIE_FP,
	AMDXDNA_ERROR_NUM_AIE_STREAM,
	AMDXDNA_ERROR_NUM_AIE_ACCESS,
	AMDXDNA_ERROR_NUM_AIE_BUS,
	AMDXDNA_ERROR_NUM_AIE_INSTRUCTION,
	AMDXDNA_ERROR_NUM_AIE_ECC,
	AMDXDNA_ERROR_NUM_AIE_LOCK,
	AMDXDNA_ERROR_NUM_AIE_DMA,
	AMDXDNA_ERROR_NUM_AIE_MEM_PARITY,
	AMDXDNA_ERROR_NUM_UNKNOWN = 15,
};

enum amdxdna_error_module {
	AMDXDNA_ERROR_MODULE_AIE_CORE = 3,
	AMDXDNA_ERROR_MODULE_AIE_MEMORY,
	AMDXDNA_ERROR_MODULE_AIE_SHIM,
	AMDXDNA_ERROR_MODULE_AIE_NOC,
	AMDXDNA_ERROR_MODULE_AIE_PL,
	AMDXDNA_ERROR_MODULE_UNKNOWN = 8,
};

#define AMDXDNA_ERROR_ENCODE(err_num, err_mod)				\
	(FIELD_PREP(AMDXDNA_ERR_NUM_MASK, err_num) |			\
	 FIELD_PREP_CONST(AMDXDNA_ERR_DRV_MASK, AMDXDNA_ERR_DRV_AIE) |	\
	 FIELD_PREP_CONST(AMDXDNA_ERR_SEV_MASK, AMDXDNA_ERR_SEV_CRITICAL) | \
	 FIELD_PREP(AMDXDNA_ERR_MOD_MASK, err_mod) |			\
	 FIELD_PREP_CONST(AMDXDNA_ERR_CLASS_MASK, AMDXDNA_ERR_CLASS_AIE))

#define AMDXDNA_EXTRA_ERR_COL_MASK	GENMASK_U64(7, 0)
#define AMDXDNA_EXTRA_ERR_ROW_MASK	GENMASK_U64(15, 8)

#define AMDXDNA_EXTRA_ERR_ENCODE(row, col)				\
	(FIELD_PREP(AMDXDNA_EXTRA_ERR_COL_MASK, col) |			\
	 FIELD_PREP(AMDXDNA_EXTRA_ERR_ROW_MASK, row))

#endif /* _VE2_ERROR_H_ */

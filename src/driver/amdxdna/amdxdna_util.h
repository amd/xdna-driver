/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2023-2024, Advanced Micro Devices, Inc.
 * All Rights Reserved.
 *
 * Authors:
 *	Min Ma <min.ma@amd.com>
 */

#ifndef _AMDXDNA_UTIL_H_
#define _AMDXDNA_UTIL_H_

#include <linux/types.h>

/*
 * This is porting from XAIE util header file.
 *
 * Below data is defined by AIE device and it is used for decode error message
 * from the device.
 */

enum aie_module_type {
	AIE_MEM_MOD = 0,
	AIE_CORE_MOD,
	AIE_PL_MOD,
};

enum aie_error_category {
	AIE_ERROR_SATURATION = 0,
	AIE_ERROR_FP,
	AIE_ERROR_STREAM,
	AIE_ERROR_ACCESS,
	AIE_ERROR_BUS,
	AIE_ERROR_INSTRUCTION,
	AIE_ERROR_ECC,
	AIE_ERROR_LOCK,
	AIE_ERROR_DMA,
	AIE_ERROR_MEM_PARITY,
	/* Unknown is not from XAIE, added for better category */
	AIE_ERROR_UNKNOWN,
};

/* Don't pack, unless XAIE side changed */
struct aie_error {
	u8			row;
	u8			col;
	enum aie_module_type mod_type;
	u8			event_id;
};

enum aie_error_category
aie_get_error_category(u8 row, u8 event_id, enum aie_module_type mod_type);

#endif /* _AMDXDNA_UTIL_H_ */

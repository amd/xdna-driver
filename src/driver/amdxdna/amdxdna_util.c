// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2023-2024, Advanced Micro Devices, Inc.
 *
 * Authors:
 *	Min Ma <min.ma@amd.com>
 */

#include <linux/kernel.h>
#include "amdxdna_util.h"

/*
 * Below data is porting from XAIE util header file.
 * We will need more data if XAIE implementation changed.
 */

struct aie_event_category {
	u8			   event_id;
	enum aie_error_category category;
};

#define EVENT_CATEGORY(id, cat) { id, cat }
static const struct aie_event_category aie_ml_mem_event_cat[] = {
	EVENT_CATEGORY(88U,  AIE_ERROR_ECC),
	EVENT_CATEGORY(90U,  AIE_ERROR_ECC),
	EVENT_CATEGORY(91U,  AIE_ERROR_MEM_PARITY),
	EVENT_CATEGORY(92U,  AIE_ERROR_MEM_PARITY),
	EVENT_CATEGORY(93U,  AIE_ERROR_MEM_PARITY),
	EVENT_CATEGORY(94U,  AIE_ERROR_MEM_PARITY),
	EVENT_CATEGORY(95U,  AIE_ERROR_MEM_PARITY),
	EVENT_CATEGORY(96U,  AIE_ERROR_MEM_PARITY),
	EVENT_CATEGORY(97U,  AIE_ERROR_DMA),
	EVENT_CATEGORY(98U,  AIE_ERROR_DMA),
	EVENT_CATEGORY(99U,  AIE_ERROR_DMA),
	EVENT_CATEGORY(100U, AIE_ERROR_DMA),
	EVENT_CATEGORY(101U, AIE_ERROR_LOCK),
};

static const struct aie_event_category aie_ml_core_event_cat[] = {
	EVENT_CATEGORY(55U, AIE_ERROR_ACCESS),
	EVENT_CATEGORY(56U, AIE_ERROR_STREAM),
	EVENT_CATEGORY(57U, AIE_ERROR_STREAM),
	EVENT_CATEGORY(58U, AIE_ERROR_BUS),
	EVENT_CATEGORY(59U, AIE_ERROR_INSTRUCTION),
	EVENT_CATEGORY(60U, AIE_ERROR_ACCESS),
	EVENT_CATEGORY(62U, AIE_ERROR_ECC),
	EVENT_CATEGORY(64U, AIE_ERROR_ECC),
	EVENT_CATEGORY(65U, AIE_ERROR_ACCESS),
	EVENT_CATEGORY(66U, AIE_ERROR_ACCESS),
	EVENT_CATEGORY(67U, AIE_ERROR_LOCK),
	EVENT_CATEGORY(70U, AIE_ERROR_INSTRUCTION),
	EVENT_CATEGORY(71U, AIE_ERROR_STREAM),
	EVENT_CATEGORY(72U, AIE_ERROR_BUS),
};

static const struct aie_event_category aie_ml_mem_tile_event_cat[] = {
	EVENT_CATEGORY(130U, AIE_ERROR_ECC),
	EVENT_CATEGORY(132U, AIE_ERROR_ECC),
	EVENT_CATEGORY(133U, AIE_ERROR_DMA),
	EVENT_CATEGORY(134U, AIE_ERROR_DMA),
	EVENT_CATEGORY(135U, AIE_ERROR_STREAM),
	EVENT_CATEGORY(136U, AIE_ERROR_STREAM),
	EVENT_CATEGORY(137U, AIE_ERROR_STREAM),
	EVENT_CATEGORY(138U, AIE_ERROR_BUS),
	EVENT_CATEGORY(139U, AIE_ERROR_LOCK),
};

static const struct aie_event_category aie_ml_shim_tile_event_cat[] = {
	EVENT_CATEGORY(64U, AIE_ERROR_BUS),
	EVENT_CATEGORY(65U, AIE_ERROR_STREAM),
	EVENT_CATEGORY(66U, AIE_ERROR_STREAM),
	EVENT_CATEGORY(67U, AIE_ERROR_BUS),
	EVENT_CATEGORY(68U, AIE_ERROR_BUS),
	EVENT_CATEGORY(69U, AIE_ERROR_BUS),
	EVENT_CATEGORY(70U, AIE_ERROR_BUS),
	EVENT_CATEGORY(71U, AIE_ERROR_BUS),
	EVENT_CATEGORY(72U, AIE_ERROR_DMA),
	EVENT_CATEGORY(73U, AIE_ERROR_DMA),
	EVENT_CATEGORY(74U, AIE_ERROR_LOCK),
};

enum aie_error_category
aie_get_error_category(u8 row, u8 event_id, enum aie_module_type mod_type)
{
	const struct aie_event_category *lut;
	int num_entry;
	int i;

	switch (mod_type) {
	case AIE_PL_MOD:
		lut = aie_ml_shim_tile_event_cat;
		num_entry = ARRAY_SIZE(aie_ml_shim_tile_event_cat);
		break;
	case AIE_CORE_MOD:
		lut = aie_ml_core_event_cat;
		num_entry = ARRAY_SIZE(aie_ml_core_event_cat);
		break;
	case AIE_MEM_MOD:
		if (row == 1) {
			lut = aie_ml_mem_tile_event_cat;
			num_entry = ARRAY_SIZE(aie_ml_mem_tile_event_cat);
		} else {
			lut = aie_ml_mem_event_cat;
			num_entry = ARRAY_SIZE(aie_ml_mem_event_cat);
		}
		break;
	default:
		return AIE_ERROR_UNKNOWN;
	}

	for (i = 0; i < num_entry; i++) {
		if (event_id != lut[i].event_id)
			continue;

		return lut[i].category;
	}

	return AIE_ERROR_UNKNOWN;
}

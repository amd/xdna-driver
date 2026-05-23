/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2026, Advanced Micro Devices, Inc.
 *
 * VE2 DRM hardware context: AIE link state and per-column handshake config.
 */

#ifndef _VE2_HWCTX_H_
#define _VE2_HWCTX_H_

#include <linux/types.h>

#include "ve2_handshake.h"

struct ve2_aie_context;
struct amdxdna_hwctx;

struct ve2_config_hwctx {
	u32	opcode_timeout_config;
};

/* Per-DRM-hwctx state: column config + ve2_aie context. */
struct ve2_hwctx_link {
	u32				mem_bitmap;
	u32				partition_id;
	struct ve2_aie_context		*aie_ctx;
	struct ve2_config_hwctx		*col_config;
};

int ve2_hwctx_setup(struct amdxdna_hwctx *hwctx);
void ve2_hwctx_teardown(struct amdxdna_hwctx *hwctx);

int ve2_hwctx_config_opcode_timeout(struct amdxdna_hwctx *hwctx, u32 op_timeout);
void ve2_hwctx_fill_hs_config(struct amdxdna_hwctx *hwctx, struct handshake *hs,
			      u32 col_idx);

extern int enable_polling;

#endif /* _VE2_HWCTX_H_ */

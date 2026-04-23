/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2025-2026, Advanced Micro Devices, Inc.
 */

#ifndef _VE2_AUX_H_
#define _VE2_AUX_H_

#include "amdxdna_drv.h"

/*
 * VE2 Device private data
 */
struct amdxdna_dev_priv {
	const char	*fw_path;
	u32		hwctx_limit;
	u32		ctx_limit;
};

extern const struct amdxdna_dev_ops ve2_ops;

#endif /* _VE2_AUX_H_ */

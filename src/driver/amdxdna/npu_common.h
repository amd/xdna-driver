/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2023-2024, Advanced Micro Devices, Inc.
 */

#ifndef _NPU_COMMON_H
#define _NPU_COMMON_H

#include "amdxdna_drv.h"
#include "amdxdna_ctx.h"
#include "npu_solver.h"

void npu_default_xrs_cfg(struct amdxdna_dev *xdna, struct init_config *xrs_cfg);
int npu_alloc_resource(struct amdxdna_hwctx *hwctx);
void npu_release_resource(struct amdxdna_hwctx *hwctx);

#endif /* _NPU_COMMON_H */

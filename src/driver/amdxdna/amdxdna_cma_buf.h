/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2025, Advanced Micro Devices, Inc.
 */

#ifndef _AMDXDNA_CMA_BUF_H_
#define _AMDXDNA_CMA_BUF_H_

#include <drm/drm_device.h>

bool amdxdna_use_cma(void);
struct dma_buf *amdxdna_get_cma_buf(struct drm_device *dev, size_t size);

#endif /* _AMDXDNA_CMA_BUF_H */

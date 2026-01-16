/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2025, Advanced Micro Devices, Inc.
 */

#ifndef _AMDXDNA_CMA_BUF_H_
#define _AMDXDNA_CMA_BUF_H_

#include <drm/drm_device.h>

#define AMDXDNA_BO_FLAGS_CACHEABLE		(1U << 24)

bool amdxdna_use_cma(void);
int get_cma_mem_index(u64 flags);
bool get_cacheable_flag(u64 flags);
struct dma_buf *amdxdna_get_cma_buf(struct device *dev, size_t size, bool cacheable);
struct dma_buf *amdxdna_get_cma_buf_with_fallback(struct device *const *region_devs,
						  int max_regions,
						  struct device *fallback_dev,
						  size_t size, u64 flags);

#endif /* _AMDXDNA_CMA_BUF_H */

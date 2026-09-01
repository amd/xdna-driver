/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2026, Advanced Micro Devices, Inc.
 */

#ifndef _AMDXDNA_CMA_BUF_H_
#define _AMDXDNA_CMA_BUF_H_

#include <drm/drm_device.h>
#include <linux/dma-buf.h>

struct amdxdna_cma_region;

struct dma_buf *amdxdna_get_cma_buf(struct drm_device *dev, size_t size);
struct dma_buf *amdxdna_get_cma_buf_with_fallback(const struct amdxdna_cma_region *regions,
						  int max_regions,
						  struct drm_device *fallback_dev,
						  size_t size, u64 flags);
u32 amdxdna_mem_region_from_addr(const struct amdxdna_cma_region *regions,
				 int max_regions, u64 addr);

#endif /* _AMDXDNA_CMA_BUF_H_ */

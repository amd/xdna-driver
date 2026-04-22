/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2025, Advanced Micro Devices, Inc.
 */

#ifndef _AMDXDNA_CMA_BUF_H_
#define _AMDXDNA_CMA_BUF_H_

#include <drm/drm_device.h>
#include <linux/bitops.h>
#include <linux/of.h>

struct amdxdna_dev;

#define AMDXDNA_BO_FLAGS_CACHEABLE	BIT(24)

bool amdxdna_use_cma(void);
struct dma_buf *amdxdna_get_cma_buf_with_fallback(struct device *const *region_devs,
						  int max_regions,
						  struct device *fallback_dev,
						  size_t size, u64 flags);
int amdxdna_cma_region_init(struct amdxdna_dev *xdna, struct device_node *mem_np);
void amdxdna_cma_region_fini(struct amdxdna_dev *xdna);

#endif /* _AMDXDNA_CMA_BUF_H */

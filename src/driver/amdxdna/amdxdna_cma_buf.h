/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2025, Advanced Micro Devices, Inc.
 */

#ifndef _AMDXDNA_CMA_BUF_H_
#define _AMDXDNA_CMA_BUF_H_

#include <drm/drm_device.h>
#include <linux/bitops.h>
#include <linux/dma-direction.h>
#include <linux/of.h>

struct amdxdna_dev;
struct amdxdna_gem_obj;

#define AMDXDNA_BO_FLAGS_CACHEABLE	BIT(24)

bool amdxdna_use_cma(void);
struct dma_buf *amdxdna_get_cma_buf_with_fallback(struct amdxdna_dev *xdna,
						  struct device *const *region_devs,
						  int max_regions,
						  struct device *fallback_dev,
						  size_t size, u64 flags);
int amdxdna_cma_region_init(struct amdxdna_dev *xdna, struct device_node *mem_np);
void amdxdna_cma_region_fini(struct amdxdna_dev *xdna);

/**
 * amdxdna_cma_sync_bo - synchronize CPU caches for a sub-range of an
 *                       amdxdna-exported CMA BO
 * @abo:    BO to sync.  Must be backed by an amdxdna CMA dma_buf (i.e.
 *          produced by amdxdna_get_cma_buf_with_fallback()).
 * @offset: byte offset within the BO.
 * @size:   number of bytes to sync.
 * @dir:    DMA_TO_DEVICE, DMA_FROM_DEVICE or DMA_BIDIRECTIONAL.
 *
 * Wraps dma_sync_single_for_{device,cpu}() against the *producer* device
 * that owns the underlying CMA region (parent for "rpu-cma", child for
 * "app-bank<N>").  Using the producer is required for correctness: the
 * bus address lives in its DMA address space and only its dma-ranges
 * yield the correct phys address for arch_sync_dma_for_*().
 *
 * Return: 0 on success, -ENODEV if @abo is not backed by an amdxdna CMA
 * dma_buf (caller should fall back to a generic flush path).
 */
int amdxdna_cma_sync_bo(struct amdxdna_gem_obj *abo, u64 offset, u64 size,
			enum dma_data_direction dir);

#endif /* _AMDXDNA_CMA_BUF_H */

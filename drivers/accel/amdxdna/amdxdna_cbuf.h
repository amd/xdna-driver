/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2026, Advanced Micro Devices, Inc.
 */
#ifndef _AMDXDNA_CBUF_H_
#define _AMDXDNA_CBUF_H_

#include "amdxdna_drv.h"
#include <drm/drm_device.h>
#include <linux/dma-buf.h>

bool amdxdna_use_carveout(struct amdxdna_dev *xdna);

/*
 * True when userspace create-BOs are backed by the cbuf path: the x86 debug
 * carveout, or -- on the platform transport -- ddev.dev's contiguous DMA pool
 * (the "aie" reserved region or system CMA). Such a client can allocate BOs
 * without PASID/SVA or an explicit carveout.
 */
static inline bool amdxdna_use_cbuf(struct amdxdna_dev *xdna)
{
	return amdxdna_use_carveout(xdna) || IS_ENABLED(CONFIG_DRM_ACCEL_AMDXDNA_PLAT);
}

int amdxdna_carveout_init(struct amdxdna_dev *xdna, u64 carveout_addr, u64 carveout_size);
void amdxdna_carveout_fini(struct amdxdna_dev *xdna);
void amdxdna_get_carveout_conf(struct amdxdna_dev *xdna, u64 *addr, u64 *size);
struct dma_buf *amdxdna_get_cbuf(struct drm_device *dev, size_t size, u64 alignment);

#endif

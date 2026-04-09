/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2026, Advanced Micro Devices, Inc.
 */
#ifndef _AMDXDNA_CBUF_H_
#define _AMDXDNA_CBUF_H_

#include <drm/drm_device.h>
#include <linux/dma-buf.h>

bool amdxdna_use_carveout(void);
void amdxdna_carveout_init(void);
void amdxdna_carveout_fini(void);
struct dma_buf *amdxdna_get_cbuf(struct drm_device *dev, size_t size, u64 alignment);

#endif

/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2025, Advanced Micro Devices, Inc.
 */
#ifndef _AMDXDNA_CARVEDOUT_BUF_H_
#define _AMDXDNA_CARVEDOUT_BUF_H_

#include <drm/drm_device.h>

bool amdxdna_use_carvedout(void);
void amdxdna_carvedout_init(void);
void amdxdna_carvedout_fini(void);
struct dma_buf *amdxdna_get_carvedout_buf(struct drm_device *dev, size_t size,
					  u64 alignment);

#endif

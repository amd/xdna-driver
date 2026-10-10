/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2026, Advanced Micro Devices, Inc.
 */

#ifndef _AMDXDNA_CMA_BUF_H_
#define _AMDXDNA_CMA_BUF_H_

#include "amdxdna_drv.h"
#include <drm/drm_device.h>
#include <linux/kconfig.h>

struct amdxdna_drm_create_bo;
struct amdxdna_gem_obj;
struct drm_gem_object;

static inline bool amdxdna_use_cma(struct amdxdna_dev *xdna)
{
#ifdef AMDXDNA_NPU3A
	return true;
#endif
	return IS_ENABLED(CONFIG_DRM_ACCEL_AMDXDNA_PLAT) ||
	       IS_ENABLED(CONFIG_DRM_ACCEL_AMDXDNA_VE2);
}

struct amdxdna_gem_obj *
amdxdna_get_cma_buf(struct drm_device *dev, struct amdxdna_drm_create_bo *args);

bool amdxdna_is_cma_bo(struct amdxdna_gem_obj *abo);

#endif /* _AMDXDNA_CMA_BUF_H_ */

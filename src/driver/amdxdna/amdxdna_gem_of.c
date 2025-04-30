// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2025, Advanced Micro Devices, Inc.
 */

#include <linux/dma-mapping.h>

#include "drm_local/amdxdna_accel.h"

#include "amdxdna_drm.h"
#include "amdxdna_gem_of.h"

/* For drm_driver->gem_create_object callback */
struct drm_gem_object *
amdxdna_gem_create_object_cb(struct drm_device *dev, size_t size)
{
	//TODO
	return NULL;
}

/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2025, Advanced Micro Devices, Inc.
 */

#ifndef _AMDXDNA_GEM_OF_H_
#define _AMDXDNA_GEM_OF_H_

#include <drm/drm_gem.h>

struct drm_gem_object *
amdxdna_gem_create_object_cb(struct drm_device *dev, size_t size);

#endif /* _AMDXDNA_GEM_OF_H_ */

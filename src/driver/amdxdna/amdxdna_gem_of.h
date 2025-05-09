/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2025, Advanced Micro Devices, Inc.
 */

#ifndef _AMDXDNA_GEM_OF_H_
#define _AMDXDNA_GEM_OF_H_

#include <drm/drm_file.h>
#include <drm/drm_gem.h>
#include <drm/drm_gem_dma_helper.h>

struct amdxdna_mem {
	u64			userptr;
	void			*kva;
	u64			dev_addr;
	size_t			size;
	struct page		**pages;
	u32			nr_pages;
#ifdef AMDXDNA_DEVEL
	struct sg_table		*sgt;
	u64			dma_addr; /* IOVA DMA address */
#endif
};

#define BO_SUBMIT_PINNED	BIT(0)
#define BO_SUBMIT_LOCKED	BIT(1)

struct amdxdna_gem_obj {
	struct drm_gem_dma_object	base;
	struct amdxdna_client           *client;
	u8                              type;
	u64                             flags;
	struct mutex                    lock; /* Protects: pinned, assigned_hwctx */
	struct amdxdna_mem              mem;
};

#define to_gobj(obj)		(&(obj)->base.base)
#define is_import_bo(obj)	(to_gobj(obj)->import_attach)

static inline struct amdxdna_gem_obj *to_xdna_obj(struct drm_gem_object *gobj)
{
	return container_of(gobj, struct amdxdna_gem_obj, base.base);
}

static inline void amdxdna_gem_put_obj(struct amdxdna_gem_obj *abo)
{
	drm_gem_object_put(to_gobj(abo));
}

struct amdxdna_gem_obj *amdxdna_gem_get_obj(struct amdxdna_client *client, u32 bo_hdl, u8 bo_type);
int amdxdna_drm_create_bo_ioctl(struct drm_device *dev, void *data, struct drm_file *filp);
int amdxdna_drm_get_bo_info_ioctl(struct drm_device *dev, void *data, struct drm_file *filp);
int amdxdna_drm_sync_bo_ioctl(struct drm_device *dev, void *data, struct drm_file *filp);

struct drm_gem_object *amdxdna_gem_create_object_cb(struct drm_device *dev, size_t size);

int amdxdna_gem_pin_nolock(struct amdxdna_gem_obj *abo);
int amdxdna_gem_pin(struct amdxdna_gem_obj *abo);
void amdxdna_gem_unpin(struct amdxdna_gem_obj *abo);

#endif /* _AMDXDNA_GEM_OF_H_ */

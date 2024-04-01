/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2024, Advanced Micro Devices, Inc.
 */

#ifndef _AMDXDNA_GEM_H_
#define _AMDXDNA_GEM_H_

#include <drm/drm_file.h>
#include <drm/drm_gem.h>
#include <drm/drm_gem_shmem_helper.h>

struct amdxdna_mem {
	u64			userptr;
	void			*kva;
	u64			dev_addr;
	size_t			size;
	struct page		**pages;
	u32			nr_pages;
	int			pin_cnt;
};

struct amdxdna_gem_obj {
	struct drm_gem_shmem_object	base;
	struct amdxdna_client		*client;
	u8				type;
	bool				pinned;
	spinlock_t			lock; /* Protects: pinned */
	u64				mmap_offset;
	struct amdxdna_mem		mem;
	struct amdxdna_gem_obj		*dev_heap;
	struct drm_mm			mm;
	struct drm_mm_node		mm_node;
};

#define to_gobj(obj)    (&(obj)->base.base)

static inline struct amdxdna_gem_obj *to_xdna_obj(struct drm_gem_object *gobj)
{
	return container_of(gobj, struct amdxdna_gem_obj, base.base);
}

static inline void amdxdna_put_dev_heap(struct amdxdna_gem_obj *dev_heap)
{
	drm_gem_object_put(&dev_heap->base.base);
}

struct drm_gem_object *
amdxdna_gem_create_object(struct drm_device *dev, size_t size);
int amdxdna_gem_pin_nolock(struct amdxdna_gem_obj *abo);
int amdxdna_gem_pin(struct amdxdna_gem_obj *abo);
void amdxdna_gem_unpin(struct amdxdna_gem_obj *abo);
struct amdxdna_gem_obj *amdxdna_gem_get_obj(struct drm_device *dev, u32 bo_hdl,
					    u8 bo_type, struct drm_file *filp);

int amdxdna_drm_create_bo_ioctl(struct drm_device *dev, void *data, struct drm_file *filp);
int amdxdna_drm_get_bo_info_ioctl(struct drm_device *dev, void *data, struct drm_file *filp);
int amdxdna_drm_sync_bo_ioctl(struct drm_device *dev, void *data, struct drm_file *filp);

#endif /* _AMDXDNA_GEM_H_ */

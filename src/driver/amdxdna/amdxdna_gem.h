/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2024, Advanced Micro Devices, Inc.
 *
 * Authors:
 *	Min Ma <min.ma@amd.com>
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
	u32			pin_cnt;
};

struct amdxdna_gem_obj {
	struct drm_gem_object	base;
	struct amdxdna_client	*client;
	struct amdxdna_mem	mem;
	u8			type;
	struct amdxdna_gem_obj	*dev_heap;

	union {
		struct drm_mm		mm;
		struct drm_mm_node	mm_node;
	};
};

#define to_xdna_gem_obj(obj)				\
	((struct amdxdna_gem_obj *)container_of((obj),	\
	struct amdxdna_gem_obj, base))

struct amdxdna_gem_shmem_obj {
	struct drm_gem_shmem_object	base;
	struct amdxdna_client		*client;
	u8				type;
	struct list_head		entry;
	u64				mmap_offset;
	bool				pinned;
};

#define to_xdna_gem_shmem_obj(shmem)				\
	((struct amdxdna_gem_shmem_obj *)container_of((shmem),	\
	struct amdxdna_gem_shmem_obj, base))

struct drm_gem_object *
amdxdna_gem_create_object(struct drm_device *dev, size_t size);
struct amdxdna_gem_obj *amdxdna_get_dev_heap(struct drm_file *filp);
int amdxdna_pin_pages(struct amdxdna_mem *mem);
void amdxdna_unpin_pages(struct amdxdna_mem *mem);

int amdxdna_drm_create_bo_ioctl(struct drm_device *dev, void *data, struct drm_file *filp);
int amdxdna_drm_get_bo_info_ioctl(struct drm_device *dev, void *data, struct drm_file *filp);
int amdxdna_drm_sync_bo_ioctl(struct drm_device *dev, void *data, struct drm_file *filp);

#endif /* _AMDXDNA_GEM_H_ */

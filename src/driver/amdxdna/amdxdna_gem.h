/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2024-2025, Advanced Micro Devices, Inc.
 */

#ifndef _AMDXDNA_GEM_H_
#define _AMDXDNA_GEM_H_

#include <drm/drm_file.h>
#include <drm/drm_gem.h>
#include <drm/drm_gem_shmem_helper.h>
#include <linux/hmm.h>

struct amdxdna_umap {
	struct vm_area_struct		*vma;
	struct mmu_interval_notifier	notifier;
	struct hmm_range		range;
	struct work_struct		hmm_unreg_work;
	struct amdxdna_gem_obj		*abo;
	struct list_head		node;
	struct kref			refcnt;
	bool				invalid;
	bool				unmapped;
};

struct amdxdna_mem {
	void				*kva;
	size_t				size;
	struct list_head		umap_list;
	bool				map_invalid;
#ifdef AMDXDNA_DEVEL
	u64				dma_addr; /* DMA mapped addr */
#endif
};

#define BO_SUBMIT_PINNED	BIT(0)
struct amdxdna_gem_obj {
	struct drm_gem_shmem_object	base;
	struct amdxdna_client		*client;
	u8				type;
	u64				flags;
	struct mutex			lock; /* Protects: pinned, assigned_ctx, mem.kv_addr */
	struct amdxdna_mem		mem;

	/* Below members are initialized when needed */
	struct drm_mm			mm; /* For AMDXDNA_BO_DEV_HEAP */
	struct drm_mm_node		mm_node; /* For AMDXDNA_BO_DEV / carvedout */
	u32				assigned_ctx; /* For debug bo */
	struct dma_buf			*dma_buf;
	struct dma_buf_attachment	*attach;
};

#define to_gobj(obj)    (&(obj)->base.base)
#define is_import_bo(obj) ((obj)->attach)

static inline struct amdxdna_gem_obj *to_xdna_obj(struct drm_gem_object *gobj)
{
	return container_of(gobj, struct amdxdna_gem_obj, base.base);
}

struct amdxdna_gem_obj *amdxdna_gem_get_obj(struct amdxdna_client *client,
					    u32 bo_hdl, u8 bo_type);
static inline void amdxdna_gem_put_obj(struct amdxdna_gem_obj *abo)
{
	drm_gem_object_put(to_gobj(abo));
}

void amdxdna_umap_put(struct amdxdna_umap *mapp);

struct drm_gem_object *
amdxdna_gem_create_shmem_object_cb(struct drm_device *dev, size_t size);
struct drm_gem_object *
amdxdna_gem_prime_import(struct drm_device *dev, struct dma_buf *dma_buf);
struct amdxdna_gem_obj *
amdxdna_drm_create_dev_bo(struct drm_device *dev, struct amdxdna_drm_create_bo *args,
			  struct drm_file *filp);

int amdxdna_gem_pin_nolock(struct amdxdna_gem_obj *abo);
int amdxdna_gem_pin(struct amdxdna_gem_obj *abo);
void amdxdna_gem_unpin(struct amdxdna_gem_obj *abo);

u32 amdxdna_gem_get_assigned_ctx(struct amdxdna_client *client, u32 bo_hdl);
int amdxdna_gem_set_assigned_ctx(struct amdxdna_client *client, u32 bo_hdl, u32 ctx_hdl);
void amdxdna_gem_clear_assigned_ctx(struct amdxdna_client *client, u32 bo_hdl);

int amdxdna_drm_create_bo_ioctl(struct drm_device *dev, void *data, struct drm_file *filp);
int amdxdna_drm_get_bo_info_ioctl(struct drm_device *dev, void *data, struct drm_file *filp);
int amdxdna_drm_sync_bo_ioctl(struct drm_device *dev, void *data, struct drm_file *filp);

void *amdxdna_gem_vmap(struct amdxdna_gem_obj *abo);
u64 amdxdna_gem_uva(struct amdxdna_gem_obj *abo);
u64 amdxdna_gem_dev_addr(struct amdxdna_gem_obj *abo);

#endif /* _AMDXDNA_GEM_H_ */

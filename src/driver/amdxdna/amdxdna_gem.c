// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2024, Advanced Micro Devices, Inc.
 */

#include "drm_local/amdxdna_accel.h"
#include <drm/drm_cache.h>

#include "amdxdna_drv.h"
#include "amdxdna_gem.h"

#define XDNA_32K_ALIGN		0x8000
#define XDNA_MAX_CMD_BO_SIZE	0x8000

static int amdxdna_pin_pages(struct amdxdna_mem *mem)
{
	int pinned, total_pinned = 0;

	if (mem->pin_cnt++ > 0)
		return 0;

	while (total_pinned < mem->nr_pages) {
		pinned = pin_user_pages_fast(mem->userptr +
					     (total_pinned << PAGE_SHIFT),
					     mem->nr_pages - total_pinned,
					     FOLL_WRITE | FOLL_LONGTERM,
					     &mem->pages[total_pinned]);
		if (pinned < 0) {
			mem->pin_cnt = 0;
			goto unpin;
		}
		total_pinned += pinned;
	}

	return 0;

unpin:
	if (total_pinned > 0)
		unpin_user_pages_dirty_lock(mem->pages, total_pinned, true);

	return pinned;
}

static void amdxdna_unpin_pages(struct amdxdna_mem *mem)
{
	if (--mem->pin_cnt > 0)
		return;

	unpin_user_pages_dirty_lock(mem->pages, mem->nr_pages, true);
}

static int
amdxdna_gem_insert_node_locked(struct amdxdna_gem_obj *heap, size_t size, bool use_vmap,
			       struct drm_mm_node *node, struct amdxdna_mem *mem)
{
	struct amdxdna_client *client = heap->client;
	struct amdxdna_dev *xdna = client->xdna;
	u64 offset;
	u32 align;
	int ret;

	align = 1 << max(PAGE_SHIFT, xdna->dev_info->dev_mem_buf_shift);
	ret = drm_mm_insert_node_generic(&heap->mm, node, size, align,
					 0, DRM_MM_INSERT_BEST);
	if (ret) {
		XDNA_ERR(xdna, "Failed to alloc dev bo memory, ret %d", ret);
		return ret;
	}

	mem->dev_addr = node->start;
	offset = mem->dev_addr - heap->mem.dev_addr;
	mem->userptr = heap->mem.userptr + offset;
	mem->size = size;
	mem->pages = &heap->mem.pages[offset >> PAGE_SHIFT];
	mem->nr_pages = mem->size >> PAGE_SHIFT;

	if (use_vmap) {
		WARN_ONCE(!heap->mem.pin_cnt, "Heap mem is unpined");
		mem->kva = vmap(mem->pages, mem->nr_pages, VM_MAP, PAGE_KERNEL);
		if (!mem->kva) {
			XDNA_ERR(xdna, "Failed to vmap");
			drm_mm_remove_node(node);
			return -EFAULT;
		}
	}

	return 0;
}

static void
amdxdna_gem_remove_node_locked(struct drm_mm_node *node, struct amdxdna_mem *mem)
{
	vunmap(mem->kva);
	drm_mm_remove_node(node);
}

static int
amdxdna_user_mem_init(struct amdxdna_mem *mem, u64 vaddr, size_t size)
{
	mem->userptr = vaddr;
	mem->size = size;
	mem->dev_addr = AMDXDNA_INVALID_ADDR;

	if (vaddr == AMDXDNA_INVALID_ADDR)
		return 0;

	mem->nr_pages = (PAGE_ALIGN(vaddr + mem->size) -
			 (vaddr & PAGE_MASK)) >> PAGE_SHIFT;

	mem->pages = kvcalloc(mem->nr_pages, sizeof(struct page *), GFP_KERNEL);
	if (!mem->pages) {
		mem->userptr = AMDXDNA_INVALID_ADDR;
		mem->size = 0;
		return -ENOMEM;
	}

	return 0;
}

static void
amdxdna_user_mem_fini(struct amdxdna_mem *mem)
{
	if (mem->pin_cnt > 0)
		unpin_user_pages_dirty_lock(mem->pages, mem->nr_pages, true);

	kvfree(mem->pages);
	memset(mem, 0, sizeof(*mem));
}

static void amdxdna_gem_destroy_obj(struct amdxdna_gem_obj *abo);

static void amdxdna_gem_obj_free(struct drm_gem_object *gobj)
{
	struct amdxdna_dev *xdna = to_xdna_dev(gobj->dev);
	struct amdxdna_gem_obj *abo = to_xdna_obj(gobj);

	if (abo->pinned)
		amdxdna_gem_unpin(abo);

	XDNA_DBG(xdna, "BO type %d userptr 0x%llx dev_addr 0x%llx",
		 abo->type, abo->mem.userptr, abo->mem.dev_addr);
	switch (abo->type) {
	case AMDXDNA_BO_DEV_HEAP:
		mutex_lock(&abo->client->mm_lock);
		drm_mm_takedown(&abo->mm);
		amdxdna_user_mem_fini(&abo->mem);
		mutex_unlock(&abo->client->mm_lock);
		break;
	case AMDXDNA_BO_DEV:
		mutex_lock(&abo->client->mm_lock);
		amdxdna_gem_remove_node_locked(&abo->mm_node, &abo->mem);
		mutex_unlock(&abo->client->mm_lock);
		drm_gem_object_put(to_gobj(abo->dev_heap));
		break;
	case AMDXDNA_BO_CMD:
		amdxdna_unpin_pages(&abo->mem);
		vunmap(abo->mem.kva - offset_in_page(abo->mem.userptr));
		amdxdna_user_mem_fini(&abo->mem);
		break;
	case AMDXDNA_BO_SHMEM:
		XDNA_DBG(xdna, "SHMEM bo pinned %d", abo->pinned);
		drm_gem_shmem_object_free(gobj);
		return;
	default:
		WARN_ONCE(1, "Unexpected BO type %d\n", abo->type);
		return;
	}

	drm_gem_object_release(gobj);
	amdxdna_gem_destroy_obj(abo);
}

static void amdxdna_gem_obj_close(struct drm_gem_object *gobj, struct drm_file *filp)
{
	struct amdxdna_gem_obj *abo = to_xdna_obj(gobj);

	if (abo->type != AMDXDNA_BO_DEV_HEAP)
		return;

	mutex_lock(&abo->client->mm_lock);
	drm_gem_object_put(to_gobj(abo->client->dev_heap));
	abo->client->dev_heap = NULL;
	mutex_unlock(&abo->client->mm_lock);
}

static const struct drm_gem_object_funcs amdxdna_gem_obj_funcs = {
	.close = amdxdna_gem_obj_close,
	.free = amdxdna_gem_obj_free,
};

static int amdxdna_gem_obj_mmap(struct drm_gem_object *gobj,
				struct vm_area_struct *vma)
{
	struct amdxdna_gem_obj *abo = to_xdna_obj(gobj);
	unsigned long num_pages;
	int ret;

	ret = drm_gem_shmem_object_mmap(gobj, vma);
	if (ret)
		return ret;

	num_pages = gobj->size >> PAGE_SHIFT;
	/* The buffer is based on memoey pages, indeed. Let's fix the flag. */
	vm_flags_mod(vma, VM_MIXEDMAP, VM_PFNMAP);
	ret = vm_insert_pages(vma, vma->vm_start, abo->base.pages, &num_pages);
	if (ret)
		XDNA_ERR(abo->client->xdna, "Failed insert pages, ret %d", ret);

	return ret;
}

static const struct drm_gem_object_funcs amdxdna_gem_shmem_funcs = {
	.free = amdxdna_gem_obj_free,
	.print_info = drm_gem_shmem_object_print_info,
	.pin = drm_gem_shmem_object_pin,
	.unpin = drm_gem_shmem_object_unpin,
	.get_sg_table = drm_gem_shmem_object_get_sg_table,
	.vmap = drm_gem_shmem_object_vmap,
	.vunmap = drm_gem_shmem_object_vunmap,
	.mmap = amdxdna_gem_obj_mmap,
	.vm_ops = &drm_gem_shmem_vm_ops,
};

static struct amdxdna_gem_obj *
amdxdna_gem_create_obj(struct drm_device *dev, size_t size,
		       enum amdxdna_bo_type type)
{
	struct amdxdna_gem_obj *abo;

	abo = kzalloc(sizeof(*abo), GFP_KERNEL);
	if (!abo)
		return ERR_PTR(-ENOMEM);

	/* The default funcs, caller should change if needed */
	to_gobj(abo)->funcs = &amdxdna_gem_obj_funcs;

	abo->pinned = false;
	abo->type = type;
	abo->assigned_hwctx = AMDXDNA_INVALID_CTX_HANDLE;
	abo->mmap_offset = AMDXDNA_INVALID_ADDR;
	mutex_init(&abo->lock);

	abo->mem.userptr = AMDXDNA_INVALID_ADDR;
	abo->mem.dev_addr = AMDXDNA_INVALID_ADDR;

	return abo;
}

static void amdxdna_gem_destroy_obj(struct amdxdna_gem_obj *abo)
{
	mutex_destroy(&abo->lock);
	kfree(abo);
}

/* For drm_driver->gem_create_object callback */
struct drm_gem_object *
amdxdna_gem_create_object_cb(struct drm_device *dev, size_t size)
{
	struct amdxdna_dev *xdna = to_xdna_dev(dev);
	struct amdxdna_gem_obj *abo;

	XDNA_DBG(xdna, "size 0x%lx", size);
	abo = amdxdna_gem_create_obj(dev, size, AMDXDNA_BO_SHMEM);
	if (IS_ERR(abo))
		return ERR_CAST(abo);

	to_gobj(abo)->funcs = &amdxdna_gem_shmem_funcs;
	return to_gobj(abo);
}

static struct amdxdna_gem_obj *
amdxdna_drm_alloc_shmem(struct drm_device *dev,
			struct amdxdna_drm_create_bo *args,
			struct drm_file *filp)
{
	struct amdxdna_client *client = filp->driver_priv;
	struct drm_gem_shmem_object *shmem;
	struct amdxdna_gem_obj *abo;

	shmem = drm_gem_shmem_create(dev, args->size);
	if (IS_ERR(shmem))
		return ERR_CAST(shmem);

	shmem->map_wc = false;

	abo = to_xdna_obj(&shmem->base);
	abo->client = client;
	abo->mmap_offset = drm_vma_node_offset_addr(&shmem->base.vma_node);

	return abo;
}

static struct amdxdna_gem_obj *
amdxdna_drm_create_dev_heap(struct drm_device *dev,
			    struct amdxdna_drm_create_bo *args,
			    struct drm_file *filp)
{
	struct amdxdna_client *client = filp->driver_priv;
	struct amdxdna_dev *xdna = to_xdna_dev(dev);
	struct amdxdna_gem_obj *abo;
	int ret;

	mutex_lock(&client->mm_lock);
	if (client->dev_heap) {
		XDNA_DBG(client->xdna, "dev heap is already created");
		ret = -EBUSY;
		goto mm_unlock;
	}

	if (args->size > xdna->dev_info->dev_mem_size) {
		XDNA_DBG(xdna, "Invalid dev heap size 0x%llx, limit 0x%lx",
			 args->size, xdna->dev_info->dev_mem_size);
		ret = -EINVAL;
		goto mm_unlock;
	}

	if (!access_ok((void __user *)(uintptr_t)args->vaddr, args->size)) {
		ret = -EFAULT;
		goto mm_unlock;
	}

	abo = amdxdna_gem_create_obj(&xdna->ddev, args->size, AMDXDNA_BO_DEV_HEAP);
	if (IS_ERR(abo)) {
		ret = PTR_ERR(abo);
		goto mm_unlock;
	}

	drm_gem_private_object_init(&xdna->ddev, to_gobj(abo), PAGE_ALIGN(args->size));

	ret = amdxdna_user_mem_init(&abo->mem, args->vaddr, to_gobj(abo)->size);
	if (ret) {
		XDNA_ERR(xdna, "user mem init failed, ret %d", ret);
		goto release_obj;
	}

	abo->client = client;
	abo->mem.dev_addr = client->xdna->dev_info->dev_mem_base;
	drm_mm_init(&abo->mm, abo->mem.dev_addr, abo->mem.size);

	client->dev_heap = abo;
	/* When close(), put this object */
	drm_gem_object_get(to_gobj(abo));
	mutex_unlock(&client->mm_lock);

	return abo;

release_obj:
	drm_gem_object_release(to_gobj(abo));
	amdxdna_gem_destroy_obj(abo);
mm_unlock:
	mutex_unlock(&client->mm_lock);
	return ERR_PTR(ret);
}

struct amdxdna_gem_obj *
amdxdna_drm_alloc_dev_bo(struct drm_device *dev,
			 struct amdxdna_drm_create_bo *args,
			 struct drm_file *filp, bool use_vmap)
{
	struct amdxdna_client *client = filp->driver_priv;
	struct amdxdna_dev *xdna = to_xdna_dev(dev);
	size_t aligned_sz = PAGE_ALIGN(args->size);
	struct amdxdna_gem_obj *abo, *heap;
	int ret;

	mutex_lock(&client->mm_lock);
	heap = client->dev_heap;
	if (!heap) {
		ret = -EINVAL;
		goto mm_unlock;
	}

	if (args->size > heap->mem.size) {
		XDNA_DBG(xdna, "Invalid dev bo size 0x%llx, limit 0x%lx",
			 args->size, heap->mem.size);
		ret = -EINVAL;
		goto mm_unlock;
	}

	abo = amdxdna_gem_create_obj(&xdna->ddev, aligned_sz, AMDXDNA_BO_DEV);
	if (IS_ERR(abo)) {
		ret = PTR_ERR(abo);
		goto mm_unlock;
	}

	drm_gem_private_object_init(&xdna->ddev, to_gobj(abo), aligned_sz);

	ret = amdxdna_gem_insert_node_locked(heap, aligned_sz, use_vmap,
					     &abo->mm_node, &abo->mem);
	if (ret) {
		XDNA_ERR(xdna, "Failed to alloc dev bo memory, ret %d", ret);
		goto free_bo;
	}

	abo->client = client;
	abo->dev_heap = heap;
	drm_gem_object_get(to_gobj(heap));
	mutex_unlock(&client->mm_lock);
	return abo;

free_bo:
	drm_gem_object_release(to_gobj(abo));
	amdxdna_gem_destroy_obj(abo);
mm_unlock:
	mutex_unlock(&client->mm_lock);
	return ERR_PTR(ret);
}

static struct amdxdna_gem_obj *
amdxdna_drm_create_cmd_bo(struct drm_device *dev,
			  struct amdxdna_drm_create_bo *args,
			  struct drm_file *filp)
{
	struct amdxdna_dev *xdna = to_xdna_dev(dev);
	struct amdxdna_gem_obj *abo;
	int ret;

	if (args->size > XDNA_MAX_CMD_BO_SIZE) {
		XDNA_ERR(xdna, "Command bo size 0x%llx too large", args->size);
		return ERR_PTR(-EINVAL);
	}

	abo = amdxdna_gem_create_obj(&xdna->ddev, args->size, AMDXDNA_BO_CMD);
	if (IS_ERR(abo))
		return ERR_CAST(abo);

	drm_gem_private_object_init(&xdna->ddev, to_gobj(abo), PAGE_ALIGN(args->size));

	ret = amdxdna_user_mem_init(&abo->mem, args->vaddr, to_gobj(abo)->size);
	if (ret) {
		XDNA_ERR(xdna, "user mem init failed, ret %d", ret);
		goto release_obj;
	}

	ret = amdxdna_pin_pages(&abo->mem);
	if (ret) {
		XDNA_ERR(xdna, "user memory init failed, ret %d", ret);
		goto fini_user_mem;
	}

	abo->mem.kva = vmap(abo->mem.pages, abo->mem.nr_pages, VM_MAP, PAGE_KERNEL);
	if (!abo->mem.kva) {
		XDNA_ERR(xdna, "vmap failed");
		ret = -EFAULT;
		goto unpin;
	}
	abo->mem.kva += offset_in_page(abo->mem.userptr);

	return abo;

unpin:
	amdxdna_unpin_pages(&abo->mem);
fini_user_mem:
	amdxdna_user_mem_fini(&abo->mem);
release_obj:
	drm_gem_object_release(to_gobj(abo));
	amdxdna_gem_destroy_obj(abo);
	return ERR_PTR(ret);
}

int amdxdna_drm_create_bo_ioctl(struct drm_device *dev, void *data, struct drm_file *filp)
{
	struct amdxdna_dev *xdna = to_xdna_dev(dev);
	struct amdxdna_drm_create_bo *args = data;
	struct amdxdna_gem_obj *abo;
	int ret;

	if (args->flags || !args->size)
		return -EINVAL;

	XDNA_DBG(xdna, "BO arg type %d vaddr 0x%llx size 0x%llx flags 0x%llx",
		 args->type, args->vaddr, args->size, args->flags);
	switch (args->type) {
	case AMDXDNA_BO_SHMEM:
		abo = amdxdna_drm_alloc_shmem(dev, args, filp);
		break;
	case AMDXDNA_BO_DEV_HEAP:
		abo = amdxdna_drm_create_dev_heap(dev, args, filp);
		break;
	case AMDXDNA_BO_DEV:
		abo = amdxdna_drm_alloc_dev_bo(dev, args, filp, false);
		break;
	case AMDXDNA_BO_CMD:
		abo = amdxdna_drm_create_cmd_bo(dev, args, filp);
		break;
	default:
		return -EINVAL;
	}
	if (IS_ERR(abo))
		return PTR_ERR(abo);

	/* ready to publish object to userspace */
	ret = drm_gem_handle_create(filp, to_gobj(abo), &args->handle);
	if (ret) {
		XDNA_ERR(xdna, "Create handle failed");
		goto put_obj;
	}

	XDNA_DBG(xdna, "BO hdl %d type %d userptr 0x%llx dev_addr 0x%llx nr_pages %d",
		 args->handle, args->type, abo->mem.userptr,
		 abo->mem.dev_addr, abo->mem.nr_pages);
put_obj:
	/* Dereference object reference. Handle holds it now. */
	drm_gem_object_put(to_gobj(abo));
	return ret;
}

struct drm_gem_object *
amdxdna_gem_import_sg_table(struct drm_device *dev,
			    struct dma_buf_attachment *attach,
			    struct sg_table *sgt)
{
	struct drm_gem_object *gobj;
	struct amdxdna_gem_obj *abo;

	gobj = drm_gem_shmem_prime_import_sg_table(dev, attach, sgt);
	if (IS_ERR(gobj))
		return gobj;

	abo = to_xdna_obj(gobj);
	abo->mmap_offset = drm_vma_node_offset_addr(&gobj->vma_node);

	return gobj;
}

int amdxdna_gem_pin_nolock(struct amdxdna_gem_obj *abo)
{
	struct amdxdna_dev *xdna = to_xdna_dev(to_gobj(abo)->dev);
	int ret;

	if (abo->type == AMDXDNA_BO_SHMEM) {
		if (is_import_bo(abo))
			return 0;

		ret = drm_gem_shmem_pin(&abo->base);
		if (ret) {
			XDNA_ERR(xdna, "pin shmem bo failed, ret %d", ret);
			return ret;
		}
	} else if (abo->type == AMDXDNA_BO_DEV) {
		ret = amdxdna_gem_pin(abo->dev_heap);
		if (ret) {
			XDNA_ERR(xdna, "pin dev bo failed, ret %d", ret);
			return ret;
		}
	} else {
		ret = amdxdna_pin_pages(&abo->mem);
		if (ret) {
			XDNA_ERR(xdna, "pin gem bo failed, ret %d", ret);
			return ret;
		}
	}

	return 0;
}

int amdxdna_gem_pin(struct amdxdna_gem_obj *abo)
{
	int ret;

	mutex_lock(&abo->lock);
	ret = amdxdna_gem_pin_nolock(abo);
	mutex_unlock(&abo->lock);

	return ret;
}

void amdxdna_gem_unpin(struct amdxdna_gem_obj *abo)
{
	mutex_lock(&abo->lock);

	if (abo->type == AMDXDNA_BO_SHMEM) {
		if (is_import_bo(abo))
			goto out_unlock;
		drm_gem_shmem_unpin(&abo->base);
	} else if (abo->type == AMDXDNA_BO_DEV) {
		amdxdna_gem_unpin(abo->dev_heap);
	} else {
		amdxdna_unpin_pages(&abo->mem);
	}

out_unlock:
	mutex_unlock(&abo->lock);
}

struct amdxdna_gem_obj *amdxdna_gem_get_obj(struct amdxdna_client *client,
					    u32 bo_hdl, u8 bo_type)
{
	struct amdxdna_dev *xdna = client->xdna;
	struct amdxdna_gem_obj *abo;
	struct drm_gem_object *gobj;

	gobj = drm_gem_object_lookup(client->filp, bo_hdl);
	if (!gobj) {
		XDNA_DBG(xdna, "Can not find bo %d", bo_hdl);
		return NULL;
	}

	abo = to_xdna_obj(gobj);
	if ((bo_type == AMDXDNA_BO_INVALID) || (abo->type == bo_type))
		return abo;

	drm_gem_object_put(gobj);
	return NULL;
}

int amdxdna_drm_get_bo_info_ioctl(struct drm_device *dev, void *data, struct drm_file *filp)
{
	struct amdxdna_drm_get_bo_info *args = data;
	struct amdxdna_dev *xdna = to_xdna_dev(dev);
	struct amdxdna_gem_obj *abo;
	struct drm_gem_object *gobj;
	int ret = 0;

	if (args->ext_flags)
		return -EINVAL;

	gobj = drm_gem_object_lookup(filp, args->handle);
	if (!gobj) {
		XDNA_DBG(xdna, "Lookup GEM object %d failed", args->handle);
		return -ENOENT;
	}

	abo = to_xdna_obj(gobj);
	args->map_offset = abo->mmap_offset;
	args->vaddr = abo->mem.userptr;
	args->xdna_addr = abo->mem.dev_addr;

	XDNA_DBG(xdna, "map_offset 0x%llx, vaddr 0x%llx, xdna_addr 0x%llx",
		 args->map_offset, args->vaddr, args->xdna_addr);

	drm_gem_object_put(gobj);
	return ret;
}

/*
 * The sync bo ioctl is to make sure the CPU cache is in sync with memory.
 * This is required because NPU is not cache coherent device. CPU cache
 * flushing/invalidation is expensive so it is best to handle this outside
 * of the command submission path. This ioctl allows explicit cache
 * flushing/invalidation outside of the critical path.
 */
int amdxdna_drm_sync_bo_ioctl(struct drm_device *dev,
			      void *data, struct drm_file *filp)
{
	struct amdxdna_dev *xdna = to_xdna_dev(dev);
	struct amdxdna_drm_sync_bo *args = data;
	struct amdxdna_gem_obj *abo;
	struct drm_gem_object *gobj;
	int ret;

	gobj = drm_gem_object_lookup(filp, args->handle);
	if (!gobj) {
		XDNA_ERR(xdna, "Lookup GEM object failed");
		return -ENOENT;
	}
	abo = to_xdna_obj(gobj);

	ret = amdxdna_gem_pin(abo);
	if (ret)
		goto put_obj;

	if (abo->type == AMDXDNA_BO_SHMEM) {
		if (is_import_bo(abo))
			drm_clflush_sg(abo->base.sgt);
		else
			drm_clflush_pages(abo->base.pages, gobj->size >> PAGE_SHIFT);
	} else {
		drm_clflush_pages(abo->mem.pages, abo->mem.nr_pages);
	}

	amdxdna_gem_unpin(abo);

	XDNA_DBG(xdna, "Sync bo %d offset 0x%llx, size 0x%llx\n",
		 args->handle, args->offset, args->size);

put_obj:
	drm_gem_object_put(gobj);
	return ret;
}

u32 amdxdna_gem_get_assigned_hwctx(struct amdxdna_client *client, u32 bo_hdl)
{
	struct amdxdna_gem_obj *abo = amdxdna_gem_get_obj(client, bo_hdl, AMDXDNA_BO_INVALID);
	u32 ctxid;

	if (!abo)
		return AMDXDNA_INVALID_CTX_HANDLE;

	mutex_lock(&abo->lock);
	ctxid = abo->assigned_hwctx;
	if (!idr_find(&client->hwctx_idr, ctxid))
		ctxid = AMDXDNA_INVALID_CTX_HANDLE;
	mutex_unlock(&abo->lock);

	amdxdna_gem_put_obj(abo);
	return ctxid;
}

int amdxdna_gem_set_assigned_hwctx(struct amdxdna_client *client, u32 bo_hdl, u32 ctxid)
{
	struct amdxdna_gem_obj *abo = amdxdna_gem_get_obj(client, bo_hdl, AMDXDNA_BO_INVALID);
	int ret = 0;

	if (!abo)
		return -EINVAL;

	mutex_lock(&abo->lock);
	if (!idr_find(&client->hwctx_idr, abo->assigned_hwctx))
		abo->assigned_hwctx = ctxid;
	else if (ctxid != abo->assigned_hwctx)
		ret = -EBUSY;
	mutex_unlock(&abo->lock);

	amdxdna_gem_put_obj(abo);
	return ret;
}

void amdxdna_gem_clear_assigned_hwctx(struct amdxdna_client *client, u32 bo_hdl)
{
	struct amdxdna_gem_obj *abo = amdxdna_gem_get_obj(client, bo_hdl, AMDXDNA_BO_INVALID);

	if (!abo)
		return;

	mutex_lock(&abo->lock);
	abo->assigned_hwctx = AMDXDNA_INVALID_CTX_HANDLE;
	mutex_unlock(&abo->lock);

	amdxdna_gem_put_obj(abo);
}

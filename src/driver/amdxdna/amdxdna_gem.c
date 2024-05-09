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
amdxdna_user_mem_init(struct amdxdna_mem *mem, u64 vaddr, size_t size)
{
	mem->userptr = vaddr;
	mem->size = size;
	mem->dev_addr = AMDXDNA_INVALID_ADDR;

	mem->nr_pages = (PAGE_ALIGN(vaddr + mem->size) -
			 (vaddr & PAGE_MASK)) >> PAGE_SHIFT;

	mem->pages = kvcalloc(mem->nr_pages, sizeof(struct page *), GFP_KERNEL);
	if (!mem->pages)
		return -ENOMEM;

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

static void amdxdna_gem_obj_free(struct drm_gem_object *gobj)
{
	struct amdxdna_gem_obj *abo = to_xdna_obj(gobj);

	if (abo->pinned)
		amdxdna_gem_unpin(abo);

	XDNA_DBG(abo->client->xdna, "type %d userptr 0x%llx dev_addr 0x%llx",
		 abo->type, abo->mem.userptr, abo->mem.dev_addr);
	switch (abo->type) {
	case AMDXDNA_BO_DEV_HEAP:
		drm_mm_takedown(&abo->mm);
		amdxdna_user_mem_fini(&abo->mem);
		abo->client->dev_heap = AMDXDNA_INVALID_BO_HANDLE;
		break;
	case AMDXDNA_BO_DEV:
		mutex_lock(&abo->client->mm_lock);
		drm_mm_remove_node(&abo->mm_node);
		mutex_unlock(&abo->client->mm_lock);
		amdxdna_put_dev_heap(abo->dev_heap);
		break;
	case AMDXDNA_BO_CMD:
		amdxdna_unpin_pages(&abo->mem);
		vunmap(abo->mem.kva - offset_in_page(abo->mem.userptr));
		amdxdna_user_mem_fini(&abo->mem);
		break;
	case AMDXDNA_BO_SHMEM:
		XDNA_DBG(abo->client->xdna, "SHMEM bo pinned %d", abo->pinned);
		drm_gem_shmem_object_free(gobj);
		return;
	default:
		WARN_ONCE(1, "Unexpected BO type %d\n", abo->type);
		return;
	}

	drm_gem_object_release(gobj);
	mutex_destroy(&abo->lock);
	kfree(abo);
}

static const struct drm_gem_object_funcs amdxdna_gem_obj_funcs = {
	.free = amdxdna_gem_obj_free,
};

static const struct drm_gem_object_funcs amdxdna_gem_shmem_funcs = {
	.free = amdxdna_gem_obj_free,
	.print_info = drm_gem_shmem_object_print_info,
	.pin = drm_gem_shmem_object_pin,
	.unpin = drm_gem_shmem_object_unpin,
	.get_sg_table = drm_gem_shmem_object_get_sg_table,
	.vmap = drm_gem_shmem_object_vmap,
	.vunmap = drm_gem_shmem_object_vunmap,
	.mmap = drm_gem_shmem_object_mmap,
	.vm_ops = &drm_gem_shmem_vm_ops,
};

struct drm_gem_object *
amdxdna_gem_create_object(struct drm_device *dev, size_t size)
{
	struct amdxdna_dev *xdna = to_xdna_dev(dev);
	struct amdxdna_gem_obj *abo;

	XDNA_DBG(xdna, "size 0x%lx", size);
	abo = kzalloc(sizeof(*abo), GFP_KERNEL);
	if (!abo)
		return ERR_PTR(-ENOMEM);

	to_gobj(abo)->funcs = &amdxdna_gem_shmem_funcs;

	return to_gobj(abo);
}

static struct amdxdna_gem_obj *
amdxdna_drm_alloc_shmem(struct drm_device *dev,
			struct amdxdna_drm_create_bo *args,
			struct drm_file *filp)
{
	struct drm_gem_shmem_object *shmem;
	struct amdxdna_gem_obj *abo;

	shmem = drm_gem_shmem_create(dev, args->size);
	if (IS_ERR(shmem))
		return ERR_CAST(shmem);

	shmem->map_wc = false;

	abo = to_xdna_obj(&shmem->base);
	abo->type = AMDXDNA_BO_SHMEM;
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

	if (args->size > xdna->dev_info->dev_mem_size) {
		XDNA_DBG(xdna, "Invalid dev heap size 0x%llx, limit 0x%lx",
			 args->size, xdna->dev_info->dev_mem_size);
		return ERR_PTR(-EINVAL);
	}

	if (!access_ok((void __user *)(uintptr_t)args->vaddr, args->size))
		return ERR_PTR(-EFAULT);

	abo = kzalloc(sizeof(*abo), GFP_KERNEL);
	if (!abo)
		return ERR_PTR(-ENOMEM);

	drm_gem_private_object_init(&xdna->ddev, to_gobj(abo), PAGE_ALIGN(args->size));
	to_gobj(abo)->funcs = &amdxdna_gem_obj_funcs;
	abo->type = AMDXDNA_BO_DEV_HEAP;

	ret = amdxdna_user_mem_init(&abo->mem, args->vaddr, to_gobj(abo)->size);
	if (ret) {
		XDNA_ERR(xdna, "user mem init failed, ret %d", ret);
		goto release_obj;
	}

	abo->mem.dev_addr = client->xdna->dev_info->dev_mem_base;
	drm_mm_init(&abo->mm, abo->mem.dev_addr, abo->mem.size);

	return abo;

release_obj:
	drm_gem_object_release(to_gobj(abo));
	kfree(abo);
	return ERR_PTR(ret);
}

static struct amdxdna_gem_obj *
amdxdna_drm_alloc_dev_bo(struct drm_device *dev,
			 struct amdxdna_drm_create_bo *args,
			 struct drm_file *filp)
{
	struct amdxdna_client *client = filp->driver_priv;
	struct amdxdna_dev *xdna = to_xdna_dev(dev);
	size_t aligned_sz = PAGE_ALIGN(args->size);
	struct amdxdna_gem_obj *abo, *heap;
	u64 offset;
	u32 align;
	int ret;

	heap = amdxdna_gem_get_obj(dev, client->dev_heap, AMDXDNA_BO_DEV_HEAP, filp);
	if (!heap) {
		XDNA_DBG(xdna, "dev heap is not created");
		return ERR_PTR(-EINVAL);
	}

	if (args->size > heap->mem.size) {
		XDNA_DBG(xdna, "Invalid dev bo size 0x%llx, limit 0x%lx",
			 args->size, heap->mem.size);
		ret = -EINVAL;
		goto put_and_err;
	}

	abo = kzalloc(sizeof(*abo), GFP_KERNEL);
	if (!abo) {
		ret = -ENOMEM;
		goto put_and_err;
	}

	drm_gem_private_object_init(&xdna->ddev, to_gobj(abo), aligned_sz);
	to_gobj(abo)->funcs = &amdxdna_gem_obj_funcs;
	abo->type = AMDXDNA_BO_DEV;
	abo->dev_heap = heap;

	align = 1 << xdna->dev_info->dev_mem_buf_shift;
	ret = drm_mm_insert_node_generic(&heap->mm, &abo->mm_node, aligned_sz,
					 align, 0, DRM_MM_INSERT_BEST);
	if (ret) {
		XDNA_ERR(xdna, "Failed to alloc dev bo memory, ret %d", ret);
		goto free_bo;
	}

	abo->mem.dev_addr = abo->mm_node.start;
	offset = abo->mem.dev_addr - heap->mem.dev_addr;
	abo->mem.userptr = heap->mem.userptr + offset;
	abo->mem.size = to_gobj(abo)->size;
	abo->mem.pages = &heap->mem.pages[offset >> PAGE_SHIFT];
	abo->mem.nr_pages = (PAGE_ALIGN(abo->mem.dev_addr + abo->mem.size) -
			     (abo->mem.dev_addr & PAGE_MASK)) >> PAGE_SHIFT;

	return abo;

free_bo:
	drm_gem_object_release(to_gobj(abo));
	kfree(abo);
put_and_err:
	amdxdna_put_dev_heap(heap);
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

	abo = kzalloc(sizeof(*abo), GFP_KERNEL);
	if (!abo)
		return ERR_PTR(-ENOMEM);

	drm_gem_private_object_init(&xdna->ddev, to_gobj(abo), PAGE_ALIGN(args->size));
	to_gobj(abo)->funcs = &amdxdna_gem_obj_funcs;
	abo->type = AMDXDNA_BO_CMD;

	ret = amdxdna_user_mem_init(&abo->mem, args->vaddr, to_gobj(abo)->size);
	if (ret) {
		XDNA_ERR(xdna, "user mem init failed, ret %d", ret);
		goto release_obj;
	}

	ret = amdxdna_pin_pages(&abo->mem);
	if (ret) {
		XDNA_ERR(xdna, "user memory init failed, ret %d", ret);
		goto fini_user_map;
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
fini_user_map:
	amdxdna_user_mem_fini(&abo->mem);
release_obj:
	drm_gem_object_release(to_gobj(abo));
	kfree(abo);
	return ERR_PTR(ret);
}

int amdxdna_drm_create_bo_ioctl(struct drm_device *dev, void *data, struct drm_file *filp)
{
	struct amdxdna_client *client = filp->driver_priv;
	struct amdxdna_dev *xdna = to_xdna_dev(dev);
	struct amdxdna_drm_create_bo *args = data;
	struct amdxdna_gem_obj *abo;
	int ret;

	if (args->flags || !args->size)
		return -EINVAL;

	XDNA_DBG(xdna, "type %d vaddr 0x%llx size 0x%llx flags 0x%llx",
		 args->type, args->vaddr, args->size, args->flags);
	mutex_lock(&client->mm_lock);
	switch (args->type) {
	case AMDXDNA_BO_SHMEM:
		abo = amdxdna_drm_alloc_shmem(dev, args, filp);
		break;
	case AMDXDNA_BO_DEV_HEAP:
		if (client->dev_heap != AMDXDNA_INVALID_BO_HANDLE) {
			XDNA_DBG(client->xdna, "dev heap is already created");
			ret = -EINVAL;
			goto err_unlock;
		}

		abo = amdxdna_drm_create_dev_heap(dev, args, filp);
		break;
	case AMDXDNA_BO_DEV:
		abo = amdxdna_drm_alloc_dev_bo(dev, args, filp);
		break;
	case AMDXDNA_BO_CMD:
		abo = amdxdna_drm_create_cmd_bo(dev, args, filp);
		break;
	default:
		ret = -EINVAL;
		goto err_unlock;
	}
	if (IS_ERR(abo)) {
		ret = PTR_ERR(abo);
		goto err_unlock;
	}

	/* ready to publish object to userspace */
	ret = drm_gem_handle_create(filp, to_gobj(abo), &args->handle);
	if (ret) {
		XDNA_ERR(client->xdna, "Create handle failed");
		goto put_bo;
	}

	abo->client = client;
	abo->pinned = false;
	abo->assigned_hwctx = AMDXDNA_INVALID_CTX_HANDLE;
	mutex_init(&abo->lock);
	if (abo->type == AMDXDNA_BO_DEV_HEAP)
		client->dev_heap = args->handle;

	XDNA_DBG(xdna, "bo hdl %d type %d userptr 0x%llx dev_addr 0x%llx nr_pages %d",
		 args->handle, args->type, abo->mem.userptr,
		 abo->mem.dev_addr, abo->mem.nr_pages);
put_bo:
	/* dereference object reference. Handle holds it now */
	drm_gem_object_put(to_gobj(abo));
err_unlock:
	mutex_unlock(&client->mm_lock);
	return ret;
}

int amdxdna_gem_pin_nolock(struct amdxdna_gem_obj *abo)
{
	int ret;

	if (abo->type == AMDXDNA_BO_SHMEM) {
		ret = drm_gem_shmem_pin(&abo->base);
		if (ret) {
			XDNA_ERR(abo->client->xdna, "pin shmem bo failed, ret %d", ret);
			return ret;
		}
	} else if (abo->type == AMDXDNA_BO_DEV) {
		ret = amdxdna_gem_pin(abo->dev_heap);
		if (ret) {
			XDNA_ERR(abo->client->xdna, "pin dev bo failed, ret %d", ret);
			return ret;
		}
	} else {
		ret = amdxdna_pin_pages(&abo->mem);
		if (ret) {
			XDNA_ERR(abo->client->xdna, "pin gem bo failed, ret %d", ret);
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

	if (abo->type == AMDXDNA_BO_SHMEM)
		drm_gem_shmem_unpin(&abo->base);
	else if (abo->type == AMDXDNA_BO_DEV)
		amdxdna_gem_unpin(abo->dev_heap);
	else
		amdxdna_unpin_pages(&abo->mem);

	mutex_unlock(&abo->lock);
}

struct amdxdna_gem_obj *amdxdna_gem_get_obj(struct drm_device *dev, u32 bo_hdl,
					    u8 bo_type, struct drm_file *filp)
{
	struct amdxdna_dev *xdna = to_xdna_dev(dev);
	struct amdxdna_gem_obj *abo;
	struct drm_gem_object *gobj;

	gobj = drm_gem_object_lookup(filp, bo_hdl);
	if (!gobj) {
		XDNA_DBG(xdna, "can not find bo %d", bo_hdl);
		return NULL;
	}

	abo = to_xdna_obj(gobj);
	if (abo->type != bo_type)
		goto put_bo;

	return abo;

put_bo:
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
		XDNA_DBG(xdna, "Lookup GEM object failed");
		return -ENOENT;
	}

	abo = to_xdna_obj(gobj);
	switch (abo->type) {
	case AMDXDNA_BO_DEV_HEAP:
	case AMDXDNA_BO_DEV:
		args->map_offset = AMDXDNA_INVALID_ADDR;
		args->vaddr = abo->mem.userptr;
		args->xdna_addr = abo->mem.dev_addr;
		break;
	case AMDXDNA_BO_CMD:
		args->map_offset = AMDXDNA_INVALID_ADDR;
		args->vaddr = abo->mem.userptr;
		args->xdna_addr = AMDXDNA_INVALID_ADDR;
		break;
	case AMDXDNA_BO_SHMEM:
		args->map_offset = abo->mmap_offset;
		args->vaddr = AMDXDNA_INVALID_ADDR;
		args->xdna_addr = AMDXDNA_INVALID_ADDR;
		break;
	default:
		drm_WARN_ON(&xdna->ddev, 1);
		ret = -EINVAL;
		break;
	}

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

	if (abo->type == AMDXDNA_BO_SHMEM)
		drm_clflush_pages(abo->base.pages, gobj->size >> PAGE_SHIFT);
	else
		drm_clflush_pages(abo->mem.pages, abo->mem.nr_pages);

	amdxdna_gem_unpin(abo);

	XDNA_DBG(xdna, "Sync bo %d offset 0x%llx, size 0x%llx\n",
		 args->handle, args->offset, args->size);

put_obj:
	drm_gem_object_put(gobj);
	return ret;
}

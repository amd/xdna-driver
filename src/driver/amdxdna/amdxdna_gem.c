// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2024, Advanced Micro Devices, Inc.
 */

#include "drm_local/amdxdna_accel.h"
#include <drm/drm_cache.h>

#include "amdxdna_drv.h"
#include "amdxdna_gem.h"

/*
 * The amdxdna_pin_pages() and amdxdna_unpin_pages() are lockless.
 * If this memory needs to be shared, the caller needs to protect this two
 * calls in a common lock.
 */
int amdxdna_pin_pages(struct amdxdna_mem *mem)
{
	int pinned, total_pinned = 0;

	if (mem->pages) {
		mem->pin_cnt++;
		return 0;
	}

	mem->pages = kvmalloc_array(mem->nr_pages, sizeof(struct page *),
				    GFP_KERNEL);
	if (!mem->pages)
		return -ENOMEM;

	while (total_pinned < mem->nr_pages) {
		pinned = pin_user_pages_fast(mem->userptr +
					     (total_pinned << PAGE_SHIFT),
					     mem->nr_pages - total_pinned,
					     FOLL_WRITE | FOLL_LONGTERM,
					     &mem->pages[total_pinned]);
		if (pinned < 0)
			goto unpin;
		total_pinned += pinned;
	}

	return 0;
unpin:
	if (total_pinned > 0)
		unpin_user_pages_dirty_lock(mem->pages, total_pinned, true);
	kvfree(mem->pages);
	return pinned;
}

void amdxdna_unpin_pages(struct amdxdna_mem *mem)
{
	if (--mem->pin_cnt > 0)
		return;

	unpin_user_pages_dirty_lock(mem->pages, mem->nr_pages, true);
	kvfree(mem->pages);
	mem->pages = NULL;
}

static void
amdxdna_user_mem_init(struct amdxdna_mem *mem, u64 vaddr, size_t size)
{
	mem->userptr = vaddr;
	mem->size = size;
	mem->dev_addr = AMDXDNA_INVALID_ADDR;

	mem->nr_pages = (PAGE_ALIGN(vaddr + mem->size) -
			 (vaddr & PAGE_MASK)) >> PAGE_SHIFT;
}

static void
amdxdna_user_mem_fini(struct amdxdna_mem *mem)
{
	if (mem->pages) {
		unpin_user_pages_dirty_lock(mem->pages, mem->nr_pages, true);
		kvfree(mem->pages);
	}

	memset(mem, 0, sizeof(*mem));
}

static void amdxdna_gem_obj_free(struct drm_gem_object *gobj)
{
	struct amdxdna_gem_obj *abo = to_xdna_gem_obj(gobj);

	switch (abo->type) {
	case AMDXDNA_BO_DEV_HEAP:
		XDNA_DBG(abo->client->xdna, "type dev heap bo");
		drm_mm_takedown(&abo->mm);
		amdxdna_user_mem_fini(&abo->mem);
		abo->client->dev_heap = AMDXDNA_INVALID_BO_HANDLE;
		break;
	case AMDXDNA_BO_DEV:
		XDNA_DBG(abo->client->xdna, "type dev bo");
		mutex_lock(&abo->client->mm_lock);
		drm_mm_remove_node(&abo->mm_node);
		mutex_unlock(&abo->client->mm_lock);
		drm_gem_object_put(&abo->dev_heap->base);
		break;
	case AMDXDNA_BO_CMD:
		amdxdna_unpin_pages(&abo->mem);
		vunmap(abo->mem.kva - offset_in_page(abo->mem.userptr));
		amdxdna_user_mem_fini(&abo->mem);
		break;
	default:
		WARN_ONCE(1, "Unexpected BO type %d\n", abo->type);
		return;
	}

	drm_gem_object_release(gobj);
	kfree(abo);
}

static const struct drm_gem_object_funcs amdxdna_gem_obj_funcs = {
	.free = amdxdna_gem_obj_free,
};

static void amdxdna_gem_shmem_free(struct drm_gem_object *gobj)
{
	struct amdxdna_gem_shmem_obj *sbo;

	sbo = to_xdna_gem_shmem_obj(to_drm_gem_shmem_obj(gobj));
	XDNA_DBG(sbo->client->xdna, "SHMEM bo pinned %d", sbo->pinned);
	if (sbo->pinned)
		drm_gem_shmem_unpin(&sbo->base);
	drm_gem_shmem_object_free(gobj);
}

static const struct drm_gem_object_funcs amdxdna_gem_shmem_funcs = {
	.free = amdxdna_gem_shmem_free,
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
	struct amdxdna_gem_shmem_obj *sbo;

	XDNA_DBG(xdna, "size 0x%lx", size);
	sbo = kzalloc(sizeof(*sbo), GFP_KERNEL);
	if (!sbo)
		return ERR_PTR(-ENOMEM);

	sbo->base.base.funcs = &amdxdna_gem_shmem_funcs;
	sbo->type = AMDXDNA_BO_SHMEM;

	return &sbo->base.base;
}

static int amdxdna_drm_alloc_shmem(struct drm_device *dev,
				   struct amdxdna_drm_create_bo *args,
				   struct drm_file *filp)
{
	struct amdxdna_client *client = filp->driver_priv;
	struct amdxdna_dev *xdna = to_xdna_dev(dev);
	struct drm_gem_shmem_object *shmem;
	struct amdxdna_gem_shmem_obj *sbo;
	int ret;

	XDNA_DBG(xdna, "vaddr 0x%llx, size 0x%llx", args->vaddr, args->size);
	shmem = drm_gem_shmem_create(dev, args->size);
	if (IS_ERR(shmem))
		return PTR_ERR(shmem);

	shmem->map_wc = false;

	sbo = to_xdna_gem_shmem_obj(shmem);
	sbo->client = client;
	sbo->mmap_offset = drm_vma_node_offset_addr(&shmem->base.vma_node);
	sbo->pinned = false;

	/* ready to publish object to userspace */
	ret = drm_gem_handle_create(filp, &shmem->base, &args->handle);

	/* dereference object reference. Handle holds it now */
	drm_gem_object_put(&shmem->base);

	return ret;
}

static int amdxdna_drm_create_dev_heap(struct drm_device *dev,
				       struct amdxdna_drm_create_bo *args,
				       struct drm_file *filp)
{
	struct amdxdna_client *client = filp->driver_priv;
	struct amdxdna_dev *xdna = to_xdna_dev(dev);
	struct amdxdna_gem_obj *abo;
	int ret;

	XDNA_DBG(xdna, "vaddr 0x%llx, size 0x%llx", args->vaddr, args->size);
	if (args->size > xdna->dev_info->dev_mem_size) {
		XDNA_DBG(xdna, "Invalid dev heap size 0x%llx, limit 0x%lx",
			 args->size, xdna->dev_info->dev_mem_size);
		return -EINVAL;
	}

	if (!access_ok((void __user *)(uintptr_t)args->vaddr, args->size))
		return -EFAULT;

	mutex_lock(&client->mm_lock);
	if (client->dev_heap > 0) {
		XDNA_DBG(xdna, "dev heap is already created");
		ret = -EINVAL;
		goto unlock_and_err;
	}

	abo = kzalloc(sizeof(*abo), GFP_KERNEL);
	if (!abo) {
		ret = -ENOMEM;
		goto unlock_and_err;
	}

	drm_gem_private_object_init(&xdna->ddev, &abo->base,
				    PAGE_ALIGN(args->size));
	abo->base.funcs = &amdxdna_gem_obj_funcs;
	abo->type = AMDXDNA_BO_DEV_HEAP;
	abo->client = client;

	amdxdna_user_mem_init(&abo->mem, args->vaddr, abo->base.size);

	abo->mem.dev_addr = client->xdna->dev_info->dev_mem_base;

	drm_mm_init(&abo->mm, abo->mem.dev_addr, abo->mem.size);

	/* ready to publish object to userspace */
	ret = drm_gem_handle_create(filp, &abo->base, &args->handle);
	if (ret) {
		XDNA_ERR(xdna, "Create handle failed");
		goto clean_bo_mem;
	}
	client->dev_heap = args->handle;
	XDNA_DBG(xdna, "bo hdl %d userptr 0x%llx dev_addr 0x%llx nr_pages %d",
		 args->handle, abo->mem.userptr, abo->mem.dev_addr, abo->mem.nr_pages);
	mutex_unlock(&client->mm_lock);

	/* dereference object reference. Handle holds it now */
	drm_gem_object_put(&abo->base);

	return 0;

clean_bo_mem:
	amdxdna_user_mem_fini(&abo->mem);
	drm_gem_object_release(&abo->base);
	kfree(abo);
unlock_and_err:
	mutex_unlock(&client->mm_lock);
	return ret;
}

struct amdxdna_gem_obj *amdxdna_get_dev_heap(struct drm_file *filp)
{
	struct amdxdna_client *client = filp->driver_priv;
	struct drm_gem_object *gobj;
	struct amdxdna_gem_obj *abo;

	gobj = drm_gem_object_lookup(filp, client->dev_heap);
	if (!gobj)
		return ERR_PTR(-ENOENT);

	if (gobj->funcs != &amdxdna_gem_obj_funcs)
		goto err_out;

	abo = to_xdna_gem_obj(gobj);
	if (abo->type != AMDXDNA_BO_DEV_HEAP)
		goto err_out;

	return abo;

err_out:
	drm_gem_object_put(gobj);
	return ERR_PTR(-EINVAL);
}

static int amdxdna_drm_alloc_dev_bo(struct drm_device *dev,
				    struct amdxdna_drm_create_bo *args,
				    struct drm_file *filp)
{
	struct amdxdna_client *client = filp->driver_priv;
	size_t aligned_sz = PAGE_ALIGN(args->size);
	struct amdxdna_dev *xdna = to_xdna_dev(dev);
	struct amdxdna_gem_obj *abo, *heap;
	u64 offset;
	int ret;

	XDNA_DBG(xdna, "size 0x%llx", args->size);
	heap = amdxdna_get_dev_heap(filp);
	if (IS_ERR(heap)) {
		ret = PTR_ERR(heap);
		XDNA_DBG(xdna, "dev heap is not created, ret %d", ret);
		return ret;
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

	drm_gem_private_object_init(&xdna->ddev, &abo->base, aligned_sz);
	abo->base.funcs = &amdxdna_gem_obj_funcs;
	abo->type = AMDXDNA_BO_DEV;
	abo->client = client;
	abo->dev_heap = heap;

	mutex_lock(&client->mm_lock);
	ret = drm_mm_insert_node_generic(&heap->mm, &abo->mm_node, aligned_sz,
					 PAGE_SIZE, 0, DRM_MM_INSERT_BEST);
	mutex_unlock(&client->mm_lock);
	if (ret) {
		XDNA_ERR(xdna, "Failed to alloc dev bo memory, ret %d", ret);
		goto free_bo;
	}

	abo->mem.dev_addr = abo->mm_node.start;
	offset = abo->mem.dev_addr - heap->mem.dev_addr;
	abo->mem.userptr = heap->mem.userptr + offset;
	abo->mem.size = abo->base.size;
	abo->mem.pages = &heap->mem.pages[offset >> PAGE_SHIFT];
	abo->mem.nr_pages = (PAGE_ALIGN(abo->mem.dev_addr + abo->mem.size) -
			     (abo->mem.dev_addr & PAGE_MASK)) >> PAGE_SHIFT;

	/* ready to publish object to usersapce */
	ret = drm_gem_handle_create(filp, &abo->base, &args->handle);
	if (ret) {
		XDNA_ERR(xdna, "Create handle failed");
		goto clean_bo_mem;
	}
	XDNA_DBG(xdna, "bo hdl %d userptr 0x%llx dev_addr 0x%llx nr_pages %d",
		 args->handle, abo->mem.userptr, abo->mem.dev_addr, abo->mem.nr_pages);
	/* dereference object reference. Handle holds it now */
	drm_gem_object_put(&abo->base);

	return 0;

clean_bo_mem:
	drm_mm_remove_node(&abo->mm_node);
free_bo:
	drm_gem_object_release(&abo->base);
	kfree(abo);
put_and_err:
	drm_gem_object_put(&heap->base);
	return ret;
}

static int amdxdna_drm_create_cmd_bo(struct drm_device *dev,
				     struct amdxdna_drm_create_bo *args,
				     struct drm_file *filp)
{
	struct amdxdna_client *client = filp->driver_priv;
	struct amdxdna_dev *xdna = to_xdna_dev(dev);
	struct amdxdna_gem_obj *abo;
	int ret;

	XDNA_DBG(xdna, "vaddr 0x%llx size 0x%llx flags 0x%llx",
		 args->vaddr, args->size, args->flags);
	if (args->size > PAGE_SIZE) {
		XDNA_ERR(xdna, "Command bo size 0x%llx too large", args->size);
		return -EINVAL;
	}

	abo = kzalloc(sizeof(*abo), GFP_KERNEL);
	if (!abo)
		return -ENOMEM;

	drm_gem_private_object_init(&xdna->ddev, &abo->base,
				    PAGE_ALIGN(args->size));
	abo->base.funcs = &amdxdna_gem_obj_funcs;
	abo->client = client;
	abo->type = AMDXDNA_BO_CMD;

	amdxdna_user_mem_init(&abo->mem, args->vaddr, abo->base.size);

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

	/* ready to publish object to userspace */
	ret = drm_gem_handle_create(filp, &abo->base, &args->handle);
	if (ret)
		goto unmap;

	/* dereference object reference. Handle holds it now */
	drm_gem_object_put(&abo->base);

	XDNA_DBG(xdna, "Command bo handle %d", args->handle);
	return 0;

unmap:
	vunmap(abo->mem.kva - offset_in_page(abo->mem.userptr));
unpin:
	amdxdna_unpin_pages(&abo->mem);
fini_user_map:
	amdxdna_user_mem_fini(&abo->mem);
	drm_gem_object_release(&abo->base);
	kfree(abo);
	return ret;
}

enum amdxdna_obj_type amdxdna_gem_get_obj_type(struct drm_gem_object *gobj)
{
	return (gobj->funcs == &amdxdna_gem_obj_funcs) ? AMDXDNA_GEM_OBJ : AMDXDNA_SHMEM_OBJ;
}

int amdxdna_drm_create_bo_ioctl(struct drm_device *dev, void *data, struct drm_file *filp)
{
	struct amdxdna_drm_create_bo *args = data;

	if (args->flags || !args->size)
		return -EINVAL;

	switch (args->type) {
	case AMDXDNA_BO_SHMEM:
		return amdxdna_drm_alloc_shmem(dev, args, filp);
	case AMDXDNA_BO_DEV_HEAP:
		return amdxdna_drm_create_dev_heap(dev, args, filp);
	case AMDXDNA_BO_DEV:
		return amdxdna_drm_alloc_dev_bo(dev, args, filp);
	case AMDXDNA_BO_CMD:
		return amdxdna_drm_create_cmd_bo(dev, args, filp);
	default:
		return -EINVAL;
	}
}

int amdxdna_drm_get_bo_info_ioctl(struct drm_device *dev, void *data, struct drm_file *filp)
{
	struct amdxdna_drm_get_bo_info *args = data;
	struct amdxdna_dev *xdna = to_xdna_dev(dev);
	struct drm_gem_object *gobj;
	enum amdxdna_obj_type type;

	if (args->ext_flags)
		return -EINVAL;

	gobj = drm_gem_object_lookup(filp, args->handle);
	if (!gobj) {
		XDNA_DBG(xdna, "Lookup GEM object failed");
		return -ENOENT;
	}

	type = amdxdna_gem_get_obj_type(gobj);
	switch (type) {
	case AMDXDNA_GEM_OBJ:
		struct amdxdna_gem_obj *abo;

		abo = to_xdna_gem_obj(gobj);
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
		default:
			args->map_offset = AMDXDNA_INVALID_ADDR;
			args->vaddr = AMDXDNA_INVALID_ADDR;
			args->xdna_addr = AMDXDNA_INVALID_ADDR;
		}
		break;
	case AMDXDNA_SHMEM_OBJ:
		struct amdxdna_gem_shmem_obj *sbo;

		sbo = to_xdna_gem_shmem_obj(to_drm_gem_shmem_obj(gobj));
		args->map_offset = sbo->mmap_offset;
		args->vaddr = AMDXDNA_INVALID_ADDR;
		args->xdna_addr = AMDXDNA_INVALID_ADDR;
		break;
	default:
		drm_WARN_ON(&xdna->ddev, 1);
	}

	XDNA_DBG(xdna, "map_offset 0x%llx, vaddr 0x%llx, xdna_addr 0x%llx",
		 args->map_offset, args->vaddr, args->xdna_addr);

	drm_gem_object_put(gobj);
	return 0;
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
	struct drm_gem_object *gobj;
	enum amdxdna_obj_type type;
	int ret = 0;

	gobj = drm_gem_object_lookup(filp, args->handle);
	if (!gobj) {
		XDNA_ERR(xdna, "Lookup GEM object failed");
		return -ENOENT;
	}

	type = amdxdna_gem_get_obj_type(gobj);
	switch (type) {
	case AMDXDNA_GEM_OBJ:
		struct amdxdna_gem_obj *abo;

		abo = to_xdna_gem_obj(gobj);
		XDNA_DBG(xdna, "type %d", abo->type);

		drm_clflush_pages(abo->mem.pages, abo->mem.nr_pages);
		break;
	case AMDXDNA_SHMEM_OBJ:
		struct amdxdna_gem_shmem_obj *sbo;

		sbo = to_xdna_gem_shmem_obj(to_drm_gem_shmem_obj(gobj));

		if (sbo->base.pages)
			drm_clflush_pages(sbo->base.pages, sbo->base.base.size >> PAGE_SHIFT);
		break;
	default:
		drm_WARN_ON(&xdna->ddev, 1);
	}

	XDNA_DBG(xdna, "Sync bo %d offset 0x%llx, size 0x%llx\n",
		 args->handle, args->offset, args->size);

	drm_gem_object_put(gobj);
	return ret;
}

int amdxdna_drm_attach_bo_ioctl(struct drm_device *dev,
				void *data, struct drm_file *filp)
{
	struct amdxdna_dev *xdna = to_xdna_dev(dev);
	struct amdxdna_drm_attach_detach_bo *args = data;

	XDNA_DBG(xdna, "Attach bo %d to ctx %d\n", args->bo, args->hwctx);
	// TODO: check BO type and send firmware command to assign to ctx
	return 0;
}

int amdxdna_drm_detach_bo_ioctl(struct drm_device *dev,
				void *data, struct drm_file *filp)
{
	struct amdxdna_dev *xdna = to_xdna_dev(dev);
	struct amdxdna_drm_attach_detach_bo *args = data;

	XDNA_DBG(xdna, "Detach bo %d from ctx %d\n", args->bo, args->hwctx);
	// TODO: check BO type and send firmware command to remove from ctx
	return 0;
}

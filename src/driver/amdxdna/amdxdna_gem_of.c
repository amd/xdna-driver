// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2025, Advanced Micro Devices, Inc.
 */

#include <linux/dma-mapping.h>
#include <linux/version.h>

#include "drm_local/amdxdna_accel.h"
#include "amdxdna_drm.h"
#include "amdxdna_gem_of.h"

#if KERNEL_VERSION(6, 13, 0) > LINUX_VERSION_CODE
MODULE_IMPORT_NS(DMA_BUF);
#else
MODULE_IMPORT_NS("DMA_BUF");
#endif

struct amdxdna_gem_obj *amdxdna_gem_get_obj(struct amdxdna_client *client, u32 bo_hdl, u8 bo_type)
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
	if (bo_type == AMDXDNA_BO_INVALID || abo->type == bo_type)
		return abo;

	drm_gem_object_put(gobj);

	return NULL;
}

static void amdxdna_gem_dma_obj_free(struct drm_gem_object *gobj)
{
	struct amdxdna_dev *xdna = to_xdna_dev(gobj->dev);
	struct amdxdna_gem_obj *abo = to_xdna_obj(gobj);

	XDNA_DBG(xdna, "BO type %d xdna_addr 0x%llx", abo->type, abo->mem.dev_addr);
	drm_gem_dma_object_free(gobj);
}

static const struct drm_gem_object_funcs amdxdna_gem_dma_funcs = {
	.free = amdxdna_gem_dma_obj_free,
	.print_info = drm_gem_dma_object_print_info,
	.get_sg_table = drm_gem_dma_object_get_sg_table,
	.vmap = drm_gem_dma_object_vmap,
	.mmap = drm_gem_dma_object_mmap,
	.vm_ops = &drm_gem_dma_vm_ops,
};

/* For drm_driver->gem_create_object callback */
struct drm_gem_object *amdxdna_gem_create_object_cb(struct drm_device *dev, size_t size)
{
	struct amdxdna_gem_obj *abo;

	abo = kzalloc(sizeof(*abo), GFP_KERNEL);
	if (!abo)
		return ERR_PTR(-ENOMEM);

	/* The default funcs, caller should change if needed */
	to_gobj(abo)->funcs = &amdxdna_gem_dma_funcs;

	abo->type = AMDXDNA_BO_SHARE;
	mutex_init(&abo->lock);

	abo->mem.userptr = AMDXDNA_INVALID_ADDR;
	abo->mem.dev_addr = AMDXDNA_INVALID_ADDR;
	abo->mem.size = size;

	return to_gobj(abo);
}

static struct amdxdna_gem_obj *amdxdna_drm_create_dma_bo(struct drm_device *dev,
							 struct amdxdna_drm_create_bo *args,
							 struct drm_file *filp)
{
	struct drm_gem_dma_object *dma;
	struct amdxdna_gem_obj *abo;
	size_t size = args->size;

	/* Round up to more than 4K to ensure to allocate memory from CMA always */
	if (size <= PAGE_SIZE)
		size = round_up(size, 2 * PAGE_SIZE);

	dma = drm_gem_dma_create(dev, size);
	if (IS_ERR(dma))
		return ERR_CAST(dma);

	abo = to_xdna_obj(&dma->base);

	abo->mem.dev_addr = dma->dma_addr;
	abo->mem.kva = dma->vaddr;
	abo->type = args->type;

	return abo;
}

int amdxdna_drm_create_bo_ioctl(struct drm_device *dev, void *data, struct drm_file *filp)
{
	struct amdxdna_dev *xdna = to_xdna_dev(dev);
	struct amdxdna_drm_create_bo *args = data;
	struct amdxdna_gem_obj *abo;
	int ret;

	if (args->flags || !args->size) {
		XDNA_ERR(xdna, "Invalid BO received, flags: 0x%llx, size: %llu", args->flags,
			 args->size);
		return -EINVAL;
	}

	XDNA_DBG(xdna, "BO arg type %d size 0x%llx flags 0x%llx", args->type, args->size,
		 args->flags);
	switch (args->type) {
	case AMDXDNA_BO_SHARE:
	case AMDXDNA_BO_CMD:
	case AMDXDNA_BO_DMA:
	case AMDXDNA_BO_DEV:
		/* CMD and DMA are traded the same */
		abo = amdxdna_drm_create_dma_bo(dev, args, filp);
		break;
	default:
		return -EINVAL;
	}
	if (IS_ERR(abo))
		return PTR_ERR(abo);

	/* ready to publish object to userspace */
	ret = drm_gem_handle_create(filp, to_gobj(abo), &args->handle);
	if (ret) {
		XDNA_ERR(xdna, "Create drm_gem handle failed, ret %d", ret);
		goto put_obj;
	}

	XDNA_DBG(xdna, "BO hdl %d type %d userptr 0x%llx xdna_addr 0x%llx size 0x%lx", args->handle,
		 args->type, abo->mem.userptr, abo->mem.dev_addr, abo->mem.size);
put_obj:
	/* Dereference object reference. Handle holds it now. */
	drm_gem_object_put(to_gobj(abo));
	return ret;
}

int amdxdna_drm_sync_bo_ioctl(struct drm_device *dev, void *data, struct drm_file *filp)
{
	struct amdxdna_dev *xdna = to_xdna_dev(dev);
	struct amdxdna_drm_sync_bo *args = data;
	struct amdxdna_gem_obj *abo;
	struct drm_gem_object *gobj;
	dma_addr_t bo_phyaddr;
	int ret = 0;

	if (!args) {
		XDNA_ERR(xdna, "Invalid input NULL BO received");
		return -EINVAL;
	}

	gobj = drm_gem_object_lookup(filp, args->handle);
	if (!gobj) {
		XDNA_ERR(xdna, "Lookup GEM object %d failed", args->handle);
		return -ENOENT;
	}

	if (args->offset > gobj->size || args->size > gobj->size ||
	    (args->offset + args->size) > gobj->size) {
		XDNA_ERR(xdna, "Invalid BO %d requested", args->handle);
		ret = -EINVAL;
		goto out;
	}

	abo = to_xdna_obj(gobj);

	/* For now we only support CMA memory*/
	bo_phyaddr = (u64)abo->base.dma_addr;
	bo_phyaddr += args->offset;

	if (args->direction == SYNC_DIRECT_TO_DEVICE) {
		dma_sync_single_for_device(dev->dev, bo_phyaddr, args->size, DMA_TO_DEVICE);
	} else if (args->direction == SYNC_DIRECT_FROM_DEVICE) {
		dma_sync_single_for_cpu(dev->dev, bo_phyaddr, args->size, DMA_FROM_DEVICE);
	} else {
		XDNA_ERR(xdna, "Invalid direction %d requested", args->direction);
		ret = -EINVAL;
	}

out:
	drm_gem_object_put(gobj);
	return ret;
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
	args->vaddr = abo->mem.userptr;
	args->xdna_addr = abo->mem.dev_addr;
	args->map_offset = drm_vma_node_offset_addr(&gobj->vma_node);

	XDNA_DBG(xdna, "BO hdl %d map_offset 0x%llx vaddr 0x%llx xdna_addr 0x%llx", args->handle,
		 args->map_offset, args->vaddr, args->xdna_addr);

	drm_gem_object_put(gobj);
	return ret;
}

int amdxdna_gem_pin_nolock(struct amdxdna_gem_obj *abo)
{
	/* TODO: implement this */
	return 0;
}

int amdxdna_gem_pin(struct amdxdna_gem_obj *abo)
{
	/* no ops */
	return 0;
}

void amdxdna_gem_unpin(struct amdxdna_gem_obj *abo)
{
	/* no ops */
}

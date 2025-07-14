// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2024-2025, Advanced Micro Devices, Inc.
 */

#include "drm_local/amdxdna_accel.h"
#include <linux/dma-buf.h>
#include <linux/dma-direct.h>
#include <linux/iosys-map.h>
#include <linux/pagemap.h>
#include <linux/pfn.h>
#include <linux/version.h>
#include <linux/vmalloc.h>
#include <drm/drm_cache.h>

#include "amdxdna_carvedout_buf.h"
#include "amdxdna_drm.h"
#include "amdxdna_pm.h"
#include "amdxdna_gem.h"
#include "amdxdna_ubuf.h"

#ifdef AMDXDNA_DEVEL
#include "amdxdna_devel.h"
#endif

#define XDNA_MAX_CMD_BO_SIZE	SZ_32K

#if KERNEL_VERSION(6, 13, 0) > LINUX_VERSION_CODE
MODULE_IMPORT_NS(DMA_BUF);
#else
MODULE_IMPORT_NS("DMA_BUF");
#endif

static int
amdxdna_gem_heap_alloc(struct amdxdna_gem_obj *abo)
{
	struct amdxdna_client *client = abo->client;
	struct amdxdna_dev *xdna = client->xdna;
	struct amdxdna_mem *mem = &abo->mem;
	struct amdxdna_gem_obj *heap;
	struct page **pages = NULL;
	u64 offset;
	u32 align;
	int ret;

	mutex_lock(&client->mm_lock);

	heap = client->dev_heap;
	if (!heap) {
		mutex_unlock(&client->mm_lock);
		return -EINVAL;
	}

	if (heap->mem.userptr == AMDXDNA_INVALID_ADDR) {
		XDNA_ERR(xdna, "Invalid dev heap userptr");
		mutex_unlock(&client->mm_lock);
		return -EINVAL;
	}

	if (mem->size == 0 || mem->size > heap->mem.size) {
		XDNA_ERR(xdna, "Invalid dev bo size 0x%lx, limit 0x%lx",
			 mem->size, heap->mem.size);
		mutex_unlock(&client->mm_lock);
		return -EINVAL;
	}

	if (heap->mem.pages)
		pages = heap->mem.pages;
	else if (client->dev_heap->base.pages)
		pages = heap->base.pages;

	align = 1 << max(PAGE_SHIFT, xdna->dev_info->dev_mem_buf_shift);
	if (heap->mem.size > SZ_64M) {
		/* TODO: remove this hack code path once FW is updated */
		u64 threshold = SZ_64M; /* Determine small or large buffer */

		XDNA_INFO(xdna, "Large heap allocation hack");
		if (mem->size > threshold) {
			XDNA_INFO(xdna, "Large buffer allocate start from bank 1");
			ret = drm_mm_insert_node_in_range(&heap->mm, &abo->mm_node,
							  mem->size, align, 0,
							  heap->mem.dev_addr + SZ_64M /* start */,
							  U64_MAX /* let DRM determine */,
							  DRM_MM_INSERT_BEST);
		} else {
			XDNA_INFO(xdna, "Small buffer allocate in bank 0");
			ret = drm_mm_insert_node_in_range(&heap->mm, &abo->mm_node,
							  mem->size, align, 0,
							  heap->mem.dev_addr /* start */,
							  heap->mem.dev_addr + SZ_64M - 1 /* end */,
							  DRM_MM_INSERT_BEST);
		}
	} else {
		ret = drm_mm_insert_node_generic(&heap->mm, &abo->mm_node, mem->size,
						 align, 0, DRM_MM_INSERT_BEST);
	}
	if (ret) {
		XDNA_ERR(xdna, "Failed to alloc dev bo memory, ret %d", ret);
		mutex_unlock(&client->mm_lock);
		return ret;
	}

	client->heap_usage += mem->size;
	mem->dev_addr = abo->mm_node.start;
	offset = mem->dev_addr - client->dev_heap->mem.dev_addr;
	mem->userptr = client->dev_heap->mem.userptr + offset;

	if (pages) {
		mem->pages = &pages[offset >> PAGE_SHIFT];
		mem->nr_pages = mem->size >> PAGE_SHIFT;
	}

	drm_gem_object_get(to_gobj(heap));

	mutex_unlock(&client->mm_lock);
	return 0;
}

static void
amdxdna_gem_heap_free(struct amdxdna_gem_obj *abo)
{
	mutex_lock(&abo->client->mm_lock);

	if (abo->mem.dev_addr != AMDXDNA_INVALID_ADDR) {
		drm_mm_remove_node(&abo->mm_node);
		abo->client->heap_usage -= abo->mem.size;
	}
	drm_gem_object_put(to_gobj(abo->client->dev_heap));

	mutex_unlock(&abo->client->mm_lock);
}

static bool amdxdna_hmm_invalidate(struct mmu_interval_notifier *mni,
				   const struct mmu_notifier_range *range,
				   unsigned long cur_seq)
{
	struct amdxdna_umap *mapp = container_of(mni, struct amdxdna_umap, notifier);
	struct amdxdna_gem_obj *abo = mapp->abo;
	struct amdxdna_dev *xdna;

	xdna = to_xdna_dev(to_gobj(abo)->dev);
	XDNA_DBG(xdna, "Invalidating range 0x%lx, 0x%lx, type %d",
		 mapp->vma->vm_start, mapp->vma->vm_end, abo->type);

	if (!mmu_notifier_range_blockable(range))
		return false;

	down_write(&xdna->notifier_lock);
	abo->mem.map_invalid = true;
	mapp->invalid = true;
	mmu_interval_set_seq(&mapp->notifier, cur_seq);
	up_write(&xdna->notifier_lock);

	xdna->dev_info->ops->hmm_invalidate(abo, cur_seq);

	if (range->event == MMU_NOTIFY_UNMAP) {
		down_write(&xdna->notifier_lock);
		if (!mapp->unmapped) {
			queue_work(xdna->notifier_wq, &mapp->hmm_unreg_work);
			mapp->unmapped = true;
		}
		up_write(&xdna->notifier_lock);
	}

	return true;
}

static const struct mmu_interval_notifier_ops amdxdna_hmm_ops = {
	.invalidate = amdxdna_hmm_invalidate,
};

static void amdxdna_hmm_unregister(struct amdxdna_gem_obj *abo,
				   struct vm_area_struct *vma)
{
	struct amdxdna_dev *xdna = to_xdna_dev(to_gobj(abo)->dev);
	struct amdxdna_umap *mapp;

	down_read(&xdna->notifier_lock);
	list_for_each_entry(mapp, &abo->mem.umap_list, node) {
		if (!vma || mapp->vma == vma) {
			if (!mapp->unmapped) {
				queue_work(xdna->notifier_wq, &mapp->hmm_unreg_work);
				mapp->unmapped = true;
			}
			if (vma)
				break;
		}
	}
	up_read(&xdna->notifier_lock);
}

static void amdxdna_umap_release(struct kref *ref)
{
	struct amdxdna_umap *mapp = container_of(ref, struct amdxdna_umap, refcnt);
	struct vm_area_struct *vma = mapp->vma;
	struct amdxdna_dev *xdna;

	mmu_interval_notifier_remove(&mapp->notifier);
	if (is_import_bo(mapp->abo) && vma->vm_file && vma->vm_file->f_mapping)
		mapping_clear_unevictable(vma->vm_file->f_mapping);

	xdna = to_xdna_dev(to_gobj(mapp->abo)->dev);
	down_write(&xdna->notifier_lock);
	list_del(&mapp->node);
	up_write(&xdna->notifier_lock);

	kvfree(mapp->range.hmm_pfns);
	kfree(mapp);
}

void amdxdna_umap_put(struct amdxdna_umap *mapp)
{
	kref_put(&mapp->refcnt, amdxdna_umap_release);
}

static void amdxdna_hmm_unreg_work(struct work_struct *work)
{
	struct amdxdna_umap *mapp = container_of(work, struct amdxdna_umap,
						 hmm_unreg_work);

	amdxdna_umap_put(mapp);
}

static int amdxdna_hmm_register(struct amdxdna_gem_obj *abo,
				struct vm_area_struct *vma)
{
	struct amdxdna_dev *xdna = to_xdna_dev(to_gobj(abo)->dev);
	unsigned long len = vma->vm_end - vma->vm_start;
	unsigned long addr = vma->vm_start;
	struct amdxdna_umap *mapp;
	u32 nr_pages;
	int ret;

	if (!xdna->dev_info->ops->hmm_invalidate)
		return 0;

	mapp = kzalloc(sizeof(*mapp), GFP_KERNEL);
	if (!mapp)
		return -ENOMEM;

	nr_pages = (PAGE_ALIGN(addr + len) - (addr & PAGE_MASK)) >> PAGE_SHIFT;
	mapp->range.hmm_pfns = kvcalloc(nr_pages, sizeof(*mapp->range.hmm_pfns),
					GFP_KERNEL);
	if (!mapp->range.hmm_pfns) {
		ret = -ENOMEM;
		goto free_map;
	}

	ret = mmu_interval_notifier_insert_locked(&mapp->notifier,
						  current->mm,
						  addr,
						  len,
						  &amdxdna_hmm_ops);
	if (ret) {
		XDNA_ERR(xdna, "Insert mmu notifier failed, ret %d", ret);
		goto free_pfns;
	}

	mapp->range.notifier = &mapp->notifier;
	mapp->range.start = vma->vm_start;
	mapp->range.end = vma->vm_end;
	mapp->range.default_flags = HMM_PFN_REQ_FAULT;
	mapp->vma = vma;
	mapp->abo = abo;
	kref_init(&mapp->refcnt);

	if (abo->mem.userptr == AMDXDNA_INVALID_ADDR)
		abo->mem.userptr = addr;
	INIT_WORK(&mapp->hmm_unreg_work, amdxdna_hmm_unreg_work);
	if (is_import_bo(abo) && vma->vm_file && vma->vm_file->f_mapping)
		mapping_set_unevictable(vma->vm_file->f_mapping);

	down_write(&xdna->notifier_lock);
	list_add_tail(&mapp->node, &abo->mem.umap_list);
	up_write(&xdna->notifier_lock);

	return 0;

free_pfns:
	kvfree(mapp->range.hmm_pfns);
free_map:
	kfree(mapp);
	return ret;
}

static struct amdxdna_gem_obj *
amdxdna_gem_create_obj(struct drm_device *dev, size_t size)
{
	struct amdxdna_gem_obj *abo;

	abo = kzalloc(sizeof(*abo), GFP_KERNEL);
	if (!abo)
		return ERR_PTR(-ENOMEM);

	abo->assigned_ctx = AMDXDNA_INVALID_CTX_HANDLE;
	mutex_init(&abo->lock);

	abo->mem.userptr = AMDXDNA_INVALID_ADDR;
	abo->mem.dev_addr = AMDXDNA_INVALID_ADDR;
	abo->mem.size = size;
	INIT_LIST_HEAD(&abo->mem.umap_list);

	return abo;
}

static void
amdxdna_gem_destroy_obj(struct amdxdna_gem_obj *abo)
{
	mutex_destroy(&abo->lock);
	kfree(abo);
}

static void amdxdna_gem_vunmap(struct amdxdna_gem_obj *abo)
{
	struct iosys_map map = IOSYS_MAP_INIT_VADDR(abo->mem.kva);

	WARN_ON(abo->mem.kva_use_count > 1);

	if (!abo->mem.kva)
		return;

	if (is_import_bo(abo))
		dma_buf_vunmap_unlocked(abo->dma_buf, &map);
	else
#if KERNEL_VERSION(6, 16, 0) > LINUX_VERSION_CODE
		drm_gem_vunmap_unlocked(to_gobj(abo), &map);
#else
		drm_gem_vunmap(to_gobj(abo), &map);
#endif
}

static void amdxdna_gem_dev_obj_free(struct drm_gem_object *gobj)
{
	struct amdxdna_dev *xdna = to_xdna_dev(gobj->dev);
	struct amdxdna_gem_obj *abo = to_xdna_obj(gobj);
	struct amdxdna_client *client = abo->client;
	struct iosys_map heap_map = IOSYS_MAP_INIT_VADDR(NULL);
	u64 offset;

	XDNA_DBG(xdna, "BO type %d xdna_addr 0x%llx", abo->type, abo->mem.dev_addr);
	if (abo->flags & BO_SUBMIT_PINNED)
		amdxdna_gem_unpin(abo);

	if (abo->mem.kva) {
		offset = abo->mem.dev_addr - client->dev_heap->mem.dev_addr;
		iosys_map_set_vaddr(&heap_map, abo->mem.kva - offset);
#if KERNEL_VERSION(6, 16, 0) > LINUX_VERSION_CODE
		drm_gem_vunmap_unlocked(to_gobj(client->dev_heap), &heap_map);
#else
		drm_gem_vunmap(to_gobj(client->dev_heap), &heap_map);
#endif
	}

	amdxdna_gem_heap_free(abo);
	drm_gem_object_release(gobj);
	amdxdna_gem_destroy_obj(abo);
}

static void amdxdna_imported_obj_free(struct amdxdna_gem_obj *abo)
{
	dma_buf_unmap_attachment_unlocked(abo->attach, abo->base.sgt, DMA_BIDIRECTIONAL);
	dma_buf_detach(abo->dma_buf, abo->attach);
	dma_buf_put(abo->dma_buf);
	drm_gem_object_release(to_gobj(abo));
	kfree(abo);
}

static void amdxdna_gem_shmem_obj_free(struct drm_gem_object *gobj)
{
	struct amdxdna_dev *xdna = to_xdna_dev(gobj->dev);
	struct amdxdna_gem_obj *abo = to_xdna_obj(gobj);

	XDNA_DBG(xdna, "BO type %d xdna_addr 0x%llx", abo->type, abo->mem.dev_addr);

	amdxdna_hmm_unregister(abo, NULL);
	flush_workqueue(xdna->notifier_wq);

	if (abo->flags & BO_SUBMIT_PINNED)
		amdxdna_gem_unpin(abo);

	if (abo->type == AMDXDNA_BO_DEV_HEAP)
		drm_mm_takedown(&abo->mm);

#ifdef AMDXDNA_DEVEL
	if (abo->type == AMDXDNA_BO_CMD)
		amdxdna_mem_unmap(xdna, &abo->mem);
	else if (iommu_mode == AMDXDNA_IOMMU_NO_PASID)
		amdxdna_bo_dma_unmap(abo);
#endif
	amdxdna_gem_vunmap(abo);
	mutex_destroy(&abo->lock);

	if (is_import_bo(abo)) {
		amdxdna_imported_obj_free(abo);
		return;
	}

	drm_gem_shmem_free(&abo->base);
}

static int amdxdna_gem_shmem_insert_pages(struct amdxdna_gem_obj *abo,
					  struct vm_area_struct *vma)
{
	struct amdxdna_dev *xdna = to_xdna_dev(to_gobj(abo)->dev);
	unsigned long num_pages = vma_pages(vma);
	unsigned long offset = 0;
	int ret;

	if (!is_import_bo(abo)) {
		ret = drm_gem_shmem_mmap(&abo->base, vma);
		if (ret) {
			XDNA_ERR(xdna, "Failed shmem mmap %d", ret);
			return ret;
		}

		/* The buffer is based on memory pages. Fix the flag. */
		vm_flags_mod(vma, VM_MIXEDMAP, VM_PFNMAP);
		ret = vm_insert_pages(vma, vma->vm_start, abo->base.pages,
				      &num_pages);
		if (ret) {
			XDNA_ERR(xdna, "Failed to insert pages %d", ret);
			vma->vm_ops->close(vma);
			return ret;
		}

		return 0;
	}

	vma->vm_private_data = NULL;
	vma->vm_ops = NULL;
	ret = dma_buf_mmap(abo->dma_buf, vma, 0);
	if (ret) {
		XDNA_ERR(xdna, "Failed to mmap dma buf %d", ret);
		return ret;
	}

	do {
		vm_fault_t fault_ret;

		fault_ret = handle_mm_fault(vma, vma->vm_start + offset,
					    FAULT_FLAG_WRITE, NULL);
		if (fault_ret & VM_FAULT_ERROR) {
			vma->vm_ops->close(vma);
			XDNA_ERR(xdna, "Fault in page failed");
			return -EFAULT;
		}

		offset += PAGE_SIZE;
	} while (--num_pages);

	/* Drop the reference drm_gem_mmap_obj() acquired.*/
	drm_gem_object_put(to_gobj(abo));

	return 0;
}

static int amdxdna_gem_shmem_obj_mmap(struct drm_gem_object *gobj,
				      struct vm_area_struct *vma)
{
	struct amdxdna_dev *xdna = to_xdna_dev(gobj->dev);
	struct amdxdna_gem_obj *abo = to_xdna_obj(gobj);
	int ret;

	ret = amdxdna_hmm_register(abo, vma);
	if (ret)
		return ret;

	ret = amdxdna_gem_shmem_insert_pages(abo, vma);
	if (ret) {
		XDNA_ERR(xdna, "Failed to insert pages, ret %d", ret);
		goto hmm_unreg;
	}

	XDNA_DBG(xdna, "SHMEM BO map_offset 0x%llx type %d userptr 0x%lx size 0x%lx",
		 drm_vma_node_offset_addr(&gobj->vma_node), abo->type,
		 vma->vm_start, gobj->size);
	return 0;

hmm_unreg:
	amdxdna_hmm_unregister(abo, vma);
	return ret;
}

static int amdxdna_gem_dmabuf_mmap(struct dma_buf *dma_buf, struct vm_area_struct *vma)
{
	struct drm_gem_object *gobj = dma_buf->priv;
	struct amdxdna_gem_obj *abo = to_xdna_obj(gobj);
	unsigned long num_pages = vma_pages(vma);
	int ret;

	vma->vm_ops = &drm_gem_shmem_vm_ops;
	vma->vm_private_data = gobj;

	drm_gem_object_get(gobj);
	ret = drm_gem_shmem_mmap(&abo->base, vma);
	if (ret)
		goto put_obj;

	/* The buffer is based on memory pages. Fix the flag. */
	vm_flags_mod(vma, VM_MIXEDMAP, VM_PFNMAP);
	ret = vm_insert_pages(vma, vma->vm_start, abo->base.pages,
			      &num_pages);
	if (ret)
		goto close_vma;

	return 0;

close_vma:
	vma->vm_ops->close(vma);
put_obj:
	drm_gem_object_put(gobj);
	return ret;
}

static int amdxdna_gem_obj_vmap(struct drm_gem_object *obj, struct iosys_map *map)
{
	struct amdxdna_gem_obj *abo = to_xdna_obj(obj);
	struct amdxdna_mem *mem = &abo->mem;

	iosys_map_clear(map);

	dma_resv_assert_held(obj->resv);

	if (mem->kva_use_count++ > 0) {
		iosys_map_set_vaddr(map, mem->kva);
		return 0;
	}

	if (is_import_bo(abo))
		dma_buf_vmap(abo->dma_buf, map);
	else
		drm_gem_shmem_object_vmap(obj, map);

	if (!map->vaddr)
		return -ENOMEM;

	mem->kva = map->vaddr;
	return 0;
}

static void amdxdna_gem_obj_vunmap(struct drm_gem_object *obj, struct iosys_map *map)
{
	struct amdxdna_gem_obj *abo = to_xdna_obj(obj);

	dma_resv_assert_held(obj->resv);

	WARN_ON(!abo->mem.kva_use_count);

	if (--abo->mem.kva_use_count > 0)
		return;

	if (is_import_bo(abo))
		dma_buf_vunmap(abo->dma_buf, map);
	else
		drm_gem_shmem_object_vunmap(obj, map);

	abo->mem.kva = NULL;
}

static const struct dma_buf_ops amdxdna_dmabuf_ops = {
#if KERNEL_VERSION(6, 16, 0) > LINUX_VERSION_CODE
	.cache_sgt_mapping = true,
#endif
	.attach = drm_gem_map_attach,
	.detach = drm_gem_map_detach,
	.map_dma_buf = drm_gem_map_dma_buf,
	.unmap_dma_buf = drm_gem_unmap_dma_buf,
	.release = drm_gem_dmabuf_release,
	.mmap = amdxdna_gem_dmabuf_mmap,
	.vmap = drm_gem_dmabuf_vmap,
	.vunmap = drm_gem_dmabuf_vunmap,
};

static struct dma_buf *amdxdna_gem_prime_export(struct drm_gem_object *gobj, int flags)
{
	struct amdxdna_gem_obj *abo = to_xdna_obj(gobj);
	DEFINE_DMA_BUF_EXPORT_INFO(exp_info);

	if (abo->dma_buf) {
		get_dma_buf(abo->dma_buf);
		return abo->dma_buf;
	}

	exp_info.ops = &amdxdna_dmabuf_ops;
	exp_info.size = gobj->size;
	exp_info.flags = flags;
	exp_info.priv = gobj;
	exp_info.resv = gobj->resv;

	return drm_gem_dmabuf_export(gobj->dev, &exp_info);
}

static const struct drm_gem_object_funcs amdxdna_gem_shmem_funcs = {
	.free = amdxdna_gem_shmem_obj_free,
	.print_info = drm_gem_shmem_object_print_info,
	.pin = drm_gem_shmem_object_pin,
	.unpin = drm_gem_shmem_object_unpin,
	.get_sg_table = drm_gem_shmem_object_get_sg_table,
	.vmap = amdxdna_gem_obj_vmap,
	.vunmap = amdxdna_gem_obj_vunmap,
	.mmap = amdxdna_gem_shmem_obj_mmap,
	.vm_ops = &drm_gem_shmem_vm_ops,
	.export = amdxdna_gem_prime_export,
};

static const struct vm_operations_struct drm_vm_ops = {
	.open = drm_gem_vm_open,
	.close = drm_gem_vm_close,
};

static const struct drm_gem_object_funcs amdxdna_gem_dev_obj_funcs = {
	.free = amdxdna_gem_dev_obj_free,
};

/* For drm_driver->gem_create_object callback, only support shmem */
struct drm_gem_object *
amdxdna_gem_create_shmem_object_cb(struct drm_device *dev, size_t size)
{
	struct amdxdna_gem_obj *abo;

	abo = amdxdna_gem_create_obj(dev, size);
	if (IS_ERR(abo))
		return ERR_CAST(abo);

	to_gobj(abo)->funcs = &amdxdna_gem_shmem_funcs;

	return to_gobj(abo);
}

static struct amdxdna_gem_obj *
amdxdna_gem_create_shmem_object(struct drm_device *dev, size_t size)
{
	struct drm_gem_shmem_object *shmem = drm_gem_shmem_create(dev, size);

	if (IS_ERR(shmem))
		return ERR_CAST(shmem);
	shmem->map_wc = false;
	return to_xdna_obj(&shmem->base);
}

static struct amdxdna_gem_obj *
amdxdna_gem_create_carvedout_object(struct drm_device *dev, size_t size, u64 align)
{
	struct drm_gem_object *gobj;
	struct dma_buf *dma_buf;

	dma_buf = amdxdna_get_carvedout_buf(dev, size, align);
	if (IS_ERR(dma_buf))
		return ERR_CAST(dma_buf);

	gobj = dev->driver->gem_prime_import(dev, dma_buf);
	if (IS_ERR(gobj)) {
		dma_buf_put(dma_buf);
		return ERR_CAST(gobj);
	}

	dma_buf_put(dma_buf);

	return to_xdna_obj(gobj);
}

static struct amdxdna_gem_obj *
amdxdna_gem_create_user_object(struct drm_device *dev, struct amdxdna_drm_create_bo *args)
{
	struct amdxdna_dev *xdna = to_xdna_dev(dev);
	enum amdxdna_ubuf_flag flags = 0;
	struct amdxdna_drm_va_tbl va_tbl;
	struct drm_gem_object *gobj;
	struct dma_buf *dma_buf;

	if (copy_from_user(&va_tbl, u64_to_user_ptr(args->vaddr), sizeof(va_tbl))) {
		XDNA_DBG(xdna, "Access va table failed");
		return ERR_PTR(-EINVAL);
	}

	if (va_tbl.num_entries > 0) {
		if (args->type == AMDXDNA_BO_CMD)
			flags |= AMDXDNA_UBUF_FLAG_MAP_DMA;

		dma_buf = amdxdna_get_ubuf(dev, flags, va_tbl.num_entries,
					   u64_to_user_ptr(args->vaddr + sizeof(va_tbl)));
	} else {
		dma_buf = dma_buf_get(va_tbl.udma_fd);
	}

	if (IS_ERR(dma_buf))
		return ERR_CAST(dma_buf);

	gobj = dev->driver->gem_prime_import(dev, dma_buf);
	if (IS_ERR(gobj)) {
		dma_buf_put(dma_buf);
		return ERR_CAST(gobj);
	}

	dma_buf_put(dma_buf);

	return to_xdna_obj(gobj);
}

static struct amdxdna_gem_obj *
amdxdna_gem_create_share_object(struct drm_device *dev,
				struct amdxdna_drm_create_bo *args)
{
	size_t aligned_sz = PAGE_ALIGN(args->size);

	if (args->vaddr)
		return amdxdna_gem_create_user_object(dev, args);

	if (amdxdna_use_carvedout()) {
		struct amdxdna_dev *xdna = to_xdna_dev(dev);
		u64 align = 0;

		if (args->type == AMDXDNA_BO_DEV_HEAP)
			align = xdna->dev_info->dev_mem_size;

		return amdxdna_gem_create_carvedout_object(dev, aligned_sz, align);
	}

	return amdxdna_gem_create_shmem_object(dev, aligned_sz);
}

struct drm_gem_object *
amdxdna_gem_prime_import(struct drm_device *dev, struct dma_buf *dma_buf)
{
	struct dma_buf_attachment *attach;
	struct amdxdna_gem_obj *abo;
	struct drm_gem_object *gobj;
	struct sg_table *sgt;
	int ret;

	get_dma_buf(dma_buf);

	attach = dma_buf_attach(dma_buf, dev->dev);
	if (IS_ERR(attach)) {
		ret = PTR_ERR(attach);
		goto put_buf;
	}

	sgt = dma_buf_map_attachment_unlocked(attach, DMA_BIDIRECTIONAL);
	if (IS_ERR(sgt)) {
		ret = PTR_ERR(sgt);
		goto fail_detach;
	}

	gobj = drm_gem_shmem_prime_import_sg_table(dev, attach, sgt);
	if (IS_ERR(gobj)) {
		ret = PTR_ERR(gobj);
		goto fail_unmap;
	}

	abo = to_xdna_obj(gobj);
	abo->attach = attach;
	abo->dma_buf = dma_buf;
	gobj->resv = dma_buf->resv;

#ifdef AMDXDNA_DEVEL
	if (iommu_mode == AMDXDNA_IOMMU_NO_PASID) {
		abo = to_xdna_obj(gobj);
		ret = amdxdna_bo_dma_map(abo);
		if (ret) {
			drm_gem_object_put(gobj);
			goto fail_unmap;
		}
		abo->mem.dev_addr = abo->mem.dma_addr;
	}
#endif

	return gobj;

fail_unmap:
	dma_buf_unmap_attachment_unlocked(attach, sgt, DMA_BIDIRECTIONAL);
fail_detach:
	dma_buf_detach(dma_buf, attach);
put_buf:
	dma_buf_put(dma_buf);

	return ERR_PTR(ret);
}

static struct amdxdna_gem_obj *
amdxdna_drm_create_share_bo(struct drm_device *dev,
			    struct amdxdna_drm_create_bo *args, struct drm_file *filp)
{
	struct amdxdna_client *client = filp->driver_priv;
	struct amdxdna_gem_obj *abo;

	abo = amdxdna_gem_create_share_object(dev, args);
	if (IS_ERR(abo))
		return ERR_CAST(abo);

	abo->client = client;
	abo->type = AMDXDNA_BO_SHARE;

#ifdef AMDXDNA_DEVEL
	if (iommu_mode == AMDXDNA_IOMMU_NO_PASID) {
		int ret;

		ret = amdxdna_bo_dma_map(abo);
		if (ret) {
			drm_gem_object_put(to_gobj(abo));
			return ERR_PTR(ret);
		}
		abo->mem.dev_addr = abo->mem.dma_addr;
	}
#endif
	return abo;
}

static struct amdxdna_gem_obj *
amdxdna_drm_create_dev_heap_bo(struct drm_device *dev,
			       struct amdxdna_drm_create_bo *args, struct drm_file *filp)
{
	struct amdxdna_client *client = filp->driver_priv;
	struct amdxdna_dev *xdna = to_xdna_dev(dev);
	struct amdxdna_gem_obj *abo;
	int ret;

	WARN_ON(!is_power_of_2(xdna->dev_info->dev_mem_size));
	if (!IS_ALIGNED(args->size, xdna->dev_info->dev_mem_size)) {
		XDNA_ERR(xdna, "The dev heap size 0x%llx is not multiple of 0x%lx",
			 args->size, xdna->dev_info->dev_mem_size);
		return ERR_PTR(-EINVAL);
	}

	mutex_lock(&client->mm_lock);
	if (client->dev_heap) {
		XDNA_ERR(client->xdna, "dev heap is already created");
		ret = -EBUSY;
		goto mm_unlock;
	}

	abo = amdxdna_gem_create_share_object(dev, args);
	if (IS_ERR(abo)) {
		ret = PTR_ERR(abo);
		goto mm_unlock;
	}

	abo->type = AMDXDNA_BO_DEV_HEAP;
	abo->client = client;
	abo->mem.dev_addr = client->xdna->dev_info->dev_mem_base;
	drm_mm_init(&abo->mm, abo->mem.dev_addr, abo->mem.size);

#ifdef AMDXDNA_DEVEL
	if (iommu_mode == AMDXDNA_IOMMU_NO_PASID) {
		ret = amdxdna_bo_dma_map(abo);
		if (ret) {
			drm_gem_object_put(to_gobj(abo));
			goto mm_unlock;
		}
	}
#endif
	client->dev_heap = abo;
	drm_gem_object_get(to_gobj(abo));
	mutex_unlock(&client->mm_lock);

	return abo;

mm_unlock:
	mutex_unlock(&client->mm_lock);
	return ERR_PTR(ret);
}

struct amdxdna_gem_obj *
amdxdna_drm_create_dev_bo(struct drm_device *dev, struct amdxdna_drm_create_bo *args,
			  struct drm_file *filp)
{
	struct amdxdna_client *client = filp->driver_priv;
	struct amdxdna_dev *xdna = to_xdna_dev(dev);
	size_t aligned_sz = PAGE_ALIGN(args->size);
	struct amdxdna_gem_obj *abo;
	struct drm_gem_object *gobj;
	struct iosys_map map = IOSYS_MAP_INIT_VADDR(NULL);
	int ret;

	abo = amdxdna_gem_create_obj(dev, aligned_sz);
	if (IS_ERR(abo))
		return abo;
	gobj = to_gobj(abo);
	gobj->funcs = &amdxdna_gem_dev_obj_funcs;

	abo->type = AMDXDNA_BO_DEV;
	abo->client = client;

	ret = amdxdna_gem_heap_alloc(abo);
	if (ret) {
		XDNA_ERR(xdna, "Failed to alloc dev bo memory, ret %d", ret);
		amdxdna_gem_destroy_obj(abo);
		return ERR_PTR(ret);
	}
	drm_gem_private_object_init(dev, gobj, aligned_sz);

#if KERNEL_VERSION(6, 16, 0) > LINUX_VERSION_CODE
	ret = drm_gem_vmap_unlocked(to_gobj(client->dev_heap), &map);
#else
	ret = drm_gem_vmap(to_gobj(client->dev_heap), &map);
#endif
	if (ret) {
		XDNA_ERR(xdna, "Vmap dev bo failed, ret %d", ret);
		drm_gem_object_put(gobj);
		return ERR_PTR(ret);
	}
	abo->mem.kva = map.vaddr + abo->mem.dev_addr - client->dev_heap->mem.dev_addr;

	return abo;
}

static struct amdxdna_gem_obj *
amdxdna_drm_create_cmd_bo(struct drm_device *dev,
			  struct amdxdna_drm_create_bo *args,
			  struct drm_file *filp)
{
	struct amdxdna_dev *xdna = to_xdna_dev(dev);
	struct amdxdna_gem_obj *abo;
	struct iosys_map map = IOSYS_MAP_INIT_VADDR(NULL);
	int ret;

	if (args->size > XDNA_MAX_CMD_BO_SIZE) {
		XDNA_ERR(xdna, "Command bo size 0x%llx too large", args->size);
		return ERR_PTR(-EINVAL);
	}

	if (args->size < sizeof(struct amdxdna_cmd)) {
		XDNA_DBG(xdna, "Command BO size 0x%llx too small", args->size);
		return ERR_PTR(-EINVAL);
	}

	abo = amdxdna_gem_create_share_object(dev, args);
	if (IS_ERR(abo))
		return ERR_CAST(abo);

	abo->type = AMDXDNA_BO_CMD;
	abo->client = filp->driver_priv;

#if KERNEL_VERSION(6, 16, 0) > LINUX_VERSION_CODE
	ret = drm_gem_vmap_unlocked(to_gobj(abo), &map);
#else
	ret = drm_gem_vmap(to_gobj(abo), &map);
#endif
	if (ret) {
		XDNA_ERR(xdna, "Vmap cmd bo failed, ret %d", ret);
		goto release_obj;
	}

	return abo;

release_obj:
	drm_gem_object_put(to_gobj(abo));
	return ERR_PTR(ret);
}

int amdxdna_drm_create_bo_ioctl(struct drm_device *dev, void *data, struct drm_file *filp)
{
	struct amdxdna_dev *xdna = to_xdna_dev(dev);
	struct amdxdna_drm_create_bo *args = data;
	struct amdxdna_gem_obj *abo;
	int ret;

	if (args->flags)
		return -EINVAL;

	ret = amdxdna_pm_resume_get(dev->dev);
	if (ret)
		return ret;

	XDNA_DBG(xdna, "BO arg type %d va_tbl 0x%llx size 0x%llx flags 0x%llx",
		 args->type, args->vaddr, args->size, args->flags);
	switch (args->type) {
	case AMDXDNA_BO_SHARE:
		abo = amdxdna_drm_create_share_bo(dev, args, filp);
		break;
	case AMDXDNA_BO_DEV_HEAP:
		abo = amdxdna_drm_create_dev_heap_bo(dev, args, filp);
		break;
	case AMDXDNA_BO_DEV:
		abo = amdxdna_drm_create_dev_bo(dev, args, filp);
		break;
	case AMDXDNA_BO_CMD:
		abo = amdxdna_drm_create_cmd_bo(dev, args, filp);
#ifdef AMDXDNA_DEVEL
		if (IS_ERR(abo))
			break;
		if (is_import_bo(abo))
			break;
		if (!abo->mem.pages) {
			abo->mem.pages = abo->base.pages;
			abo->mem.nr_pages = to_gobj(abo)->size >> PAGE_SHIFT;
		}
		ret = amdxdna_mem_map(xdna, &abo->mem);
		if (ret)
			goto put_obj;
		abo->mem.dev_addr = abo->mem.dma_addr;
#endif
		break;
	default:
		ret = -EINVAL;
		goto suspend;
	}
	if (IS_ERR(abo)) {
		ret = PTR_ERR(abo);
		goto suspend;
	}

	/* ready to publish object to userspace */
	ret = drm_gem_handle_create(filp, to_gobj(abo), &args->handle);
	if (ret) {
		XDNA_ERR(xdna, "Create handle failed");
		goto put_obj;
	}

	XDNA_DBG(xdna, "BO hdl %d type %d userptr 0x%llx xdna_addr 0x%llx size 0x%lx",
		 args->handle, args->type, abo->mem.userptr,
		 abo->mem.dev_addr, abo->mem.size);
put_obj:
	/* Dereference object reference. Handle holds it now. */
	drm_gem_object_put(to_gobj(abo));
suspend:
	amdxdna_pm_suspend_put(dev->dev);
	return ret;
}

int amdxdna_gem_pin_nolock(struct amdxdna_gem_obj *abo)
{
	struct amdxdna_dev *xdna = to_xdna_dev(to_gobj(abo)->dev);
	int ret;

	if (abo->type == AMDXDNA_BO_DEV)
		abo = abo->client->dev_heap;

	if (is_import_bo(abo))
		return 0;

	ret = drm_gem_shmem_pin(&abo->base);

	XDNA_DBG(xdna, "BO type %d ret %d", abo->type, ret);
	return ret;
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
	if (abo->type == AMDXDNA_BO_DEV)
		abo = abo->client->dev_heap;

	if (is_import_bo(abo))
		return;

	mutex_lock(&abo->lock);
	drm_gem_shmem_unpin(&abo->base);
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
	if (bo_type == AMDXDNA_BO_INVALID || abo->type == bo_type)
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

	if (args->ext || args->ext_flags)
		return -EINVAL;

	ret = amdxdna_pm_resume_get(dev->dev);
	if (ret)
		return ret;

	gobj = drm_gem_object_lookup(filp, args->handle);
	if (!gobj) {
		XDNA_DBG(xdna, "Lookup GEM object %d failed", args->handle);
		ret = -ENOENT;
		goto suspend;
	}

	abo = to_xdna_obj(gobj);
	args->vaddr = abo->mem.userptr;
	args->xdna_addr = abo->mem.dev_addr;

	if (abo->type != AMDXDNA_BO_DEV)
		args->map_offset = drm_vma_node_offset_addr(&gobj->vma_node);
	else
		args->map_offset = AMDXDNA_INVALID_ADDR;

	XDNA_DBG(xdna, "BO hdl %d map_offset 0x%llx vaddr 0x%llx xdna_addr 0x%llx",
		 args->handle, args->map_offset, args->vaddr, args->xdna_addr);

	drm_gem_object_put(gobj);
suspend:
	amdxdna_pm_suspend_put(dev->dev);
	return ret;
}

static void
amdxdna_drm_clflush(struct amdxdna_gem_obj *abo, u32 start, u32 size)
{
	struct amdxdna_dev *xdna = to_xdna_dev(to_gobj(abo)->dev);
	u32 start_page, start_page_off;
	u32 end_page, end_page_size;
	u32 end = start + size - 1;
	u32 pages_in_middle;
	struct page **pages;
	void *addr;

	start_page = start >> PAGE_SHIFT;
	end_page = end >> PAGE_SHIFT;
	start_page_off = start & ~PAGE_MASK;
	end_page_size = (end & ~PAGE_MASK) + 1;

	pages = abo->mem.pages ? abo->mem.pages : abo->base.pages;
	if (!pages)
		return;

	XDNA_DBG(xdna, "Flush range [%d, %d]. page,size: [%d, %d] to [%d, %d]",
		 start, end, start_page, start_page_off, end_page, end_page_size);

	/* If start and end are on the page, use lightweight kernel API for best
	 * performance.
	 */
	addr = page_to_virt(pages[start_page]);
	addr = (void *)((u64)addr + start_page_off);
	if (start_page == end_page) {
		drm_clflush_virt_range(addr, size);
		return;
	}

	/* There are multiple pages */
	if (start_page_off)
		drm_clflush_virt_range(addr, PAGE_SIZE - start_page_off);
	else
		drm_clflush_pages(&pages[0], 1);

	pages_in_middle = end_page - start_page - 1;
	if (pages_in_middle)
		drm_clflush_pages(&pages[1], pages_in_middle);

	addr = page_to_virt(pages[end_page]);
	if (end_page_size < PAGE_SIZE)
		drm_clflush_virt_range(addr, end_page_size);
	else
		drm_clflush_pages(&pages[end_page], 1);
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
	struct amdxdna_client *client = filp->driver_priv;
	struct amdxdna_dev *xdna = to_xdna_dev(dev);
	struct amdxdna_drm_sync_bo *args = data;
	struct amdxdna_gem_obj *abo;
	struct drm_gem_object *gobj;
	u32 ctx_hdl;
	int ret;

	ret = amdxdna_pm_resume_get(dev->dev);
	if (ret)
		return ret;

	gobj = drm_gem_object_lookup(filp, args->handle);
	if (!gobj) {
		XDNA_ERR(xdna, "Lookup GEM object failed");
		ret = -ENOENT;
		goto suspend;
	}
	abo = to_xdna_obj(gobj);

	if (gobj->size < args->offset + args->size) {
		ret = -EINVAL;
		goto put_obj;
	}

	ret = amdxdna_gem_pin(abo);
	if (ret) {
		XDNA_ERR(xdna, "Pin BO %d failed, ret %d", args->handle, ret);
		goto put_obj;
	}

	/* For import bo, still sync whole BO */
	if (abo->mem.kva)
		drm_clflush_virt_range(abo->mem.kva + args->offset, args->size);
	else if (abo->mem.pages || abo->base.pages)
		amdxdna_drm_clflush(abo, args->offset, args->size);
	else if (abo->base.sgt)
		drm_clflush_sg(abo->base.sgt);
	else
		WARN_ONCE(1, "Can not find memory to sync");

	amdxdna_gem_unpin(abo);

	if (abo->assigned_ctx != AMDXDNA_INVALID_CTX_HANDLE &&
	    args->direction == SYNC_DIRECT_FROM_DEVICE) {
		u64 seq;

		ctx_hdl = amdxdna_gem_get_assigned_ctx(client, args->handle);
		if (ctx_hdl == AMDXDNA_INVALID_CTX_HANDLE ||
		    args->direction != SYNC_DIRECT_FROM_DEVICE) {
			XDNA_ERR(xdna, "Sync failed, dir %d", args->direction);
			ret = -EINVAL;
			goto put_obj;
		}

		ret = amdxdna_cmd_submit(client, OP_SYNC_BO, AMDXDNA_INVALID_BO_HANDLE,
					 &args->handle, 1, NULL, NULL, 0, ctx_hdl, &seq);
		if (ret) {
			XDNA_ERR(xdna, "Submit command failed");
			goto put_obj;
		}

		ret = amdxdna_cmd_wait(client, ctx_hdl, seq, 3000 /* ms */);
	}

	XDNA_DBG(xdna, "Sync bo %d offset 0x%llx, size 0x%llx, dir %d, ctx %d",
		 args->handle, args->offset, args->size, args->direction,
		 abo->assigned_ctx);

put_obj:
	drm_gem_object_put(gobj);
suspend:
	amdxdna_pm_suspend_put(dev->dev);
	return ret;
}

u32 amdxdna_gem_get_assigned_ctx(struct amdxdna_client *client, u32 bo_hdl)
{
	struct amdxdna_gem_obj *abo = amdxdna_gem_get_obj(client, bo_hdl, AMDXDNA_BO_INVALID);
	u32 ctxid;

	if (!abo) {
		XDNA_DBG(client->xdna, "Get bo %d failed", bo_hdl);
		return AMDXDNA_INVALID_CTX_HANDLE;
	}

	mutex_lock(&abo->lock);
	ctxid = abo->assigned_ctx;
	if (!xa_load(&client->ctx_xa, ctxid))
		ctxid = AMDXDNA_INVALID_CTX_HANDLE;
	mutex_unlock(&abo->lock);

	amdxdna_gem_put_obj(abo);
	return ctxid;
}

int amdxdna_gem_set_assigned_ctx(struct amdxdna_client *client, u32 bo_hdl, u32 ctxid)
{
	struct amdxdna_gem_obj *abo = amdxdna_gem_get_obj(client, bo_hdl, AMDXDNA_BO_INVALID);
	int ret = 0;

	if (!abo) {
		XDNA_DBG(client->xdna, "Get bo %d failed", bo_hdl);
		return -EINVAL;
	}

	mutex_lock(&abo->lock);
	if (!xa_load(&client->ctx_xa, abo->assigned_ctx))
		abo->assigned_ctx = ctxid;
	else if (ctxid != abo->assigned_ctx)
		ret = -EBUSY;
	mutex_unlock(&abo->lock);

	amdxdna_gem_put_obj(abo);
	return ret;
}

void amdxdna_gem_clear_assigned_ctx(struct amdxdna_client *client, u32 bo_hdl)
{
	struct amdxdna_gem_obj *abo = amdxdna_gem_get_obj(client, bo_hdl, AMDXDNA_BO_INVALID);

	if (!abo) {
		XDNA_DBG(client->xdna, "Get bo %d failed", bo_hdl);
		return;
	}

	mutex_lock(&abo->lock);
	abo->assigned_ctx = AMDXDNA_INVALID_CTX_HANDLE;
	mutex_unlock(&abo->lock);

	amdxdna_gem_put_obj(abo);
}

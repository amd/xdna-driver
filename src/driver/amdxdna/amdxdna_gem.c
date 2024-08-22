// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2024, Advanced Micro Devices, Inc.
 */

#include "drm_local/amdxdna_accel.h"
#include <linux/dma-buf.h>
#include <linux/dma-direct.h>
#include <linux/iosys-map.h>
#include <linux/pagemap.h>
#include <linux/pfn.h>
#include <linux/vmalloc.h>
#include <drm/drm_cache.h>

#include "amdxdna_drm.h"
#include "amdxdna_gem.h"

#ifdef AMDXDNA_DEVEL
#include "amdxdna_devel.h"
#endif

#define XDNA_MAX_CMD_BO_SIZE	0x8000

MODULE_IMPORT_NS(DMA_BUF);

static int
amdxdna_gem_insert_node_locked(struct amdxdna_gem_obj *abo, bool use_vmap)
{
	struct amdxdna_client *client = abo->client;
	struct amdxdna_dev *xdna = client->xdna;
	struct amdxdna_mem *mem = &abo->mem;
	u64 offset;
	u32 align;
	int ret;

	align = 1 << max(PAGE_SHIFT, xdna->dev_info->dev_mem_buf_shift);
	ret = drm_mm_insert_node_generic(&abo->dev_heap->mm, &abo->mm_node,
					 mem->size, align,
					 0, DRM_MM_INSERT_BEST);
	if (ret) {
		XDNA_ERR(xdna, "Failed to alloc dev bo memory, ret %d", ret);
		return ret;
	}

	mem->dev_addr = abo->mm_node.start;
	offset = mem->dev_addr - abo->dev_heap->mem.dev_addr;
	mem->userptr = abo->dev_heap->mem.userptr + offset;
	mem->pages = &abo->dev_heap->base.pages[offset >> PAGE_SHIFT];
	mem->nr_pages = mem->size >> PAGE_SHIFT;

	if (use_vmap) {
		mem->kva = vmap(mem->pages, mem->nr_pages, VM_MAP, PAGE_KERNEL);
		if (!mem->kva) {
			XDNA_ERR(xdna, "Failed to vmap");
			drm_mm_remove_node(&abo->mm_node);
			return -EFAULT;
		}
	}

	return 0;
}

static void amdxdna_gem_obj_free(struct drm_gem_object *gobj)
{
	struct amdxdna_dev *xdna = to_xdna_dev(gobj->dev);
	struct amdxdna_gem_obj *abo = to_xdna_obj(gobj);
	struct iosys_map map = IOSYS_MAP_INIT_VADDR(abo->mem.kva);

	XDNA_DBG(xdna, "BO type %d xdna_addr 0x%llx", abo->type, abo->mem.dev_addr);
	if (abo->flags & BO_SUBMIT_PINNED)
		amdxdna_gem_unpin(abo);

	flush_work(&abo->hmm_unreg_work);
	if (abo->type == AMDXDNA_BO_DEV) {
		mutex_lock(&abo->client->mm_lock);
		drm_mm_remove_node(&abo->mm_node);
		mutex_unlock(&abo->client->mm_lock);

		vunmap(abo->mem.kva);
		drm_gem_object_put(to_gobj(abo->dev_heap));
		drm_gem_object_release(gobj);
		mutex_destroy(&abo->lock);
		kfree(abo);
		return;
	}

	if (abo->type == AMDXDNA_BO_DEV_HEAP)
		drm_mm_takedown(&abo->mm);

#ifdef AMDXDNA_DEVEL
	if (abo->type == AMDXDNA_BO_CMD)
		amdxdna_mem_unmap(xdna, &abo->mem);
	else if (iommu_mode == AMDXDNA_IOMMU_NO_PASID)
		amdxdna_bo_dma_unmap(abo);
#endif
	drm_gem_vunmap_unlocked(gobj, &map);
	mutex_destroy(&abo->lock);
	drm_gem_shmem_free(&abo->base);
}

static const struct drm_gem_object_funcs amdxdna_gem_dev_obj_funcs = {
	.free = amdxdna_gem_obj_free,
};

static bool amdxdna_hmm_invalidate(struct mmu_interval_notifier *mni,
				   const struct mmu_notifier_range *range,
				   unsigned long cur_seq)
{
	struct amdxdna_gem_obj *abo = container_of(mni, struct amdxdna_gem_obj,
						   mem.notifier);
	struct amdxdna_dev *xdna = to_xdna_dev(to_gobj(abo)->dev);

	XDNA_DBG(xdna, "Invalid range 0x%llx, 0x%lx, type %d",
		 abo->mem.userptr, abo->mem.size, abo->type);

	if (!mmu_notifier_range_blockable(range))
		return false;

	xdna->dev_info->ops->hmm_invalidate(abo, cur_seq);

	if (range->event == MMU_NOTIFY_UNMAP)
		schedule_work(&abo->hmm_unreg_work);

	return true;
}

static const struct mmu_interval_notifier_ops amdxdna_hmm_ops = {
	.invalidate = amdxdna_hmm_invalidate,
};

static void amdxdna_hmm_unregister(struct amdxdna_gem_obj *abo)
{
	struct amdxdna_dev *xdna = to_xdna_dev(to_gobj(abo)->dev);
	struct vm_area_struct *vma = abo->mem.vma;

	if (!xdna->dev_info->ops->hmm_invalidate)
		return;

	if (!abo->mem.pfns)
		return;

	mmu_interval_notifier_remove(&abo->mem.notifier);
	kvfree(abo->mem.pfns);
	abo->mem.pfns = NULL;

	if (is_import_bo(abo) && vma->vm_file && vma->vm_file->f_mapping)
		mapping_clear_unevictable(vma->vm_file->f_mapping);
}

static int amdxdna_hmm_register(struct amdxdna_gem_obj *abo,
				struct vm_area_struct *vma)
{
	struct amdxdna_dev *xdna = to_xdna_dev(to_gobj(abo)->dev);
	unsigned long len = vma->vm_end - vma->vm_start;
	unsigned long addr = vma->vm_start;
	u32 nr_pages;
	int ret;

	if (!xdna->dev_info->ops->hmm_invalidate)
		return 0;

	if (abo->mem.pfns)
		return -EEXIST;

	nr_pages = (PAGE_ALIGN(addr + len) - (addr & PAGE_MASK)) >> PAGE_SHIFT;
	abo->mem.pfns = kvcalloc(nr_pages, sizeof(unsigned long),
				 GFP_KERNEL);
	if (!abo->mem.pfns)
		return -ENOMEM;

	ret = mmu_interval_notifier_insert_locked(&abo->mem.notifier,
						  current->mm,
						  addr,
						  len,
						  &amdxdna_hmm_ops);
	if (ret) {
		XDNA_ERR(xdna, "Insert mmu notifier failed, ret %d", ret);
		kvfree(abo->mem.pfns);
		abo->mem.pfns = NULL;
		return ret;
	}
	abo->mem.userptr = addr;
	abo->mem.vma = vma;
	if (is_import_bo(abo) && vma->vm_file && vma->vm_file->f_mapping)
		mapping_set_unevictable(vma->vm_file->f_mapping);

	return 0;
}

static int is_mapped_fn(pte_t *pte, unsigned long addr, void *data)
{
	if (pte_none(ptep_get(pte)))
		return -EINVAL;

	*(bool *)data = true;
	return 0;
}

static int amdxdna_insert_pages(struct amdxdna_gem_obj *abo,
				struct vm_area_struct *vma)
{
	unsigned long num_pages = (vma->vm_end - vma->vm_start) >> PAGE_SHIFT;
	struct sg_dma_page_iter sg_iter;
	bool has_mapped_page = false;
	unsigned long offset = 0;
	int ret;

	if (!is_import_bo(abo)) {
		/* The buffer is based on memory pages. Fix the flag. */
		vm_flags_mod(vma, VM_MIXEDMAP, VM_PFNMAP);
		return vm_insert_pages(vma, vma->vm_start, abo->base.pages,
				       &num_pages);
	}

	ret = apply_to_page_range(vma->vm_mm, vma->vm_start, num_pages,
				  is_mapped_fn, &has_mapped_page);
	if (!ret)
		return 0;

	if (has_mapped_page)
		return -EBUSY;

	for_each_sgtable_dma_page(abo->base.sgt, &sg_iter, 0) {
		dma_addr_t addr = sg_page_iter_dma_address(&sg_iter);
		unsigned long pfn;

		pfn = PFN_DOWN(dma_to_phys(to_gobj(abo)->dev->dev, addr));
		ret = io_remap_pfn_range(vma, vma->vm_start + offset, pfn,
					 PAGE_SIZE, vma->vm_page_prot);
		if (ret)
			break;

		offset += PAGE_SIZE;
	}

	return ret;
}

static int amdxdna_gem_obj_mmap(struct drm_gem_object *gobj,
				struct vm_area_struct *vma)
{
	struct amdxdna_dev *xdna = to_xdna_dev(gobj->dev);
	struct amdxdna_gem_obj *abo = to_xdna_obj(gobj);
	int ret;

	if (vma->vm_end - vma->vm_start > gobj->size)
		return -EINVAL;

	ret = amdxdna_hmm_register(abo, vma);
	if (ret)
		return ret;

	ret = drm_gem_shmem_mmap(&abo->base, vma);
	if (ret) {
		XDNA_ERR(xdna, "failed shmem mmap %d", ret);
		goto hmm_unreg;
	}

	ret = amdxdna_insert_pages(abo, vma);
	if (ret) {
		XDNA_ERR(xdna, "Failed insert pages, ret %d", ret);
		goto close_vma;
	}

	XDNA_DBG(xdna, "BO map_offset 0x%llx type %d userptr 0x%llx size 0x%lx",
		 drm_vma_node_offset_addr(&gobj->vma_node), abo->type,
		 abo->mem.userptr, gobj->size);
	return 0;

close_vma:
	vma->vm_ops->close(vma);
hmm_unreg:
	amdxdna_hmm_unregister(abo);
	return ret;
}

static int amdxdna_gem_dmabuf_mmap(struct dma_buf *dma_buf, struct vm_area_struct *vma)
{
	struct drm_gem_object *gobj = dma_buf->priv;
	struct amdxdna_gem_obj *abo = to_xdna_obj(gobj);
	int ret;

	vma->vm_ops = &drm_gem_shmem_vm_ops;
	vma->vm_private_data = gobj;

	drm_gem_object_get(gobj);
	ret = drm_gem_shmem_mmap(&abo->base, vma);
	if (ret)
		drm_gem_object_put(gobj);

	return ret;
}

static const struct dma_buf_ops amdxdna_dmabuf_ops = {
	.cache_sgt_mapping = true,
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
	DEFINE_DMA_BUF_EXPORT_INFO(exp_info);

	exp_info.ops = &amdxdna_dmabuf_ops;
	exp_info.size = gobj->size;
	exp_info.flags = flags;
	exp_info.priv = gobj;
	exp_info.resv = gobj->resv;

	return drm_gem_dmabuf_export(gobj->dev, &exp_info);
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
	.export = amdxdna_gem_prime_export,
};

static void amdxdna_hmm_unreg_work(struct work_struct *work)
{
	struct amdxdna_gem_obj *abo = container_of(work, struct amdxdna_gem_obj,
						   hmm_unreg_work);
	struct mm_struct *mm = abo->mem.notifier.mm;

	if (!mmget_not_zero(mm))
		return;

	mmap_read_lock(mm);
	amdxdna_hmm_unregister(abo);
	mmap_read_unlock(mm);

	mmput(mm);
}

static struct amdxdna_gem_obj *
amdxdna_gem_create_obj(struct drm_device *dev, size_t size)
{
	struct amdxdna_gem_obj *abo;

	abo = kzalloc(sizeof(*abo), GFP_KERNEL);
	if (!abo)
		return ERR_PTR(-ENOMEM);

	abo->assigned_hwctx = AMDXDNA_INVALID_CTX_HANDLE;
	mutex_init(&abo->lock);
	INIT_WORK(&abo->hmm_unreg_work, amdxdna_hmm_unreg_work);

	abo->mem.userptr = AMDXDNA_INVALID_ADDR;
	abo->mem.dev_addr = AMDXDNA_INVALID_ADDR;
	abo->mem.size = size;

	return abo;
}

/* For drm_driver->gem_create_object callback */
struct drm_gem_object *
amdxdna_gem_create_object_cb(struct drm_device *dev, size_t size)
{
	struct amdxdna_gem_obj *abo;

	abo = amdxdna_gem_create_obj(dev, size);
	if (IS_ERR(abo))
		return ERR_CAST(abo);

	to_gobj(abo)->funcs = &amdxdna_gem_shmem_funcs;

	return to_gobj(abo);
}

struct drm_gem_object *
amdxdna_gem_prime_import(struct drm_device *dev, struct dma_buf *dma_buf)
{
	struct dma_buf_attachment *attach;
	struct drm_gem_object *gobj;
	struct sg_table *sgt;
	int ret;

	attach = dma_buf_attach(dma_buf, dev->dev);
	if (IS_ERR(attach))
		return ERR_CAST(attach);

	get_dma_buf(dma_buf);

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

	gobj->import_attach = attach;
	gobj->resv = dma_buf->resv;

#ifdef AMDXDNA_DEVEL
	if (iommu_mode == AMDXDNA_IOMMU_NO_PASID) {
		struct amdxdna_gem_obj *abo;

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
	dma_buf_put(dma_buf);

	return ERR_PTR(ret);
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
	abo->type = AMDXDNA_BO_SHMEM;

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
amdxdna_drm_create_dev_heap(struct drm_device *dev,
			    struct amdxdna_drm_create_bo *args,
			    struct drm_file *filp)
{
	struct amdxdna_client *client = filp->driver_priv;
	struct amdxdna_dev *xdna = to_xdna_dev(dev);
	struct drm_gem_shmem_object *shmem;
	struct amdxdna_gem_obj *abo;
	int ret;

	if (args->size > xdna->dev_info->dev_mem_size) {
		XDNA_DBG(xdna, "Invalid dev heap size 0x%llx, limit 0x%lx",
			 args->size, xdna->dev_info->dev_mem_size);
		return ERR_PTR(-EINVAL);
	}

	mutex_lock(&client->mm_lock);
	if (client->dev_heap) {
		XDNA_DBG(client->xdna, "dev heap is already created");
		ret = -EBUSY;
		goto mm_unlock;
	}

	shmem = drm_gem_shmem_create(dev, args->size);
	if (IS_ERR(shmem)) {
		ret = PTR_ERR(shmem);
		goto mm_unlock;
	}

	shmem->map_wc = false;
	abo = to_xdna_obj(&shmem->base);

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

	if (heap->mem.userptr == AMDXDNA_INVALID_ADDR) {
		XDNA_ERR(xdna, "Invalid dev heap userptr");
		ret = -EINVAL;
		goto mm_unlock;
	}

	if (args->size > heap->mem.size) {
		XDNA_ERR(xdna, "Invalid dev bo size 0x%llx, limit 0x%lx",
			 args->size, heap->mem.size);
		ret = -EINVAL;
		goto mm_unlock;
	}

	abo = amdxdna_gem_create_obj(&xdna->ddev, aligned_sz);
	if (IS_ERR(abo)) {
		ret = PTR_ERR(abo);
		goto mm_unlock;
	}
	to_gobj(abo)->funcs = &amdxdna_gem_dev_obj_funcs;
	abo->type = AMDXDNA_BO_DEV;
	abo->client = client;
	abo->dev_heap = heap;
	ret = amdxdna_gem_insert_node_locked(abo, use_vmap);
	if (ret) {
		XDNA_ERR(xdna, "Failed to alloc dev bo memory, ret %d", ret);
		goto mm_unlock;
	}

	drm_gem_object_get(to_gobj(heap));
	drm_gem_private_object_init(&xdna->ddev, to_gobj(abo), aligned_sz);

	mutex_unlock(&client->mm_lock);
	return abo;

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
	struct drm_gem_shmem_object *shmem;
	struct amdxdna_gem_obj *abo;
	struct iosys_map map;
	int ret;

	if (args->size > XDNA_MAX_CMD_BO_SIZE) {
		XDNA_ERR(xdna, "Command bo size 0x%llx too large", args->size);
		return ERR_PTR(-EINVAL);
	}

	if (args->size < sizeof(struct amdxdna_cmd)) {
		XDNA_DBG(xdna, "Command BO size 0x%llx too small", args->size);
		return ERR_PTR(-EINVAL);
	}

	shmem = drm_gem_shmem_create(dev, args->size);
	if (IS_ERR(shmem))
		return ERR_CAST(shmem);

	shmem->map_wc = false;
	abo = to_xdna_obj(&shmem->base);

	abo->type = AMDXDNA_BO_CMD;
	abo->client = filp->driver_priv;

	ret = drm_gem_vmap_unlocked(to_gobj(abo), &map);
	if (ret) {
		XDNA_ERR(xdna, "Vmap cmd bo failed, ret %d", ret);
		goto release_obj;
	}
	abo->mem.kva = map.vaddr;

	return abo;

release_obj:
	drm_gem_shmem_free(shmem);
	return ERR_PTR(ret);
}

int amdxdna_drm_create_bo_ioctl(struct drm_device *dev, void *data, struct drm_file *filp)
{
	struct amdxdna_dev *xdna = to_xdna_dev(dev);
	struct amdxdna_drm_create_bo *args = data;
	struct amdxdna_gem_obj *abo;
	int ret;

	if (args->flags || args->vaddr || !args->size)
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
#ifdef AMDXDNA_DEVEL
		if (IS_ERR(abo))
			break;
		abo->mem.pages = abo->base.pages;
		abo->mem.nr_pages = to_gobj(abo)->size >> PAGE_SHIFT;
		ret = amdxdna_mem_map(xdna, &abo->mem);
		if (ret)
			goto put_obj;
		abo->mem.dev_addr = abo->mem.dma_addr;
#endif
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

	XDNA_DBG(xdna, "BO hdl %d type %d userptr 0x%llx xdna_addr 0x%llx size 0x%lx",
		 args->handle, args->type, abo->mem.userptr,
		 abo->mem.dev_addr, abo->mem.size);
put_obj:
	/* Dereference object reference. Handle holds it now. */
	drm_gem_object_put(to_gobj(abo));
	return ret;
}

int amdxdna_gem_pin_nolock(struct amdxdna_gem_obj *abo)
{
	struct amdxdna_dev *xdna = to_xdna_dev(to_gobj(abo)->dev);
	int ret;

	if (is_import_bo(abo))
		return 0;

	switch (abo->type) {
	case AMDXDNA_BO_SHMEM:
	case AMDXDNA_BO_DEV_HEAP:
		ret = drm_gem_shmem_pin(&abo->base);
		break;
	case AMDXDNA_BO_DEV:
		ret = amdxdna_gem_pin(abo->dev_heap);
		break;
	default:
		ret = -EOPNOTSUPP;
	}

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
	if (is_import_bo(abo))
		return;

	mutex_lock(&abo->lock);
	XDNA_DBG(abo->client->xdna, "BO type %d", abo->type);
	switch (abo->type) {
	case AMDXDNA_BO_SHMEM:
	case AMDXDNA_BO_DEV_HEAP:
		drm_gem_shmem_unpin(&abo->base);
		break;
	case AMDXDNA_BO_DEV:
		amdxdna_gem_unpin(abo->dev_heap);
		break;
	default:
		/* Should never go here */
		WARN_ONCE(1, "Unexpected BO type %d\n", abo->type);
	}
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

	if (abo->type != AMDXDNA_BO_DEV)
		args->map_offset = drm_vma_node_offset_addr(&gobj->vma_node);
	else
		args->map_offset = AMDXDNA_INVALID_ADDR;

	XDNA_DBG(xdna, "BO hdl %d map_offset 0x%llx vaddr 0x%llx xdna_addr 0x%llx",
		 args->handle, args->map_offset, args->vaddr, args->xdna_addr);

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
	struct amdxdna_client *client = filp->driver_priv;
	struct amdxdna_dev *xdna = to_xdna_dev(dev);
	struct amdxdna_drm_sync_bo *args = data;
	struct amdxdna_gem_obj *abo;
	struct drm_gem_object *gobj;
	u32 hwctx_hdl;
	int ret;

	gobj = drm_gem_object_lookup(filp, args->handle);
	if (!gobj) {
		XDNA_ERR(xdna, "Lookup GEM object failed");
		return -ENOENT;
	}
	abo = to_xdna_obj(gobj);

	ret = amdxdna_gem_pin(abo);
	if (ret) {
		XDNA_ERR(xdna, "Pin BO %d failed, ret %d", args->handle, ret);
		goto put_obj;
	}

	if (abo->type == AMDXDNA_BO_DEV) {
		drm_clflush_pages(abo->mem.pages, abo->mem.nr_pages);
	} else {
		if (is_import_bo(abo))
			drm_clflush_sg(abo->base.sgt);
		else
			drm_clflush_pages(abo->base.pages, gobj->size >> PAGE_SHIFT);
	}

	amdxdna_gem_unpin(abo);

	if (abo->assigned_hwctx != AMDXDNA_INVALID_CTX_HANDLE &&
	    args->direction == SYNC_DIRECT_FROM_DEVICE) {
		u64 seq;

		hwctx_hdl = amdxdna_gem_get_assigned_hwctx(client, args->handle);
		if (hwctx_hdl == AMDXDNA_INVALID_CTX_HANDLE ||
		    args->direction != SYNC_DIRECT_FROM_DEVICE) {
			XDNA_ERR(xdna, "Sync failed, dir %d", args->direction);
			ret = -EINVAL;
			goto put_obj;
		}

		ret = amdxdna_cmd_submit(client, OP_SYNC_BO, AMDXDNA_INVALID_BO_HANDLE,
					 &args->handle, 1, hwctx_hdl, &seq);
		if (ret) {
			XDNA_ERR(xdna, "Submit command failed");
			goto put_obj;
		}

		ret = amdxdna_cmd_wait(client, hwctx_hdl, seq, 3000 /* ms */);
	}

	XDNA_DBG(xdna, "Sync bo %d offset 0x%llx, size 0x%llx, dir %d, hwctx %d\n",
		 args->handle, args->offset, args->size, args->direction,
		 abo->assigned_hwctx);

put_obj:
	drm_gem_object_put(gobj);
	return ret;
}

u32 amdxdna_gem_get_assigned_hwctx(struct amdxdna_client *client, u32 bo_hdl)
{
	struct amdxdna_gem_obj *abo = amdxdna_gem_get_obj(client, bo_hdl, AMDXDNA_BO_INVALID);
	u32 ctxid;

	if (!abo) {
		XDNA_DBG(client->xdna, "Get bo %d failed", bo_hdl);
		return AMDXDNA_INVALID_CTX_HANDLE;
	}

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

	if (!abo) {
		XDNA_DBG(client->xdna, "Get bo %d failed", bo_hdl);
		return -EINVAL;
	}

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

	if (!abo) {
		XDNA_DBG(client->xdna, "Get bo %d failed", bo_hdl);
		return;
	}

	mutex_lock(&abo->lock);
	abo->assigned_hwctx = AMDXDNA_INVALID_CTX_HANDLE;
	mutex_unlock(&abo->lock);

	amdxdna_gem_put_obj(abo);
}

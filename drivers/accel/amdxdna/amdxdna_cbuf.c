// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2026, Advanced Micro Devices, Inc.
 */

#include "drm/amdxdna_accel.h"
#include <drm/drm_gem.h>
#include <drm/drm_mm.h>
#include <drm/drm_prime.h>
#include <drm/drm_vma_manager.h>
#include <linux/dma-buf.h>
#include <linux/dma-mapping.h>
#include <linux/io.h>
#include <linux/iosys-map.h>
#include <linux/mm.h>
#include <linux/scatterlist.h>
#include <linux/slab.h>
#include <linux/string.h>

#include "amdxdna_cbuf.h"
#include "amdxdna_drv.h"
#include "amdxdna_gem.h"

/*
 * Carveout memory is a chunk of memory which is physically contiguous and
 * is reserved during early boot time. There is only one chunk of such memory
 * per device. Once available, all BOs accessible from device should be
 * allocated from this memory. This is a platform debug/bringup feature.
 *
 * A carveout BO is a native DRM GEM object -- there is no eager export/import
 * round-trip to back it.  The backing is bare physical memory with no struct
 * page (ioremap_cache for vmap, PFNMAP for mmap, dma_map_resource for the
 * device sg_table), so it cannot use the standard GEM PRIME dma_map_sgtable()
 * path; PRIME export is instead served on demand by a private dma_buf_ops that
 * dma_map_resource()s the range for the importer (amdxdna_gem_cbuf_obj_export).
 */
struct amdxdna_carveout {
	u64		addr;
	u64		size;
	struct drm_mm	mm;
	struct mutex	lock; /* protect mm */
};

bool amdxdna_use_carveout(struct amdxdna_dev *xdna)
{
	return !!xdna->carveout;
}

void amdxdna_get_carveout_conf(struct amdxdna_dev *xdna, u64 *addr, u64 *size)
{
	if (amdxdna_use_carveout(xdna)) {
		*addr = xdna->carveout->addr;
		*size = xdna->carveout->size;
	} else {
		*addr = 0;
		*size = 0;
	}
}

int amdxdna_carveout_init(struct amdxdna_dev *xdna, u64 carveout_addr, u64 carveout_size)
{
	struct amdxdna_carveout *carveout;

	/* Only allow carveout memory to be set up once. */
	if (amdxdna_use_carveout(xdna)) {
		XDNA_ERR(xdna, "Carveout memory has already been set up.");
		return -EBUSY;
	}

	carveout = kzalloc_obj(*carveout);
	if (!carveout)
		return -ENOMEM;

	carveout->addr = carveout_addr;
	carveout->size = carveout_size;
	mutex_init(&carveout->lock);
	drm_mm_init(&carveout->mm, carveout->addr, carveout->size);

	xdna->carveout = carveout;
	XDNA_INFO(xdna, "Use carveout mem: 0x%llx@0x%llx\n", carveout->size, carveout->addr);
	return 0;
}

void amdxdna_carveout_fini(struct amdxdna_dev *xdna)
{
	struct amdxdna_carveout *carveout = xdna->carveout;

	if (!amdxdna_use_carveout(xdna))
		return;

	XDNA_INFO(xdna, "Cleanup carveout mem: 0x%llx@0x%llx\n", carveout->size, carveout->addr);
	mutex_destroy(&carveout->lock);
	drm_mm_takedown(&carveout->mm);
	kfree(carveout);
	xdna->carveout = NULL;
}

/*
 * Device sg_table for the carveout range.  The memory is a bare resource (no
 * struct page), so map it with dma_map_resource() as one contiguous mapping
 * split into DMA-segment-sized sg entries.  Cached in abo->mem.sgt, this is what
 * amdxdna_gem_get_sgt() returns and amdxdna_dma_map_bo() reads sg_dma_address()
 * from on the IOVA-off path.
 */
static struct sg_table *amdxdna_cbuf_map_resource(struct device *dev, u64 start,
						  size_t size, enum dma_data_direction dir)
{
	struct scatterlist *sgl, *sg;
	int ret, n_entries, i;
	struct sg_table *sgt;
	dma_addr_t dma_addr;
	size_t dma_size;
	size_t max_seg;

	sgt = kzalloc_obj(*sgt);
	if (!sgt)
		return ERR_PTR(-ENOMEM);

	max_seg = min_t(size_t, UINT_MAX, dma_max_mapping_size(dev));
	n_entries = (size + max_seg - 1) / max_seg;
	sgl = kzalloc_objs(*sg, n_entries);
	if (!sgl) {
		ret = -ENOMEM;
		goto free_sgt;
	}
	sg_init_table(sgl, n_entries);
	sgt->orig_nents = n_entries;
	sgt->nents = n_entries;
	sgt->sgl = sgl;

	dma_addr = dma_map_resource(dev, start, size, dir, DMA_ATTR_SKIP_CPU_SYNC);
	ret = dma_mapping_error(dev, dma_addr);
	if (ret) {
		pr_err("Failed to dma_map_resource carveout, ret %d\n", ret);
		goto free_sgl;
	}

	dma_size = size;
	for_each_sgtable_dma_sg(sgt, sg, i) {
		size_t len = min_t(size_t, max_seg, dma_size);

		sg_dma_address(sg) = dma_addr;
		sg_dma_len(sg) = len;
		dma_addr += len;
		dma_size -= len;
	}

	return sgt;

free_sgl:
	kfree(sgl);
free_sgt:
	kfree(sgt);
	return ERR_PTR(ret);
}

static void amdxdna_cbuf_unmap_resource(struct device *dev, struct sg_table *sgt,
					enum dma_data_direction dir)
{
	dma_unmap_resource(dev, sg_dma_address(sgt->sgl),
			   drm_prime_get_contiguous_size(sgt), dir,
			   DMA_ATTR_SKIP_CPU_SYNC);
	sg_free_table(sgt);
	kfree(sgt);
}

static void amdxdna_gem_cbuf_obj_free(struct drm_gem_object *gobj)
{
	struct amdxdna_dev *xdna = to_xdna_dev(gobj->dev);
	struct amdxdna_gem_obj *abo = to_xdna_obj(gobj);
	struct amdxdna_carveout *carveout = xdna->carveout;

	/*
	 * No amdxdna_dma_unmap_bo() here: carveout never holds a private IOVA
	 * mapping (amdxdna_dma_map_bo() only records sg_dma_address on IOVA-off and
	 * is rejected on IOVA-on as the resource sgt is not page-backed). The
	 * dma_map_resource() mapping is torn down by amdxdna_cbuf_unmap_resource()
	 * below.
	 *
	 * Release the cached CPU mapping; unlike CMA's page_address(), the
	 * carveout vmap ioremap_cache()s and must be iounmap()ed.
	 */
	if (abo->mem.kva) {
		iounmap(abo->mem.kva);
		abo->mem.kva = NULL;
	}
	if (abo->mem.sgt) {
		amdxdna_cbuf_unmap_resource(xdna->ddev.dev, abo->mem.sgt, DMA_BIDIRECTIONAL);
		abo->mem.sgt = NULL;
	}

	mutex_lock(&carveout->lock);
	drm_mm_remove_node(&abo->mm_node);
	mutex_unlock(&carveout->lock);

	drm_gem_object_release(gobj);
	amdxdna_gem_destroy_obj(abo);
}

static int amdxdna_gem_cbuf_obj_vmap(struct drm_gem_object *gobj, struct iosys_map *map)
{
	struct amdxdna_gem_obj *abo = to_xdna_obj(gobj);
	void *kva;

	kva = ioremap_cache(abo->mm_node.start, abo->mem.size);
	if (!kva) {
		pr_err("Failed to vmap carveout BO\n");
		return -EINVAL;
	}

	iosys_map_set_vaddr(map, kva);
	return 0;
}

static void amdxdna_gem_cbuf_obj_vunmap(struct drm_gem_object *gobj, struct iosys_map *map)
{
	iounmap(map->vaddr);
}

static int amdxdna_gem_cbuf_obj_mmap(struct drm_gem_object *gobj, struct vm_area_struct *vma)
{
	struct amdxdna_gem_obj *abo = to_xdna_obj(gobj);

	/*
	 * drm_gem_mmap() encodes a fake buffer offset in vm_pgoff; rebase it to the
	 * page offset into the BO. The carveout is a bare physical range with no
	 * struct page, so map it from that offset with remap_pfn_range() (PFNMAP) --
	 * drm_gem_mmap() has already validated offset+length against the BO size.
	 */
	vma->vm_pgoff -= drm_vma_node_start(&gobj->vma_node);
	vm_flags_set(vma, VM_PFNMAP | VM_DONTEXPAND | VM_DONTDUMP);
	vma->vm_page_prot = vm_get_page_prot(vma->vm_flags);

	return remap_pfn_range(vma, vma->vm_start,
			       (abo->mm_node.start >> PAGE_SHIFT) + vma->vm_pgoff,
			       vma->vm_end - vma->vm_start, vma->vm_page_prot);
}

static const struct vm_operations_struct amdxdna_gem_cbuf_vm_ops = {
	.open = drm_gem_vm_open,
	.close = drm_gem_vm_close,
};

/*
 * PRIME export: the carveout is page-less, so the standard GEM dma-buf path
 * (drm_gem_map_dma_buf() -> dma_map_sgtable()) does not apply.  Map the resource
 * for the importer's device on attach with a private dma_buf_ops; mmap/vmap and
 * release route back to the GEM object, so the drm_mm node stays owned by the BO
 * and the dma-buf only holds a reference to it.
 */
static struct sg_table *amdxdna_gem_cbuf_dmabuf_map(struct dma_buf_attachment *attach,
						    enum dma_data_direction dir)
{
	struct amdxdna_gem_obj *abo = to_xdna_obj(attach->dmabuf->priv);

	return amdxdna_cbuf_map_resource(attach->dev, abo->mm_node.start,
					 abo->mem.size, dir);
}

static void amdxdna_gem_cbuf_dmabuf_unmap(struct dma_buf_attachment *attach,
					  struct sg_table *sgt,
					  enum dma_data_direction dir)
{
	amdxdna_cbuf_unmap_resource(attach->dev, sgt, dir);
}

static const struct dma_buf_ops amdxdna_gem_cbuf_dmabuf_ops = {
	.map_dma_buf = amdxdna_gem_cbuf_dmabuf_map,
	.unmap_dma_buf = amdxdna_gem_cbuf_dmabuf_unmap,
	.release = drm_gem_dmabuf_release,
	.mmap = drm_gem_dmabuf_mmap,
	.vmap = drm_gem_dmabuf_vmap,
	.vunmap = drm_gem_dmabuf_vunmap,
};

static struct dma_buf *amdxdna_gem_cbuf_obj_export(struct drm_gem_object *gobj, int flags)
{
	DEFINE_DMA_BUF_EXPORT_INFO(exp_info);

	exp_info.ops = &amdxdna_gem_cbuf_dmabuf_ops;
	exp_info.size = gobj->size;
	exp_info.flags = flags;
	exp_info.priv = gobj;
	exp_info.resv = gobj->resv;

	return drm_gem_dmabuf_export(gobj->dev, &exp_info);
}

static const struct drm_gem_object_funcs amdxdna_gem_cbuf_obj_funcs = {
	.free = amdxdna_gem_cbuf_obj_free,
	.open = amdxdna_gem_obj_open,
	.close = amdxdna_gem_obj_close,
	.export = amdxdna_gem_cbuf_obj_export,
	.vmap = amdxdna_gem_cbuf_obj_vmap,
	.vunmap = amdxdna_gem_cbuf_obj_vunmap,
	.mmap = amdxdna_gem_cbuf_obj_mmap,
	.vm_ops = &amdxdna_gem_cbuf_vm_ops,
};

struct amdxdna_gem_obj *
amdxdna_get_cbuf(struct drm_device *dev, struct amdxdna_drm_create_bo *args)
{
	struct amdxdna_dev *xdna = to_xdna_dev(dev);
	struct amdxdna_carveout *carveout = xdna->carveout;
	size_t size = PAGE_ALIGN(args->size);
	struct amdxdna_gem_obj *abo;
	struct sg_table *sgt;
	void *kva;
	u64 align;
	int ret;

	if (!size) {
		XDNA_ERR(xdna, "Invalid BO size 0x%llx", args->size);
		return ERR_PTR(-EINVAL);
	}

	abo = amdxdna_gem_create_obj(dev, size);
	if (IS_ERR(abo))
		return abo;

	align = (args->type == AMDXDNA_BO_DEV_HEAP) ? xdna->dev_info->dev_mem_size : 0;

	mutex_lock(&carveout->lock);
	ret = drm_mm_insert_node_generic(&carveout->mm, &abo->mm_node, size,
					 align, 0, DRM_MM_INSERT_BEST);
	mutex_unlock(&carveout->lock);
	if (ret)
		goto destroy_obj;

	sgt = amdxdna_cbuf_map_resource(xdna->ddev.dev, abo->mm_node.start, size,
					DMA_BIDIRECTIONAL);
	if (IS_ERR(sgt)) {
		ret = PTR_ERR(sgt);
		goto remove_node;
	}
	abo->mem.sgt = sgt;
	abo->private_buffer = true;
	abo->type = AMDXDNA_BO_SHARE;

	/*
	 * Zero the carveout before exposing it to userspace: the region is
	 * recycled through drm_mm, so failing to clear it would leak a previous
	 * BO's contents. Treat a mapping failure as fatal rather than skipping.
	 */
	kva = ioremap_cache(abo->mm_node.start, size);
	if (!kva) {
		XDNA_ERR(xdna, "Map carveout BO for zeroing failed");
		ret = -ENOMEM;
		goto unmap_sgt;
	}
	memset(kva, 0, size);
	iounmap(kva);

	to_gobj(abo)->funcs = &amdxdna_gem_cbuf_obj_funcs;
	drm_gem_private_object_init(dev, to_gobj(abo), size);

	ret = drm_gem_create_mmap_offset(to_gobj(abo));
	if (ret) {
		XDNA_ERR(xdna, "Create mmap offset failed, ret %d", ret);
		drm_gem_object_release(to_gobj(abo));
		goto unmap_sgt;
	}

	return abo;

unmap_sgt:
	amdxdna_cbuf_unmap_resource(xdna->ddev.dev, abo->mem.sgt, DMA_BIDIRECTIONAL);
	abo->mem.sgt = NULL;
remove_node:
	mutex_lock(&carveout->lock);
	drm_mm_remove_node(&abo->mm_node);
	mutex_unlock(&carveout->lock);
destroy_obj:
	amdxdna_gem_destroy_obj(abo);
	return ERR_PTR(ret);
}

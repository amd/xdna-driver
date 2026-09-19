// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2026, Advanced Micro Devices, Inc.
 */

#include "drm/amdxdna_accel.h"
#include <drm/drm_device.h>
#include <drm/drm_gem.h>
#include <drm/drm_prime.h>
#include <drm/drm_vma_manager.h>
#include <linux/dma-mapping.h>
#include <linux/iosys-map.h>
#include <linux/log2.h>
#include <linux/scatterlist.h>
#include <linux/slab.h>

#include "amdxdna_cma_buf.h"
#include "amdxdna_drv.h"
#include "amdxdna_gem.h"

/*
 * CMA create-BO backing.  Physically contiguous memory from the device's DMA
 * pool via dma_alloc_coherent(): the DT-reserved "aie" reusable shared-dma-pool
 * memory-region bound to the device (dev->cma_area), otherwise the system CMA.
 *
 * On the non-coherent platform dma_alloc_coherent() returns a non-cacheable
 * mapping, so the device and CPU stay coherent with no cache maintenance
 * (SYNC_BO is a no-op); on a cache-coherent part it is plain coherent memory.
 * The BO is addressed directly by its dma_addr -- no page array and no streaming
 * sgt.
 *
 * Why non-cacheable rather than cacheable + SYNC_BO: these are control buffers
 * the CPU *produces* and the device consumes (instruction, command and
 * HSA/host-queue BOs).  The common pattern is a sparse write -- patching a few
 * addresses into a large, otherwise-unchanged instruction BO -- followed by a
 * single submit (low reuse).  For that pattern non-cacheable wins because its
 * cache maintenance is free: SYNC_BO is a no-op whatever the size, whereas a
 * cacheable BO must clflush the whole synced range on every submit, a cost that
 * grows with the BO size rather than with the few bytes actually touched.
 *
 * Measured on the platform (xrt bo micro-bench), CPU-produce then one device
 * read (reuse=1), cacheable(+sync) vs non-cacheable:
 *
 *	size	cacheable   noncache	faster
 *	 512B	 0.884us     0.062us	noncache 14x
 *	   4K	 1.304us     0.304us	noncache 4.3x
 *	  64K	 9.884us     5.372us	noncache 1.8x
 *	   1M	129.562us   85.948us	noncache 1.5x
 *	   4M	522.062us  343.668us	noncache 1.5x
 *
 * The root cause is the maintenance asymmetry -- SYNC_BO cost vs buffer size:
 *
 *	size	cacheable sync	noncache sync
 *	   4K	    0.78us	    0.56us
 *	   1M	   28.05us	    0.56us
 *	   4M	  107.85us	    0.56us
 *
 * Cacheable only pays off when the CPU re-reads a buffer many times (consume /
 * read-modify-write reuse), which these produce-once control buffers do not.
 *
 * The BO is a native DRM GEM object, PRIME-exportable via a .get_sg_table built
 * with dma_get_sgtable() over the coherent allocation.  SYNC_BO stays a no-op
 * for it (amdxdna_is_cma_bo() keys off the funcs pointer, which gains callbacks
 * but keeps its identity); the exported memory is coherent, so an importer never
 * sees a stale cached copy.
 */

static void amdxdna_gem_cma_obj_free(struct drm_gem_object *gobj)
{
	struct amdxdna_dev *xdna = to_xdna_dev(gobj->dev);
	struct amdxdna_gem_obj *abo = to_xdna_obj(gobj);

	/*
	 * No amdxdna_dma_unmap_bo() here: the BO is addressed by its own coherent
	 * dma_addr, not a private IOVA mapping (amdxdna_dma_map_bo() no-ops on a
	 * preset dma_addr), so there is nothing to unmap. dma_free_coherent()
	 * releases the allocation via cma_dma_addr.
	 */
	dma_free_coherent(xdna->ddev.dev, abo->mem.size, abo->mem.kva,
			  abo->cma_dma_addr);
	drm_gem_object_release(gobj);
	amdxdna_gem_destroy_obj(abo);
}

static int amdxdna_gem_cma_obj_vmap(struct drm_gem_object *gobj, struct iosys_map *map)
{
	struct amdxdna_gem_obj *abo = to_xdna_obj(gobj);

	/* The CPU address from dma_alloc_coherent() (non-cacheable on the platform). */
	iosys_map_set_vaddr(map, abo->mem.kva);
	return 0;
}

static void amdxdna_gem_cma_obj_vunmap(struct drm_gem_object *gobj, struct iosys_map *map)
{
	/* dma_alloc_coherent()'s mapping is released on free; nothing to tear down. */
	iosys_map_clear(map);
}

static int amdxdna_gem_cma_obj_mmap(struct drm_gem_object *gobj, struct vm_area_struct *vma)
{
	struct amdxdna_dev *xdna = to_xdna_dev(gobj->dev);
	struct amdxdna_gem_obj *abo = to_xdna_obj(gobj);

	/* drm_gem_mmap() encodes a fake buffer offset in vm_pgoff; rebase to 0. */
	vma->vm_pgoff -= drm_vma_node_start(&gobj->vma_node);

	/* dma_mmap_coherent() maps the region and sets the page prot itself. */
	return dma_mmap_coherent(xdna->ddev.dev, vma, abo->mem.kva,
				 abo->cma_dma_addr, vma->vm_end - vma->vm_start);
}

/*
 * Build an sg_table over the coherent allocation for a PRIME importer.
 * dma_get_sgtable() derives the backing pages from the DMA address, so it works
 * even for the non-cacheable remap on the platform. drm_gem_map_dma_buf() then
 * dma_map_sgtable()s this for the importer's device; drm_gem_unmap_dma_buf()
 * frees it (sg_free_table + kfree).
 */
static struct sg_table *amdxdna_gem_cma_obj_get_sg_table(struct drm_gem_object *gobj)
{
	struct amdxdna_dev *xdna = to_xdna_dev(gobj->dev);
	struct amdxdna_gem_obj *abo = to_xdna_obj(gobj);
	struct sg_table *sgt;
	int ret;

	sgt = kzalloc_obj(*sgt);
	if (!sgt)
		return ERR_PTR(-ENOMEM);

	ret = dma_get_sgtable(xdna->ddev.dev, sgt, abo->mem.kva,
			      abo->cma_dma_addr, abo->mem.size);
	if (ret) {
		kfree(sgt);
		return ERR_PTR(ret);
	}

	return sgt;
}

static const struct vm_operations_struct amdxdna_gem_cma_vm_ops = {
	.open = drm_gem_vm_open,
	.close = drm_gem_vm_close,
};

static const struct drm_gem_object_funcs amdxdna_gem_cma_obj_funcs = {
	.free = amdxdna_gem_cma_obj_free,
	.open = amdxdna_gem_obj_open,
	.close = amdxdna_gem_obj_close,
	.vmap = amdxdna_gem_cma_obj_vmap,
	.vunmap = amdxdna_gem_cma_obj_vunmap,
	.mmap = amdxdna_gem_cma_obj_mmap,
	.get_sg_table = amdxdna_gem_cma_obj_get_sg_table,
	/*
	 * No .export: with a NULL export callback, DRM PRIME defaults to
	 * drm_gem_prime_export(), which wraps these funcs so map_dma_buf/mmap/vmap
	 * route back to get_sg_table/mmap/vmap above -- all CMA-correct (and not the
	 * shmem-assuming amdxdna_gem_prime_export).
	 */
	.vm_ops = &amdxdna_gem_cma_vm_ops,
};

/* True if @abo was created by amdxdna_get_cma_buf() (identified by its funcs). */
bool amdxdna_is_cma_bo(struct amdxdna_gem_obj *abo)
{
	return to_gobj(abo)->funcs == &amdxdna_gem_cma_obj_funcs;
}

struct amdxdna_gem_obj *
amdxdna_get_cma_buf(struct drm_device *dev, struct amdxdna_drm_create_bo *args)
{
	struct amdxdna_dev *xdna = to_xdna_dev(dev);
	struct device *cma_dev = xdna->ddev.dev;
	size_t size = PAGE_ALIGN(args->size);
	struct amdxdna_gem_obj *abo;
	dma_addr_t dma_addr;
	void *kva;
	u64 align;
	int ret;

	if (!size) {
		XDNA_ERR(xdna, "Invalid BO size 0x%llx", args->size);
		return ERR_PTR(-EINVAL);
	}

	/*
	 * A dev-heap BO must be self-aligned to its size.  dma_alloc_coherent()
	 * aligns to get_order(size) (capped by CONFIG_CMA_ALIGNMENT), so grow the
	 * request until natural alignment satisfies @align; alignments beyond
	 * CONFIG_CMA_ALIGNMENT need that Kconfig raised.
	 */
	align = (args->type == AMDXDNA_BO_DEV_HEAP) ? xdna->dev_info->dev_mem_size : 0;
	if (align > size)
		size = roundup_pow_of_two(align);

	kva = dma_alloc_coherent(cma_dev, size, &dma_addr, GFP_KERNEL);
	if (!kva) {
		XDNA_DBG(xdna, "CMA alloc failed on %s: size 0x%zx",
			 dev_name(cma_dev), size);
		return ERR_PTR(-ENOMEM);
	}
	/* dma_alloc_coherent() returns zeroed memory. */

	abo = amdxdna_gem_create_obj(dev, size);
	if (IS_ERR(abo)) {
		ret = PTR_ERR(abo);
		goto free_coherent;
	}

	abo->mem.kva = kva;
	/* Addressed by its own dma_addr; amdxdna_dma_map_bo() no-ops on a set addr. */
	abo->mem.dma_addr = dma_addr;
	abo->cma_dma_addr = dma_addr;
	abo->private_buffer = true;
	abo->type = AMDXDNA_BO_SHARE;

	to_gobj(abo)->funcs = &amdxdna_gem_cma_obj_funcs;
	drm_gem_private_object_init(dev, to_gobj(abo), size);

	/*
	 * A private GEM object gets no fake mmap offset for free, so create one
	 * here; GET_BO_INFO returns it and userspace mmap()s the BO handle at that
	 * offset (drm_gem_mmap() -> amdxdna_gem_cma_obj_mmap()).
	 */
	ret = drm_gem_create_mmap_offset(to_gobj(abo));
	if (ret) {
		XDNA_ERR(xdna, "Create mmap offset failed, ret %d", ret);
		drm_gem_object_release(to_gobj(abo));
		goto destroy_obj;
	}

	return abo;

destroy_obj:
	amdxdna_gem_destroy_obj(abo);
free_coherent:
	dma_free_coherent(cma_dev, size, kva, dma_addr);
	return ERR_PTR(ret);
}

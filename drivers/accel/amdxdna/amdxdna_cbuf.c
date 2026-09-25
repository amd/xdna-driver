// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2026, Advanced Micro Devices, Inc.
 */

#include <drm/drm_drv.h>
#include <drm/drm_mm.h>
#include <drm/drm_prime.h>
#include <linux/dma-mapping.h>
#include <linux/log2.h>
#include <linux/mm.h>

#include "amdxdna_cbuf.h"
#include "amdxdna_drv.h"

/*
 * Carveout memory is a chunk of memory which is physically contiguous and
 * is reserved during early boot time. There is only one chunk of such memory
 * per device. Once available, all BOs accessible from device should be
 * allocated from this memory. This is a platform debug/bringup feature.
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
 * Common header for every create-BO backing.  Embedded first in each backend's
 * private struct so the shared mmap/sgt/clear helpers can reach these fields
 * regardless of backend.  @base_pfn is the first page frame of the physically
 * contiguous range; @size its byte length.
 */
struct amdxdna_cbuf {
	struct amdxdna_dev	*xdna;
	unsigned long		base_pfn;
	size_t			size;
};

/* Describe [dma_addr, dma_addr+size) for @dev as a max_seg-segmented sgt. */
static struct sg_table *amdxdna_cbuf_make_sgt(struct device *dev, dma_addr_t dma_addr,
					      size_t size)
{
	size_t max_seg = min_t(size_t, UINT_MAX, dma_max_mapping_size(dev));
	struct scatterlist *sgl, *sg;
	int n_entries, i;
	struct sg_table *sgt;

	sgt = kzalloc_obj(*sgt);
	if (!sgt)
		return ERR_PTR(-ENOMEM);

	n_entries = (size + max_seg - 1) / max_seg;
	sgl = kzalloc_objs(*sg, n_entries);
	if (!sgl) {
		kfree(sgt);
		return ERR_PTR(-ENOMEM);
	}
	sg_init_table(sgl, n_entries);
	sgt->orig_nents = n_entries;
	sgt->nents = n_entries;
	sgt->sgl = sgl;

	for_each_sgtable_dma_sg(sgt, sg, i) {
		size_t len = min_t(size_t, max_seg, size);

		sg_dma_address(sg) = dma_addr;
		sg_dma_len(sg) = len;
		dma_addr += len;
		size -= len;
	}

	return sgt;
}

/*
 * Shared userspace mapping: both backings are physically contiguous, so map the
 * range from @base_pfn cached (default prot).  Coherency with a non-coherent
 * device is done by SYNC_BO; on a coherent device that sync is a no-op.
 */
static int amdxdna_cbuf_mmap(struct dma_buf *dbuf, struct vm_area_struct *vma)
{
	struct amdxdna_cbuf *cbuf = dbuf->priv;
	size_t size = vma->vm_end - vma->vm_start;

	if (vma->vm_pgoff)
		return -EINVAL;
	if (size > cbuf->size)
		return -EINVAL;

	vm_flags_set(vma, VM_DONTEXPAND | VM_DONTDUMP);

	return remap_pfn_range(vma, vma->vm_start, cbuf->base_pfn, size,
			       vma->vm_page_prot);
}

static int amdxdna_cbuf_clear(struct dma_buf *dbuf)
{
	struct iosys_map vmap = IOSYS_MAP_INIT_VADDR(NULL);
	int ret;

	ret = dma_buf_vmap(dbuf, &vmap);
	if (ret)
		return ret;

	memset(vmap.vaddr, 0, dbuf->size);
	dma_buf_vunmap(dbuf, &vmap);

	return 0;
}

/*
 * Carveout backing (x86 debug/bring-up): a slice of a reserved, no-map physical
 * carveout.  With no struct page it is DMA-mapped as a resource and kernel-
 * mapped with ioremap_cache().
 */
struct amdxdna_carveout_buf {
	struct amdxdna_cbuf	cbuf;
	struct drm_mm_node	node;
};

static struct sg_table *amdxdna_carveout_map(struct dma_buf_attachment *attach,
					     enum dma_data_direction dir)
{
	struct amdxdna_carveout_buf *cb = attach->dmabuf->priv;
	struct device *dev = attach->dev;
	struct sg_table *sgt;
	dma_addr_t dma_addr;

	dma_addr = dma_map_resource(dev, cb->node.start, cb->cbuf.size, dir,
				    DMA_ATTR_SKIP_CPU_SYNC);
	if (dma_mapping_error(dev, dma_addr))
		return ERR_PTR(-ENOMEM);

	sgt = amdxdna_cbuf_make_sgt(dev, dma_addr, cb->cbuf.size);
	if (IS_ERR(sgt))
		dma_unmap_resource(dev, dma_addr, cb->cbuf.size, dir,
				   DMA_ATTR_SKIP_CPU_SYNC);

	return sgt;
}

static void amdxdna_carveout_unmap(struct dma_buf_attachment *attach,
				   struct sg_table *sgt, enum dma_data_direction dir)
{
	dma_unmap_resource(attach->dev, sg_dma_address(sgt->sgl),
			   drm_prime_get_contiguous_size(sgt), dir,
			   DMA_ATTR_SKIP_CPU_SYNC);
	sg_free_table(sgt);
	kfree(sgt);
}

static void amdxdna_carveout_release(struct dma_buf *dbuf)
{
	struct amdxdna_carveout_buf *cb = dbuf->priv;
	struct amdxdna_dev *xdna = cb->cbuf.xdna;
	struct amdxdna_carveout *carveout = xdna->carveout;

	mutex_lock(&carveout->lock);
	drm_mm_remove_node(&cb->node);
	mutex_unlock(&carveout->lock);

	kfree(cb);
	/* Drop the ref taken in _get() that kept the DRM device (and its DMA
	 * regions) alive for this exported buffer's lifetime.
	 */
	drm_dev_put(&xdna->ddev);
}

static int amdxdna_carveout_vmap(struct dma_buf *dbuf, struct iosys_map *map)
{
	struct amdxdna_carveout_buf *cb = dbuf->priv;
	void *kva;

	kva = ioremap_cache(cb->node.start, cb->cbuf.size);
	if (!kva)
		return -EINVAL;

	iosys_map_set_vaddr(map, kva);
	return 0;
}

static void amdxdna_carveout_vunmap(struct dma_buf *dbuf, struct iosys_map *map)
{
	iounmap(map->vaddr);
}

static const struct dma_buf_ops amdxdna_carveout_dmabuf_ops = {
	.map_dma_buf = amdxdna_carveout_map,
	.unmap_dma_buf = amdxdna_carveout_unmap,
	.release = amdxdna_carveout_release,
	.mmap = amdxdna_cbuf_mmap,
	.vmap = amdxdna_carveout_vmap,
	.vunmap = amdxdna_carveout_vunmap,
};

static struct dma_buf *amdxdna_carveout_get(struct amdxdna_dev *xdna, size_t size,
					    u64 alignment)
{
	DEFINE_DMA_BUF_EXPORT_INFO(exp_info);
	struct amdxdna_carveout *carveout;
	struct amdxdna_carveout_buf *cb;
	struct dma_buf *dbuf;
	int ret;

	cb = kzalloc_obj(*cb);
	if (!cb)
		return ERR_PTR(-ENOMEM);
	cb->cbuf.xdna = xdna;
	cb->cbuf.size = size;

	carveout = xdna->carveout;
	mutex_lock(&carveout->lock);
	ret = drm_mm_insert_node_generic(&carveout->mm, &cb->node, size,
					 alignment, 0, DRM_MM_INSERT_BEST);
	mutex_unlock(&carveout->lock);
	if (ret)
		goto free_cb;
	cb->cbuf.base_pfn = cb->node.start >> PAGE_SHIFT;

	exp_info.size = size;
	exp_info.ops = &amdxdna_carveout_dmabuf_ops;
	exp_info.priv = cb;
	exp_info.flags = O_RDWR;
	dbuf = dma_buf_export(&exp_info);
	if (IS_ERR(dbuf)) {
		ret = PTR_ERR(dbuf);
		goto remove_node;
	}
	/*
	 * Hold the DRM device (and thus its DMA regions) for the exported buffer's
	 * lifetime: the fd can outlive the GEM object, so the release op must run
	 * before the regions are torn down at DRM final release.  Dropped in the
	 * release op -- reached below via dma_buf_put() on the clear-failure path.
	 */
	drm_dev_get(&xdna->ddev);

	/*
	 * Zero the carveout before exposing it: on failure tear the buffer down
	 * rather than leak a previous owner's contents to user space.  dma_buf_put()
	 * runs the release op, which removes the node and frees cb.
	 */
	ret = amdxdna_cbuf_clear(dbuf);
	if (ret) {
		dma_buf_put(dbuf);
		return ERR_PTR(ret);
	}

	return dbuf;

remove_node:
	drm_mm_remove_node(&cb->node);
free_cb:
	kfree(cb);
	return ERR_PTR(ret);
}

/*
 * CMA backing: physically contiguous, cacheable pages from ddev.dev's default
 * DMA pool -- the "aie" reserved region when the DT names one, otherwise system
 * CMA.  dma_alloc_pages() keeps a cached CPU mapping (fast for command BO
 * writes); coherency with the non-coherent CERT is done by SYNC_BO.  On a
 * cache-coherent device the accompanying syncs are no-ops, so this backing is
 * correct there too.
 */
struct amdxdna_cmabuf_buf {
	struct amdxdna_cbuf	cbuf;
	struct device		*dev;
	struct page		*page;
	void			*cpu_addr;
	dma_addr_t		dma_addr;
};

static struct sg_table *amdxdna_cmabuf_map(struct dma_buf_attachment *attach,
					   enum dma_data_direction dir)
{
	struct amdxdna_cmabuf_buf *cb = attach->dmabuf->priv;
	struct sg_table *sgt;
	int ret;

	sgt = kzalloc_obj(*sgt);
	if (!sgt)
		return ERR_PTR(-ENOMEM);

	/* Describe the allocation's pages, then map them for the importer. */
	ret = dma_get_sgtable(cb->dev, sgt, cb->cpu_addr, cb->dma_addr, cb->cbuf.size);
	if (ret)
		goto free_sgt;

	ret = dma_map_sgtable(attach->dev, sgt, dir, 0);
	if (ret)
		goto free_table;

	return sgt;

free_table:
	sg_free_table(sgt);
free_sgt:
	kfree(sgt);
	return ERR_PTR(ret);
}

static void amdxdna_cmabuf_unmap(struct dma_buf_attachment *attach,
				 struct sg_table *sgt, enum dma_data_direction dir)
{
	dma_unmap_sgtable(attach->dev, sgt, dir, 0);
	sg_free_table(sgt);
	kfree(sgt);
}

static void amdxdna_cmabuf_release(struct dma_buf *dbuf)
{
	struct amdxdna_cmabuf_buf *cb = dbuf->priv;
	struct amdxdna_dev *xdna;

	if (!cb)
		return;

	xdna = cb->cbuf.xdna;
	/* Free the pages while the DRM device (and its CMA region) is still
	 * alive, then drop the ref taken in _get().
	 */
	dma_free_pages(cb->dev, cb->cbuf.size, cb->page, cb->dma_addr,
		       DMA_BIDIRECTIONAL);
	kfree(cb);
	dbuf->priv = NULL;
	drm_dev_put(&xdna->ddev);
}

static int amdxdna_cmabuf_vmap(struct dma_buf *dbuf, struct iosys_map *map)
{
	struct amdxdna_cmabuf_buf *cb = dbuf->priv;

	iosys_map_set_vaddr(map, cb->cpu_addr);
	return 0;
}

static int amdxdna_cmabuf_mmap(struct dma_buf *dbuf, struct vm_area_struct *vma)
{
	struct amdxdna_cmabuf_buf *cb = dbuf->priv;

	/*
	 * Map the backing page into user space with the DMA API's own helper
	 * (remap_pfn_range on the page, cached default prot); coherency with a
	 * non-coherent device is done by SYNC_BO.
	 */
	return dma_mmap_pages(cb->dev, vma, cb->cbuf.size, cb->page);
}

static const struct dma_buf_ops amdxdna_cmabuf_dmabuf_ops = {
	.map_dma_buf = amdxdna_cmabuf_map,
	.unmap_dma_buf = amdxdna_cmabuf_unmap,
	.release = amdxdna_cmabuf_release,
	.mmap = amdxdna_cmabuf_mmap,
	.vmap = amdxdna_cmabuf_vmap,
};

static struct dma_buf *amdxdna_cmabuf_get(struct amdxdna_dev *xdna, struct device *dev,
					  size_t size, u64 alignment)
{
	DEFINE_DMA_BUF_EXPORT_INFO(exp_info);
	struct amdxdna_cmabuf_buf *cb;
	struct dma_buf *dbuf;
	dma_addr_t dma_addr;
	void *cpu_addr;
	struct page *page;
	int ret;

	cb = kzalloc_obj(*cb);
	if (!cb)
		return ERR_PTR(-ENOMEM);

	size = PAGE_ALIGN(size);
	/*
	 * dma_alloc from a CMA pool aligns to get_order(size), capped by
	 * CONFIG_CMA_ALIGNMENT. Grow the request so that natural alignment also
	 * satisfies @alignment (e.g. the dev-heap's self-alignment); alignments
	 * beyond CONFIG_CMA_ALIGNMENT need that Kconfig raised.
	 */
	if (alignment > size)
		size = roundup_pow_of_two(alignment);
	/*
	 * dma_alloc_pages() allocates cacheable pages from dev's CMA area (the
	 * "aie"/fw memory-region) and returns the backing page directly, so the
	 * userspace mapping (dma_mmap_pages()) and the kernel vaddr (page_to_virt())
	 * both come from it -- no virt_to_page() on a DMA pointer.
	 */
	page = dma_alloc_pages(dev, size, &dma_addr, DMA_BIDIRECTIONAL, GFP_KERNEL);
	if (!page) {
		XDNA_DBG(xdna, "CMA alloc failed on %s: size 0x%zx", dev_name(dev), size);
		ret = -ENOMEM;
		goto free_cb;
	}
	cpu_addr = page_to_virt(page);

	/* dma_alloc_pages() does not zero; clear before exposing to userspace. */
	memset(cpu_addr, 0, size);

	cb->cbuf.xdna = xdna;
	cb->cbuf.size = size;
	cb->dev = dev;
	cb->page = page;
	cb->cpu_addr = cpu_addr;
	cb->dma_addr = dma_addr;

	exp_info.size = size;
	exp_info.ops = &amdxdna_cmabuf_dmabuf_ops;
	exp_info.priv = cb;
	exp_info.flags = O_RDWR;
	dbuf = dma_buf_export(&exp_info);
	if (IS_ERR(dbuf)) {
		ret = PTR_ERR(dbuf);
		goto free_dma;
	}
	/* Hold the DRM device (and its CMA region) for the exported buffer's
	 * lifetime; the fd can outlive the GEM object.  Dropped in the release op.
	 */
	drm_dev_get(&xdna->ddev);

	return dbuf;

free_dma:
	dma_free_pages(dev, size, page, dma_addr, DMA_BIDIRECTIONAL);
free_cb:
	kfree(cb);
	return ERR_PTR(ret);
}

/*
 * Userspace create-BO backing.  The x86 debug/bring-up carveout takes priority
 * when configured; otherwise BOs come from ddev.dev's contiguous DMA pool (the
 * "aie" reserved region or system CMA).
 */
struct dma_buf *amdxdna_get_cbuf(struct drm_device *dev, size_t size, u64 alignment)
{
	struct amdxdna_dev *xdna = to_xdna_dev(dev);

	if (amdxdna_use_carveout(xdna))
		return amdxdna_carveout_get(xdna, size, alignment);

	return amdxdna_cmabuf_get(xdna, xdna->ddev.dev, size, alignment);
}

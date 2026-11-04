// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2026, Advanced Micro Devices, Inc.
 */

#include <linux/dma-buf.h>
#include <linux/dma-mapping.h>
#include <linux/iosys-map.h>
#include <linux/kernel.h>

#include "amdxdna_cma_buf.h"
#include "amdxdna_drv.h"

/*
 * CMA backend. On platforms without IOMMU/SVA (e.g. arm64), the device cannot
 * use shared virtual addressing and there may be no carveout configured. In
 * that case BOs are backed by physically contiguous, DMA-coherent memory
 * allocated from the system CMA pool and exported as a dma-buf.
 */
struct amdxdna_cmabuf_priv {
	struct device	*dev;
	dma_addr_t	dma_addr;
	void		*cpu_addr;
	size_t		size;
	bool		cpu_cacheable;
};

#define AMDXDNA_CMA_BO_FLAG_CACHEABLE	BIT_ULL(24)

static struct sg_table *
amdxdna_cmabuf_map(struct dma_buf_attachment *attach,
		   enum dma_data_direction dir)
{
	struct amdxdna_cmabuf_priv *cbuf = attach->dmabuf->priv;
	struct sg_table *sgt;
	int ret;

	sgt = kzalloc_obj(*sgt);
	if (!sgt)
		return ERR_PTR(-ENOMEM);

	ret = dma_get_sgtable(cbuf->dev, sgt, cbuf->cpu_addr, cbuf->dma_addr,
			      cbuf->size);
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
				 struct sg_table *sgt,
				 enum dma_data_direction dir)
{
	dma_unmap_sgtable(attach->dev, sgt, dir, 0);
	sg_free_table(sgt);
	kfree(sgt);
}

static void amdxdna_cmabuf_release(struct dma_buf *dbuf)
{
	struct amdxdna_cmabuf_priv *cmabuf = dbuf->priv;

	if (!cmabuf)
		return;

	if (cmabuf->cpu_cacheable)
		dma_free_noncoherent(cmabuf->dev, cmabuf->size, cmabuf->cpu_addr,
				     cmabuf->dma_addr, DMA_BIDIRECTIONAL);
	else
		dma_free_coherent(cmabuf->dev, cmabuf->size, cmabuf->cpu_addr,
				  cmabuf->dma_addr);
	kfree(cmabuf);
	dbuf->priv = NULL;
}

static int amdxdna_cmabuf_mmap(struct dma_buf *dbuf, struct vm_area_struct *vma)
{
	struct amdxdna_cmabuf_priv *cmabuf = dbuf->priv;
	size_t size = vma->vm_end - vma->vm_start;

	if (vma->vm_pgoff > cmabuf->size >> PAGE_SHIFT ||
	    size > cmabuf->size - (vma->vm_pgoff << PAGE_SHIFT))
		return -EINVAL;

	vm_flags_set(vma, VM_DONTEXPAND | VM_DONTDUMP);

	if (cmabuf->cpu_cacheable) {
		vma->vm_page_prot = vm_get_page_prot(vma->vm_flags);
		return dma_mmap_pages(cmabuf->dev, vma, cmabuf->size,
				      virt_to_page(cmabuf->cpu_addr));
	}

	return dma_mmap_coherent(cmabuf->dev, vma, cmabuf->cpu_addr,
				cmabuf->dma_addr, cmabuf->size);
}

static int amdxdna_cmabuf_vmap(struct dma_buf *dbuf, struct iosys_map *map)
{
	struct amdxdna_cmabuf_priv *cmabuf = dbuf->priv;

	iosys_map_set_vaddr(map, cmabuf->cpu_addr);

	return 0;
}

static const struct dma_buf_ops amdxdna_cmabuf_dmabuf_ops = {
	.map_dma_buf	= amdxdna_cmabuf_map,
	.unmap_dma_buf	= amdxdna_cmabuf_unmap,
	.release	= amdxdna_cmabuf_release,
	.mmap		= amdxdna_cmabuf_mmap,
	.vmap		= amdxdna_cmabuf_vmap,
};

static struct dma_buf *amdxdna_alloc_cma_buf_from_dev(struct device *ddev, size_t size,
						      bool cpu_cacheable)
{
	DEFINE_DMA_BUF_EXPORT_INFO(exp_info);
	struct amdxdna_cmabuf_priv *cmabuf;
	struct dma_buf *dbuf;
	dma_addr_t dma_addr;
	void *cpu_addr;
	int ret;

	cmabuf = kzalloc_obj(*cmabuf);
	if (!cmabuf)
		return ERR_PTR(-ENOMEM);

	size = PAGE_ALIGN(size);
	if (cpu_cacheable)
		cpu_addr = dma_alloc_noncoherent(ddev, size, &dma_addr,
						 DMA_BIDIRECTIONAL, GFP_KERNEL);
	else
		cpu_addr = dma_alloc_coherent(ddev, size, &dma_addr, GFP_KERNEL);

	if (!cpu_addr) {
		ret = -ENOMEM;
		goto free_cmabuf;
	}

	cmabuf->dev = ddev;
	cmabuf->cpu_addr = cpu_addr;
	cmabuf->dma_addr = dma_addr;
	cmabuf->size = size;
	cmabuf->cpu_cacheable = cpu_cacheable;

	exp_info.size = size;
	exp_info.ops = &amdxdna_cmabuf_dmabuf_ops;
	exp_info.priv = cmabuf;
	exp_info.flags = O_RDWR;

	dbuf = dma_buf_export(&exp_info);
	if (IS_ERR(dbuf)) {
		ret = PTR_ERR(dbuf);
		goto free_dma;
	}

	return dbuf;

free_dma:
	if (cpu_cacheable)
		dma_free_noncoherent(ddev, size, cpu_addr, dma_addr,
				     DMA_BIDIRECTIONAL);
	else
		dma_free_coherent(ddev, size, cpu_addr, dma_addr);
free_cmabuf:
	kfree(cmabuf);
	return ERR_PTR(ret);
}

struct dma_buf *amdxdna_get_cma_buf(struct drm_device *dev, size_t size)
{
	struct amdxdna_dev *xdna = to_xdna_dev(dev);
	struct dma_buf *dbuf;

	dbuf = amdxdna_alloc_cma_buf_from_dev(dev->dev, size, false);
	if (IS_ERR(dbuf))
		XDNA_ERR(xdna, "Failed to alloc 0x%zx CMA bytes", size);
	return dbuf;
}

/**
 * amdxdna_get_cma_buf_with_fallback - Allocate CMA buffer from a specific bank
 * with fallback to default CMA.
 *
 * @regions: Array of per-bank regions (dev == NULL = not initialized)
 * @max_regions: Size of regions array
 * @fallback_dev: DRM device to fall back to if no bank device matched
 * @size: Allocation size in bytes
 * @flags: Low 8 bits are the mem_bitmap (one bit per bank). Bit 24 requests
 *         a CPU-cacheable mapping.
 *
 * Tries each set bit in the bitmap in order; on first success returns the buf.
 * Falls back to the default DRM device CMA if no bank device is available.
 */
struct dma_buf *amdxdna_get_cma_buf_with_fallback(const struct amdxdna_cma_region *regions,
						  int max_regions,
						  struct drm_device *fallback_dev,
						  size_t size, u64 flags)
{
	u32 mem_bitmap = (u32)(flags & 0xFFULL);
	bool cpu_cacheable = flags & AMDXDNA_CMA_BO_FLAG_CACHEABLE;
	struct dma_buf *dbuf;
	int i;

	for (i = 0; i < max_regions; i++) {
		if ((mem_bitmap & (1U << i)) && regions[i].dev) {
			dbuf = amdxdna_alloc_cma_buf_from_dev(regions[i].dev, size,
							      cpu_cacheable);
			if (!IS_ERR(dbuf))
				return dbuf;
		}
	}

	return amdxdna_alloc_cma_buf_from_dev(fallback_dev->dev, size, cpu_cacheable);
}

/**
 * amdxdna_mem_region_from_addr - Find the bank backing a device address.
 *
 * @regions: Array of per-bank regions (dev == NULL = not initialized)
 * @max_regions: Size of regions array
 * @addr: Device address to look up
 *
 * Returns the bank index owning @addr, or 0 when no bank matches. Index 0 is
 * deliberately both a valid answer and the fallback: buffers allocated from
 * the default CMA pool belong to no declared region, and platforms that
 * declare none must keep reporting 0.
 */
u32 amdxdna_mem_region_from_addr(const struct amdxdna_cma_region *regions,
				 int max_regions, u64 addr)
{
	int i;

	for (i = 0; i < max_regions; i++) {
		const struct amdxdna_cma_region *region = &regions[i];

		if (region->dev && addr >= region->base &&
		    addr < region->base + region->size)
			return i;
	}

	return 0;
}

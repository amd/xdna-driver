// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2025, Advanced Micro Devices, Inc.
 */

#include <linux/kernel.h>
#include <linux/dma-buf.h>
#include <linux/of_reserved_mem.h>
#include "amdxdna_drm.h"
#include "amdxdna_cma_buf.h"

struct amdxdna_cmabuf_priv {
	struct device *dev;
	dma_addr_t dma_addr;
	void *cpu_addr;
	size_t size;
	bool cacheable;
};

static struct sg_table *
amdxdna_cmabuf_map(struct dma_buf_attachment *attach,
		   enum dma_data_direction dir)
{
	struct amdxdna_cmabuf_priv *cbuf = attach->dmabuf->priv;
	struct scatterlist *sg;
	struct sg_table *sgt;
	int ret;

	sgt = kzalloc(sizeof(*sgt), GFP_KERNEL);
	if (!sgt)
		return ERR_PTR(-ENOMEM);

	sg = kzalloc(sizeof(*sg), GFP_KERNEL);
	if (!sg) {
		ret = -ENOMEM;
		goto free_sgt;
	}

	sg_init_table(sg, 1);
	sg_dma_address(sg) = dma_map_resource(attach->dev, cbuf->dma_addr,
					      cbuf->size, dir,
					      DMA_ATTR_SKIP_CPU_SYNC);
	ret = dma_mapping_error(attach->dev, sg->dma_address);
	if (ret)
		goto free_sg;

	sg_assign_page(sg, NULL);
	sg->offset = 0;
	sg_dma_len(sg) = cbuf->size;
	sgt->orig_nents = 1;
	sgt->nents = sgt->orig_nents;
	sgt->sgl = sg;

	return sgt;

free_sg:
	kfree(sg);
free_sgt:
	kfree(sgt);
	return ERR_PTR(ret);
}

static void amdxdna_cmabuf_unmap(struct dma_buf_attachment *attach,
				 struct sg_table *sgt,
				 enum dma_data_direction dir)
{
	struct scatterlist *sg = sgt->sgl;

	dma_unmap_resource(attach->dev, sg_dma_address(sg), sg_dma_len(sg),
			   dir, DMA_ATTR_SKIP_CPU_SYNC);
	kfree(sg);
	kfree(sgt);
}

static void amdxdna_cmabuf_free(struct device *dev, void *cpu_addr,
				dma_addr_t dma_addr, size_t size,
				bool cacheable)
{
	if (cacheable)
		dma_free_wc(dev, size, cpu_addr, dma_addr);
	else
		dma_free_coherent(dev, size, cpu_addr, dma_addr);
}

static void amdxdna_cmabuf_release(struct dma_buf *dbuf)
{
	struct amdxdna_cmabuf_priv *cmabuf = dbuf->priv;

	if (!cmabuf)
		return;
	amdxdna_cmabuf_free(cmabuf->dev, cmabuf->cpu_addr, cmabuf->dma_addr,
			    cmabuf->size, cmabuf->cacheable);
	kfree(cmabuf);
	dbuf->priv = NULL;
}

static int amdxdna_cmabuf_mmap(struct dma_buf *dbuf, struct vm_area_struct *vma)
{
	struct amdxdna_cmabuf_priv *cmabuf = dbuf->priv;
	size_t size = vma->vm_end - vma->vm_start;
	unsigned long vm_pgoff;
	int ret;

	if (size > cmabuf->size)
		return -EINVAL;

	vm_pgoff = vma->vm_pgoff;
	/* clear the vm_pgoff to avoid dma_buf_ops.mmap failure */
	vma->vm_pgoff = 0;

	vm_flags_set(vma, VM_IO | VM_DONTEXPAND | VM_DONTDUMP);

	if (cmabuf->cacheable)
		ret = dma_mmap_wc(cmabuf->dev, vma,
				  cmabuf->cpu_addr,
				  cmabuf->dma_addr,
				  cmabuf->size);
	else
		ret = dma_mmap_coherent(cmabuf->dev, vma,
					cmabuf->cpu_addr,
					cmabuf->dma_addr,
					cmabuf->size);

	vma->vm_pgoff = vm_pgoff;

	return ret;
}

static int amdxdna_cmabuf_vmap(struct dma_buf *dbuf, struct iosys_map *map)
{
	struct amdxdna_cmabuf_priv *cmabuf = dbuf->priv;

	iosys_map_set_vaddr(map, cmabuf->cpu_addr);

	return 0;
}

static const struct dma_buf_ops amdxdna_cmabuf_dmabuf_ops = {
	.map_dma_buf = amdxdna_cmabuf_map,
	.unmap_dma_buf = amdxdna_cmabuf_unmap,
	.release = amdxdna_cmabuf_release,
	.mmap = amdxdna_cmabuf_mmap,
	.vmap = amdxdna_cmabuf_vmap,
};

static struct dma_buf *amdxdna_get_cma_buf(struct device *dev,
					   size_t size, bool cacheable)
{
	struct amdxdna_cmabuf_priv *cmabuf;
	struct dma_buf *dbuf;
	dma_addr_t dma_addr;
	void *cpu_addr;
	int ret;
	DEFINE_DMA_BUF_EXPORT_INFO(exp_info);

	cmabuf = kzalloc(sizeof(*cmabuf), GFP_KERNEL);
	if (!cmabuf)
		return ERR_PTR(-ENOMEM);

	size = PAGE_ALIGN(size);

	if (cacheable)
		cpu_addr = dma_alloc_wc(dev, size, &dma_addr, GFP_KERNEL);
	else
		cpu_addr = dma_alloc_coherent(dev, size, &dma_addr, GFP_KERNEL);
	if (!cpu_addr) {
		ret = -ENOMEM;
		goto free_cmabuf;
	}

	cmabuf->dev = dev;
	cmabuf->cpu_addr = cpu_addr;
	cmabuf->dma_addr = dma_addr;
	cmabuf->size = size;
	cmabuf->cacheable = cacheable;

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
	amdxdna_cmabuf_free(dev, cpu_addr, dma_addr, size, cacheable);
free_cmabuf:
	kfree(cmabuf);
	return ERR_PTR(ret);
}

bool amdxdna_use_cma(void)
{
#if defined(CONFIG_CMA) && !defined(CONFIG_X86_64) && !defined(CONFIG_X86)
	return true;
#else
	return false;
#endif
}

static bool get_cacheable_flag(u64 flags)
{
	return (flags & AMDXDNA_BO_FLAGS_CACHEABLE) != 0;
}

/**
 * amdxdna_get_cma_buf_with_fallback - Allocate CMA buffer with region fallback
 * @region_devs: Array of device pointers for CMA regions (NULL = not initialized)
 * @max_regions: Maximum number of regions in the array
 * @fallback_dev: Device to use as final fallback (system default CMA)
 * @size: Size of buffer to allocate
 * @flags: Cacheable and region index bitmap
 *
 * Attempts allocation in order:
 * 1. Requested region/s (extracted from flags)
 * 2. System default CMA (fallback_dev)
 *
 * Return: dma_buf pointer on success, ERR_PTR on failure
 */
struct dma_buf *amdxdna_get_cma_buf_with_fallback(struct device *const *region_devs,
						  int max_regions,
						  struct device *fallback_dev,
						  size_t size, u64 flags)
{
	struct dma_buf *dma_buf;
	bool cacheable;
	u32 mem_bitmap;
	unsigned int i;

	cacheable = get_cacheable_flag(flags);
	mem_bitmap = (u32)(flags & 0xFFULL);

	/* Try to allocate from the requested region(s) in bitmap order (bit 0, then 1, ...). */
	for (i = 0; i < max_regions; i++) {
		if ((mem_bitmap & (1U << i)) && region_devs[i]) {
			dma_buf = amdxdna_get_cma_buf(region_devs[i], size, cacheable);
			if (!IS_ERR(dma_buf))
				return dma_buf;
		}
	}

	/* Final fallback to system default CMA */
	return amdxdna_get_cma_buf(fallback_dev, size, cacheable);
}

static void amdxdna_cma_device_release(struct device *dev)
{
	kfree(dev);
}

/**
 * amdxdna_cma_region_init - Populate CMA regions from a DT node
 * @xdna: XDNA device
 * @mem_np: Device tree node with memory-region phandles
 *
 * Iterates through memory-region phandles and only binds those marked
 * "reusable" (CMA pools), skipping non-CMA carveouts (e.g. mailbox or
 * doorbell shared memory regions with "no-map").
 *
 * The first CMA region is bound to the parent device (xdna->ddev.dev)
 * so that dma_alloc_coherent() and friends use it by default.
 * Subsequent CMA regions become child devices stored in
 * cma_region_devs[] for bank-based BO allocation.
 *
 * Return: 0 on success (including when no CMA regions found),
 *         negative errno on failure
 */
int amdxdna_cma_region_init(struct amdxdna_dev *xdna, struct device_node *mem_np)
{
	struct device *parent_dev = xdna->ddev.dev;
	struct device_node *rmem_np;
	struct device *child_dev;
	int num_regions;
	int bank = 0;
	int ret;
	int i;

	num_regions = of_count_phandle_with_args(mem_np, "memory-region", NULL);
	if (num_regions <= 0)
		return 0;

	for (i = 0; i < num_regions; i++) {
		rmem_np = of_parse_phandle(mem_np, "memory-region", i);
		if (!rmem_np)
			break;

		if (!of_property_read_bool(rmem_np, "reusable")) {
			of_node_put(rmem_np);
			continue;
		}
		of_node_put(rmem_np);

		if (bank == 0) {
			ret = of_reserved_mem_device_init_by_idx(parent_dev,
								 mem_np, i);
			if (ret) {
				XDNA_ERR(xdna,
					 "Failed to bind default CMA (idx %d): %d",
					 i, ret);
				return ret;
			}
			XDNA_INFO(xdna, "Default CMA region bound (idx %d)", i);
			bank++;
			continue;
		}

		if (bank > MAX_MEM_REGIONS) {
			XDNA_WARN(xdna, "Too many CMA banks, skipping idx %d",
				  i);
			continue;
		}

		child_dev = kzalloc(sizeof(*child_dev), GFP_KERNEL);
		if (!child_dev) {
			ret = -ENOMEM;
			goto cleanup;
		}

		device_initialize(child_dev);
		child_dev->parent = parent_dev;
		child_dev->of_node = mem_np;
		child_dev->coherent_dma_mask = DMA_BIT_MASK(64);
		child_dev->dma_mask = &child_dev->coherent_dma_mask;
		child_dev->release = amdxdna_cma_device_release;

		ret = dev_set_name(child_dev, "amdxdna-mem%d", bank - 1);
		if (ret)
			goto put_dev;

		ret = of_reserved_mem_device_init_by_idx(child_dev, mem_np, i);
		if (ret) {
			XDNA_ERR(xdna, "Failed to init CMA bank %d (idx %d): %d",
				 bank - 1, i, ret);
			goto put_dev;
		}

		xdna->cma_region_devs[bank - 1] = child_dev;
		XDNA_INFO(xdna, "CMA bank %d initialized (idx %d)", bank - 1, i);
		bank++;
	}

	return 0;

put_dev:
	put_device(child_dev);
cleanup:
	amdxdna_cma_region_fini(xdna);
	return ret;
}

void amdxdna_cma_region_fini(struct amdxdna_dev *xdna)
{
	int i;

	for (i = 0; i < MAX_MEM_REGIONS; i++) {
		struct device *dev = xdna->cma_region_devs[i];

		if (dev) {
			of_reserved_mem_device_release(dev);
			put_device(dev);
			xdna->cma_region_devs[i] = NULL;
		}
	}

	/* Release the default CMA region bound to the parent device */
	of_reserved_mem_device_release(xdna->ddev.dev);
}

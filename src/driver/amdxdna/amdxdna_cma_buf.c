// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2025, Advanced Micro Devices, Inc.
 */

#include <linux/kernel.h>
#include <linux/dma-buf.h>
#include "amdxdna_cma_buf.h"

struct amdxdna_cmabuf_priv {
	struct device *dev;
	dma_addr_t dma_addr;
	void *cpu_addr;
	size_t size;
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

static void amdxdna_cmabuf_release(struct dma_buf *dbuf)
{
	struct amdxdna_cmabuf_priv *cmabuf = dbuf->priv;

	if (!cmabuf)
		return;

	dma_free_coherent(cmabuf->dev, cmabuf->size,
			  cmabuf->cpu_addr, cmabuf->dma_addr);
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

struct dma_buf *amdxdna_get_cma_buf(struct device *dev,
				    size_t size)
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

	cpu_addr = dma_alloc_coherent(dev, size, &dma_addr, GFP_KERNEL);
	if (!cpu_addr) {
		ret = -ENOMEM;
		goto free_cmabuf;
	}

	cmabuf->dev = dev;
	cmabuf->cpu_addr = cpu_addr;
	cmabuf->dma_addr = dma_addr;
	cmabuf->size = size;

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
	dma_free_coherent(dev, size, cpu_addr, dma_addr);
free_cmabuf:
	kfree(cmabuf);
	return ERR_PTR(ret);
}

bool amdxdna_is_cma_buf(struct dma_buf *dbuf)
{
	return dbuf && dbuf->ops == &amdxdna_cmabuf_dmabuf_ops;
}

bool amdxdna_use_cma(void)
{
#if defined(CONFIG_CMA) && !defined(CONFIG_X86_64) && !defined(CONFIG_X86)
	return true;
#else
	return false;
#endif
}

int get_cma_mem_index(u64 flags)
{
	/*
	 * Extract lower 8 bits for memory index (0-255 range).
	 * Valid indexes: 0-15
	 * Invalid indexes (16-255): trigger fallback to default CMA region
	 */
	return flags & 0xFF;
}

/**
 * amdxdna_get_cma_buf_with_fallback - Allocate CMA buffer with region fallback
 * @region_devs: Array of device pointers for CMA regions (NULL = not initialized)
 * @max_regions: Maximum number of regions in the array
 * @fallback_dev: Device to use as final fallback (system default CMA)
 * @size: Size of buffer to allocate
 * @flags: Flags containing region index in bits [7:0]
 *
 * Attempts allocation in order:
 * 1. Requested region (extracted from flags)
 * 2. Other available initialized regions
 * 3. System default CMA (fallback_dev)
 *
 * Return: dma_buf pointer on success, ERR_PTR on failure
 */
struct dma_buf *amdxdna_get_cma_buf_with_fallback(struct device *const *region_devs,
						  int max_regions,
						  struct device *fallback_dev,
						  size_t size, u64 flags)
{
	struct dma_buf *dma_buf;
	int mem_index;
	int i;

	mem_index = get_cma_mem_index(flags);

	/* Try requested region first */
	if (mem_index < max_regions && region_devs[mem_index]) {
		dma_buf = amdxdna_get_cma_buf(region_devs[mem_index], size);
		if (!IS_ERR(dma_buf))
			return dma_buf;
	}

	/* Try any other available initialized region */
	for (i = 0; i < max_regions; i++) {
		if (i == mem_index || !region_devs[i])
			continue;

		dma_buf = amdxdna_get_cma_buf(region_devs[i], size);
		if (!IS_ERR(dma_buf))
			return dma_buf;
	}

	/* Final fallback to system default CMA */
	return amdxdna_get_cma_buf(fallback_dev, size);
}

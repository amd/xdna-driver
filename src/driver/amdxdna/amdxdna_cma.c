/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2025, Advanced Micro Devices, Inc.
 */

#include <linux/kernel.h>
#include <linux/dma-buf.h>
#include "amdxdna_cma.h"

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

	dma_free_coherent(cmabuf->dev->dev, cmabuf->size,
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

	ret = dma_mmap_coherent(cmabuf->dev->dev, vma,
			cmabuf->cpu_addr,
			cmabuf->dma_addr,
			cmabuf->size);
	if (ret)
		return ret;

	vma->vm_pgoff = vm_pgoff;

	return 0;
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

struct dma_buf *amdxdna_get_cma_buf(struct drm_device *dev,
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

	cpu_addr = dma_alloc_coherent(dev->dev, size, &dma_addr, GFP_KERNEL);
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
	dma_free_coherent(dev->dev, size, cpu_addr, dma_addr);
free_cmabuf:
	kfree(cmabuf);
	return ERR_PTR(ret);
}

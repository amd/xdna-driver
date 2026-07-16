// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2026, Advanced Micro Devices, Inc.
 */

#include <linux/dma-buf.h>
#include <linux/dma-mapping.h>
#include <linux/iosys-map.h>
#include <linux/kernel.h>

#include "amdxdna_cma_buf.h"
#include "amdxdna_pci_drv.h"

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
};

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

	dma_free_coherent(cmabuf->dev, cmabuf->size, cmabuf->cpu_addr,
			  cmabuf->dma_addr);
	kfree(cmabuf);
	dbuf->priv = NULL;
}

static int amdxdna_cmabuf_mmap(struct dma_buf *dbuf, struct vm_area_struct *vma)
{
	struct amdxdna_cmabuf_priv *cmabuf = dbuf->priv;
	size_t size = vma->vm_end - vma->vm_start;

	if (vma->vm_pgoff)
		return -EINVAL;
	if (size > cmabuf->size)
		return -EINVAL;

	vm_flags_set(vma, VM_IO | VM_DONTEXPAND | VM_DONTDUMP);

	return dma_mmap_coherent(cmabuf->dev, vma, cmabuf->cpu_addr,
				 cmabuf->dma_addr, size);
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

struct dma_buf *amdxdna_get_cma_buf(struct drm_device *dev, size_t size)
{
	struct amdxdna_dev *xdna = to_xdna_dev(dev);
	DEFINE_DMA_BUF_EXPORT_INFO(exp_info);
	struct amdxdna_cmabuf_priv *cmabuf;
	struct device *ddev = dev->dev;
	struct dma_buf *dbuf;
	dma_addr_t dma_addr;
	void *cpu_addr;
	int ret;

	cmabuf = kzalloc_obj(*cmabuf);
	if (!cmabuf)
		return ERR_PTR(-ENOMEM);

	size = PAGE_ALIGN(size);
	cpu_addr = dma_alloc_coherent(ddev, size, &dma_addr, GFP_KERNEL);
	if (!cpu_addr) {
		XDNA_ERR(xdna, "Failed to alloc 0x%zx CMA bytes", size);
		ret = -ENOMEM;
		goto free_cmabuf;
	}

	cmabuf->dev = ddev;
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
	dma_free_coherent(ddev, size, cpu_addr, dma_addr);
free_cmabuf:
	kfree(cmabuf);
	return ERR_PTR(ret);
}

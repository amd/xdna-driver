// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2025, Advanced Micro Devices, Inc.
 */

#include <drm/drm_mm.h>
#include <linux/dma-buf.h>

#include "amdxdna_carvedout_buf.h"
#include "amdxdna_drm.h"

/*
 * Carvedout memory is a chunk of memory which is physically contiguous and
 * is reserved during early boot time. There is only one chunk of such memory
 * per system. Once available, all BOs accessible from device should be
 * allocated from this memory.
 */
u64 carvedout_addr;
module_param(carvedout_addr, ullong, 0644);
MODULE_PARM_DESC(carvedout_addr, "Physical memory address for reserved memory chunk");

u64 carvedout_size;
module_param(carvedout_size, ullong, 0644);
MODULE_PARM_DESC(carvedout_size, "Physical memory size for reserved memory chunk");

struct amdxdna_carvedout {
	struct drm_mm	mm;
	struct mutex	lock; /* protect mm */
} carvedout;

bool amdxdna_use_carvedout(void)
{
	return !!carvedout_size;
}

void amdxdna_carvedout_init(void)
{
	if (!amdxdna_use_carvedout())
		return;
	mutex_init(&carvedout.lock);
	drm_mm_init(&carvedout.mm, carvedout_addr, carvedout_size);
}

void amdxdna_carvedout_fini(void)
{
	if (!amdxdna_use_carvedout())
		return;
	mutex_destroy(&carvedout.lock);
	drm_mm_takedown(&carvedout.mm);
}

struct amdxdna_cbuf_priv {
	struct drm_mm_node node;
};

static struct sg_table *amdxdna_cbuf_map(struct dma_buf_attachment *attach,
					 enum dma_data_direction direction)
{
	struct amdxdna_cbuf_priv *cbuf = attach->dmabuf->priv;
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
	sg_dma_address(sg) = dma_map_resource(attach->dev, cbuf->node.start,
					      cbuf->node.size, direction,
					      DMA_ATTR_SKIP_CPU_SYNC);
	ret = dma_mapping_error(attach->dev, sg->dma_address);
	if (ret)
		goto free_sg;

	sg_assign_page(sg, NULL);
	sg->offset = 0;
	sg_dma_len(sg) = cbuf->node.size;
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

static void amdxdna_cbuf_unmap(struct dma_buf_attachment *attach,
			       struct sg_table *sgt,
			       enum dma_data_direction direction)
{
	struct scatterlist *sg = sgt->sgl;

	dma_unmap_resource(attach->dev, sg_dma_address(sg), sg_dma_len(sg),
			   direction, DMA_ATTR_SKIP_CPU_SYNC);
	kfree(sg);
	kfree(sgt);
}

static void amdxdna_cbuf_release(struct dma_buf *dbuf)
{
	struct amdxdna_cbuf_priv *cbuf = dbuf->priv;

	mutex_lock(&carvedout.lock);
	drm_mm_remove_node(&cbuf->node);
	mutex_unlock(&carvedout.lock);

	kfree(cbuf);
}

static vm_fault_t amdxdna_cbuf_vm_fault(struct vm_fault *vmf)
{
	struct vm_area_struct *vma = vmf->vma;
	struct amdxdna_cbuf_priv *cbuf;
	unsigned long pfn;
	pgoff_t pgoff;

	cbuf = vma->vm_private_data;
	pgoff = (vmf->address - vma->vm_start) >> PAGE_SHIFT;
	pfn = (cbuf->node.start >> PAGE_SHIFT) + pgoff;

	return vmf_insert_pfn(vma, vmf->address, pfn);
}

static const struct vm_operations_struct amdxdna_cbuf_vm_ops = {
	.fault = amdxdna_cbuf_vm_fault,
};

static int amdxdna_cbuf_mmap(struct dma_buf *dbuf, struct vm_area_struct *vma)
{
	struct amdxdna_cbuf_priv *cbuf = dbuf->priv;

	vma->vm_ops = &amdxdna_cbuf_vm_ops;
	vma->vm_private_data = cbuf;
	vm_flags_set(vma, VM_PFNMAP | VM_DONTEXPAND | VM_DONTDUMP);

	return 0;
}

static int amdxdna_cbuf_vmap(struct dma_buf *dbuf, struct iosys_map *map)
{
	struct amdxdna_cbuf_priv *cbuf = dbuf->priv;
	void *kva;

	kva = ioremap_uc(cbuf->node.start, cbuf->node.size);
	if (!kva)
		return -EINVAL;

	iosys_map_set_vaddr(map, kva);
	return 0;
}

static void amdxdna_cbuf_vunmap(struct dma_buf *dbuf, struct iosys_map *map)
{
	iounmap(map->vaddr);
}

static const struct dma_buf_ops amdxdna_cbuf_dmabuf_ops = {
	.map_dma_buf = amdxdna_cbuf_map,
	.unmap_dma_buf = amdxdna_cbuf_unmap,
	.release = amdxdna_cbuf_release,
	.mmap = amdxdna_cbuf_mmap,
	.vmap = amdxdna_cbuf_vmap,
	.vunmap = amdxdna_cbuf_vunmap,
};

struct dma_buf *amdxdna_get_carvedout_buf(struct drm_device *dev, size_t size,
					  u64 alignment)
{
	struct amdxdna_cbuf_priv *cbuf;
	struct dma_buf *dbuf;
	int ret;
	DEFINE_DMA_BUF_EXPORT_INFO(exp_info);

	cbuf = kzalloc(sizeof(*cbuf), GFP_KERNEL);
	if (!cbuf)
		return ERR_PTR(-ENOMEM);

	mutex_lock(&carvedout.lock);
	ret = drm_mm_insert_node_generic(&carvedout.mm, &cbuf->node, size,
					 alignment, 0, DRM_MM_INSERT_BEST);
	mutex_unlock(&carvedout.lock);
	if (ret)
		goto free_cbuf;

	exp_info.size = size;
	exp_info.ops = &amdxdna_cbuf_dmabuf_ops;
	exp_info.priv = cbuf;
	exp_info.flags = O_RDWR;

	dbuf = dma_buf_export(&exp_info);
	if (IS_ERR(dbuf)) {
		ret = PTR_ERR(dbuf);
		goto remove_node;
	}

	return dbuf;

remove_node:
	drm_mm_remove_node(&cbuf->node);
free_cbuf:
	kfree(cbuf);
	return ERR_PTR(ret);
}

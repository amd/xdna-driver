// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2026, Advanced Micro Devices, Inc.
 */

#include <drm/drm_mm.h>
#include <drm/drm_prime.h>

#include "amdxdna_cbuf.h"
#include "amdxdna_pci_drv.h"

/*
 * This is a platform debug/bringup feature.
 *
 * Carveout memory is a chunk of memory which is physically contiguous and
 * is reserved during early boot time. There is only one chunk of such memory
 * per system. Once available, all BOs accessible from device should be
 * allocated from this memory.
 */
u64 carveout_addr;
module_param(carveout_addr, ullong, 0400);
MODULE_PARM_DESC(carveout_addr, "Physical memory address for reserved memory chunk");

u64 carveout_size;
module_param(carveout_size, ullong, 0400);
MODULE_PARM_DESC(carveout_size, "Physical memory size for reserved memory chunk");

struct amdxdna_carveout {
	struct drm_mm	mm;
	struct mutex	lock; /* protect mm */
} carveout;

bool amdxdna_use_carveout(void)
{
	return !!carveout_size;
}

void amdxdna_carveout_init(void)
{
	if (!amdxdna_use_carveout())
		return;
	mutex_init(&carveout.lock);
	drm_mm_init(&carveout.mm, carveout_addr, carveout_size);
	pr_info("Use carveout mem, addr=0x%llx, size=0x%llx\n", carveout_addr, carveout_size);
}

void amdxdna_carveout_fini(void)
{
	if (!amdxdna_use_carveout())
		return;
	mutex_destroy(&carveout.lock);
	drm_mm_takedown(&carveout.mm);
}

struct amdxdna_cbuf_priv {
	struct drm_mm_node node;
};

static struct sg_table *amdxdna_cbuf_map(struct dma_buf_attachment *attach,
					 enum dma_data_direction direction)
{
	struct amdxdna_cbuf_priv *cbuf = attach->dmabuf->priv;
	struct device *dev = attach->dev;
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
	n_entries = (cbuf->node.size + max_seg - 1) / max_seg;
	sgl = kzalloc_objs(*sg, n_entries);
	if (!sgl) {
		ret = -ENOMEM;
		goto free_sgt;
	}
	sg_init_table(sgl, n_entries);
	sgt->orig_nents = n_entries;
	sgt->nents = n_entries;
	sgt->sgl = sgl;

	dma_size = cbuf->node.size;
	dma_addr = dma_map_resource(dev, cbuf->node.start, dma_size,
				    direction, DMA_ATTR_SKIP_CPU_SYNC);
	ret = dma_mapping_error(dev, dma_addr);
	if (ret) {
		pr_err("Failed to dma_map_resource carveout dma buf, ret %d\n", ret);
		goto free_sgl;
	}

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

static void amdxdna_cbuf_unmap(struct dma_buf_attachment *attach,
			       struct sg_table *sgt,
			       enum dma_data_direction direction)
{
	dma_unmap_resource(attach->dev, sg_dma_address(sgt->sgl),
			   drm_prime_get_contiguous_size(sgt), direction,
			   DMA_ATTR_SKIP_CPU_SYNC);
	sg_free_table(sgt);
	kfree(sgt);
}

static void amdxdna_cbuf_release(struct dma_buf *dbuf)
{
	struct amdxdna_cbuf_priv *cbuf = dbuf->priv;

	mutex_lock(&carveout.lock);
	drm_mm_remove_node(&cbuf->node);
	mutex_unlock(&carveout.lock);

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

	kva = ioremap_cache(cbuf->node.start, cbuf->node.size);
	if (!kva) {
		pr_err("Failed to vmap carveout dma buf\n");
		return -EINVAL;
	}

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

static void amdxdna_cbuf_clear(struct dma_buf *dbuf)
{
	struct iosys_map vmap = IOSYS_MAP_INIT_VADDR(NULL);

	dma_buf_vmap(dbuf, &vmap);
	if (!vmap.vaddr)
		return;

	memset(vmap.vaddr, 0, dbuf->size);
	dma_buf_vunmap(dbuf, &vmap);
}

struct dma_buf *amdxdna_get_cbuf(struct drm_device *dev, size_t size, u64 alignment)
{
	DEFINE_DMA_BUF_EXPORT_INFO(exp_info);
	struct amdxdna_cbuf_priv *cbuf;
	struct dma_buf *dbuf;
	int ret;

	cbuf = kzalloc_obj(*cbuf);
	if (!cbuf)
		return ERR_PTR(-ENOMEM);

	mutex_lock(&carveout.lock);
	ret = drm_mm_insert_node_generic(&carveout.mm, &cbuf->node, size,
					 alignment, 0, DRM_MM_INSERT_BEST);
	mutex_unlock(&carveout.lock);
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

	amdxdna_cbuf_clear(dbuf);
	return dbuf;

remove_node:
	drm_mm_remove_node(&cbuf->node);
free_cbuf:
	kfree(cbuf);
	return ERR_PTR(ret);
}

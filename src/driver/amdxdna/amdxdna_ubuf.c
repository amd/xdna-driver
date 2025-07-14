// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2025, Advanced Micro Devices, Inc.
 */

#include <linux/dma-buf.h>
#include <linux/pagemap.h>
#include <linux/vmalloc.h>

#include "drm_local/amdxdna_accel.h"
#include "amdxdna_drm.h"
#include "amdxdna_ubuf.h"

struct amdxdna_ubuf_priv {
	struct page **pages;
	u64 nr_pages;
	enum amdxdna_ubuf_flag flags;
};

static struct sg_table *amdxdna_ubuf_map(struct dma_buf_attachment *attach,
					 enum dma_data_direction direction)
{
	struct amdxdna_ubuf_priv *ubuf = attach->dmabuf->priv;
	struct sg_table *sg;
	int ret;

	sg = kzalloc(sizeof(*sg), GFP_KERNEL);
	if (!sg)
		return ERR_PTR(-ENOMEM);

	ret = sg_alloc_table_from_pages(sg, ubuf->pages, ubuf->nr_pages, 0,
					ubuf->nr_pages << PAGE_SHIFT, GFP_KERNEL);
	if (ret)
		return ERR_PTR(ret);

	if (ubuf->flags & AMDXDNA_UBUF_FLAG_MAP_DMA) {
		ret = dma_map_sgtable(attach->dev, sg, direction, 0);
		if (ret)
			return ERR_PTR(ret);
	}

	return sg;
}

static void amdxdna_ubuf_unmap(struct dma_buf_attachment *attach,
			       struct sg_table *sg,
			       enum dma_data_direction direction)
{
	struct amdxdna_ubuf_priv *ubuf = attach->dmabuf->priv;

	if (ubuf->flags & AMDXDNA_UBUF_FLAG_MAP_DMA)
		dma_unmap_sgtable(attach->dev, sg, direction, 0);

	sg_free_table(sg);
	kfree(sg);
}

static void amdxdna_ubuf_release(struct dma_buf *dbuf)
{
	struct amdxdna_ubuf_priv *ubuf = dbuf->priv;

	unpin_user_pages(ubuf->pages, ubuf->nr_pages);
	kvfree(ubuf->pages);
	kfree(ubuf);
}

static vm_fault_t amdxdna_ubuf_vm_fault(struct vm_fault *vmf)
{
	struct vm_area_struct *vma = vmf->vma;
	struct amdxdna_ubuf_priv *ubuf;
	unsigned long pfn;
	pgoff_t pgoff;

	ubuf = vma->vm_private_data;
	pgoff = (vmf->address - vma->vm_start) >> PAGE_SHIFT;

	pfn = page_to_pfn(ubuf->pages[pgoff]);
	return vmf_insert_pfn(vma, vmf->address, pfn);
}

static const struct vm_operations_struct amdxdna_ubuf_vm_ops = {
	.fault = amdxdna_ubuf_vm_fault,
};

static int amdxdna_ubuf_mmap(struct dma_buf *dbuf, struct vm_area_struct *vma)
{
	struct amdxdna_ubuf_priv *ubuf = dbuf->priv;

	vma->vm_ops = &amdxdna_ubuf_vm_ops;
	vma->vm_private_data = ubuf;
	vm_flags_set(vma, VM_PFNMAP | VM_DONTEXPAND | VM_DONTDUMP);

	return 0;
}

static int amdxdna_ubuf_vmap(struct dma_buf *dbuf, struct iosys_map *map)
{
	struct amdxdna_ubuf_priv *ubuf = dbuf->priv;
	void *kva;

	kva = vmap(ubuf->pages, ubuf->nr_pages, VM_MAP, PAGE_KERNEL);
	if (!kva)
		return -EINVAL;

	iosys_map_set_vaddr(map, kva);
	return 0;
}

static void amdxdna_ubuf_vunmap(struct dma_buf *dbuf, struct iosys_map *map)
{
	vunmap(map->vaddr);
}

static const struct dma_buf_ops amdxdna_ubuf_dmabuf_ops = {
	.map_dma_buf = amdxdna_ubuf_map,
	.unmap_dma_buf = amdxdna_ubuf_unmap,
	.release = amdxdna_ubuf_release,
	.mmap = amdxdna_ubuf_mmap,
	.vmap = amdxdna_ubuf_vmap,
	.vunmap = amdxdna_ubuf_vunmap,
};

struct dma_buf *amdxdna_get_ubuf(struct drm_device *dev,
				 enum amdxdna_ubuf_flag flags,
				 u32 num_entries, void __user *va_entries)
{
	struct amdxdna_dev *xdna = to_xdna_dev(dev);
	struct amdxdna_drm_va_entry *va_ent;
	struct amdxdna_ubuf_priv *ubuf;
	struct dma_buf *dbuf;
	u32 npages, start = 0;
	int i, ret;
	DEFINE_DMA_BUF_EXPORT_INFO(exp_info);

	ubuf = kzalloc(sizeof(*ubuf), GFP_KERNEL);
	if (!ubuf)
		return ERR_PTR(-ENOMEM);

	ubuf->flags = flags;

	va_ent = kvcalloc(num_entries, sizeof(*va_ent), GFP_KERNEL);
	if (!va_ent) {
		ret = -ENOMEM;
		goto free_ubuf;
	}

	if (copy_from_user(va_ent, va_entries, sizeof(*va_ent) * num_entries)) {
		XDNA_DBG(xdna, "Access va entries failed");
		ret = -EINVAL;
		goto free_ent;
	}

	for (i = 0, exp_info.size = 0; i < num_entries; i++) {
		if ((va_ent[i].vaddr & (PAGE_SIZE - 1)) ||
		    (va_ent[i].len & (PAGE_SIZE - 1))) {
			XDNA_ERR(xdna, "Invalid address or len %llx, %llx",
				 va_ent[i].vaddr, va_ent[i].len);
			ret = -EINVAL;
			goto free_ent;
		}

		exp_info.size += va_ent[i].len;
	}

	ubuf->nr_pages = exp_info.size >> PAGE_SHIFT;
	ubuf->pages = kvmalloc_array(ubuf->nr_pages, sizeof(*ubuf->pages), GFP_KERNEL);
	if (!ubuf->pages) {
		ret = -ENOMEM;
		goto free_ent;
	}

	for (i = 0; i < num_entries; i++) {
		npages = va_ent[i].len >> PAGE_SHIFT;

		ret = pin_user_pages_fast(va_ent[i].vaddr, npages,
					  FOLL_WRITE | FOLL_LONGTERM,
					  &ubuf->pages[start]);
		if (ret < 0 || ret != npages) {
			ret = -ENOMEM;
			XDNA_ERR(xdna, "Failed to pin pages ret %d", ret);
			goto destroy_pages;
		}

		start += ret;
	}

	exp_info.ops = &amdxdna_ubuf_dmabuf_ops;
	exp_info.priv = ubuf;
	exp_info.flags = O_RDWR;

	dbuf = dma_buf_export(&exp_info);
	if (IS_ERR(dbuf)) {
		ret = PTR_ERR(dbuf);
		goto destroy_pages;
	}
	kvfree(va_ent);

	return dbuf;

destroy_pages:
	if (start)
		unpin_user_pages(ubuf->pages, start);
	kvfree(ubuf->pages);
free_ent:
	kvfree(va_ent);
free_ubuf:
	kfree(ubuf);
	return ERR_PTR(ret);
}

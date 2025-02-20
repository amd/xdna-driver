// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2023-2025, Advanced Micro Devices, Inc.
 */

#include <linux/version.h>
#include <linux/dma-mapping.h>
#include <linux/sched/clock.h>

#include "amdxdna_devel.h"
#include "amdxdna_trace.h"

int iommu_mode;
module_param(iommu_mode, int, 0644);
MODULE_PARM_DESC(iommu_mode, "0 = w/ PASID (Default), 1 = wo/ PASID, 2 = Bypass");

/*
 * Carvedout memory is a chunck of memory which is physically contiguous and
 * is reserved during early boot time. There is only one chunck of such memory
 * per system. Once available, all BOs accessible from device should be
 * allocated from this memory.
 */
u64 carvedout_addr;
module_param(carvedout_addr, ullong, 0644);
MODULE_PARM_DESC(carvedout_addr, "Physical memory address for reserved memory chunk");

u64 carvedout_size;
module_param(carvedout_size, ullong, 0644);
MODULE_PARM_DESC(carvedout_size, "Physical memory size for reserved memory chunk");

bool priv_load;
module_param(priv_load, bool, 0644);
MODULE_PARM_DESC(priv_load, "Privileged loading runtime configure (Default false)");

int start_col_index = -1;
module_param(start_col_index, int, 0600);
MODULE_PARM_DESC(start_col_index, "Force start column, default -1 (auto select)");

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

int amdxdna_carvedout_alloc(struct drm_mm_node *node, u64 size, u64 alignment)
{
	int ret;

	mutex_lock(&carvedout.lock);
	ret = drm_mm_insert_node_generic(&carvedout.mm, node, size, alignment,
					 0, DRM_MM_INSERT_BEST);
	mutex_unlock(&carvedout.lock);
	return ret;
}

void amdxdna_carvedout_free(struct drm_mm_node *node)
{
	mutex_lock(&carvedout.lock);
	drm_mm_remove_node(node);
	mutex_unlock(&carvedout.lock);
}

int amdxdna_iommu_mode_setup(struct amdxdna_dev *xdna)
{
	struct iommu_domain *domain = NULL;

	switch (iommu_mode) {
	case AMDXDNA_IOMMU_PASID:
		// default case
		break;
	case AMDXDNA_IOMMU_NO_PASID:
		// Can't use carvedout memory due to no struct page, so can't do dma map
		if (amdxdna_use_carvedout()) {
			XDNA_ERR(xdna, "Carvedout memory can't be used with this iommu mode");
			return -EOPNOTSUPP;
		}
#if KERNEL_VERSION(6, 13, 0) > LINUX_VERSION_CODE
		if (!iommu_present(xdna->ddev.dev->bus)) {
#else
		if (!device_iommu_mapped(xdna->ddev.dev)) {
#endif
			XDNA_ERR(xdna, "IOMMU not present");
			return -ENODEV;
		}

		domain = iommu_get_domain_for_dev(xdna->ddev.dev);
		if (!iommu_is_dma_domain(domain)) {
			XDNA_ERR(xdna, "Set amd_iommu=force_isolation for DMA domain");
			return -EOPNOTSUPP;
		}

		break;
	case AMDXDNA_IOMMU_BYPASS:
		 // IOMMU bypass mode requires carvedout memory reserved.
		if (!amdxdna_use_carvedout()) {
			XDNA_ERR(xdna, "No carvedout memory reserved!");
			return -EOPNOTSUPP;
		}
		break;
	default:
		XDNA_ERR(xdna, "Invalid IOMMU mode %d", iommu_mode);
		return -EINVAL;
	}

	return 0;
}

struct sg_table *amdxdna_alloc_sgt(struct amdxdna_dev *xdna, size_t sz,
				   struct page **pages, u32 nr_pages)
{
	struct sg_table *sgt;

	sgt = kmalloc(sizeof(*sgt), GFP_KERNEL);
	if (!sgt) {
		XDNA_ERR(xdna, "Allocate sgt failed");
		return NULL;
	}

	if (sg_alloc_table_from_pages(sgt, pages, nr_pages, 0, sz, GFP_KERNEL)) {
		XDNA_ERR(xdna, "Allocate sg alloc from pages failed");
		kfree(sgt);
		sgt = NULL;
	}

	return sgt;
}

void amdxdna_free_sgt(struct amdxdna_dev *xdna, struct sg_table *sgt)
{
	if (!sgt)
		return;

	sg_free_table(sgt);
	kfree(sgt);
}

int amdxdna_mem_map(struct amdxdna_dev *xdna, struct amdxdna_mem *mem)
{
	struct device *dev = xdna->ddev.dev;
	struct sg_table *sgt = NULL;
	int ret;

	if (!mem) {
		XDNA_ERR(xdna, "mem is not init");
		return -EINVAL;
	}

	XDNA_DBG(xdna, "size %ld, nr_pages %d", mem->size, mem->nr_pages);

	sgt = amdxdna_alloc_sgt(xdna, mem->size, mem->pages, mem->nr_pages);
	if (!sgt)
		return -ENOMEM;

	if (!dma_map_sg(dev, sgt->sgl, sgt->orig_nents, DMA_BIDIRECTIONAL)) {
		XDNA_ERR(xdna, "dma map sg failed");
		ret = -ENOMEM;
		goto free_sgt;
	}

	/* Device doesn't do scatter/gather, fail non-contiguous map */
	if (drm_prime_get_contiguous_size(sgt) != mem->size) {
		XDNA_ERR(xdna, "noncontiguous dma map, size:%ld", mem->size);
		ret = -ENOMEM;
		goto unmap_and_free;
	}

	mem->sgt = sgt;
	mem->dma_addr = sg_dma_address(sgt->sgl);

	XDNA_DBG(xdna, "dma_addr 0x%llx phy_addr 0x%llx", mem->dma_addr, sg_phys(sgt->sgl));

	return 0;

unmap_and_free:
	dma_unmap_sg(dev, sgt->sgl, sgt->orig_nents, DMA_BIDIRECTIONAL);
free_sgt:
	amdxdna_free_sgt(xdna, sgt);
	return ret;
}

void amdxdna_mem_unmap(struct amdxdna_dev *xdna, struct amdxdna_mem *mem)
{
	struct device *dev = xdna->ddev.dev;
	struct sg_table *sgt = mem->sgt;

	if (!sgt)
		return;

	dma_unmap_sg(dev, sgt->sgl, sgt->orig_nents, DMA_BIDIRECTIONAL);
	amdxdna_free_sgt(xdna, sgt);
}

#ifdef AMDXDNA_SHMEM
int amdxdna_bo_dma_map(struct amdxdna_gem_obj *abo)
{
	struct amdxdna_dev *xdna = to_xdna_dev(to_gobj(abo)->dev);
	struct sg_table *sgt;

	sgt = drm_gem_shmem_get_pages_sgt(&abo->base);
	if (IS_ERR(sgt)) {
		XDNA_ERR(xdna, "Get sgt failed, ret %ld", PTR_ERR(sgt));
		return PTR_ERR(sgt);
	}

	/* Device doesn't do scatter/gather, fail non-contiguous map */
	if (drm_prime_get_contiguous_size(sgt) != abo->mem.size) {
		XDNA_ERR(xdna, "noncontiguous dma map, size:%ld", abo->mem.size);
		drm_gem_shmem_put_pages(&abo->base);
		return -ENOMEM;
	}

	abo->mem.dma_addr = sg_dma_address(sgt->sgl);

	XDNA_DBG(xdna, "BO type %d dma_addr 0x%llx", abo->type, abo->mem.dma_addr);
	return 0;
}

void amdxdna_bo_dma_unmap(struct amdxdna_gem_obj *abo)
{
	struct amdxdna_dev *xdna = to_xdna_dev(to_gobj(abo)->dev);

	XDNA_DBG(xdna, "BO type %d dma_addr 0x%llx", abo->type, abo->mem.dma_addr);
	if (is_import_bo(abo))
		return;

	drm_gem_shmem_put_pages(&abo->base);
}
#else
int amdxdna_bo_dma_map(struct amdxdna_gem_obj *abo)
{
	return -EOPNOTSUPP;
}

void amdxdna_bo_dma_unmap(struct amdxdna_gem_obj *abo)
{
}
#endif /* AMDXDNA_SHMEM */

void amdxdna_gem_dump_mm(struct amdxdna_dev *xdna)
{
	struct drm_printer p = drm_dbg_printer(&xdna->ddev, DRM_UT_DRIVER, NULL);

	drm_mm_print(&xdna->ddev.vma_offset_manager->vm_addr_space_mm, &p);
}

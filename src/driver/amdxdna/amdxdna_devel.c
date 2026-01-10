// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2023-2025, Advanced Micro Devices, Inc.
 */

#include <linux/version.h>
#include <linux/dma-mapping.h>
#include <linux/sched/clock.h>

#include "amdxdna_carvedout_buf.h"
#include "amdxdna_cma_buf.h"
#include "amdxdna_devel.h"
#include "amdxdna_trace.h"

int iommu_mode = AMDXDNA_IOMMU_PASID;

bool priv_load;
module_param(priv_load, bool, 0644);
MODULE_PARM_DESC(priv_load, "Privileged loading runtime configure (Default false)");

int start_col_index = -1;
module_param(start_col_index, int, 0600);
MODULE_PARM_DESC(start_col_index, "Force start column, default -1 (auto select)");

static bool is_iommu_off(struct amdxdna_dev *xdna)
{
#ifdef HAVE_device_iommu_mapped
	return !device_iommu_mapped(xdna->ddev.dev);
#else
	return !iommu_present(xdna->ddev.dev->bus);
#endif
}

int amdxdna_iommu_mode_setup(struct amdxdna_dev *xdna)
{
	struct iommu_domain *domain;
	bool iommu_iova;
	bool iommu_off;

	if (amdxdna_iova_enabled(xdna)) {
		iommu_mode = AMDXDNA_IOMMU_NO_PASID;
		return 0;
	}

	domain = iommu_get_domain_for_dev(xdna->ddev.dev);
	iommu_iova = domain ? iommu_is_dma_domain(domain) : false;
	iommu_off = is_iommu_off(xdna);

	/* Working non-PASID mode */
	if (amdxdna_use_carvedout() || amdxdna_use_cma()) {
		if (iommu_off)
			XDNA_INFO(xdna, "Physical address mode enabled");
		else
			XDNA_INFO(xdna, "IOVA address mode enabled");
		iommu_mode = AMDXDNA_IOMMU_NO_PASID;
		return 0;
	}

	/* IOVA mode w/o carveout, warn user about potential failure. */
	if (iommu_iova) {
		XDNA_WARN(xdna,
			  "IOVA address mode enabled w/o carveout, BO allocation may fail");
		iommu_mode = AMDXDNA_IOMMU_NO_PASID;
		return 0;
	}

	/* Physical memory mode w/o carveout, not supported */
	if (iommu_off) {
		XDNA_ERR(xdna, "IOMMU is off, require carveout memory");
		return -ENODEV;
	}

	/* PASID mode */
	XDNA_INFO(xdna, "PASID address mode enabled");
	iommu_mode = AMDXDNA_IOMMU_PASID;
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

int amdxdna_bo_dma_map(struct amdxdna_gem_obj *abo)
{
	struct amdxdna_dev *xdna = to_xdna_dev(to_gobj(abo)->dev);
	struct sg_table *sgt;
	size_t contig_sz;

	if (amdxdna_iova_enabled(xdna))
		return amdxdna_iommu_map_bo(xdna, abo);

	sgt = drm_gem_shmem_get_pages_sgt(&abo->base);
	if (IS_ERR(sgt)) {
		XDNA_ERR(xdna, "Get sgt failed, ret %ld", PTR_ERR(sgt));
		return PTR_ERR(sgt);
	}

	/* Device doesn't do scatter/gather, fail non-contiguous map */
	contig_sz = drm_prime_get_contiguous_size(sgt);
	if (contig_sz != abo->mem.size) {
		XDNA_ERR(xdna, "noncontiguous dma map, contig size:%ld, expected size:%ld",
			 contig_sz, abo->mem.size);
		return -ENOMEM;
	}

	abo->mem.dma_addr = sg_dma_address(sgt->sgl);

	XDNA_DBG(xdna, "BO type %d dma_addr 0x%llx", abo->type, abo->mem.dma_addr);
	return 0;
}

void amdxdna_gem_dump_mm(struct amdxdna_dev *xdna)
{
	struct drm_printer p = drm_dbg_printer(&xdna->ddev, DRM_UT_DRIVER, NULL);

	drm_mm_print(&xdna->ddev.vma_offset_manager->vm_addr_space_mm, &p);
}

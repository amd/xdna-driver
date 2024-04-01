// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2023-2024, Advanced Micro Devices, Inc.
 */

#include <linux/version.h>
#include <linux/sched/clock.h>

#include "amdxdna_devel.h"
#include "amdxdna_trace.h"

int iommu_mode;
module_param(iommu_mode, int, 0644);
MODULE_PARM_DESC(iommu_mode, "0 = w/ PASID (Default), 1 = wo/ PASID, 2 = Bypass");

int amdxdna_iommu_mode_setup(struct amdxdna_dev *xdna)
{
	struct iommu_domain *domain = NULL;

	switch (iommu_mode) {
	case AMDXDNA_IOMMU_PASID:
		break;
	case AMDXDNA_IOMMU_NO_PASID:
		if (!iommu_present(xdna->ddev.dev->bus)) {
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
		/*
		 * IOMMU bypass mode is always supported, but
		 * with 4MB contiguous physical memory limitation.
		 */
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

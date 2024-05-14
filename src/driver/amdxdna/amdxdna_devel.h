/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2024, Advanced Micro Devices, Inc.
 */

#ifndef _AMDXDNA_DEVEL_
#define _AMDXDNA_DEVEL_

#include <linux/amd-iommu.h>
#include <linux/iommu.h>

#include "amdxdna_drv.h"

#define AMDXDNA_IOMMU_PASID 0
#define AMDXDNA_IOMMU_NO_PASID 1
#define AMDXDNA_IOMMU_BYPASS 2
extern int iommu_mode;
extern bool priv_load;
extern int start_col_index;

int amdxdna_iommu_mode_setup(struct amdxdna_dev *aie);
struct sg_table *amdxdna_alloc_sgt(struct amdxdna_dev *aie, size_t sz,
				   struct page **pages, u32 nr_pages);
void amdxdna_free_sgt(struct amdxdna_dev *aie, struct sg_table *sgt);

int amdxdna_mem_map(struct amdxdna_dev *xdna, struct amdxdna_mem *mem);
void amdxdna_mem_unmap(struct amdxdna_dev *xdna, struct amdxdna_mem *mem);
#endif /* _AMDXDNA_DEVEL_ */

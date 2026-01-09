// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2025, Advanced Micro Devices, Inc.
 */

#include <drm/drm_cache.h>
#include <linux/log2.h>
#include <linux/string_helpers.h>

#include "amdxdna_mgmt.h"

#define MGMT_BUF_REGION_SIZE		SZ_64M

/*
 * Validate DMA buffer constraints:
 * 1. Buffer must be entirely within a single 64MB-aligned region
 * 2. Buffer size must be between 8KB (inclusive) and 64MB (inclusive)
 * 3. Buffer size must be a power of 2
 * 4. Buffer address must be aligned to the buffer size
 */
static int amdxdna_mgmt_buff_validate(struct amdxdna_dev *xdna, dma_addr_t addr, size_t size)
{
	if (size < SZ_8K || size > MGMT_BUF_REGION_SIZE) {
		XDNA_ERR(xdna, "Buffer size 0x%lx not in range [8KB, 64MB]", size);
		return -EINVAL;
	}

	if (!is_power_of_2(size)) {
		XDNA_ERR(xdna, "Buffer size 0x%lx is not a power of 2", size);
		return -EINVAL;
	}

	if (!IS_ALIGNED(addr, size)) {
		XDNA_ERR(xdna, "Buffer addr 0x%llx is not aligned to size 0x%lx", addr, size);
		return -EINVAL;
	}

	if ((addr & ~(MGMT_BUF_REGION_SIZE - 1)) !=
	    ((addr + size - 1) & ~(MGMT_BUF_REGION_SIZE - 1))) {
		XDNA_ERR(xdna, "Buffer [0x%llx, 0x%llx) crosses 64MB boundary", addr, addr + size);
		return -EINVAL;
	}

	return 0;
}

struct amdxdna_mgmt_dma_hdl *amdxdna_mgmt_buff_alloc(struct amdxdna_dev *xdna, size_t size,
						     enum dma_data_direction dir)
{
	struct amdxdna_mgmt_dma_hdl *dma_hdl;

	if (!size || size < SZ_8K)
		return ERR_PTR(-EINVAL);

	if (size > SZ_4M)
		return ERR_PTR(-ENOMEM);

	dma_hdl = kzalloc(sizeof(*dma_hdl), GFP_KERNEL);
	if (!dma_hdl)
		return ERR_PTR(-ENOMEM);

	/*
	 * The aligned size calculation is implemented to work around a known firmware issue that
	 * can cause the system to hang. By aligning the size to the nearest power of two and then
	 * doubling it, we ensure that the memory allocation is compatible with the firmware's
	 * requirements, thus preventing potential system instability.
	 */
	dma_hdl->aligned_size = PAGE_ALIGN(size);
	dma_hdl->aligned_size = roundup_pow_of_two(dma_hdl->aligned_size);
	dma_hdl->aligned_size *= 2;

	/*
	 * The behavior of dma_alloc_noncoherent() was tested on the 6.13 kernel.
	 * 1. This function eventually calls __alloc_frozen_pages_noprof().
	 * 2. The maximum allocatable size is 4MB, constrained by MAX_PAGE_ORDER 10.
	 *    Exceeding this limit results in a NULL pointer return.
	 * 3. For valid sizes, this function provides physically contiguous memory.
	 *
	 * If there is a requirement for physical contiguous memory larger than 4MB,
	 * consider allocating the buffer from carved-out memory.
	 */
	if (dma_hdl->aligned_size > SZ_4M)
		dma_hdl->aligned_size = SZ_4M;

	if (amdxdna_iova_enabled(xdna)) {
		dma_hdl->vaddr = amdxdna_iommu_alloc(xdna, dma_hdl->aligned_size, &dma_hdl->dma_hdl);
		if (IS_ERR(dma_hdl->vaddr)) {
			kfree(dma_hdl);
			return ERR_CAST(dma_hdl->vaddr);
		}
	} else {
		dma_hdl->vaddr = dma_alloc_noncoherent(xdna->ddev.dev, dma_hdl->aligned_size,
					       &dma_hdl->dma_hdl, dir, GFP_KERNEL);
		if (!dma_hdl->vaddr) {
			kfree(dma_hdl);
			return ERR_PTR(-ENOMEM);
		}
	}

	if (amdxdna_mgmt_buff_validate(xdna, dma_hdl->dma_hdl, dma_hdl->aligned_size))
		goto free_buf;

	dma_hdl->size = size;
	dma_hdl->xdna = xdna;
	dma_hdl->dir = dir;

	return dma_hdl;

free_buf:
	amdxdna_mgmt_buff_free(dma_hdl);
	return ERR_PTR(-EINVAL);
}

int amdxdna_mgmt_buff_clflush(struct amdxdna_mgmt_dma_hdl *dma_hdl, u32 offset, size_t size)
{
	if (!dma_hdl)
		return -EINVAL;

	if (offset + size > dma_hdl->size)
		return -EINVAL;

	/*
	 * After flushing the buffer and handing it over to the device,
	 * the user must wait for the device to complete its operations and return
	 * control before attempting to write to the buffer again.
	 */
	drm_clflush_virt_range(dma_hdl->vaddr + offset, size ? size : dma_hdl->size);
	return 0;
}

dma_addr_t amdxdna_mgmt_buff_get_dma_addr(struct amdxdna_mgmt_dma_hdl *dma_hdl)
{
	if (!dma_hdl)
		return 0;

	if (!dma_hdl->aligned_size)
		return 0;

	return dma_hdl->dma_hdl;
}

void *amdxdna_mgmt_buff_get_cpu_addr(struct amdxdna_mgmt_dma_hdl *dma_hdl, u32 offset)
{
	if (!dma_hdl)
		return ERR_PTR(-EINVAL);

	if (!dma_hdl->aligned_size || offset >= dma_hdl->size)
		return ERR_PTR(-EINVAL);

	return dma_hdl->vaddr + offset;
}

void amdxdna_mgmt_buff_free(struct amdxdna_mgmt_dma_hdl *dma_hdl)
{
	if (!dma_hdl)
		return;

	if (amdxdna_iova_enabled(dma_hdl->xdna)) {
		amdxdna_iommu_free(dma_hdl->xdna, dma_hdl->aligned_size,
				   dma_hdl->vaddr, dma_hdl->dma_hdl);
	} else {
		dma_free_noncoherent(dma_hdl->xdna->ddev.dev,
				     dma_hdl->aligned_size, dma_hdl->vaddr,
				     dma_hdl->dma_hdl, dma_hdl->dir);
	}

	dma_hdl->vaddr = NULL;
	dma_hdl->size = 0;
	dma_hdl->dma_hdl = 0;
	dma_hdl->aligned_size = 0;
	kfree(dma_hdl);
	dma_hdl = NULL;
}

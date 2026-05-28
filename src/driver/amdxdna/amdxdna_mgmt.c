// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2025, Advanced Micro Devices, Inc.
 */

#include <drm/drm_cache.h>
#include <linux/device.h>
#include <linux/dma-mapping.h>
#include <linux/log2.h>
#include <linux/pci.h>
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

	/*
	 * On the platform/RPMsg transport the parent device's DMA pool is the
	 * only memory the remote firmware can address. That pool is supplied
	 * by the DT-declared "rpu-cma" reserved-memory region (bound in
	 * amdxdna_cma_region_init). Refuse to allocate from the system
	 * default DMA pool here -- those addresses are not in the RPU's bus
	 * map and DRAM_LOGGING_START / IDENTIFY-style buffers handed off to
	 * the firmware will be silently rejected (or worse, race with other
	 * Linux users of the same memory). PCI keeps its existing behaviour:
	 * the device's own BAR / IOMMU mapping makes any DMA-direct address
	 * reachable.
	 */
	if (!dev_is_pci(xdna->ddev.dev) && !xdna->rpu_cma_bound) {
		XDNA_ERR(xdna,
			 "mgmt buffer alloc refused: 'rpu-cma' reserved-memory region not bound (add memory-region-names=\"rpu-cma\" in the amd,versal-aie DT node)");
		return ERR_PTR(-ENODEV);
	}

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
		dma_hdl->vaddr = amdxdna_iommu_alloc(xdna, dma_hdl->aligned_size,
						     &dma_hdl->dma_hdl);
		if (IS_ERR(dma_hdl->vaddr)) {
			int ret = PTR_ERR(dma_hdl->vaddr);

			kfree(dma_hdl);
			return ERR_PTR(ret);
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

/*
 * Resolve effective length: callers pass size=0 to mean "from offset to end
 * of buffer". Returns 0 and *len_out on success, -EINVAL on out-of-range.
 */
static int amdxdna_mgmt_buff_resolve_len(struct amdxdna_mgmt_dma_hdl *dma_hdl,
					 u32 offset, size_t size, size_t *len_out)
{
	size_t len;

	if (!dma_hdl)
		return -EINVAL;

	if (offset > dma_hdl->size)
		return -EINVAL;

	len = size ? size : dma_hdl->size - offset;

	if (offset + len > dma_hdl->size)
		return -EINVAL;

	*len_out = len;
	return 0;
}

/**
 * amdxdna_mgmt_buff_sync_for_device - hand a sub-range to the firmware
 * @dma_hdl: handle returned by amdxdna_mgmt_buff_alloc()
 * @offset:  byte offset within the buffer
 * @size:    sub-range length in bytes; 0 means "to end of buffer"
 *
 * Call this immediately before passing the buffer's DMA address to the
 * remote firmware so that any CPU-side writes are visible in DRAM and any
 * stale CPU cache lines covering the device-writable range are evicted.
 *
 * Uses the streaming direction recorded on the handle at alloc time
 * (DMA_TO_DEVICE / DMA_FROM_DEVICE / DMA_BIDIRECTIONAL), so the underlying
 * dma_sync_single_for_device() does the minimum work required for that
 * direction (clean only for TO_DEVICE, invalidate only for FROM_DEVICE).
 */
int amdxdna_mgmt_buff_sync_for_device(struct amdxdna_mgmt_dma_hdl *dma_hdl,
				      u32 offset, size_t size)
{
	size_t len;
	int ret;

	ret = amdxdna_mgmt_buff_resolve_len(dma_hdl, offset, size, &len);
	if (ret)
		return ret;

	if (amdxdna_iova_enabled(dma_hdl->xdna))
		drm_clflush_virt_range(dma_hdl->vaddr + offset, len);
	else
		dma_sync_single_for_device(dma_hdl->xdna->ddev.dev,
					   dma_hdl->dma_hdl + offset, len,
					   dma_hdl->dir);
	return 0;
}

/**
 * amdxdna_mgmt_buff_sync_for_cpu - reclaim a sub-range from the firmware
 * @dma_hdl: handle returned by amdxdna_mgmt_buff_alloc()
 * @offset:  byte offset within the buffer
 * @size:    sub-range length in bytes; 0 means "to end of buffer"
 *
 * Call this after the remote firmware has finished writing into the
 * buffer and before the CPU reads the new contents. Invalidates any CPU
 * cache lines covering the range so subsequent loads pull fresh data
 * from DRAM.
 *
 * On a buffer allocated DMA_TO_DEVICE the underlying
 * dma_sync_single_for_cpu() is effectively a no-op, which is the correct
 * thing: the CPU should never read back a TO_DEVICE buffer.
 */
int amdxdna_mgmt_buff_sync_for_cpu(struct amdxdna_mgmt_dma_hdl *dma_hdl,
				   u32 offset, size_t size)
{
	size_t len;
	int ret;

	ret = amdxdna_mgmt_buff_resolve_len(dma_hdl, offset, size, &len);
	if (ret)
		return ret;

	if (amdxdna_iova_enabled(dma_hdl->xdna))
		drm_clflush_virt_range(dma_hdl->vaddr + offset, len);
	else
		dma_sync_single_for_cpu(dma_hdl->xdna->ddev.dev,
					dma_hdl->dma_hdl + offset, len,
					dma_hdl->dir);
	return 0;
}

/*
 * Backwards-compatible flush that brackets both directions in a single call.
 * Most legacy call sites use this immediately before sending a buffer to the
 * firmware; preserving the existing for_device semantics keeps those paths
 * working. New code should prefer the directional helpers above and call
 * _for_device before the send and _for_cpu after the response.
 */
int amdxdna_mgmt_buff_clflush(struct amdxdna_mgmt_dma_hdl *dma_hdl, u32 offset, size_t size)
{
	return amdxdna_mgmt_buff_sync_for_device(dma_hdl, offset, size);
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

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
	size_t pow2_size, raw_size, offset;
	dma_addr_t raw_dma, aligned_dma;
	void *raw_vaddr;

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

	/*
	 * Firmware requires the buffer base address to be aligned to its
	 * power-of-two size and to fit in a single MGMT_BUF_REGION_SIZE
	 * region (see amdxdna_mgmt_buff_validate()). Linux CMA only honours
	 * CONFIG_CMA_ALIGNMENT (~1 MB) for large allocations, so we over-
	 * allocate by 2x and carve out a naturally-aligned sub-window.
	 *
	 * On the non-IOMMU path dma_alloc_noncoherent() is backed by
	 * __alloc_frozen_pages_noprof() which is constrained by
	 * MAX_PAGE_ORDER to 4 MB per allocation. That caps the largest
	 * exposed sub-window (pow2_size) at 2 MB on this transport.
	 */
	pow2_size = roundup_pow_of_two(PAGE_ALIGN(size));
	raw_size  = pow2_size * 2;
	if (raw_size > SZ_4M) {
		XDNA_ERR(xdna,
			 "mgmt buffer alloc refused: requested 0x%zx exceeds 2 MB (raw alloc capped at 4 MB by MAX_PAGE_ORDER); lower fw_log_size",
			 size);
		return ERR_PTR(-ENOMEM);
	}

	dma_hdl = kzalloc(sizeof(*dma_hdl), GFP_KERNEL);
	if (!dma_hdl)
		return ERR_PTR(-ENOMEM);

	/*
	 * Populate identity fields *before* the underlying alloc so the
	 * cleanup path (amdxdna_mgmt_buff_free) can safely dereference
	 * dma_hdl->xdna if we have to bail out below.
	 */
	dma_hdl->xdna         = xdna;
	dma_hdl->dir          = dir;
	dma_hdl->size         = size;
	dma_hdl->aligned_size = pow2_size;
	dma_hdl->raw_size     = raw_size;

	if (amdxdna_iova_enabled(xdna)) {
		raw_vaddr = amdxdna_iommu_alloc(xdna, raw_size, &raw_dma);
		if (IS_ERR(raw_vaddr)) {
			int ret = PTR_ERR(raw_vaddr);

			kfree(dma_hdl);
			return ERR_PTR(ret);
		}
	} else {
		raw_vaddr = dma_alloc_noncoherent(xdna->ddev.dev, raw_size,
						  &raw_dma, dir, GFP_KERNEL);
		if (!raw_vaddr) {
			kfree(dma_hdl);
			return ERR_PTR(-ENOMEM);
		}
	}

	dma_hdl->raw_vaddr    = raw_vaddr;
	dma_hdl->raw_dma_addr = raw_dma;

	/* Carve a naturally-aligned pow2_size sub-window out of the raw alloc. */
	aligned_dma      = ALIGN(raw_dma, pow2_size);
	offset           = aligned_dma - raw_dma;
	dma_hdl->dma_hdl = aligned_dma;
	dma_hdl->vaddr   = (u8 *)raw_vaddr + offset;

	if (amdxdna_mgmt_buff_validate(xdna, dma_hdl->dma_hdl, dma_hdl->aligned_size))
		goto free_buf;

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

	/*
	 * Be tolerant of partially-constructed handles: amdxdna_mgmt_buff_alloc()
	 * may bail out and call us before the underlying DMA allocation succeeded.
	 * The underlying free APIs all need the raw_* triplet that was returned by
	 * the allocator, plus xdna (for the device pointer / IOMMU dispatch).
	 */
	if (dma_hdl->xdna && dma_hdl->raw_vaddr) {
		if (amdxdna_iova_enabled(dma_hdl->xdna))
			amdxdna_iommu_free(dma_hdl->xdna, dma_hdl->raw_size,
					   dma_hdl->raw_vaddr,
					   dma_hdl->raw_dma_addr);
		else
			dma_free_noncoherent(dma_hdl->xdna->ddev.dev,
					     dma_hdl->raw_size,
					     dma_hdl->raw_vaddr,
					     dma_hdl->raw_dma_addr,
					     dma_hdl->dir);
	}

	kfree(dma_hdl);
}

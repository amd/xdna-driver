/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2025, Advanced Micro Devices, Inc.
 */
#ifndef _AMDXDNA_MGMT_H_
#define _AMDXDNA_MGMT_H_

#include <linux/dma-mapping.h>

#include "amdxdna_drm.h"

/*
 * Management DMA buffer descriptor.
 *
 * The firmware indexes its mgmt buffers with hardware that requires the
 * buffer base address to be aligned to its (power-of-two) size and to
 * live entirely inside a single 64 MB region.  Linux's CMA allocator
 * only guarantees CONFIG_CMA_ALIGNMENT (typically 1 MB) alignment, so on
 * the non-IOMMU/RPU path amdxdna_mgmt_buff_alloc() over-allocates
 * (raw_*) and carves out a naturally-aligned sub-window (vaddr/dma_hdl/
 * aligned_size) for the firmware.  The raw_* triplet is what the kernel
 * DMA API allocated and is the only thing the free path may pass back.
 */
struct amdxdna_mgmt_dma_hdl {
	struct amdxdna_dev		*xdna;
	enum dma_data_direction		dir;

	/* Sub-window exposed to callers / firmware (naturally aligned). */
	void				*vaddr;
	dma_addr_t			dma_hdl;
	size_t				size;          /* user-requested */
	size_t				aligned_size;  /* sub-window, pow2 */

	/* Raw allocation, used only by amdxdna_mgmt_buff_free(). */
	void				*raw_vaddr;
	dma_addr_t			raw_dma_addr;
	size_t				raw_size;
};

struct amdxdna_mgmt_dma_hdl *amdxdna_mgmt_buff_alloc(struct amdxdna_dev *xdna, size_t size,
						     enum dma_data_direction dir);
int amdxdna_mgmt_buff_sync_for_device(struct amdxdna_mgmt_dma_hdl *dma_hdl,
				      u32 offset, size_t size);
int amdxdna_mgmt_buff_sync_for_cpu(struct amdxdna_mgmt_dma_hdl *dma_hdl,
				   u32 offset, size_t size);
dma_addr_t amdxdna_mgmt_buff_get_dma_addr(struct amdxdna_mgmt_dma_hdl *dma_hdl);
void *amdxdna_mgmt_buff_get_cpu_addr(struct amdxdna_mgmt_dma_hdl *dma_hdl, u32 offset);
void amdxdna_mgmt_buff_free(struct amdxdna_mgmt_dma_hdl *dma_hdl);

#endif /* _AMDXDNA_MGMT_H_ */

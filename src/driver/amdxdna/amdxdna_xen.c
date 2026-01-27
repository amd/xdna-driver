// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2026, Advanced Micro Devices, Inc.
 */

#include "amdxdna_xen.h"

#ifdef HAVE_xen_phy_dma_ops
#include <xen/phy-dma-ops.h>
#endif

void *amdxdna_xen_alloc_buf_phys(struct device *dev, u32 size, dma_addr_t *dma_addr)
{
	if (!is_xen_initial_pvh_domain()) {
		dev_err(dev, "failed to allocate Xen buffer, not in a Xen initial PvH domain");
		return NULL;
	}

#ifdef HAVE_xen_phy_dma_ops
	if (!size || !dma_addr) {
		dev_err(dev, "failed to allocate Xen buffer, invalid arguments");
		return NULL;
	}

	return xen_phy_dma_ops.alloc(dev, size, dma_addr, GFP_KERNEL, 0);
#else
	dev_err(dev, "failed to allocate Xen buffer, xen phy dma ops not supported");
	return NULL;
#endif
}

void amdxdna_xen_free_buf_phys(struct device *dev, void *vaddr, dma_addr_t dma_addr, u32 size)
{
	if (!is_xen_initial_pvh_domain()) {
		dev_err(dev, "failed to free Xen buffer, not in a Xen initial PvH domain");
		return;
	}

#ifdef HAVE_xen_phy_dma_ops
	if (!vaddr || !size) {
		dev_err(dev, "failed to free Xen buffer, invalid arguments");
		return;
	}

	xen_phy_dma_ops.free(dev, size, vaddr, dma_addr, 0);
#endif
}


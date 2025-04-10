/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2026, Advanced Micro Devices, Inc.
 */

#ifndef _AMDXDNA_XEN_H_
#define _AMDXDNA_XEN_H_

#include <linux/device.h>
#include <linux/gfp.h>
#include <linux/types.h>
#include <xen/xen.h>
#include <xen/xen-ops.h>

static inline bool is_xen_initial_pvh_domain(void)
{
	return xen_initial_domain() && xen_pvh_domain();
}

 /**
  * @brief Allocate a physical buffer for the Xen domain
  * @param dev: The device to allocate the buffer for
  * @param size: The requested size of the buffer to allocate
  * @param dma_addr: The DMA address of the buffer
  * @return: A virtual address pointer to the allocated buffer on success, or NULL on failure.
  */
void *amdxdna_xen_alloc_buf_phys(struct device *dev, u32 size, dma_addr_t *dma_addr);

 /**
  * @brief Free a physical buffer for the Xen domain
  * @param dev: The device to free the buffer for
  * @param vaddr: The virtual address of the buffer
  * @param dma_addr: The DMA address of the buffer
  * @param size: The size of the buffer
  */
void amdxdna_xen_free_buf_phys(struct device *dev, void *vaddr, dma_addr_t dma_addr, u32 size);

 #endif /* _AMDXDNA_XEN_H_ */


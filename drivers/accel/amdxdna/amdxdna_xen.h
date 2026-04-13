/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2026, Advanced Micro Devices, Inc.
 */

#ifndef _AMDXDNA_XEN_H_
#define _AMDXDNA_XEN_H_

#include <drm/drm_device.h>
#include <linux/device.h>
#include <linux/list.h>
#include <linux/types.h>
#include <xen/xen.h>
#include <xen/xen-ops.h>

struct amdxdna_xen_bufs_mgr {
	struct device		*dev;
	struct list_head	bufs;
};

static inline bool amdxdna_is_xen_initial_pvh_domain(void)
{
	return xen_initial_domain() && xen_pvh_domain();
}

/**
 * amdxdna_xen_bufs_init() - Initialize the Xen buffer manager
 * @mgr: Buffer manager to initialize
 * @dev: Device used for Xen DMA allocations
 */
void amdxdna_xen_bufs_init(struct amdxdna_xen_bufs_mgr *mgr, struct device *dev);

/**
 * amdxdna_xen_bufs_alloc() - Allocate a DMA buffer and track it
 * @mgr: Buffer manager
 * @size: Requested buffer size in bytes
 * @paddr: On success, filled with the machine physical address
 *
 * Return: Virtual address of the allocated buffer, or NULL on failure.
 */
void *amdxdna_xen_bufs_alloc(struct amdxdna_xen_bufs_mgr *mgr, u32 size,
			     u64 *paddr);

/**
 * amdxdna_xen_bufs_drmm_release() - drmm callback wrapper for amdxdna_xen_bufs_fini()
 * @dev: DRM device (unused)
 * @data: Pointer to an amdxdna_xen_bufs_mgr
 *
 * Suitable for use with drmm_add_action_or_reset().
 */
void amdxdna_xen_bufs_drmm_release(struct drm_device *dev, void *data);

#endif /* _AMDXDNA_XEN_H_ */

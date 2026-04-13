// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2026, Advanced Micro Devices, Inc.
 */

#include <linux/slab.h>
#include <linux/dma-mapping.h>

#include "amdxdna_xen.h"

#ifdef HAVE_xen_phy_dma_ops
#include <xen/phy-dma-ops.h>
#endif

struct amdxdna_xen_buf {
	struct list_head	node;
	void			*vaddr;
	dma_addr_t		dma_addr;
	u32			size;
};

static void *xen_alloc_buf(struct device *dev, u32 size, dma_addr_t *dma_addr)
{
#ifdef HAVE_xen_phy_dma_ops
	return xen_phy_dma_ops.alloc(dev, size, dma_addr, GFP_KERNEL, 0);
#else
	dev_err(dev, "xen phy dma ops not supported\n");
	return NULL;
#endif
}

static void xen_free_buf(struct device *dev, void *vaddr, dma_addr_t dma_addr,
			 u32 size)
{
#ifdef HAVE_xen_phy_dma_ops
	xen_phy_dma_ops.free(dev, size, vaddr, dma_addr, 0);
#endif
}

void amdxdna_xen_bufs_init(struct amdxdna_xen_bufs_mgr *mgr, struct device *dev)
{
	mgr->dev = dev;
	INIT_LIST_HEAD(&mgr->bufs);
}

void *amdxdna_xen_bufs_alloc(struct amdxdna_xen_bufs_mgr *mgr, u32 size,
			     u64 *paddr)
{
	struct amdxdna_xen_buf *buf;
	dma_addr_t dma_addr;
	void *vaddr;

	if (!amdxdna_is_xen_initial_pvh_domain()) {
		dev_err(mgr->dev, "not a Xen initial PvH domain\n");
		return NULL;
	}

	vaddr = xen_alloc_buf(mgr->dev, size, &dma_addr);
	if (!vaddr)
		return NULL;

	buf = kzalloc_obj(*buf);
	if (!buf) {
		xen_free_buf(mgr->dev, vaddr, dma_addr, size);
		return NULL;
	}

	buf->vaddr = vaddr;
	buf->dma_addr = dma_addr;
	buf->size = size;
	list_add_tail(&buf->node, &mgr->bufs);

	*paddr = dma_addr;
	return vaddr;
}

static void amdxdna_xen_bufs_fini(struct amdxdna_xen_bufs_mgr *mgr)
{
	struct amdxdna_xen_buf *buf, *tmp;

	list_for_each_entry_safe(buf, tmp, &mgr->bufs, node) {
		xen_free_buf(mgr->dev, buf->vaddr, buf->dma_addr, buf->size);
		list_del(&buf->node);
		kfree(buf);
	}
}

void amdxdna_xen_bufs_drmm_release(struct drm_device *dev, void *data)
{
	amdxdna_xen_bufs_fini(data);
}

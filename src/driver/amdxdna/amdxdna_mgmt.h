/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2025, Advanced Micro Devices, Inc.
 */
#ifndef _AMDXDNA_MGMT_H_
#define _AMDXDNA_MGMT_H_

#include <linux/dma-mapping.h>

#include "amdxdna_drm.h"

struct amdxdna_mgmt_dma_hdl {
	struct amdxdna_dev		*xdna;
	enum dma_data_direction		dir;
	void				*vaddr;
	dma_addr_t			dma_hdl;
	size_t				size;
	size_t				aligned_size;
};

struct amdxdna_mgmt_dma_hdl *amdxdna_mgmt_buff_alloc(struct amdxdna_dev *xdna, size_t size,
						     enum dma_data_direction dir);
int amdxdna_mgmt_buff_clflush(struct amdxdna_mgmt_dma_hdl *dma_hdl, u32 offset, size_t size);
dma_addr_t amdxdna_mgmt_buff_get_dma_addr(struct amdxdna_mgmt_dma_hdl *dma_hdl);
void *amdxdna_mgmt_buff_get_cpu_addr(struct amdxdna_mgmt_dma_hdl *dma_hdl, u32 offset);
void amdxdna_mgmt_buff_free(struct amdxdna_mgmt_dma_hdl *dma_hdl);

#endif /* _AMDXDNA_MGMT_H_ */

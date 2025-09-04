#ifndef _AMDXDNA_CMA_H_
#define _AMDXDNA_CMA_H_
#include <linux/dma-mapping.h>
#include "amdxdna_drm.h"

struct amdxdna_cmabuf_priv {
    struct drm_device *dev;
    dma_addr_t dma_addr;
    void *cpu_addr;
    size_t size;
};


struct dma_buf *amdxdna_get_cma_buf(struct drm_device *dev, size_t size);

#endif /* _AMDXDNA_CMA_H */

// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2025, Advanced Micro Devices, Inc. All rights reserved.

#ifndef _BO_VIRTIO_H_
#define _BO_VIRTIO_H_

#include "../bo.h"

#include <set>

namespace shim_xdna {

class bo_virtio : public bo {
public:
  bo_virtio(const device& device, xrt_core::hwctx_handle::slot_id ctx_id,
    size_t size, uint64_t flags);

  ~bo_virtio();

  void
  sync(direction dir, size_t size, size_t offset) override;

public:
  // Support BO creation from internal
  bo_virtio(const device& device, size_t size, int type);

private:
  bo_virtio(const device& device, xrt_core::hwctx_handle::slot_id ctx_id,
    size_t size, uint64_t flags, int type);
  
  uint32_t
  alloc_drm_bo(const shim_xdna::pdev& dev, int type, size_t size) override;

  void
  get_drm_bo_info(const shim_xdna::pdev& dev, uint32_t boh, amdxdna_drm_get_bo_info* bo_info) override;

  void
  free_drm_bo(const shim_xdna::pdev& dev, uint32_t boh) override;
};

} // namespace shim_xdna

#endif // _BO_VIRTIO_H_

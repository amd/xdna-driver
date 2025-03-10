// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2025, Advanced Micro Devices, Inc. All rights reserved.

#ifndef _BO_VIRTIO_H_
#define _BO_VIRTIO_H_

#include "../bo.h"

#include <set>

namespace shim_xdna {

class bo_virtio : public bo {
public:
  bo_virtio(const pdev& pdev, xrt_core::hwctx_handle::slot_id ctx_id,
    size_t size, uint64_t flags);

  ~bo_virtio();

  void
  sync(direction dir, size_t size, size_t offset) override;

public:
  // Support BO creation from internal
  bo_virtio(const pdev& pdev, size_t size, int type);

private:
  uint32_t m_res_handle;

  bo_virtio(const pdev& pdev, xrt_core::hwctx_handle::slot_id ctx_id,
    size_t size, uint64_t flags, int type);
  
  uint32_t
  alloc_drm_bo(int type, size_t size) override;

  void
  get_drm_bo_info(uint32_t boh, amdxdna_drm_get_bo_info* bo_info) override;

  void
  free_drm_bo(uint32_t boh) override;
};

} // namespace shim_xdna

#endif // _BO_VIRTIO_H_

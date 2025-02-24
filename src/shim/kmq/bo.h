// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2023-2025, Advanced Micro Devices, Inc. All rights reserved.

#ifndef _BO_KMQ_H_
#define _BO_KMQ_H_

#include "../bo.h"
#include "drm_local/amdxdna_accel.h"

#include <set>

namespace shim_xdna {

class bo_kmq : public bo {
public:
  bo_kmq(const pdev& pdev, xrt_core::hwctx_handle::slot_id ctx_id,
    size_t size, uint64_t flags);

  bo_kmq(const pdev& pdev, xrt_core::shared_handle::export_handle ehdl);

  ~bo_kmq();

  void
  sync(direction dir, size_t size, size_t offset) override;

  void
  bind_at(size_t pos, const buffer_handle* bh, size_t offset, size_t size) override;

public:
  // Support BO creation from internal
  bo_kmq(const pdev& pdev, size_t size, int type);

  // Obtain array of arg BO handles, returns real number of handles
  uint32_t
  get_arg_bo_handles(uint32_t *handles, size_t num) const;

private:
  bo_kmq(const pdev& pdev, xrt_core::hwctx_handle::slot_id ctx_id,
    size_t size, uint64_t flags, int type);

  // Only for AMDXDNA_BO_CMD type
  std::map<size_t, uint32_t> m_args_map;
  mutable std::mutex m_args_map_lock;
};

} // namespace shim_xdna

#endif // _BO_KMQ_H_

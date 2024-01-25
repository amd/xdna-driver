// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2023-2024, Advanced Micro Devices, Inc. All rights reserved.

#ifndef _FENCE_XDNA_H_
#define _FENCE_XDNA_H_

#include "shim_debug.h"
#include "core/common/shim/fence_handle.h"

namespace shim_xdna {

class fence : public xrt_core::fence_handle
{
public:
  ~fence();

  // TODO
  std::unique_ptr<xrt_core::fence_handle>
  clone() const override
  { shim_not_supported_err(__func__); }

  // TODO
  std::unique_ptr<xrt_core::shared_handle>
  share() const override
  { shim_not_supported_err(__func__); }

  // TODO
  void
  wait(uint32_t timeout_ms) const override
  { shim_not_supported_err(__func__); }

  // TODO
  uint64_t
  get_next_state() const override
  { shim_not_supported_err(__func__); }

};

} // shim_xdna

#endif // _FENCE_XDNA_H_

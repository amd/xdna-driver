// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2025 Advanced Micro Devices, Inc. All rights

#ifndef DEV_XDNA_H
#define DEV_XDNA_H

#include "core/edge/user/dev.h"

namespace shim_xdna_edge {

class dev_xdna : public xrt_core::edge::dev
{
public:
  std::shared_ptr<xrt_core::device>
  create_device(xrt_core::device::handle_type handle, xrt_core::device::id_type id) const override;

  virtual xrt_core::device::handle_type
  create_shim(xrt_core::device::id_type id) const override;
};

} //namespace shim_xdna_edge

#endif
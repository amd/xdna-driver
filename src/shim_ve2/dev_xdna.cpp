// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2025 Advanced Micro Devices, Inc. All rights

#include "dev_xdna.h"
#include "xdna_device.h"

namespace shim_xdna_edge {

xrt_core::device::handle_type
dev_xdna::
create_shim(xrt_core::device::id_type id) const
{
  auto handle = new shim_xdna_edge::shim(id);
  return static_cast<xrt_core::device::handle_type>(handle);
}

std::shared_ptr<xrt_core::device>
dev_xdna::
create_device(xrt_core::device::handle_type handle, xrt_core::device::id_type id) const
{
  // deliberately not using std::make_shared (used with weak_ptr)
  return std::shared_ptr<device_xdna>(new device_xdna(handle, id));
}

}
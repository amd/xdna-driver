// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2025, Advanced Micro Devices, Inc. All rights reserved.

#include "bo.h"
#include "device.h"

namespace shim_xdna {

device_virtio::
device_virtio(const pdev& pdev, handle_type shim_handle, id_type device_id)
: device(pdev, shim_handle, device_id)
{
  shim_debug("Created VIRTIO device (%s)", get_pdev().m_sysfs_name.c_str());
}

device_virtio::
~device_virtio()
{
  shim_debug("Destroying VIRTIO device (%s)", get_pdev().m_sysfs_name.c_str());
}

std::unique_ptr<xrt_core::hwctx_handle>
device_virtio::
create_hw_context(const device& dev, const xrt::xclbin& xclbin, const xrt::hw_context::qos_type& qos) const
{
  shim_not_supported_err(__func__);
}

std::unique_ptr<xrt_core::buffer_handle>
device_virtio::
alloc_bo(void* userptr, xrt_core::hwctx_handle::slot_id ctx_id,
  size_t size, uint64_t flags)
{
  // Sanity check
  auto f = xcl_bo_flags{flags};
  if (f.boflags == 0)
    shim_not_supported_err("unsupported buffer type: none flag");
  if (userptr)
    shim_not_supported_err("User ptr BO");

  return std::make_unique<bo_virtio>(get_pdev(), ctx_id, size, flags);
}

std::unique_ptr<xrt_core::buffer_handle>
device_virtio::
import_bo(xrt_core::shared_handle::export_handle ehdl) const
{
  shim_not_supported_err(__func__);
}

} // namespace shim_xdna

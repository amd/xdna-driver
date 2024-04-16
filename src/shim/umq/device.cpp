// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2023-2024, Advanced Micro Devices, Inc. All rights reserved.

#include "bo.h"
#include "device.h"
#include "hwctx.h"

namespace shim_xdna {

device_umq::
device_umq(const pdev& pdev, handle_type shim_handle, id_type device_id)
: device(pdev, shim_handle, device_id)
{
  shim_debug("Created UMQ device (%s) ...", get_pdev().m_sysfs_name.c_str());
}

device_umq::
~device_umq()
{
  shim_debug("Destroying UMQ device (%s) ...", get_pdev().m_sysfs_name.c_str());
}

std::unique_ptr<xrt_core::hwctx_handle>
device_umq::
create_hw_context(const device& dev, const xrt::xclbin& xclbin, const xrt::hw_context::qos_type& qos) const
{
  return std::make_unique<hw_ctx_umq>(dev, xclbin, qos);
}

std::unique_ptr<xrt_core::buffer_handle>
device_umq::
alloc_bo(void* userptr, xrt_core::hwctx_handle::slot_id ctx_id,
  size_t size, uint64_t flags)
{
  if (userptr)
    shim_not_supported_err("User ptr BO");;

  return std::make_unique<bo_umq>(*this, ctx_id, size, flags);
}

} // namespace shim_xdna

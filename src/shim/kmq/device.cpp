// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2023-2024, Advanced Micro Devices, Inc. All rights reserved.

#include "bo.h"
#include "device.h"
#include "hwctx.h"
#include "drm_local/amdxdna_accel.h"

namespace {

// Device memory heap needs to be within one 64MB page. The maximum size is 48MB.
const size_t dev_mem_size = (48 << 20);

}

namespace shim_xdna {

device_kmq::
device_kmq(const pdev& pdev, handle_type shim_handle, id_type device_id)
: device(pdev, shim_handle, device_id)
{
  // Alloc and register device memory w/ driver.
  m_dev_heap_bo = std::make_unique<bo_kmq>(*this, dev_mem_size, AMDXDNA_BO_DEV_HEAP);
  shim_debug("Created KMQ device (%s) ...", get_pdev().m_sysfs_name.c_str());
}

device_kmq::
~device_kmq()
{
  shim_debug("Destroying KMQ device (%s) ...", get_pdev().m_sysfs_name.c_str());
}

std::unique_ptr<xrt_core::hwctx_handle>
device_kmq::
create_hw_context(const device& dev, const xrt::xclbin& xclbin, const xrt::hw_context::qos_type& qos) const
{
  return std::make_unique<hw_ctx_kmq>(dev, xclbin, qos);
}

std::unique_ptr<xrt_core::buffer_handle>
device_kmq::
alloc_bo(void* userptr, xrt_core::hwctx_handle::slot_id ctx_id,
  size_t size, uint64_t flags)
{
  if (userptr)
    shim_not_supported_err("User ptr BO");;

  // TODO:
  // For now, debug BO is just a normal device BO. Let's associate all device
  // BO with a HW CTX since we can't tell if they are a debug BO or not.
  auto f = xcl_bo_flags{flags};
  if ((ctx_id == AMDXDNA_INVALID_CTX_HANDLE) && !!(f.flags & XRT_BO_FLAGS_CACHEABLE))
    ctx_id = f.slot;
  return std::make_unique<bo_kmq>(*this, ctx_id, size, flags);
}

std::unique_ptr<xrt_core::buffer_handle>
device_kmq::
import_bo(xrt_core::shared_handle::export_handle ehdl) const
{
  return std::make_unique<bo_kmq>(*this, ehdl);
}

} // namespace shim_xdna

// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2023-2024, Advanced Micro Devices, Inc. All rights reserved.

#include "bo.h"
#include "device.h"
#include "hwctx.h"
#include "drm_local/amdxdna_accel.h"

namespace {

// Device memory on NPU needs to be within one 64MB page. The maximum size is 48MB.
const size_t dev_mem_size = (48 << 20);

}

namespace shim_xdna {

device_npu::
device_npu(const pdev& pdev, handle_type shim_handle, id_type device_id)
: device(pdev, shim_handle, device_id)
{
  // Alloc and register device memory w/ driver.
  m_dev_heap_bo = std::make_unique<bo_npu>(*this, dev_mem_size, AMDXDNA_BO_DEV_HEAP);
  shim_debug("Created NPU device (%s) ...", get_pdev().m_sysfs_name.c_str());
}

device_npu::
~device_npu()
{
  shim_debug("Destroying NPU device (%s) ...", get_pdev().m_sysfs_name.c_str());
}

std::unique_ptr<xrt_core::hwctx_handle>
device_npu::
create_hw_context(const device& dev, const xrt::xclbin& xclbin, const xrt::hw_context::qos_type& qos) const
{
  return std::make_unique<hw_ctx_npu>(dev, xclbin, qos);
}

std::unique_ptr<xrt_core::buffer_handle>
device_npu::
alloc_bo(void* userptr, xrt_core::hwctx_handle::slot_id ctx_id,
  size_t size, uint64_t flags)
{
  if (userptr)
    shim_not_supported_err("User ptr BO");;
  return std::make_unique<bo_npu>(*this, ctx_id, size, flags);
}

} // namespace shim_xdna

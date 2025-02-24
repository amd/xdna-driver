// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2023-2024, Advanced Micro Devices, Inc. All rights reserved.

#include "bo.h"
#include "device.h"
#include "hwctx.h"
#include "drm_local/amdxdna_accel.h"

namespace shim_xdna {

device_kmq::
device_kmq(const pdev& pdev, handle_type shim_handle, id_type device_id)
: device(pdev, shim_handle, device_id)
{
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
  // Sanity check
  auto f = xcl_bo_flags{flags};
  if (f.boflags == 0)
    shim_not_supported_err("unsupported buffer type: none flag");
  if (userptr)
    shim_not_supported_err("User ptr BO");

  return std::make_unique<bo_kmq>(get_pdev(), ctx_id, size, flags);
}

std::unique_ptr<xrt_core::buffer_handle>
device_kmq::
import_bo(xrt_core::shared_handle::export_handle ehdl) const
{
  return std::make_unique<bo_kmq>(get_pdev(), ehdl);
}

std::vector<char>
device::
read_aie_mem(uint16_t col, uint16_t row, uint32_t offset, uint32_t size)
{
  amdxdna_drm_aie_mem mem;
  std::vector<char> store_buf(size);

  mem.col = col;
  mem.row = row;
  mem.addr = offset;
  mem.size = size;
  mem.buf_p = reinterpret_cast<uintptr_t>(store_buf.data());

  amdxdna_drm_get_info arg = {
    .param = DRM_AMDXDNA_READ_AIE_MEM,
    .buffer_size = sizeof(mem),
    .buffer = reinterpret_cast<uintptr_t>(&mem)
  };

  m_pdev.ioctl(DRM_IOCTL_AMDXDNA_GET_INFO, &arg);

  return store_buf;
}

uint32_t
device::
read_aie_reg(uint16_t col, uint16_t row, uint32_t reg_addr)
{
  amdxdna_drm_aie_reg reg;

  reg.col = col;
  reg.row = row;
  reg.addr = reg_addr;
  reg.val = 0;

  amdxdna_drm_get_info arg = {
    .param = DRM_AMDXDNA_READ_AIE_REG,
    .buffer_size = sizeof(reg),
    .buffer = reinterpret_cast<uintptr_t>(&reg)
  };

  m_pdev.ioctl(DRM_IOCTL_AMDXDNA_GET_INFO, &arg);

  return reg.val;
}

size_t
device::
write_aie_mem(uint16_t col, uint16_t row, uint32_t offset, const std::vector<char>& buf)
{
  amdxdna_drm_aie_mem mem;
  uint32_t size = static_cast<uint32_t>(buf.size());

  mem.col = col;
  mem.row = row;
  mem.addr = offset;
  mem.size = size;
  mem.buf_p = reinterpret_cast<uintptr_t>(buf.data());

  amdxdna_drm_get_info arg = {
    .param = DRM_AMDXDNA_WRITE_AIE_MEM,
    .buffer_size = sizeof(mem),
    .buffer = reinterpret_cast<uintptr_t>(&mem)
  };

  m_pdev.ioctl(DRM_IOCTL_AMDXDNA_SET_STATE, &arg);

  return size;
}

bool
device::
write_aie_reg(uint16_t col, uint16_t row, uint32_t reg_addr, uint32_t reg_val)
{
  amdxdna_drm_aie_reg reg;

  reg.col = col;
  reg.row = row;
  reg.addr = reg_addr;
  reg.val = reg_val;

  amdxdna_drm_get_info arg = {
    .param = DRM_AMDXDNA_WRITE_AIE_REG,
    .buffer_size = sizeof(reg),
    .buffer = reinterpret_cast<uintptr_t>(&reg)
  };

  m_pdev.ioctl(DRM_IOCTL_AMDXDNA_SET_STATE, &arg);

  return true;
}

} // namespace shim_xdna

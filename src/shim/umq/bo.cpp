// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2023-2024, Advanced Micro Devices, Inc. All rights reserved.

#include "bo.h"

namespace {

amdxdna_bo_type
umq_flags_to_type(uint64_t bo_flags)
{
  auto flags = xcl_bo_flags{bo_flags};
  auto boflags = (static_cast<uint32_t>(flags.boflags) << 24);
  switch (boflags) {
  case XCL_BO_FLAGS_NONE:
  case XCL_BO_FLAGS_HOST_ONLY:
    return AMDXDNA_BO_SHMEM;
  case XCL_BO_FLAGS_CACHEABLE:
  case XCL_BO_FLAGS_EXECBUF:
    return AMDXDNA_BO_CMD;
  default:
    break;
  }
  return AMDXDNA_BO_INVALID;
}

}

namespace shim_xdna {

bo_umq::
bo_umq(const device& device, xrt_core::hwctx_handle::slot_id ctx_id,
  size_t size, uint64_t flags)
  : bo_umq(device, ctx_id, size, flags, umq_flags_to_type(flags))
{
  if (m_type == AMDXDNA_BO_INVALID)
    shim_err(EINVAL, "Invalid BO flags: 0x%lx", flags);
}

bo_umq::
bo_umq(const device& device, xrt_core::hwctx_handle::slot_id ctx_id,
  size_t size, uint64_t flags, amdxdna_bo_type type)
  : bo(device, ctx_id, size, flags, type)
{
  switch (m_type) {
  case AMDXDNA_BO_SHMEM:
    alloc_bo();
    m_buf = map(bo::map_type::write);
    break;
  case AMDXDNA_BO_CMD:
    alloc_buf();
    alloc_bo();
    break;
  case AMDXDNA_BO_DEV:
  case AMDXDNA_BO_DEV_HEAP:
    shim_err(EINVAL, "Unsupported BO type: %d", type);
    break;
  default:
    shim_err(EINVAL, "Invalid BO type: %d", type);
    break;
  }

  shim_debug("Allocated UMQ BO for: userptr=0x%lx, size=%ld, flags=0x%llx",
    m_buf, m_size, m_flags);
}

bo_umq::
bo_umq(const device& device, xrt_core::shared_handle::export_handle ehdl)
  : bo(device, ehdl)
{
    alloc_bo();
    m_buf = map(bo::map_type::write);
}

bo_umq::
~bo_umq()
{
  shim_debug("Freeing UMQ BO, %s", describe().c_str());

  // If BO is in use, we should block and wait in driver
  free_bo();

  switch (m_type) {
  case AMDXDNA_BO_SHMEM:
    unmap(m_buf);
    break;
  default:
    break;
  }
}

void
bo_umq::
sync(bo_umq::direction dir, size_t size, size_t offset)
{
  // No-op
}

void
bo_umq::
bind_at(size_t pos, const buffer_handle* bh, size_t offset, size_t size)
{
  // No-op
}

} // namespace shim_xdna

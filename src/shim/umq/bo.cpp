// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2023-2025, Advanced Micro Devices, Inc. All rights reserved.

#include "bo.h"

namespace {

int
umq_flags_to_type(uint64_t bo_flags)
{
  auto flags = xcl_bo_flags{bo_flags};
  auto boflags = (static_cast<uint32_t>(flags.boflags) << 24);

  /*
   * boflags scope:
   * HOST_ONLY: any input, output buffers, can be large size
   * CACHEABLE: control code buffer, can be large size too
   *            on cache coherent systems, no need to sync.
   * EXECBUF: small size buffer that can be accessed by both
   *          userland(map), kernel(kva) and device(dev_addr).
   */
  switch (boflags) {
  case XCL_BO_FLAGS_NONE:
  case XCL_BO_FLAGS_HOST_ONLY:
  case XCL_BO_FLAGS_CACHEABLE:
    return AMDXDNA_BO_SHARE;
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
bo_umq(const pdev& pdev, xrt_core::hwctx_handle::slot_id ctx_id,
  size_t size, uint64_t flags)
  : bo_umq(pdev, ctx_id, size, flags, umq_flags_to_type(flags))
{
  if (m_type == AMDXDNA_BO_INVALID)
    shim_err(EINVAL, "Invalid BO flags: 0x%lx", flags);
}

bo_umq::
bo_umq(const pdev& pdev, xrt_core::hwctx_handle::slot_id ctx_id,
  size_t size, uint64_t flags, int type)
  : bo(pdev, ctx_id, size, flags, type)
{
  alloc_bo();
  mmap_bo();
  /*TODO: no need if cache coherent */
  sync(direction::host2device, size, 0);

  shim_debug("Allocated UMQ BO, %s", describe().c_str());
}

bo_umq::
bo_umq(const pdev& pdev, xrt_core::shared_handle::export_handle ehdl)
  : bo(pdev, ehdl)
{
    alloc_bo();
    mmap_bo();
}

bo_umq::
~bo_umq()
{
  shim_debug("Freeing UMQ BO, %s", describe().c_str());

  munmap_bo();
  // If BO is in use, we should block and wait in driver
  free_bo();
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

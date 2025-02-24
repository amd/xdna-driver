// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2025, Advanced Micro Devices, Inc. All rights reserved.

#include "bo.h"
#include "drm_local/amdxdna_accel.h"
#include <drm/virtgpu_drm.h>

namespace {

int
flag_to_type(uint64_t bo_flags)
{
  auto flags = xcl_bo_flags{bo_flags};
  auto boflags = (static_cast<uint32_t>(flags.boflags) << 24);
  switch (boflags) {
  case XCL_BO_FLAGS_HOST_ONLY:
    return AMDXDNA_BO_SHARE;
  case XCL_BO_FLAGS_CACHEABLE:
    return AMDXDNA_BO_DEV;
  case XCL_BO_FLAGS_EXECBUF:
    return AMDXDNA_BO_CMD;
  default:
    break;
  }
  return AMDXDNA_BO_INVALID;
}

// flash cache line for non coherence memory
inline void
clflush_data(const void *base, size_t offset, size_t len)
{
  static long cacheline_size = 0;

  if (!cacheline_size) {
    long sz = sysconf(_SC_LEVEL1_DCACHE_LINESIZE);
    if (sz <= 0)
      shim_err(EINVAL, "Invalid cache line size: %ld", sz);
    cacheline_size = sz;
  }

  const char *cur = (const char *)base;
  cur += offset;
  uintptr_t lastline = (uintptr_t)(cur + len - 1) | (cacheline_size - 1);
  do {
    shim_xdna::flush_cache_line(cur);
    cur += cacheline_size;
  } while (cur <= (const char *)lastline);
}

}

namespace shim_xdna {

bo_virtio::
bo_virtio(const pdev& pdev, xrt_core::hwctx_handle::slot_id ctx_id,
  size_t size, uint64_t flags)
  : bo_virtio(pdev, ctx_id, size, flags, flag_to_type(flags))
{
  if (m_type == AMDXDNA_BO_INVALID)
    shim_err(EINVAL, "Invalid BO flags: 0x%lx", flags);
}

bo_virtio::
bo_virtio(const pdev& pdev, size_t size, int type)
  : bo_virtio(pdev, AMDXDNA_INVALID_CTX_HANDLE, size, 0, type)
{
}

bo_virtio::
bo_virtio(const pdev& pdev, xrt_core::hwctx_handle::slot_id ctx_id,
  size_t size, uint64_t flags, int type)
  : bo(pdev, ctx_id, size, flags, type)
{
  size_t align = 0;

  if (m_type == AMDXDNA_BO_DEV_HEAP)
    align = 64 * 1024 * 1024; // Device mem heap must align at 64MB boundary.

  alloc_bo();
  mmap_bo(align);

  // Newly allocated buffer may contain dirty pages. If used as output buffer,
  // the data in cacheline will be flushed onto memory and pollute the output
  // from device. We perform a cache flush right after the BO is allocated to
  // avoid this issue.
  if (m_type == AMDXDNA_BO_SHARE)
    sync(direction::host2device, size, 0);

  shim_debug("Allocated VIRTIO BO, %s", describe().c_str());
}

bo_virtio::
~bo_virtio()
{
  shim_debug("Freeing VIRTIO BO, %s", describe().c_str());

  munmap_bo();
  try {
    // If BO is in use, we should block and wait in driver
    free_bo();
  } catch (const xrt_core::system_error& e) {
    shim_debug("Failed to free BO: %s", e.what());
  }
}

void
bo_virtio::
sync(direction dir, size_t size, size_t offset)
{
  if (offset + size > m_aligned_size)
    shim_err(EINVAL, "Invalid BO offset and size for sync'ing: %ld, %ld", offset, size);
  clflush_data(m_aligned, offset, size); 
}

uint32_t
bo_virtio::
alloc_drm_bo(const shim_xdna::pdev& dev, int type, size_t size)
{
  shim_debug("Allocating VIRTIO BO");
  return 0;
}

void
bo_virtio::
get_drm_bo_info(const shim_xdna::pdev& dev, uint32_t boh, amdxdna_drm_get_bo_info* bo_info)
{
  shim_debug("Getting info of VIRTIO BO");
}

void
bo_virtio::
free_drm_bo(const shim_xdna::pdev& dev, uint32_t boh)
{
  shim_debug("Allocating VIRTIO BO");
}

} // namespace shim_xdna

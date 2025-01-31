// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2023-2025, Advanced Micro Devices, Inc. All rights reserved.

#include "bo.h"
#include "core/common/config_reader.h"

namespace {

amdxdna_bo_type
flag_to_type(uint64_t bo_flags)
{
  auto flags = xcl_bo_flags{bo_flags};
  auto boflags = (static_cast<uint32_t>(flags.boflags) << 24);
  switch (boflags) {
  case XCL_BO_FLAGS_HOST_ONLY:
    return AMDXDNA_BO_SHMEM;
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

void
sync_drm_bo(const shim_xdna::pdev& dev, uint32_t boh, xrt_core::buffer_handle::direction dir,
  size_t offset, size_t len)
{
  amdxdna_drm_sync_bo sbo = {
    .handle = boh,
    .direction = (dir == xrt_core::buffer_handle::direction::host2device ?
      SYNC_DIRECT_TO_DEVICE : SYNC_DIRECT_FROM_DEVICE),
    .offset = offset,
    .size = len,
  };
  dev.ioctl(DRM_IOCTL_AMDXDNA_SYNC_BO, &sbo);
}

bool
is_driver_sync()
{
  static int drv_sync = -1;

  if (drv_sync == -1) {
    bool ds = xrt_core::config::detail::get_bool_value("Debug.force_driver_sync", false);
    drv_sync = ds ? 1 : 0;
  }
  return drv_sync == 1;
}

}

namespace shim_xdna {

bo_kmq::
bo_kmq(const device& device, xrt_core::hwctx_handle::slot_id ctx_id,
  size_t size, uint64_t flags)
  : bo_kmq(device, ctx_id, size, flags, flag_to_type(flags))
{
  if (m_type == AMDXDNA_BO_INVALID)
    shim_err(EINVAL, "Invalid BO flags: 0x%lx", flags);
}

bo_kmq::
bo_kmq(const device& device, size_t size, amdxdna_bo_type type)
  : bo_kmq(device, AMDXDNA_INVALID_CTX_HANDLE, size, 0, type)
{
}

bo_kmq::
bo_kmq(const device& device, xrt_core::hwctx_handle::slot_id ctx_id,
  size_t size, uint64_t flags, amdxdna_bo_type type)
  : bo(device, ctx_id, size, flags, type)
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
  if (m_type == AMDXDNA_BO_SHMEM)
    sync(direction::host2device, size, 0);

  attach_to_ctx();

  shim_debug("Allocated KMQ BO (userptr=0x%lx, size=%ld, flags=0x%llx, type=%d, drm_bo=%d)",
    m_aligned, m_aligned_size, m_flags, m_type, get_drm_bo_handle());
}

bo_kmq::
bo_kmq(const device& device, xrt_core::shared_handle::export_handle ehdl)
  : bo(device, ehdl)
{
  import_bo();
  mmap_bo();
  shim_debug("Imported KMQ BO (userptr=0x%lx, size=%ld, flags=0x%llx, type=%d, drm_bo=%d)",
    m_aligned, m_aligned_size, m_flags, m_type, get_drm_bo_handle());
}

bo_kmq::
~bo_kmq()
{
  shim_debug("Freeing KMQ BO, %s", describe().c_str());

  munmap_bo();
  try {
    detach_from_ctx();
    // If BO is in use, we should block and wait in driver
    free_bo();
  } catch (const xrt_core::system_error& e) {
    shim_debug("Failed to free BO: %s", e.what());
  }
}

void
bo_kmq::
sync(direction dir, size_t size, size_t offset)
{
  if (is_driver_sync()) {
    sync_drm_bo(m_pdev, get_drm_bo_handle(), dir, offset, size);
    return;
  }

  if (offset + size > m_aligned_size)
    shim_err(EINVAL, "Invalid BO offset and size for sync'ing: %ld, %ld", offset, size);

  switch (m_type) {
  case AMDXDNA_BO_SHMEM:
  case AMDXDNA_BO_CMD:
    clflush_data(m_aligned, offset, size); 
    break;
  case AMDXDNA_BO_DEV:
    if (m_owner_ctx_id == AMDXDNA_INVALID_CTX_HANDLE)
      clflush_data(m_aligned, offset, size); 
    else
      sync_drm_bo(m_pdev, get_drm_bo_handle(), dir, offset, size);
    break;
  default:
    shim_err(ENOTSUP, "Can't sync bo type %d", m_type);
  }
}

void
bo_kmq::
bind_at(size_t pos, const buffer_handle* bh, size_t offset, size_t size)
{
  auto boh = reinterpret_cast<const bo_kmq*>(bh);
  std::lock_guard<std::mutex> lg(m_args_map_lock);

  if (m_type != AMDXDNA_BO_CMD)
    shim_err(EINVAL, "Can't call bind_at() on non-cmd BO");

  if (!pos)
    m_args_map.clear();

  if (boh->get_type() != AMDXDNA_BO_CMD) {
    auto h = boh->get_drm_bo_handle();
    m_args_map[pos] = h;
    shim_debug("Added arg BO %d to cmd BO %d", h, get_drm_bo_handle());
  } else {
    const size_t max_args_order = 6;
    const size_t max_args = 1 << max_args_order;
    size_t key = pos << max_args_order;
    uint32_t hs[max_args];
    auto arg_cnt = boh->get_arg_bo_handles(hs, max_args);
    std::string bohs;
    for (int i = 0; i < arg_cnt; i++) {
      m_args_map[key + i] = hs[i];
      bohs += std::to_string(hs[i]) + " ";
    }
    shim_debug("Added arg BO %s to cmd BO %d", bohs.c_str(), get_drm_bo_handle());
  }
}

uint32_t
bo_kmq::
get_arg_bo_handles(uint32_t *handles, size_t num) const
{
  std::lock_guard<std::mutex> lg(m_args_map_lock);

  auto sz = m_args_map.size();
  if (sz > num)
    shim_err(E2BIG, "There are %ld BO args, provided buffer can hold only %ld", sz, num);

  for (auto &m : m_args_map)
    *(handles++) = m.second;

  return sz;
}

} // namespace shim_xdna

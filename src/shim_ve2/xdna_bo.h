// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2025, Advanced Micro Devices, Inc. All rights reserved.

#ifndef XDNA_EDGE_BO_H__
#define XDNA_EDGE_BO_H__

#include <atomic>
#include <string>
#include <unistd.h>

#include "drm_local/amdxdna_accel.h"
#include "core/common/shim/buffer_handle.h"
#include "core/common/memalign.h"
#include "core/common/shim/shared_handle.h"
#include "shim_debug.h"
#include "xdna_device.h"
#include "xdna_edgedev.h"
#include "xdna_hwctx.h"

namespace shim_xdna_edge {

class shared : public xrt_core::shared_handle
{
public:
  shared(int fd) : m_fd(fd)
  {}

  ~shared() override
  {
    if (m_fd != -1)
      close(m_fd);
  }

  export_handle
  get_export_handle() const override
  { return m_fd; }

private:
  const int m_fd;
};

// DRM BO managed by driver.
class xdna_bo : public xrt_core::buffer_handle {
public:
  void*
  map(map_type) override;

  void
  unmap(void* addr) override;

  void
  sync(direction, size_t size, size_t offset) override;

  properties
  get_properties() const override;

  std::unique_ptr<xrt_core::shared_handle>
  share() const override;

  void
  copy(const xrt_core::buffer_handle* src, size_t size, size_t dst_offset, size_t src_offset) override
  { shim_not_supported_err(__func__); }

  int
  export_drm_bo(uint32_t boh) const;
  
  uint32_t
  import_drm_bo(const shim_xdna_edge::shared&, uint32_t*, size_t*) const;
public:
  xdna_bo(const device_xdna& device, xrt_core::hwctx_handle::slot_id ctx_id,
     size_t size, uint64_t flags, uint32_t type);

  xdna_bo(const device_xdna& device, xrt_core::shared_handle::export_handle ehdl);

  ~xdna_bo();

  std::string
  describe() const;

  // Alloc BO from driver
  void
  alloc_bo();

  // Sync the BO
  void
  sync_bo(direction dir, size_t size, size_t offset);

  // Import DRM BO from m_import shared object
  void
  import_bo();

  void
  bind_at(size_t pos, const xrt_core::buffer_handle* bh, size_t offset, size_t size) override;

  // Free DRM BO in driver
  void
  free_bo();

  void
  mmap_bo(bool is_write);

  void
  munmap_bo();

  uint64_t
  get_paddr() const;

  uint32_t
  get_drm_bo_handle() const;

  std::string
  type_to_name() const;

  void
  attach_to_ctx(uint32_t flag);

  void
  detach_from_ctx(uint32_t flag);

  void
  config(xrt_core::hwctx_handle* ctx, const std::map<uint32_t, size_t>& buf_sizes) override;

  void
  get_drm_bo_info(uint32_t boh);

  uint32_t
  get_type() const;

  // For cmd BO only
  void
  set_cmd_id(uint64_t id);

  // For cmd BO only
  uint64_t
  get_cmd_id() const;

  const xrt_core::device *m_core_device;
  std::shared_ptr<xdna_edgedev> m_edev;
  void* m_ptr = nullptr;
  size_t m_aligned_size = 0;
  uint64_t m_flags = 0;
  uint32_t m_type = AMDXDNA_BO_INVALID;
  uint32_t m_handle = AMDXDNA_INVALID_BO_HANDLE;
  off_t m_map_offset = AMDXDNA_INVALID_ADDR;
  uint64_t m_xdna_addr = AMDXDNA_INVALID_ADDR;
  uint64_t m_vaddr = AMDXDNA_INVALID_ADDR;

  const shared m_import;

  // Command ID in the queue after command submission.
  // Only valid for cmd BO.
  uint64_t m_cmd_id = -1;

  // Used when exclusively assigned to a HW context. By default, BO is shared
  // among all HW contexts.
  xrt_core::hwctx_handle::slot_id m_owner_ctx_id = AMDXDNA_INVALID_CTX_HANDLE;

  // Only for AMDXDNA_BO_CMD type
  uint32_t
  get_arg_bo_handles(uint32_t *handles, size_t num) const;

  std::map<size_t, uint32_t> m_args_map;
  mutable std::mutex m_args_map_lock;

};

} // namespace shim_xdna_edge

#endif // __XDNA_EDGE_BO_H__

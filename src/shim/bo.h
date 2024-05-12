// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2022-2024, Advanced Micro Devices, Inc. All rights reserved.

#ifndef _BO_XDNA_H_
#define _BO_XDNA_H_

#include "device.h"
#include "hwctx.h"
#include "pcidev.h"

#include "shared.h"
#include "shim_debug.h"

#include "core/common/memalign.h"
#include "core/common/shim/buffer_handle.h"
#include "drm_local/amdxdna_accel.h"
#include <string>
#include <atomic>

namespace shim_xdna {

class bo : public xrt_core::buffer_handle
{
public:
  bo(const device& device, xrt_core::hwctx_handle::slot_id ctx_id,
    size_t size, uint64_t flags, amdxdna_bo_type type);

  bo(const device& device, xrt_core::shared_handle::export_handle ehdl);

  ~bo();

  void*
  map(map_type) override;

  void
  unmap(void* addr) override;

  void
  sync(direction, size_t size, size_t offset) override = 0;

  properties
  get_properties() const override;

  std::unique_ptr<xrt_core::shared_handle>
  share() const override;

  void
  copy(const buffer_handle* src, size_t size, size_t dst_offset, size_t src_offset) override
  { shim_not_supported_err(__func__); }

public:
  // For cmd BO only
  void
  set_cmd_id(uint64_t id);
  // For cmd BO only
  uint64_t
  get_cmd_id() const;

  uint32_t
  get_drm_bo_handle() const;

protected:
  
  // DRM BO managed by driver.
  class drm_bo {
  public:
    bo& m_parent;
    uint32_t m_handle = AMDXDNA_INVALID_BO_HANDLE;
    off_t m_map_offset = AMDXDNA_INVALID_ADDR;
    uint64_t m_xdna_addr = AMDXDNA_INVALID_ADDR;
    uint64_t m_vaddr = AMDXDNA_INVALID_ADDR;

    drm_bo(bo& parent, const amdxdna_drm_get_bo_info& bo_info);
    ~drm_bo();
  };

  std::string
  describe() const;

  // Alloc DRM BO from driver
  void
  alloc_bo();

  // Import DRM BO from m_imported_bo_fd
  void
  import_bo();

  // Free DRM BO in driver
  void
  free_bo();

  void
  alloc_buf(size_t align = 0);

  uint64_t
  get_paddr() const;

  std::string
  type_to_name() const;

  void
  attach_to_ctx();

  void
  detach_from_ctx();

  const pdev& m_pdev;
  void* m_buf = nullptr;
  std::atomic<int> m_mmap_cnt = 0;
  size_t m_size = 0;
  uint64_t m_flags = 0;
  amdxdna_bo_type m_type = AMDXDNA_BO_INVALID;
  xrt_core::aligned_ptr_type m_private_buf{};
  std::unique_ptr<drm_bo> m_bo;
  const shared m_import;

  // Command ID in the queue after command submission.
  // Only valid for cmd BO.
  uint64_t m_cmd_id = -1;

  // Used when exclusively assigned to a HW context. By default, BO is shared
  // among all HW contexts.
  xrt_core::hwctx_handle::slot_id m_owner_ctx_id = AMDXDNA_INVALID_CTX_HANDLE;
};

} // namespace shim_xdna

#endif

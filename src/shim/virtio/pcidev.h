// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2025, Advanced Micro Devices, Inc. All rights reserved.

#ifndef PCIDEV_VIRTIO_H
#define PCIDEV_VIRTIO_H

#include "../pcidrv_virtio.h"
#include "../pcidev.h"
#include "drm_local/amdxdna_accel.h"

#include <atomic>

namespace shim_xdna {

class pdev_virtio : public pdev
{
public:
  pdev_virtio(std::shared_ptr<const drv_virtio> driver, std::string sysfs_name);
  ~pdev_virtio();
 
  std::shared_ptr<xrt_core::device>
  create_device(xrt_core::device::handle_type handle, xrt_core::device::id_type id) const override;

public:
  void
  host_call(void *in_buf, size_t in_size, void *out_buf, size_t out_size) const;

  uint32_t
  get_unique_id() const;

  uint64_t
  get_dev_bo_vaddr(uint64_t dev_bo_xdna_addr) const;

private:
  // Below are init'ed on first device open and removed right before device is closed
  mutable uint32_t m_resp_buf_bo_hdl = AMDXDNA_INVALID_BO_HANDLE;
  mutable uint32_t m_resp_buf_res_hdl = AMDXDNA_INVALID_BO_HANDLE;
  mutable void *m_resp_buf = nullptr;
  mutable std::unique_ptr<xrt_core::buffer_handle> m_dev_heap_bo;

  // Ever incrementing to provide generic per device unique ID. May wrap around in
  // theory, should not happen in practice.
  // Can be used for BO's blob ID.
  mutable std::atomic<std::uint32_t> m_id = 0;

  // Serialize host call
  mutable std::mutex m_lock;

  virtual void
  on_first_open() const override;

  virtual void
  on_last_close() const override;
};

} // namespace shim_xdna

#endif

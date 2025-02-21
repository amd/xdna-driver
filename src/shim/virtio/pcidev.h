// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2025, Advanced Micro Devices, Inc. All rights reserved.

#ifndef PCIDEV_VIRTIO_H
#define PCIDEV_VIRTIO_H

#include "../pcidrv_virtio.h"
#include "../pcidev.h"
#include <drm/virtgpu_drm.h>

namespace shim_xdna {

class pdev_virtio : public pdev
{
public:
  pdev_virtio(std::shared_ptr<const drv_virtio> driver, std::string sysfs_name);
  ~pdev_virtio();
 
  std::shared_ptr<xrt_core::device>
  create_device(xrt_core::device::handle_type handle, xrt_core::device::id_type id) const override;

private:
  // Below are init'ed on first device open and removed right before device is closed
  mutable uint32_t m_shmem_bo_hdl;
  mutable struct vdrm_shmem *m_shmem;

  virtual void
  on_first_open() const override;

  virtual void
  on_last_close() const override;
};

} // namespace shim_xdna

#endif

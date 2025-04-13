// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2022-2025, Advanced Micro Devices, Inc. All rights reserved.

#ifndef PCIDRV_XDNA_H_
#define PCIDRV_XDNA_H_

#include "drm_local/amdxdna_accel.h"
#include "core/pcie/linux/pcidrv.h"

namespace shim_xdna {

enum class drv_ioctl_cmd {
};

class drv : public xrt_core::pci::drv
{
public:
  bool
  is_user() const override;

public:
  virtual void
  drv_ioctl(int dev_fd, drv_ioctl_cmd cmd, void* arg) const = 0;

private:
  // Set once and never change
  mutable int m_device_type = AMDXDNA_DEV_TYPE_UNKNOWN;

  std::shared_ptr<xrt_core::pci::dev>
  create_pcidev(const std::string& sysfs) const override;

  virtual int
  get_dev_type(const std::string& sysfs) const = 0;
};

}

#endif

// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2022-2025, Advanced Micro Devices, Inc. All rights reserved.

#ifndef PCIDRV_XDNA_H
#define PCIDRV_XDNA_H

#include "drm_local/amdxdna_accel.h"
#include "core/pcie/linux/pcidrv.h"
#include <set>
#include <string>

namespace shim_xdna {

// Resolve a device's sysfs directory from the name the scan hands us: a PCI
// device's name is a BDF and lives under /sys/bus/pci/devices/, while a
// platform/rpmsg device's name is already an absolute canonical sysfs path.
inline std::string
dev_sysfs_root(const std::string& sysfs_name)
{
  if (!sysfs_name.empty() && sysfs_name.front() == '/')
    return sysfs_name;
  return "/sys/bus/pci/devices/" + sysfs_name;
}

class drv : public xrt_core::pci::drv
{
public:
  //using xrt_core::pci::drv::drv;

  bool
  is_user() const override;

  std::string
  get_dev_node(const std::string& sysfs_name) const;
};

}

#endif

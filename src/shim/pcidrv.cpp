// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2022-2025, Advanced Micro Devices, Inc. All rights reserved.

#include "pcidrv.h"
#include <sys/types.h>
#include <dirent.h>

namespace shim_xdna {

bool
drv::
is_user() const
{
  return true;
}

std::string
drv::
get_dev_node(const std::string& sysfs_name) const
{
  // For non-PCI devices, the sysfs_name starts with '/' and the
  // corresponding accel dev node can be found under /sys/class/accel/.
  const std::string sysfs_root = (sysfs_name.front() == '/')
    ? sysfs_name + "/"
    : std::string("/sys/bus/pci/devices/") + sysfs_name + "/";

  const std::string dev_path_dir = sysfs_root + sysfs_dev_node_dir();
  const auto prefix = dev_node_prefix();

  auto dp = opendir(dev_path_dir.c_str());
  if (dp) {
    std::string valid;
    while (auto entry = readdir(dp)) {
      std::string dirname{entry->d_name};
      if(dirname.compare(0, prefix.size(), prefix) == 0) {
        valid = std::move(dirname);
        break;
      }
    }
    closedir(dp);
    if (!valid.empty())
      return std::string("/dev/") + dev_node_dir() + "/" + valid;
  }
  throw std::invalid_argument(std::string("Bad sysfs name: ") + sysfs_name.c_str());
}

}

// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2025, Advanced Micro Devices, Inc. All rights reserved.

#include "shim_debug.h"
#include "pcidrv_amdxdna.h"
#include "core/pcie/linux/system_linux.h"
#include <fstream>

namespace {

struct X
{
  X() { xrt_core::pci::register_driver(std::make_shared<shim_xdna::drv_amdxdna>()); }
} x;

}

namespace shim_xdna {

std::string
drv_amdxdna::
name() const
{
  return "amdxdna";
}

std::string
drv_amdxdna::
dev_node_prefix() const
{
  return "accel";
}

std::string
drv_amdxdna::
dev_node_dir() const
{
  return "accel";
}

std::string
drv_amdxdna::
sysfs_dev_node_dir() const
{
  return "accel";
}

void
drv_amdxdna::
drv_ioctl(int dev_fd, drv_ioctl_cmd cmd, void* cmd_arg) const
{
  switch (cmd) {
  default:
    shim_err(EINVAL, "Unknown drv_ioctl: %d", cmd);
    break;
  }
}

int
drv_amdxdna::
get_dev_type(const std::string& sysfs) const
{
  const std::string sysfs_root{"/sys/bus/pci/devices/"};
  const std::string dev_type_path = sysfs_root + sysfs + "/device_type";

  std::ifstream ifs(dev_type_path);
  if (!ifs.is_open())
    throw std::invalid_argument(dev_type_path + " is missing?");

  std::string line;
  std::getline(ifs, line);
  return static_cast<int>(std::stoi(line));
}

}

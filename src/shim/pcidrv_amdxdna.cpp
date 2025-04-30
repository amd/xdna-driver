// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2025, Advanced Micro Devices, Inc. All rights reserved.

#include "shim_debug.h"
#include "kmq/pcidev.h"
#include "umq/pcidev.h"
#include "platform_host.h"
#include "pcidrv_amdxdna.h"
#include "core/pcie/linux/system_linux.h"
#include <fstream>

namespace {

struct X
{
  X() { xrt_core::pci::register_driver(std::make_shared<shim_xdna::drv_amdxdna>()); }
} x;

int
get_dev_type(const std::string& sysfs)
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

std::shared_ptr<xrt_core::pci::dev>
drv_amdxdna::
create_pcidev(const std::string& sysfs) const
{
  static int device_type = AMDXDNA_DEV_TYPE_UNKNOWN;
  auto driver = std::dynamic_pointer_cast<const drv>(shared_from_this());
  auto platform_driver = std::dynamic_pointer_cast<const platform_drv>(
    std::make_shared<const platform_drv_host>(driver));

  if (device_type == AMDXDNA_DEV_TYPE_UNKNOWN)
    device_type = get_dev_type(sysfs);

  if (device_type == AMDXDNA_DEV_TYPE_KMQ)
    return std::make_shared<pdev_kmq>(platform_driver, sysfs);
  if (device_type == AMDXDNA_DEV_TYPE_UMQ)
    return std::make_shared<pdev_umq>(platform_driver, sysfs);
  shim_err(EINVAL, "Unknown device type: %d", device_type);
}

}

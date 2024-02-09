// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2022-2024, Advanced Micro Devices, Inc. All rights reserved.
//
#include "npu/pcidev.h"
#include "drm_local/amdxdna_accel.h"
#include "pcidev.h"
#include "pcidrv.h"
#include "core/pcie/linux/system_linux.h"
#include <fstream>

namespace {

struct X
{
  X() { xrt_core::pci::register_driver(std::make_shared<shim_xdna::drv>()); }
} x;

amdxdna_device_type
get_dev_type(const std::string& sysfs)
{
  const std::string sysfs_root{"/sys/bus/pci/devices/"};
  const std::string dev_type_path = sysfs_root + sysfs + "/device_type";

  std::ifstream ifs(dev_type_path);
  if (!ifs.is_open())
    throw std::invalid_argument(dev_type_path + " is missing?");

  std::string line;
  std::getline(ifs, line);
  return static_cast<amdxdna_device_type>(std::stoi(line));
}

}

namespace shim_xdna {

std::string
drv::
name() const
{
  return "amdxdna";
}

std::string
drv::
dev_node_prefix() const
{
  return "accel";
}

std::string
drv::
dev_node_dir() const
{
  return "accel";
}

std::string
drv::
sysfs_dev_node_dir() const
{
  return "accel";
}

bool
drv::
is_user() const
{
  return true;
}

std::shared_ptr<xrt_core::pci::dev>
drv::
create_pcidev(const std::string& sysfs) const
{
  auto t = get_dev_type(sysfs);
  auto driver = std::static_pointer_cast<const drv>(shared_from_this());
  if (t == AMDXDNA_DEV_TYPE_NPU)
    return std::make_shared<pdev_npu>(driver, sysfs);
  shim_err(-EINVAL, "Unknown device type: %d", t);
}

} // namespace shim_xdna


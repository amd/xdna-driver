// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2025-2026, Advanced Micro Devices, Inc. All rights reserved.

#include "../shim_debug.h"
#include "../kmq/pcidev.h"
#include "../umq/pcidev.h"
#include "platform_host.h"
#include "pcidrv_amdxdna.h"
#include "core/pcie/linux/system_linux.h"
#include <filesystem>
#include <fstream>

namespace {

struct X
{
  X() { xrt_core::pci::register_driver(std::make_shared<shim_xdna::drv_amdxdna>()); }
} x;

// scan_devices() in pcidrv.cpp uses fname.find(':') to distinguish PCI
// BDFs from platform/rpmsg sysfs paths.  DT-style platform names like
// "axi:amdxdna-shmem" contain ':' and are misclassified as BDFs,
// causing the short basename to be passed instead of the canonical
// /sys/devices/... path.  Resolve here so all downstream sysfs lookups
// (device_type, accel instance, pci::dev path helpers) work correctly.
// PCI BDFs won't match /sys/bus/platform/devices/ and pass through.
std::string
resolve_sysfs(const std::string& sysfs)
{
  if (!sysfs.empty() && sysfs.front() == '/')
    return sysfs;

  namespace sfs = std::filesystem;
  auto platform_path = sfs::path("/sys/bus/platform/devices") / sysfs;
  if (sfs::exists(platform_path))
    return sfs::canonical(platform_path).string();

  return sysfs;
}

int
get_dev_type(const std::string& sysfs)
{
  std::string dev_type_path;
  if (!sysfs.empty() && sysfs.front() == '/') {
    // Non-PCI: device_type is created on the DRM device kobj, which lives
    // under accel/accelN/ beneath the platform device sysfs directory.
    namespace sfs = std::filesystem;
    auto accel_dir = sfs::path(sysfs) / "accel";
    if (sfs::exists(accel_dir)) {
      for (auto& entry : sfs::directory_iterator(accel_dir)) {
        auto candidate = entry.path() / "device_type";
        if (sfs::exists(candidate)) {
          dev_type_path = candidate.string();
          break;
        }
      }
    }
    if (dev_type_path.empty())
      dev_type_path = sysfs + "/device_type";
  } else {
    dev_type_path = "/sys/bus/pci/devices/" + sysfs + "/device_type";
  }

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
  auto resolved = resolve_sysfs(sysfs);

  auto driver = std::dynamic_pointer_cast<const drv>(shared_from_this());
  auto platform_driver = std::dynamic_pointer_cast<const platform_drv>(
    std::make_shared<const platform_drv_host>(driver));
  auto device_type = get_dev_type(resolved);

  if (device_type == AMDXDNA_DEV_TYPE_KMQ)
    return std::make_shared<pdev_kmq>(platform_driver, resolved);
  if (device_type == AMDXDNA_DEV_TYPE_UMQ)
    return std::make_shared<pdev_umq>(platform_driver, resolved);
  if (device_type == AMDXDNA_DEV_TYPE_PF)
    return nullptr;

  shim_err(EINVAL, "Unknown device type: %d", device_type);
}

}

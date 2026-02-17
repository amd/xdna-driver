// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2025 Advanced Micro Devices, Inc. All rights

#include <drm/drm.h>
#include <fcntl.h>
#include <filesystem>
#include <fstream>
#include <memory>
#include <regex>
#include <sys/ioctl.h>

#include "drv_xdna.h"
#include "dev_xdna.h"
#include "core/common/message.h"
#include "core/edge/user/system_linux.h"

namespace {

struct X
{
  X() { xrt_core::edge_linux::register_driver(std::make_shared<shim_xdna_edge::drv_xdna>()); }
} x;
}

namespace shim_xdna_edge {


namespace fs = std::filesystem;

void
drv_xdna::
scan_devices(std::vector<std::shared_ptr<xrt_core::edge::dev>>& dev_list)
{
  // For Ve2 accel device (amdxdna auxiliary driver) we search /sys/class/accel/accel*
  // and match by driver name: device/driver symlink points to .../drivers/amdxdna
  const std::string driver_name{"amdxdna"};
  const std::string base_path = "/sys/class/accel";
  const std::string driver_link = "/device/driver";
  const std::regex accel_regex("accel.*");
  std::string accel_dev_name;

  try 
  {
    if (!fs::exists(base_path))
    {
      throw std::runtime_error("Device search path: " + base_path + " doesn't exist\n");
    }
    for (const auto& entry : fs::directory_iterator(base_path)) 
    {
      if (fs::is_directory(entry) && std::regex_match(entry.path().filename().string(), accel_regex)) 
      {
        const std::string driver_path = entry.path().string() + driver_link;
        if (fs::exists(driver_path) && fs::is_symlink(driver_path))
        {
          std::string target = fs::read_symlink(driver_path).string();
          if (target.find(driver_name) != std::string::npos)
          {
            accel_dev_name = entry.path().filename().string();
            break;
          }
        }
      }
    }

    if (accel_dev_name.empty())
      throw std::runtime_error("Entry not found\n");

    const std::string accel_dev_sym_dir{"/dev/accel/"};
    if (fs::exists(accel_dev_sym_dir + accel_dev_name))
      dev_list.push_back(create_edev());
  }
  catch (const std::exception& e) 
  {
    std::string msg = "Error while searching for AIARM accel device: " + std::string(e.what());
    xrt_core::message::send(xrt_core::message::severity_level::info, "XRT", msg);
  }
}

std::shared_ptr<xrt_core::edge::dev>
drv_xdna::
create_edev(const std::string& sysfs) const
{
  return std::make_shared<dev_xdna>();
}

} //namespace shim_xdna_edge

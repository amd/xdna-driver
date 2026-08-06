// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2022-2025, Advanced Micro Devices, Inc. All rights reserved.

#include "pcidev.h"
#include "../shim_debug.h"
#include <algorithm>
#include <cctype>
#include <dirent.h>
#include <memory>

namespace shim_xdna {

void
pdev_umq::
on_first_open() const
{
  // do nothing
}

void
pdev_umq::
on_last_close() const
{
  // do nothing
}

bool
pdev_umq::
is_cache_coherent() const
{
  return true;
}

void *
pdev_umq::
get_heap_vaddr() const
{
  return nullptr;
}

uint64_t
pdev_umq::
get_heap_paddr() const
{
  return AMDXDNA_INVALID_ADDR;
}

bool
pdev_umq::
is_umq() const
{
  return true;
}

void
pdev_umq::
create_drm_bo(bo_info *arg) const
{
  drv_ioctl(drv_ioctl_cmd::create_bo, arg);
}

pdev_pf::
pdev_pf(std::shared_ptr<const platform_drv>& driver,
        const std::string& sysfs_name)
  : pdev_umq(driver, sysfs_name)
{
  // XRT reads 'instance' sysfs for mgmt devices (m_is_mgmt=true) which does
  // not exist for XDNA PF. Derive m_instance from the accelN dir entry,
  // same as VF/classic devices do via get_render_value().
  const std::string accel_dir = "/sys/bus/pci/devices/" + m_sysfs_name + "/accel";
  std::unique_ptr<DIR, int(*)(DIR*)> dp(opendir(accel_dir.c_str()), closedir);
  if (!dp)
    throw std::invalid_argument("No accel dir: " + accel_dir);

  while (auto entry = readdir(dp.get())) {
    const std::string name{entry->d_name};
    if (name.size() <= 5 || name.compare(0, 5, "accel") != 0)
      continue;
    const std::string suffix = name.substr(5);
    if (!std::all_of(suffix.begin(), suffix.end(), ::isdigit))
      continue;
    m_instance = std::stoi(suffix);
    return;
  }
  throw std::invalid_argument("No accelN entry under: " + accel_dir);
}

bool
pdev_pf::
is_umq() const
{
  return false;
}

void
pdev_pf::
create_drm_bo(bo_info *arg) const
{
  shim_err(ENOTSUP, "PF device does not support BO creation");
}

}


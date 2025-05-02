// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2022-2025, Advanced Micro Devices, Inc. All rights reserved.

#include "device.h"
#include "pcidev.h"
#include "pcidrv.h"
#include "shim_debug.h"
#include "core/common/trace.h"

namespace shim_xdna {

pdev::
pdev(std::shared_ptr<const platform_drv>& driver, const std::string& sysfs_name)
  : m_driver(driver)
  , xrt_core::pci::dev(driver->get_pdrv(), sysfs_name)
{
  m_is_ready = true; // We're always ready
  shim_debug("Created pcidev (%s)", m_sysfs_name.c_str());
}

pdev::
~pdev()
{
  shim_debug("Destroying pcidev (%s)", m_sysfs_name.c_str());
}

xrt_core::device::handle_type
pdev::
create_shim(xrt_core::device::id_type id) const
{
  auto s = new shim(id);
  return static_cast<xrt_core::device::handle_type>(s);
}

void
pdev::
open() const
{
  const std::lock_guard<std::mutex> lock(m_lock);

  if (m_dev_users == 0) {
    m_driver->drv_open(m_sysfs_name);
    try {
      on_first_open();
    } catch (...) {
      m_driver->drv_close();
      throw;
    }
  }
  ++m_dev_users;
}

void
pdev::
close() const
{
  const std::lock_guard<std::mutex> lock(m_lock);

  --m_dev_users;
  if (m_dev_users == 0) {
    try {
      on_last_close();
      m_driver->drv_close();
    } catch (const xrt_core::system_error& e) {
      shim_debug("Failed to close device: %s", e.what());
    }
  }
}

void*
pdev::
mmap(void *addr, size_t len, int prot, int flags, off_t offset) const
{
  return m_driver->drv_mmap(addr, len, prot, flags, offset);
}

void
pdev::
munmap(void* addr, size_t len) const
{
  m_driver->drv_munmap(addr, len);
}

void
pdev::
drv_ioctl(drv_ioctl_cmd cmd, void* arg) const
{
  m_driver->drv_ioctl(cmd, arg);
}

std::shared_ptr<xrt_core::device>
pdev::
create_device(xrt_core::device::handle_type handle, xrt_core::device::id_type id) const
{
  return std::make_shared<device>(*this, handle, id);
}

}

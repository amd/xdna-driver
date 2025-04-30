// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2025, Advanced Micro Devices, Inc. All rights reserved.

#include "platform.h"
#include "shim_debug.h"
#include <sys/mman.h>
#include <fcntl.h>

namespace shim_xdna {

platform_drv::
platform_drv(std::shared_ptr<const drv>& driver)
  : m_driver(driver)
{
}

platform_drv::
~platform_drv()
{
}

void *
platform_drv::
drv_mmap(void *addr, size_t len, int prot, int flags, off_t offset) const
{
  void* ret = mmap(addr, len, prot, flags, m_dev_fd, offset);

  if (ret == MAP_FAILED) {
    shim_err(-errno, "mmap(addr=%p, len=%ld, prot=%d, flags=%d, offset=%ld) failed",
      addr, len, prot, flags, offset);
  }
  return ret;
}

void
platform_drv::
drv_munmap(void* addr, size_t len) const
{
  munmap(addr, len);
}

void
platform_drv::
drv_open(const std::string& sysfs_name) const
{
  if (m_dev_fd != -1)
    shim_err(EBUSY, "Platform driver is already opened");

  auto dev_node = m_driver->get_dev_node(sysfs_name);
  m_dev_fd = open(dev_node.c_str(), O_RDWR);
  if (m_dev_fd == -1)
    shim_err(-errno, "Open %s failed", dev_node.c_str());
  else
    shim_debug("Opened %s as %d", dev_node.c_str(), m_dev_fd);
}

void
platform_drv::
drv_close() const
{
  close(m_dev_fd);
  shim_debug("Closed %d", m_dev_fd);
  m_dev_fd = -1;
}

int
platform_drv::
dev_fd() const
{
  return m_dev_fd;
}

std::shared_ptr<const drv>
platform_drv::
get_pdrv() const
{
  return m_driver;
}

}

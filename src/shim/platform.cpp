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

void
platform_drv::
drv_ioctl(drv_ioctl_cmd cmd, void* cmd_arg) const
{
  switch (cmd) {
  case drv_ioctl_cmd::create_ctx:
    create_ctx(*static_cast<create_ctx_arg*>(cmd_arg));
    break;
  case drv_ioctl_cmd::destroy_ctx:
    destroy_ctx(*static_cast<destroy_ctx_arg*>(cmd_arg));
    break;
  case drv_ioctl_cmd::config_ctx_cu_config:
    config_ctx_cu_config(*static_cast<config_ctx_cu_config_arg*>(cmd_arg));
    break;
  case drv_ioctl_cmd::config_ctx_debug_bo:
    config_ctx_debug_bo(*static_cast<config_ctx_debug_bo_arg*>(cmd_arg));
    break;
  case drv_ioctl_cmd::create_bo:
    create_bo(*static_cast<create_bo_arg*>(cmd_arg));
    break;
  case drv_ioctl_cmd::destroy_bo:
    destroy_bo(*static_cast<destroy_bo_arg*>(cmd_arg));
    break;
  case drv_ioctl_cmd::sync_bo:
    sync_bo(*static_cast<sync_bo_arg*>(cmd_arg));
    break;
  case drv_ioctl_cmd::export_bo:
    export_bo(*static_cast<export_bo_arg*>(cmd_arg));
    break;
  case drv_ioctl_cmd::import_bo:
    import_bo(*static_cast<import_bo_arg*>(cmd_arg));
    break;
  case drv_ioctl_cmd::submit_cmd:
    submit_cmd(*static_cast<submit_cmd_arg*>(cmd_arg));
    break;
  case drv_ioctl_cmd::submit_dep:
    submit_dep(*static_cast<submit_dep_arg*>(cmd_arg));
    break;
  case drv_ioctl_cmd::submit_sig:
    submit_sig(*static_cast<submit_sig_arg*>(cmd_arg));
    break;
  case drv_ioctl_cmd::wait_cmd:
    wait_cmd(*static_cast<wait_cmd_arg*>(cmd_arg));
    break;
  case drv_ioctl_cmd::get_info:
    get_info(*static_cast<amdxdna_drm_get_info*>(cmd_arg));
    break;
  case drv_ioctl_cmd::set_state:
    set_state(*static_cast<amdxdna_drm_set_state*>(cmd_arg));
    break;
  case drv_ioctl_cmd::create_syncobj:
    create_syncobj(*static_cast<create_destroy_syncobj_arg*>(cmd_arg));
    break;
  case drv_ioctl_cmd::destroy_syncobj:
    destroy_syncobj(*static_cast<create_destroy_syncobj_arg*>(cmd_arg));
    break;
  case drv_ioctl_cmd::export_syncobj:
    export_syncobj(*static_cast<export_import_syncobj_arg*>(cmd_arg));
    break;
  case drv_ioctl_cmd::import_syncobj:
    import_syncobj(*static_cast<export_import_syncobj_arg*>(cmd_arg));
    break;
  case drv_ioctl_cmd::signal_syncobj:
    signal_syncobj(*static_cast<signal_syncobj_arg*>(cmd_arg));
    break;
  case drv_ioctl_cmd::wait_syncobj:
    wait_syncobj(*static_cast<wait_syncobj_arg*>(cmd_arg));
    break;
  default:
    shim_err(EINVAL, "Unknown drv_ioctl: %d", cmd);
    break;
  }
}

}

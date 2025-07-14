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

int64_t
platform_drv::
timeout_ms2abs_ns(int64_t timeout_ms)
{
  if (!timeout_ms)
    return std::numeric_limits<int64_t>::max(); // 0 means wait forever

  struct timespec tp;
  clock_gettime(CLOCK_MONOTONIC, &tp);
  return timeout_ms * 1000000 + tp.tv_sec * 1000000000ULL + tp.tv_nsec;
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

  m_sysfs_root += "/sys/bus/pci/devices/";
  m_sysfs_root += sysfs_name;

  auto dev_node = m_driver->get_dev_node(sysfs_name);
  m_dev_fd = open(dev_node.c_str(), O_RDWR);
  if (m_dev_fd == -1)
    shim_err(-errno, "Open %s failed", dev_node.c_str());
  else
    shim_debug("Opened %s as %d, sysfs: %s", dev_node.c_str(), m_dev_fd, m_sysfs_root.c_str());
}

void
platform_drv::
drv_close() const
{
  close(m_dev_fd);
  shim_debug("Closed %d", m_dev_fd);
  m_dev_fd = -1;
  m_sysfs_root.clear();
}

int
platform_drv::
dev_fd() const
{
  return m_dev_fd;
}

const std::string&
platform_drv::
sysfs_root() const
{
  return m_sysfs_root;
}

std::shared_ptr<const drv>
platform_drv::
get_pdrv() const
{
  return m_driver;
}

void
platform_drv::
create_syncobj(create_destroy_syncobj_arg& sobj_arg) const
{
  drm_syncobj_create arg = {};
  arg.handle = AMDXDNA_INVALID_FENCE_HANDLE;
  arg.flags = 0;
  ioctl(dev_fd(), DRM_IOCTL_SYNCOBJ_CREATE, &arg);
  sobj_arg.handle = arg.handle;
}

void
platform_drv::
destroy_syncobj(create_destroy_syncobj_arg& sobj_arg) const
{
  drm_syncobj_destroy arg = {};
  arg.handle = sobj_arg.handle;
  ioctl(dev_fd(), DRM_IOCTL_SYNCOBJ_DESTROY, &arg);
}

void
platform_drv::
export_syncobj(export_import_syncobj_arg& sobj_arg) const
{
  drm_syncobj_handle arg = {};
  arg.handle = sobj_arg.handle;
  arg.flags = 0;
  arg.fd = -1;
  ioctl(dev_fd(), DRM_IOCTL_SYNCOBJ_HANDLE_TO_FD, &arg);
  sobj_arg.fd = arg.fd;
}

void
platform_drv::
import_syncobj(export_import_syncobj_arg& sobj_arg) const
{
  drm_syncobj_handle arg = {};
  arg.handle = AMDXDNA_INVALID_FENCE_HANDLE;
  arg.flags = 0;
  arg.fd = sobj_arg.fd;
  ioctl(dev_fd(), DRM_IOCTL_SYNCOBJ_FD_TO_HANDLE, &arg);
  sobj_arg.handle = arg.handle;
}

void
platform_drv::
wait_syncobj(wait_syncobj_arg& sobj_arg) const
{
  drm_syncobj_timeline_wait arg = {};
  arg.handles = reinterpret_cast<uintptr_t>(&sobj_arg.handle);
  arg.points = reinterpret_cast<uintptr_t>(&sobj_arg.timepoint);
  arg.timeout_nsec = timeout_ms2abs_ns(sobj_arg.timeout_ms);
  arg.count_handles = 1;
  /* Keep waiting even if not submitted yet */
  arg.flags = DRM_SYNCOBJ_WAIT_FLAGS_WAIT_FOR_SUBMIT;
  ioctl(dev_fd(), DRM_IOCTL_SYNCOBJ_TIMELINE_WAIT, &arg);
}

void
platform_drv::
signal_syncobj(signal_syncobj_arg& sobj_arg) const
{
  drm_syncobj_timeline_array arg = {};
  arg.handles = reinterpret_cast<uintptr_t>(&sobj_arg.handle);
  arg.points = reinterpret_cast<uintptr_t>(&sobj_arg.timepoint);
  arg.count_handles = 1;
  ioctl(dev_fd(), DRM_IOCTL_SYNCOBJ_TIMELINE_SIGNAL, &arg);
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
  case drv_ioctl_cmd::create_uptr_bo:
    create_uptr_bo(*static_cast<create_uptr_bo_arg*>(cmd_arg));
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
  case drv_ioctl_cmd::wait_cmd_ioctl:
    wait_cmd_ioctl(*static_cast<wait_cmd_arg*>(cmd_arg));
    break;
  case drv_ioctl_cmd::wait_cmd_syncobj:
    wait_cmd_syncobj(*static_cast<wait_cmd_arg*>(cmd_arg));
    break;
  case drv_ioctl_cmd::get_info:
    get_info(*static_cast<amdxdna_drm_get_info*>(cmd_arg));
    break;
  case drv_ioctl_cmd::get_info_array:
    get_info_array(*static_cast<amdxdna_drm_get_info_array*>(cmd_arg));
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
  case drv_ioctl_cmd::get_sysfs:
    get_sysfs(*static_cast<get_sysfs_arg*>(cmd_arg));
    break;
  case drv_ioctl_cmd::put_sysfs:
    put_sysfs(*static_cast<put_sysfs_arg*>(cmd_arg));
    break;
  default:
    shim_err(EINVAL, "Unknown drv_ioctl: %d", cmd);
    break;
  }
}

}

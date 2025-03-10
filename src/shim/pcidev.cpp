// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2022-2025, Advanced Micro Devices, Inc. All rights reserved.

#include "device.h"
#include "pcidev.h"
#include "pcidrv.h"
#include "shim_debug.h"
#include "drm_local/amdxdna_accel.h"
#include "core/common/trace.h"
#include <drm/virtgpu_drm.h>

namespace {

  std::string
  ioctl_cmd2name(unsigned long cmd)
  {
    switch(cmd) {
    case DRM_IOCTL_AMDXDNA_CREATE_CTX:
      return "DRM_IOCTL_AMDXDNA_CREATE_CTX";
    case DRM_IOCTL_AMDXDNA_DESTROY_CTX:
      return "DRM_IOCTL_AMDXDNA_DESTROY_CTX";
    case DRM_IOCTL_AMDXDNA_CONFIG_CTX:
      return "DRM_IOCTL_AMDXDNA_CONFIG_CTX";
    case DRM_IOCTL_AMDXDNA_CREATE_BO:
      return "DRM_IOCTL_AMDXDNA_CREATE_BO";
    case DRM_IOCTL_AMDXDNA_GET_BO_INFO:
      return "DRM_IOCTL_AMDXDNA_GET_BO_INFO";
    case DRM_IOCTL_AMDXDNA_SYNC_BO:
      return "DRM_IOCTL_AMDXDNA_SYNC_BO";
    case DRM_IOCTL_AMDXDNA_EXEC_CMD:
      return "DRM_IOCTL_AMDXDNA_EXEC_CMD";
    case DRM_IOCTL_AMDXDNA_WAIT_CMD:
      return "DRM_IOCTL_AMDXDNA_WAIT_CMD";
    case DRM_IOCTL_AMDXDNA_GET_INFO:
      return "DRM_IOCTL_AMDXDNA_GET_INFO";
    case DRM_IOCTL_AMDXDNA_SET_STATE:
      return "DRM_IOCTL_AMDXDNA_SET_STATE";
    case DRM_IOCTL_GEM_CLOSE:
      return "DRM_IOCTL_GEM_CLOSE";
    case DRM_IOCTL_PRIME_HANDLE_TO_FD:
      return "DRM_IOCTL_PRIME_HANDLE_TO_FD";
    case DRM_IOCTL_PRIME_FD_TO_HANDLE:
      return "DRM_IOCTL_PRIME_FD_TO_HANDLE";
    case DRM_IOCTL_SYNCOBJ_CREATE:
      return "DRM_IOCTL_SYNCOBJ_CREATE";
    case DRM_IOCTL_SYNCOBJ_QUERY:
      return "DRM_IOCTL_SYNCOBJ_QUERY";
    case DRM_IOCTL_SYNCOBJ_DESTROY:
      return "DRM_IOCTL_SYNCOBJ_DESTROY";
    case DRM_IOCTL_SYNCOBJ_HANDLE_TO_FD:
      return "DRM_IOCTL_SYNCOBJ_HANDLE_TO_FD";
    case DRM_IOCTL_SYNCOBJ_FD_TO_HANDLE:
      return "DRM_IOCTL_SYNCOBJ_FD_TO_HANDLE";
    case DRM_IOCTL_SYNCOBJ_TIMELINE_SIGNAL:
      return "DRM_IOCTL_SYNCOBJ_TIMELINE_SIGNAL";
    case DRM_IOCTL_SYNCOBJ_TIMELINE_WAIT:
      return "DRM_IOCTL_SYNCOBJ_TIMELINE_WAIT";
    case DRM_IOCTL_VIRTGPU_RESOURCE_CREATE_BLOB:
      return "DRM_IOCTL_VIRTGPU_RESOURCE_CREATE_BLOB";
    case DRM_IOCTL_VIRTGPU_EXECBUFFER:
      return "DRM_IOCTL_VIRTGPU_EXECBUFFER";
    case DRM_IOCTL_VIRTGPU_MAP:
      return "DRM_IOCTL_VIRTGPU_MAP";
    }

    return "UNKNOWN(" + std::to_string(cmd) + ")";
  }

}

namespace shim_xdna {

pdev::
pdev(std::shared_ptr<const xrt_core::pci::drv> driver, std::string sysfs_name)
  : xrt_core::pci::dev(std::move(driver), std::move(sysfs_name))
{
  m_is_ready = true; // We're always ready.
}

pdev::
~pdev()
{
  if (m_dev_fd != -1)
    shim_debug("Device node fd leaked!! fd=%d", m_dev_fd);
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
  int fd;
  const std::lock_guard<std::mutex> lock(m_lock);

  if (m_dev_users == 0) {
    fd = xrt_core::pci::dev::open("", O_RDWR);
    if (fd < 0)
      shim_err(EINVAL, "Failed to open KMQ device");
    else
      shim_debug("Device opened, fd=%d", fd);
    // Publish the fd for other threads to use.
    m_dev_fd = fd;
  }
  ++m_dev_users;

  on_first_open();
}

void
pdev::
close() const
{
  int fd;
  const std::lock_guard<std::mutex> lock(m_lock);

  --m_dev_users;
  if (m_dev_users == 0) {
    on_last_close();

    // Stop new users of the fd from other threads.
    fd = m_dev_fd;
    m_dev_fd = -1;
    // Kernel will wait for existing users to quit.
    ::close(fd);
    shim_debug("Device closed, fd=%d", fd);
  }
}

void
pdev::
ioctl(unsigned long cmd, void* arg) const
{
  XRT_TRACE_POINT_SCOPE2(ioctl, cmd, arg);
  if (xrt_core::pci::dev::ioctl(m_dev_fd, cmd, arg) == -1)
    shim_err(errno, "%s IOCTL failed", ioctl_cmd2name(cmd).c_str());
}

void*
pdev::
mmap(void *addr, size_t len, int prot, int flags, off_t offset) const
{
  void* ret = ::mmap(addr, len, prot, flags, m_dev_fd, offset);

  if (ret == reinterpret_cast<void*>(-1))
    shim_err(errno, "mmap(addr=%p, len=%ld, prot=%d, flags=%d, offset=%ld) failed", addr, len, prot, flags, offset);
  return ret;
}

void
pdev::
munmap(void* addr, size_t len) const
{
  ::munmap(addr, len);
}

} // namespace shim_xdna


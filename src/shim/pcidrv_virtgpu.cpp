// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2025, Advanced Micro Devices, Inc. All rights reserved.

#include "shim_debug.h"
#include "pcidrv_virtgpu.h"
#include "drm_local/amdxdna_accel.h"
#include "core/pcie/linux/system_linux.h"

namespace {

struct X
{
  X() { xrt_core::pci::register_driver(std::make_shared<shim_xdna::drv_virtgpu>()); }
} x;

}

namespace shim_xdna {

std::string
drv_virtgpu::
name() const
{
  return "virtio-pci";
}

std::string
drv_virtgpu::
dev_node_prefix() const
{
  return "renderD";
}

std::string
drv_virtgpu::
dev_node_dir() const
{
  return "dri";
}

std::string
drv_virtgpu::
sysfs_dev_node_dir() const
{
  return "drm";
}

void
drv_virtgpu::
drv_ioctl(int dev_fd, drv_ioctl_cmd cmd, void* cmd_arg) const
{
  switch (cmd) {
  default:
    shim_err(EINVAL, "Unknown drv_ioctl: %d", cmd);
    break;
  }
}

int
drv_virtgpu::
get_dev_type(const std::string& sysfs) const
{
  // TODO: properly retrieve device type from host
  return AMDXDNA_DEV_TYPE_KMQ;
}

}

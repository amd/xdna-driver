// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2025, Advanced Micro Devices, Inc. All rights reserved.

#include "../shim_debug.h"
#include "../kmq/pcidev.h"
#include "../umq/pcidev.h"
#include "platform_virtio.h"
#include "amdxdna_proto.h"
#include "pcidrv_virtgpu.h"
#include "core/pcie/linux/system_linux.h"

namespace {

struct X
{
  X() { xrt_core::pci::register_driver(std::make_shared<shim_xdna::drv_virtgpu>()); }
} x;

int
get_dev_type(std::shared_ptr<const shim_xdna::platform_drv_virtio>& drv,
  const std::string& sysfs)
{
  std::vector<char> val(50);
  shim_xdna::get_sysfs_arg arg = { "device_type", val, };
  drv->drv_open(sysfs);
  drv->drv_ioctl(shim_xdna::drv_ioctl_cmd::get_sysfs, &arg);
  drv->drv_close();
  return static_cast<int>(std::stoi(arg.data.data()));
}

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

std::shared_ptr<xrt_core::pci::dev>
drv_virtgpu::
create_pcidev(const std::string& sysfs) const
{
  auto driver = std::dynamic_pointer_cast<const drv>(shared_from_this());
  auto platform_driver_virtio = std::make_shared<const platform_drv_virtio>(driver);
  auto device_type = get_dev_type(platform_driver_virtio, sysfs);

  auto platform_driver = std::dynamic_pointer_cast<const platform_drv>(platform_driver_virtio);
  if (device_type == AMDXDNA_DEV_TYPE_KMQ)
    return std::make_shared<pdev_kmq>(platform_driver, sysfs);
  if (device_type == AMDXDNA_DEV_TYPE_UMQ)
    return std::make_shared<pdev_umq>(platform_driver, sysfs);
  shim_err(EINVAL, "Unknown device type: %d", device_type);
}

}

// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2025, Advanced Micro Devices, Inc. All rights reserved.
//
#include "virtio/pcidev.h"
#include "pcidrv_virtio.h"
#include "core/pcie/linux/system_linux.h"
#include <fstream>

namespace {

struct X
{
  X() { xrt_core::pci::register_driver(std::make_shared<shim_xdna::drv_virtio>()); }
} x;

}

namespace shim_xdna {

std::string
drv_virtio::
name() const
{
  return "virtio-pci";
}

std::string
drv_virtio::
dev_node_prefix() const
{
  return "renderD";
}

std::string
drv_virtio::
dev_node_dir() const
{
  return "dri";
}

std::string
drv_virtio::
sysfs_dev_node_dir() const
{
  return "drm";
}

bool
drv_virtio::
is_user() const
{
  return true;
}

std::shared_ptr<xrt_core::pci::dev>
drv_virtio::
create_pcidev(const std::string& sysfs) const
{
  auto driver = std::static_pointer_cast<const drv_virtio>(shared_from_this());
  return std::make_shared<pdev_virtio>(driver, sysfs);
}

} // namespace shim_xdna


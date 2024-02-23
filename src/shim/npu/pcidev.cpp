// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2022-2024, Advanced Micro Devices, Inc. All rights reserved.

#include "device.h"
#include "pcidev.h"

namespace shim_xdna {

pdev_npu::
pdev_npu(std::shared_ptr<const drv> driver, std::string sysfs_name)
  : pdev(driver, sysfs_name)
{
  shim_debug("Created NPU pcidev");
}

pdev_npu::
~pdev_npu()
{
  shim_debug("Destroying NPU pcidev");
}

std::shared_ptr<xrt_core::device>
pdev_npu::
create_device(xrt_core::device::handle_type handle, xrt_core::device::id_type id) const
{
  return std::make_shared<device_npu>(*this, handle, id);
}

} // namespace shim_xdna


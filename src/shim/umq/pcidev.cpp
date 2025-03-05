// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2022-2024, Advanced Micro Devices, Inc. All rights reserved.

#include "device.h"
#include "pcidev.h"

namespace shim_xdna {

pdev_umq::
pdev_umq(std::shared_ptr<const drv> driver, std::string sysfs_name)
  : pdev(std::move(driver), std::move(sysfs_name))
{
  shim_debug("Created UMQ pcidev");
}

pdev_umq::
~pdev_umq()
{
  shim_debug("Destroying UMQ pcidev");
}

std::shared_ptr<xrt_core::device>
pdev_umq::
create_device(xrt_core::device::handle_type handle, xrt_core::device::id_type id) const
{
  return std::make_shared<device_umq>(*this, handle, id);
}

} // namespace shim_xdna


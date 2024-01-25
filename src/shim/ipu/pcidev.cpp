// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2022-2024, Advanced Micro Devices, Inc. All rights reserved.

#include "device.h"
#include "pcidev.h"

namespace shim_xdna {

pdev_ipu::
pdev_ipu(std::shared_ptr<const drv> driver, std::string sysfs_name)
  : pdev(driver, sysfs_name)
{
  shim_debug("Created IPU pcidev");
}

pdev_ipu::
~pdev_ipu()
{
  shim_debug("Destroying IPU pcidev");
}

std::shared_ptr<xrt_core::device>
pdev_ipu::
create_device(xrt_core::device::handle_type handle, xrt_core::device::id_type id) const
{
  return std::make_shared<device_ipu>(*this, handle, id);
}

void
pdev_ipu::
open() const
{
  m_dev_fd = xrt_core::pci::dev::open("", O_RDWR);
  if (m_dev_fd < 0)
      shim_err(EINVAL, "Failed to open IPU device fd");
}

} // namespace shim_xdna


// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2022-2025, Advanced Micro Devices, Inc. All rights reserved.

#include "shim_debug.h"
#include "pcidrv.h"
#include "kmq/pcidev.h"
#include "umq/pcidev.h"

namespace shim_xdna {

bool
drv::
is_user() const
{
  return true;
}

std::shared_ptr<xrt_core::pci::dev>
drv::
create_pcidev(const std::string& sysfs) const
{
  auto driver = std::dynamic_pointer_cast<const drv>(shared_from_this());

  if (m_device_type == AMDXDNA_DEV_TYPE_UNKNOWN)
    m_device_type = get_dev_type(sysfs);

  if (m_device_type == AMDXDNA_DEV_TYPE_KMQ)
    return std::make_shared<pdev_kmq>(driver, sysfs);
  if (m_device_type == AMDXDNA_DEV_TYPE_UMQ)
    return std::make_shared<pdev_umq>(driver, sysfs);
  shim_err(EINVAL, "Unknown device type: %d", m_device_type);
}

}

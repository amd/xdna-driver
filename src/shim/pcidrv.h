// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2022-2025, Advanced Micro Devices, Inc. All rights reserved.

#ifndef PCIDRV_XDNA_H
#define PCIDRV_XDNA_H

#include "drm_local/amdxdna_accel.h"
#include "core/pcie/linux/pcidrv.h"
#include <set>
#include <string>

namespace shim_xdna {

class drv : public xrt_core::pci::drv
{
public:
  //using xrt_core::pci::drv::drv;

  bool
  is_user() const override;

  std::string
  get_dev_node(const std::string& sysfs_name) const;
};

}

#endif

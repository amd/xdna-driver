// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2025, Advanced Micro Devices, Inc. All rights reserved.

#ifndef PCIDRV_AMDXDNA_H
#define PCIDRV_AMDXDNA_H

#include "../pcidrv.h"
#include "core/pcie/linux/pcidev.h"
#include <string>

namespace shim_xdna {

class drv_amdxdna : public drv
{
public:
  using drv::drv;

  std::string
  name() const override;

  std::string
  dev_node_prefix() const override;

  std::string
  dev_node_dir() const override;

  std::string
  sysfs_dev_node_dir() const override;

private:  
  std::shared_ptr<xrt_core::pci::dev>
  create_pcidev(const std::string& sysfs) const override;
};

}

#endif

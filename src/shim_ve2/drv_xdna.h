// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2025 Advanced Micro Devices, Inc. All rights

#ifndef DRV_XDNA_H
#define DRV_XDNA_H

#include "core/edge/user/drv.h"

namespace xrt_core::edge {
  class dev;
}

namespace shim_xdna_edge {

class drv_xdna : public xrt_core::edge::drv
{
public:
  std::string
  name() const override { return "aiarm"; }

  void
  scan_devices(std::vector<std::shared_ptr<xrt_core::edge::dev>>& dev_list) override;
  
  std::shared_ptr<xrt_core::edge::dev>
  create_edev(const std::string& sysfs="") const override;
};

}
#endif

// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2025, Advanced Micro Devices, Inc. All rights reserved.

#ifndef PCIDRV_AMDXDNA_H_
#define PCIDRV_AMDXDNA_H_

#include "pcidrv.h"
#include <string>

namespace shim_xdna {

class drv_amdxdna : public drv
{
public:
  std::string
  name() const override;

  std::string
  dev_node_prefix() const override;

  std::string
  dev_node_dir() const override;

  std::string
  sysfs_dev_node_dir() const override;

public:
  void
  drv_ioctl(int dev_fd, drv_ioctl_cmd cmd, void* arg) const override;

private:  
  int
  get_dev_type(const std::string& sysfs) const override;
};

}

#endif

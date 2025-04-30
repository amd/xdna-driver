// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2025, Advanced Micro Devices, Inc. All rights reserved.

#ifndef PLAT_HOST_H
#define PLAT_HOST_H

#include "../platform.h"

namespace shim_xdna {

class platform_drv_host : public platform_drv
{
public:
  using platform_drv::platform_drv;

  void
  drv_ioctl(drv_ioctl_cmd cmd, void* arg) const override;
};

}

#endif

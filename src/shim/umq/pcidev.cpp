// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2022-2024, Advanced Micro Devices, Inc. All rights reserved.

#include "device.h"
#include "pcidev.h"

namespace shim_xdna {

std::shared_ptr<xrt_core::device>
pdev_umq::
create_device(xrt_core::device::handle_type handle, xrt_core::device::id_type id) const
{
  return std::make_shared<device_umq>(*this, handle, id);
}

void
pdev_umq::
on_first_open() const
{
  // do nothing
}

void
pdev_umq::
on_last_close() const
{
  // do nothing
}

}


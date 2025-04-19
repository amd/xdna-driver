// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2022-2024, Advanced Micro Devices, Inc. All rights reserved.

#ifndef PCIDEV_UMQ_H
#define PCIDEV_UMQ_H

#include "../pcidev.h"

namespace shim_xdna {

class pdev_umq : public pdev
{
public:
  using shim_xdna::pdev::pdev;
 
  std::shared_ptr<xrt_core::device>
  create_device(xrt_core::device::handle_type handle, xrt_core::device::id_type id) const override;

  bool
  is_cache_coherent() const override;

  bool
  has_heap_buffer() const override;

private:
  virtual void
  on_first_open() const override;

  virtual void
  on_last_close() const override;
};

}

#endif

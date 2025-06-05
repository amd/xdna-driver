// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2022-2025, Advanced Micro Devices, Inc. All rights reserved.

#ifndef PCIDEV_UMQ_H
#define PCIDEV_UMQ_H

#include "../pcidev.h"

namespace shim_xdna {

class pdev_umq : public pdev
{
public:
  using pdev::pdev;

public:
  bool
  is_cache_coherent() const override;

  uint64_t
  get_heap_paddr() const override;

  void *
  get_heap_vaddr() const override;

  bool
  is_umq() const override;

private:
  virtual void
  on_first_open() const override;

  virtual void
  on_last_close() const override;
};

}

#endif

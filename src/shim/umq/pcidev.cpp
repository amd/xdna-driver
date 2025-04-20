// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2022-2025, Advanced Micro Devices, Inc. All rights reserved.

#include "pcidev.h"

namespace shim_xdna {

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

bool
pdev_umq::
is_cache_coherent() const
{
  return true;
}

bool
pdev_umq::
has_heap_buffer() const
{
  return false;
}

bool
pdev_umq::
is_umq() const
{
  return true;
}

}


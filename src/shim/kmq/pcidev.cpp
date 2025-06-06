// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2022-2025, Advanced Micro Devices, Inc. All rights reserved.

#include "../buffer.h"
#include "pcidev.h"
#include "core/common/config_reader.h"

namespace {

// Device memory heap needs to be multiple of 64MB page.
const size_t heap_page_size = (64 << 20);

unsigned int
get_heap_num_pages()
{
  static unsigned int num = 0;

  if (!num)
    num = xrt_core::config::detail::get_uint_value("Debug.num_heap_pages", 1);
  return num;
}

}

namespace shim_xdna {

void
pdev_kmq::
on_first_open() const
{
  auto heap_sz = heap_page_size * get_heap_num_pages();
  // Alloc device memory on first device open.
  m_dev_heap_bo = std::make_unique<buffer>(*this, heap_sz, AMDXDNA_BO_DEV_HEAP);
}

void
pdev_kmq::
on_last_close() const
{
  m_dev_heap_bo.reset();
}

bool
pdev_kmq::
is_cache_coherent() const
{
  return false;
}

uint64_t
pdev_kmq::
get_heap_paddr() const
{
  return m_dev_heap_bo->paddr();
}

void *
pdev_kmq::
get_heap_vaddr() const
{
  return m_dev_heap_bo->vaddr();
}

bool
pdev_kmq::
is_umq() const
{
  return false;
}

} // namespace shim_xdna


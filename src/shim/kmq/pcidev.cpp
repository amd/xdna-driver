// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2022-2024, Advanced Micro Devices, Inc. All rights reserved.

#include "bo.h"
#include "device.h"
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

std::shared_ptr<xrt_core::device>
pdev_kmq::
create_device(xrt_core::device::handle_type handle, xrt_core::device::id_type id) const
{
  return std::make_shared<device_kmq>(*this, handle, id);
}

void
pdev_kmq::
on_first_open() const
{
  auto heap_sz = heap_page_size * get_heap_num_pages();
  // Alloc device memory on first device open.
  m_dev_heap_bo = std::make_unique<bo_kmq>(*this, heap_sz, AMDXDNA_BO_DEV_HEAP);
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

bool
pdev_kmq::
has_heap_buffer() const
{
  return true;
}

} // namespace shim_xdna


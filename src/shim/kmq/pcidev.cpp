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

void
pdev_kmq::
create_drm_dev_bo(create_bo_arg *arg) const
{
  const std::lock_guard<std::mutex> lock(m_lock);

  // Make sure we are allocating device BO.
  arg->type = AMDXDNA_BO_DEV;

  try {
    drv_ioctl(drv_ioctl_cmd::create_bo, arg);
  } catch (const xrt_core::system_error& ex) {
    if (ex.get_code() != ENOMEM)
      throw;
    // Expanding current heap size and try one more time.
    m_dev_heap_bo->expand(arg->size);
    drv_ioctl(drv_ioctl_cmd::create_bo, arg);
  }
}

} // namespace shim_xdna


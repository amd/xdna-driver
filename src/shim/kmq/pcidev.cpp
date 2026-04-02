// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2022-2025, Advanced Micro Devices, Inc. All rights reserved.

#include <algorithm>

#include "../buffer.h"
#include "pcidev.h"
#include "core/common/config_reader.h"

namespace {

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

constexpr size_t heap_page_size = 64ul * 1024 * 1024;

void
pdev_kmq::
on_first_open() const
{
  const size_t max_heap_sz = 512UL << 20;
  auto heap_sz = std::min(heap_page_size * get_heap_num_pages(), max_heap_sz);
  m_dev_heap_bo = std::make_unique<buffer>(*this, heap_sz, max_heap_sz, AMDXDNA_BO_DEV_HEAP, heap_page_size);
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
create_drm_bo(bo_info *arg) const
{
  if (arg->type != AMDXDNA_BO_DEV) {
    drv_ioctl(drv_ioctl_cmd::create_bo, arg);
    return;
  }

  // Dynamically expanding heap buffer when allocating device BO.
  // Expand one heap_page_size chunk at a time and retry until
  // the allocation succeeds or the heap is maxed out.
  // e.g. In case of QEMU guest, QEMU can have number of SG entries
  // virtio gpu mem limitation, limited to 64MB each time
  // to avoid failure.
  // we need to lock when we are trying to allocate DEV BO as
  // it is possible that the heap is being expanded by another thread.
  const std::lock_guard<std::mutex> lock(m_lock);
  for (;;) {
    try {
      drv_ioctl(drv_ioctl_cmd::create_bo, arg);
      return;
    } catch (const xrt_core::system_error& ex) {
      if (ex.get_code() != EAGAIN)
        throw;
      m_dev_heap_bo->expand(heap_page_size);
    }
  }
}

} // namespace shim_xdna


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

pdev_kmq::
pdev_kmq(std::shared_ptr<const drv> driver, std::string sysfs_name)
  : pdev(std::move(driver), std::move(sysfs_name))
{
  shim_debug("Created KMQ pcidev");
}

pdev_kmq::
~pdev_kmq()
{
  shim_debug("Destroying KMQ pcidev");
}

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
  shim_debug("HEAP BO size: 0x%lx", heap_sz);
  // Alloc device memory on first device open.
  m_dev_heap_bo = std::make_unique<bo_kmq>(*this, heap_sz, AMDXDNA_BO_DEV_HEAP);
}

void
pdev_kmq::
on_last_close() const
{
  m_dev_heap_bo.reset();
}

} // namespace shim_xdna


// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2022-2024, Advanced Micro Devices, Inc. All rights reserved.

#include "bo.h"
#include "device.h"
#include "pcidev.h"

namespace {

// Device memory heap needs to be within one 64MB page. The maximum size is 64MB.
const size_t dev_mem_size = (64 << 20);

}

namespace shim_xdna {

pdev_kmq::
pdev_kmq(std::shared_ptr<const drv> driver, std::string sysfs_name)
  : pdev(driver, std::move(sysfs_name))
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
  auto dev = std::make_shared<device_kmq>(*this, handle, id);
  try {
    // Alloc device memory on first device creation.
    // No locking is needed since driver will ensure only one heap BO is created.
    if (m_dev_heap_bo == nullptr)
      m_dev_heap_bo = std::make_unique<bo_kmq>(*dev, dev_mem_size, AMDXDNA_BO_DEV_HEAP);
  } catch (const xrt_core::system_error& ex) {
    if (ex.get_code() != EBUSY)
      throw;
  }
  return dev;
}

void
pdev_kmq::
on_last_close() const
{
  m_dev_heap_bo.reset();
}

} // namespace shim_xdna


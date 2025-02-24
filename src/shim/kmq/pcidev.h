// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2022-2024, Advanced Micro Devices, Inc. All rights reserved.

#ifndef PCIDEV_KMQ_H
#define PCIDEV_KMQ_H

#include "../pcidrv.h"
#include "../pcidev.h"


namespace shim_xdna {

class pdev_kmq : public pdev
{
public:
  pdev_kmq(std::shared_ptr<const drv> driver, std::string sysfs_name);
  ~pdev_kmq();
 
  std::shared_ptr<xrt_core::device>
  create_device(xrt_core::device::handle_type handle, xrt_core::device::id_type id) const override;

private:
  mutable std::unique_ptr<xrt_core::buffer_handle> m_dev_heap_bo;

  virtual void
  on_first_open() const override;

  virtual void
  on_last_close() const override;
};

} // namespace shim_xdna

#endif

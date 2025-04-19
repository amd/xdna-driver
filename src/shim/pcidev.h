// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2022-2024, Advanced Micro Devices, Inc. All rights reserved.

#ifndef PCIDEV_XDNA_H
#define PCIDEV_XDNA_H

#include "pcidrv.h"
#include "core/pcie/linux/pcidev.h"

namespace shim_xdna {

class pdev : public xrt_core::pci::dev
{
public:
  pdev(std::shared_ptr<const drv>& driver, const std::string& sysfs_name);
  ~pdev();

  xrt_core::device::handle_type
  create_shim(xrt_core::device::id_type id) const override;

public:
  void
  ioctl(unsigned long cmd, void* arg) const;

  void*
  mmap(void *addr, size_t len, int prot, int flags, off_t offset) const;

  void
  munmap(void* addr, size_t len) const;

  void
  open() const;

  void
  close() const;

  void
  drv_ioctl(drv_ioctl_cmd cmd, void* arg) const;

  virtual bool
  is_cache_coherent() const = 0;

  virtual bool
  has_heap_buffer() const = 0;

private:
  virtual void
  on_first_open() const = 0;

  virtual void
  on_last_close() const = 0;

  mutable int m_dev_fd = -1;
  mutable int m_dev_users = 0;
  mutable std::mutex m_lock;
  std::shared_ptr<const drv> m_driver;
};

}

#endif

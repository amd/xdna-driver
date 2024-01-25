// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2022-2024, Advanced Micro Devices, Inc. All rights reserved.

#ifndef PCIDEV_XDNA_H
#define PCIDEV_XDNA_H

#include "shim_debug.h"

#include "core/pcie/linux/device_linux.h"
#include "core/pcie/linux/pcidev.h"

namespace shim_xdna {

// Forward declaration
class drv;

class pdev : public xrt_core::pci::dev
{
public:
  pdev(std::shared_ptr<const drv> driver, std::string sysfs_name);
  ~pdev();

  int
  pcieBarRead(uint64_t offset, void *buf, uint64_t len) const override
  { shim_not_supported_err(__func__); }

  int
  pcieBarWrite(uint64_t offset, const void *buf, uint64_t len) const override
  { shim_not_supported_err(__func__); }

  int
  poll(int devhdl, short events, int timeoutMilliSec) override
  { shim_not_supported_err(__func__); }

  int
  flock(int devhdl, int op) override
  { shim_not_supported_err(__func__); }

  int
  get_partinfo(std::vector<std::string>& info, void *blob = nullptr) override
  { shim_not_supported_err(__func__); }

  std::shared_ptr<xrt_core::pci::dev>
  lookup_peer_dev() override
  { shim_not_supported_err(__func__); }

  xrt_core::device::handle_type
  create_shim(xrt_core::device::id_type id) const override;
 
  std::shared_ptr<xrt_core::device>
  create_device(xrt_core::device::handle_type handle, xrt_core::device::id_type id) const override
  { shim_not_supported_err(__func__); }

public:
  void
  ioctl(unsigned long cmd, void* arg) const;

  void*
  mmap(size_t len, int prot, int flags, off_t offset) const;

  void
  munmap(void* addr, size_t len) const;

protected:
  mutable int m_dev_fd = -1;

  virtual void
  open() const = 0;

private:
  mutable std::mutex m_lock;

  int
  get_dev_fd() const;
};

} // namespace shim_xdna

#endif

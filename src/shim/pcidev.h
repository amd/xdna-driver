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

  void
  open() const;

  void
  close() const;

  bool
  is_force_unchained_command() const;

  // Below routines are for managing drm_bo_hdl -> buffer_handle* mapping.
  // This is only a temporary hack for supporting forcibly unchained runlist.
  void
  insert_hdl_mapping(uint32_t hdl, uint64_t ptr) const
  { m_hdl_map[hdl] = ptr; }
  void
  remove_hdl_mapping(uint32_t hdl) const
  { m_hdl_map.erase(hdl); }
  uint64_t
  lookup_hdl_mapping(uint32_t hdl) const
  { return m_hdl_map[hdl]; }

private:
  mutable int m_dev_fd = -1;
  mutable int m_dev_users = 0;
  mutable std::mutex m_lock;
  const bool m_force_unchained_command = true;
  // Mark it as mutable since pdev does not look at what is saved in this map
  mutable std::map<uint32_t, uint64_t> m_hdl_map;
};

} // namespace shim_xdna

#endif

// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2022-2025, Advanced Micro Devices, Inc. All rights reserved.

#ifndef PCIDEV_XDNA_H
#define PCIDEV_XDNA_H

#include "platform.h"
#include "core/pcie/linux/pcidev.h"
#include <shared_mutex>

namespace shim_xdna {

class pdev : public xrt_core::pci::dev
{
public:
  pdev(std::shared_ptr<const platform_drv>& driver, const std::string& sysfs_name);
  ~pdev();

  xrt_core::device::handle_type
  create_shim(xrt_core::device::id_type id) const override;
 
  std::shared_ptr<xrt_core::device>
  create_device(xrt_core::device::handle_type handle, xrt_core::device::id_type id) const override;

  void
  sysfs_get(const std::string& subdev, const std::string& entry, std::string& err,
    std::vector<std::string>& sv) override;

  void
  sysfs_get(const std::string& subdev, const std::string& entry, std::string& err,
    std::vector<uint64_t>& iv) override;

  void
  sysfs_get(const std::string& subdev, const std::string& entry, std::string& err,
    std::string& s) override;

  void
  sysfs_get(const std::string& subdev, const std::string& entry, std::string& err,
    std::vector<char>& buf) override;

  void
  sysfs_put(const std::string& subdev, const std::string& entry, std::string& err,
    const std::string& input) override;

  void
  sysfs_put(const std::string& subdev, const std::string& entry, std::string& err,
    const std::vector<char>& buf) override;

  void
  sysfs_put(const std::string& subdev, const std::string& entry, std::string& err,
    const unsigned int& buf) override;

public:
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

  virtual uint64_t
  get_heap_paddr() const = 0;

  virtual void *
  get_heap_vaddr() const = 0;

  virtual bool
  is_umq() const = 0;

  virtual void
  create_drm_bo(bo_info *arg) const = 0;

  // Maintaining bo handle to ptr mapping.
  // For now, used by runlist processing where cmd_bo handles are passed down
  // in exec buf. These handles has to be mapped to original ptr for submission.
  void
  insert_bo_handle(uint64_t handle, xrt_core::buffer_handle *ptr) const;
  void
  remove_bo_handle(uint64_t handle) const;
  xrt_core::buffer_handle *
  find_bo_by_handle(uint64_t handle) const;

private:
  virtual void
  on_first_open() const = 0;

  virtual void
  on_last_close() const = 0;

  mutable int m_dev_users = 0;
  mutable std::mutex m_open_close_lock;

  std::shared_ptr<const platform_drv> m_driver;

  mutable std::shared_mutex m_bo_map_lock;
  mutable std::unordered_map<uint64_t, xrt_core::buffer_handle *> m_bo_map;
};

}

#endif

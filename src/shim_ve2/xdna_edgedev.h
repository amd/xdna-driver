// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2025, Advanced Micro Devices, Inc. All rights reserved.

#ifndef XDNA_EDGE_DEV_H__
#define XDNA_EDGE_DEV_H__

#include <cstring>
#include <fcntl.h>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <memory> // Include necessary headers
#include <mutex>
#include <regex>
#include <sys/ioctl.h> // Include this header for ioctl
#include <sys/mman.h>  // Include this header for munmap
#include <string>
#include <sstream>

#include "core/common/device.h"
#include "core/edge/user/device_linux.h"
#include "shim_debug.h"

namespace shim_xdna_edge {

class xdna_edgedev {
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
  sysfs_get(const std::string& entry, std::string& err_msg,
		 std::vector<std::string>& sv) const;
  void
  sysfs_get(const std::string& entry, std::string& err_msg,
		 std::vector<uint64_t>& iv) const;
  void
  sysfs_get(const std::string& entry, std::string& err_msg,
		 std::string& s) const;
  void
  sysfs_get(const std::string& entry, std::string& err_msg,
		 std::vector<char>& buf) const;

  template <typename T>
  void
  sysfs_get(const std::string& entry, std::string& err_msg,
	    T& i, T def) {
    std::vector<uint64_t> iv;
    sysfs_get(entry, err_msg, iv);
    if (!iv.empty())
      i = static_cast<T>(iv[0]);
    else
      i = def; // user defined default value
  }

  void
  sysfs_put(const std::string& entry, std::string& err_msg,
		 const std::string& input);
  void
  sysfs_put(const std::string& entry, std::string& err_msg,
		 const std::vector<char>& buf);
  std::string get_sysfs_path(const std::string& entry) const;

public:
  //xdna_edgedev(std::shared_ptr<const xdna_edgedrv> driver, std::string sysfs_name);
  xdna_edgedev(std::string sysfs_name, std::string dev_name);
  ~xdna_edgedev();

  xrt_core::device::handle_type
  create_shim(xrt_core::device::id_type id) const;

  std::shared_ptr<xrt_core::device>
  create_device(xrt_core::device::handle_type handle, xrt_core::device::id_type id) const;

  static std::string
  get_edge_devname();

  static std::shared_ptr<xdna_edgedev>
  get_edgedev();

private:
  std::fstream
  sysfs_open(const std::string& entry, std::string& err,
		  bool write = false, bool binary = false) const;

  mutable int m_dev_fd		= -1;
  mutable int m_dev_users	= 0;
  //std::shared_ptr<const xdna_edgedrv> m_driver;
  std::string m_sysfs_name;
  std::string m_dev_name;
  mutable std::mutex m_lock;

};

} // namespace shim_xdna_edge

#endif // __XDNA_EDGE_DEV_H__

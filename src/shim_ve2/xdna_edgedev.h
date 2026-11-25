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
#include <sys/types.h>
#include <unistd.h>
#include <string>
#include <sstream>
#include <unordered_map>

#include "core/common/device.h"
#include "core/edge/user/device_linux.h"
#include "shim_debug.h"

namespace shim_xdna_edge {

class xdna_edgedev {
public:
  // GEM handles are not reference counted by the kernel.  There is one
  // handle per object per DRM file, so importing a dma-buf exported from
  // this same file returns the exporter's existing handle.  Every xdna_bo
  // holding a handle is therefore an owner, and DRM_IOCTL_GEM_CLOSE must be
  // issued only when the last owner releases it.
  //
  // m_bo_ref_mtx is held across the ioctls that hand out or close a handle,
  // not only across the map update.  Otherwise a handle can be closed
  // between PRIME_FD_TO_HANDLE and the reference being taken, or between the
  // last reference being dropped and GEM_CLOSE running.

  // Take a reference on a handle freshly returned by CREATE_BO.
  void bo_handle_ref_inc(uint32_t hdl);

  // Import a dma-buf with DRM_IOCTL_PRIME_FD_TO_HANDLE and take a reference
  // on the returned handle.  Throws, without taking a reference, if the
  // ioctl fails.  Release with bo_handle_release().
  uint32_t bo_handle_import(int fd);

  // Drop a reference.  Issues DRM_IOCTL_GEM_CLOSE when it was the last one.
  // A handle with no reference held (e.g. a BO inherited across fork()) is
  // ignored, not closed.  For a handle returned by CREATE_BO that has not been
  // given a reference yet, call bo_handle_ref_inc() first.
  void bo_handle_release(uint32_t hdl);

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
  mutable std::mutex m_bo_ref_mtx;
  mutable std::unordered_map<uint32_t,int> m_bo_refcnt;
  std::fstream
  sysfs_open(const std::string& entry, std::string& err,
		  bool write = false, bool binary = false) const;

  mutable int m_dev_fd		= -1;
  mutable int m_dev_users	= 0;
  mutable pid_t m_pid		= 0;
  //std::shared_ptr<const xdna_edgedrv> m_driver;
  std::string m_sysfs_name;
  std::string m_dev_name;
  mutable std::mutex m_lock;

};

} // namespace shim_xdna_edge

#endif // __XDNA_EDGE_DEV_H__

// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2025, Advanced Micro Devices, Inc. All rights reserved.

#ifndef PLAT_XDNA_H
#define PLAT_XDNA_H

#include "pcidrv.h"
#include "shim_debug.h"
#include "drm_local/amdxdna_accel.h"
#include "core/common/shim/buffer_handle.h"
#include <set>
#include <tuple>
#include <vector>
#include <cstddef>
#include <stdint.h>

namespace shim_xdna {

enum class drv_ioctl_cmd {
  create_ctx,
  destroy_ctx,
  config_ctx_cu_config,
  config_ctx_debug_bo,

  create_bo,
  create_uptr_bo,
  destroy_bo,
  sync_bo,
  export_bo,
  import_bo,

  submit_cmd,
  wait_cmd_ioctl,
  wait_cmd_syncobj,

  get_info,
  get_info_array,
  set_state,

  get_sysfs,
  put_sysfs,

  create_syncobj,
  destroy_syncobj,
  export_syncobj,
  import_syncobj,
  signal_syncobj,
  wait_syncobj,
};

struct bo_id {
  // In non-VM case, not valid. In VM case, DRM BO handle in guest
  uint32_t res_id = AMDXDNA_INVALID_BO_HANDLE;
  // In non-VM case, DRM BO handle. In VM case, DRM BO handle in host
  uint32_t handle = AMDXDNA_INVALID_BO_HANDLE;
  bool operator<(const bo_id& other) const
  { return std::tie(handle, res_id) < std::tie(other.handle, other.res_id); }
};

struct create_ctx_arg {
  const amdxdna_qos_info& qos;
  bo_id umq_bo;
  bo_id log_buf_bo;
  uint32_t max_opc;
  uint32_t num_tiles;
  uint32_t mem_size;
  uint32_t ctx_handle;
  uint32_t umq_doorbell;
  uint32_t syncobj_handle;
};

struct destroy_ctx_arg {
  uint32_t ctx_handle;
  uint32_t syncobj_handle;
};

struct config_ctx_cu_config_arg {
  uint32_t ctx_handle;
  const std::vector<char>& conf_buf;
};

struct config_ctx_debug_bo_arg {
  uint32_t ctx_handle;
  bool is_detach;
  bo_id bo;
};

struct create_bo_arg {
  int type;
  size_t size;
  uint64_t xdna_addr_align;
  bo_id bo;
  uint64_t xdna_addr;
  uint64_t map_offset;
};

struct create_uptr_bo_arg {
  void *buf;
  size_t size;
  bo_id bo;
  uint64_t xdna_addr;
  uint64_t map_offset;
};

struct destroy_bo_arg {
  bo_id bo;
};

struct sync_bo_arg {
  bo_id bo;
  xrt_core::buffer_handle::direction direction;
  uint64_t offset;
  size_t size;
};

struct export_bo_arg {
  bo_id bo;
  int fd;
};

struct import_bo_arg {
  int fd;
  uint32_t type;
  size_t size;
  bo_id bo;
  uint64_t xdna_addr;
  void *vaddr;
  uint64_t map_offset;
};

struct submit_cmd_arg {
  uint32_t ctx_handle;
  bo_id cmd_bo;
  const std::set<bo_id>& arg_bos;
  uint64_t seq;
};

struct wait_cmd_arg {
  union {
    uint32_t ctx_handle;
    uint32_t ctx_syncobj_handle;
  };
  uint32_t timeout_ms;
  uint64_t seq;
};

struct create_destroy_syncobj_arg {
  uint32_t handle;
};

struct export_import_syncobj_arg {
  uint32_t handle;
  int fd;
};

struct signal_syncobj_arg {
  uint32_t handle;
  uint64_t timepoint;
};

struct wait_syncobj_arg {
  uint32_t handle;
  uint32_t timeout_ms;
  uint64_t timepoint;
};

struct get_sysfs_arg {
  const std::string& sysfs_node;
  std::vector<char>& data;
  size_t real_size;
};

struct put_sysfs_arg {
  const std::string& sysfs_node;
  const std::vector<char>& data;
};

class platform_drv
{
public:
  platform_drv(std::shared_ptr<const drv>& driver);
  ~platform_drv();

  virtual void
  drv_open(const std::string& sysfs_name) const;

  virtual void
  drv_close() const;

  void
  drv_ioctl(drv_ioctl_cmd cmd, void* arg) const;

  void *
  drv_mmap(void *addr, size_t len, int prot, int flags, off_t offset) const;

  void
  drv_munmap(void* addr, size_t len) const;

  std::shared_ptr<const drv>
  get_pdrv() const;

  static int64_t
  timeout_ms2abs_ns(int64_t timeout_ms);

protected:
  int
  dev_fd() const;

  const std::string&
  sysfs_root() const;

  virtual void
  wait_syncobj(wait_syncobj_arg& arg) const;

  virtual void
  destroy_syncobj(create_destroy_syncobj_arg& arg) const;

  virtual void
  signal_syncobj(signal_syncobj_arg& arg) const;

private:
  std::shared_ptr<const drv> m_driver;

  // Supposed to be set once and used till object is destroyed.
  // No locking protection here. Caller should make sure there is no race.
  mutable int m_dev_fd = -1;
  mutable std::string m_sysfs_root;

  std::string
  get_dev_node(const std::string& sysfs_name);

  virtual void
  create_ctx(create_ctx_arg& arg) const
  { shim_not_supported_err(__func__); }

  virtual void
  destroy_ctx(destroy_ctx_arg& arg) const
  { shim_not_supported_err(__func__); }

  virtual void
  config_ctx_cu_config(config_ctx_cu_config_arg& arg) const
  { shim_not_supported_err(__func__); }

  virtual void
  config_ctx_debug_bo(config_ctx_debug_bo_arg& arg) const
  { shim_not_supported_err(__func__); }

  virtual void
  create_bo(create_bo_arg& arg) const
  { shim_not_supported_err(__func__); }

  virtual void
  create_uptr_bo(create_uptr_bo_arg& arg) const
  { shim_not_supported_err(__func__); }

  virtual void
  destroy_bo(destroy_bo_arg& arg) const
  { shim_not_supported_err(__func__); }

  virtual void
  sync_bo(sync_bo_arg& arg) const
  { shim_not_supported_err(__func__); }

  virtual void
  export_bo(export_bo_arg& arg) const
  { shim_not_supported_err(__func__); }

  virtual void
  import_bo(import_bo_arg& arg) const
  { shim_not_supported_err(__func__); }

  virtual void
  submit_cmd(submit_cmd_arg& arg) const
  { shim_not_supported_err(__func__); }

  virtual void
  wait_cmd_ioctl(wait_cmd_arg& arg) const
  { shim_not_supported_err(__func__); }

  virtual void
  wait_cmd_syncobj(wait_cmd_arg& arg) const
  { shim_not_supported_err(__func__); }

  virtual void
  get_info(amdxdna_drm_get_info& arg) const
  { shim_not_supported_err(__func__); }

  virtual void
  get_info_array(amdxdna_drm_get_info_array& arg) const
  { shim_not_supported_err(__func__); }

  virtual void
  set_state(amdxdna_drm_set_state& arg) const
  { shim_not_supported_err(__func__); }

  virtual void
  create_syncobj(create_destroy_syncobj_arg& arg) const;

  virtual void
  export_syncobj(export_import_syncobj_arg& arg) const;

  virtual void
  import_syncobj(export_import_syncobj_arg& arg) const;

  virtual void
  get_sysfs(get_sysfs_arg& arg) const
  { shim_not_supported_err(__func__); }

  virtual void
  put_sysfs(put_sysfs_arg& arg) const
  { shim_not_supported_err(__func__); }
};

}

#endif

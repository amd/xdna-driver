// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2022-2025, Advanced Micro Devices, Inc. All rights reserved.

#ifndef PCIDRV_XDNA_H_
#define PCIDRV_XDNA_H_

#include "drm_local/amdxdna_accel.h"
#include "core/pcie/linux/pcidrv.h"

namespace shim_xdna {

enum class drv_ioctl_cmd {
  create_ctx,
  destroy_ctx,
  config_ctx_cu_config,
  config_ctx_debug_bo,

  create_bo,
  destroy_bo,
  sync_bo,
  export_bo,
  import_bo,

  submit_cmd,
  submit_dep,
  submit_sig,
  wait_cmd,

  get_info,
  set_state,

  create_syncobj,
  destroy_syncobj,
  export_syncobj,
  import_syncobj,
  wait_syncobj,
};

struct bo_id {
  uint32_t handle;
  uint32_t res_id;
};

struct create_ctx_arg {
 	const amdxdna_qos_info& qos;
	uint32_t umq_bo;
	uint32_t log_buf_bo;
	uint32_t max_opc;
	uint32_t num_tiles;
	uint32_t mem_size;
	uint32_t ctx_handle;
	uint32_t umq_doorbell;
	uint32_t syncobj_handle;
};

struct destroy_ctx_arg {
  uint32_t ctx_handle;
};

struct config_ctx_cu_config_arg {
  uint32_t ctx_handle;
  const std::vector<char>& conf_buf;
};

struct config_ctx_debug_bo_arg {
  uint32_t ctx_handle;
  bool is_detach;
  uint32_t bo;
};

struct create_bo_arg {
  int type;
  size_t size;
  bo_id id;
  uint64_t paddr;
  void *vaddr;
  uint64_t map_offset;
};

struct destroy_bo_arg {
  bo_id id;
};

struct sync_bo_arg {
  uint32_t handle;
  xrt_core::buffer_handle::direction direction;
  uint64_t offset;
  size_t size;
};

struct export_bo_arg {
  bo_id id;
  int fd;
};

struct import_bo_arg {
  int fd;
  uint32_t type;
  size_t size;
  bo_id id;
  uint64_t paddr;
  void *vaddr;
  uint64_t map_offset;
};

struct submit_cmd_arg {
  uint32_t ctx_handle;
  uint32_t cmd_bo;
  uint32_t *arg_bo_host_handles;
  size_t num_arg_bos;
  uint64_t seq;
};

struct submit_dep_arg {
  uint32_t ctx_handle;
  uint32_t count;
  uint32_t *sync_objs;
  uint64_t *sync_points;
};

struct submit_sig_arg {
  uint32_t ctx_handle;
  uint32_t sync_obj;
  uint64_t sync_obj_point;
};

struct wait_cmd_arg {
  uint32_t sync_obj;
  uint64_t seq;
  uint32_t timeout_ms;
  bool timedout;
};

struct create_destroy_syncobj_arg {
  uint32_t handle;
};

struct export_import_syncobj_arg {
  uint32_t handle;
  int fd;
};

struct wait_syncobj_arg {
  uint32_t handle;
  uint32_t timeout_ms;
  uint64_t timepoint;
};

class drv : public xrt_core::pci::drv
{
public:
  bool
  is_user() const override;

public:
  virtual void
  drv_ioctl(int dev_fd, drv_ioctl_cmd cmd, void* arg) const = 0;

private:
  // Set once and never change
  mutable int m_device_type = AMDXDNA_DEV_TYPE_UNKNOWN;

  std::shared_ptr<xrt_core::pci::dev>
  create_pcidev(const std::string& sysfs) const override;

  virtual int
  get_dev_type(const std::string& sysfs) const = 0;
};

}

#endif

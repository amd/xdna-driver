// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2025, Advanced Micro Devices, Inc. All rights reserved.

#ifndef PLAT_HOST_H
#define PLAT_HOST_H

#include "../platform.h"

namespace shim_xdna {

class platform_drv_host : public platform_drv
{
public:
  using platform_drv::platform_drv;

private:
  void
  create_ctx(create_ctx_arg& arg) const override;

  void
  destroy_ctx(destroy_ctx_arg& arg) const override;

  void
  config_ctx_cu_config(config_ctx_cu_config_arg& arg) const override;

  void
  config_ctx_debug_bo(config_ctx_debug_bo_arg& arg) const override;

  void
  create_bo(create_bo_arg& arg) const override;

  void
  create_uptr_bo(create_uptr_bo_arg& arg) const override;

  void
  destroy_bo(destroy_bo_arg& arg) const override;

  void
  sync_bo(sync_bo_arg& arg) const override;

  void
  export_bo(export_bo_arg& arg) const override;

  void
  import_bo(import_bo_arg& arg) const override;

  void
  submit_cmd(submit_cmd_arg& arg) const override;

  void
  wait_cmd_ioctl(wait_cmd_arg& arg) const override;

  void
  wait_cmd_syncobj(wait_cmd_arg& arg) const override;

  void
  get_info(amdxdna_drm_get_info& arg) const override;

  void
  get_info_array(amdxdna_drm_get_info_array& arg) const override;

  void
  set_state(amdxdna_drm_set_state& arg) const override;

  std::pair<uint64_t, uint64_t>
  get_bo_info(uint32_t boh) const;

  std::tuple<uint32_t, uint64_t, uint64_t>
  create_drm_bo(void *uva_tbl, size_t size, int type) const;

  void
  get_sysfs(get_sysfs_arg& arg) const override;

  void
  put_sysfs(put_sysfs_arg& arg) const override;
};

}

#endif

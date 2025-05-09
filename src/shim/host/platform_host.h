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
  submit_dep(submit_dep_arg& arg) const override;

  void
  submit_sig(submit_sig_arg& arg) const override;

  void
  wait_cmd(wait_cmd_arg& arg) const override;

  void
  get_info(amdxdna_drm_get_info& arg) const override;

  void
  get_info_array(amdxdna_drm_get_info_array& arg) const override;

  void
  set_state(amdxdna_drm_set_state& arg) const override;

  void
  create_syncobj(create_destroy_syncobj_arg& arg) const override;

  void
  destroy_syncobj(create_destroy_syncobj_arg& arg) const override;

  void
  export_syncobj(export_import_syncobj_arg& arg) const override;

  void
  import_syncobj(export_import_syncobj_arg& arg) const override;

  void
  signal_syncobj(signal_syncobj_arg& arg) const override;

  void
  wait_syncobj(wait_syncobj_arg& arg) const override;
};

}

#endif

// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2025, Advanced Micro Devices, Inc. All rights reserved.

#ifndef PLAT_VIRTIO_H
#define PLAT_VIRTIO_H

#include "../platform.h"
#include <string>

namespace shim_xdna {

class platform_drv_virtio : public platform_drv
{
public:
  using platform_drv::platform_drv;

  void
  drv_open(const std::string& sysfs_name) const override;

  void
  drv_close() const override;

private:

  // Managing response buffer for hypercall.
  class response_buffer {
  public:
    response_buffer(int dev_fd);
    ~response_buffer();

    uint32_t
    res_id() const;

    void *
    get() const;

  private:
    int m_dev_fd = -1;
    bo_id m_id;
    void *m_ptr = nullptr;
  };

  // Setup once and used forever
  mutable std::unique_ptr<response_buffer> m_resp_buf;
  // Lock to serialize hypercall.
  mutable std::mutex m_lock;

  void
  hcall(void *req, void *out_buf, size_t out_size) const;

  void
  hcall(void *req) const;

  void
  create_ctx(create_ctx_arg& arg) const override;

  void
  destroy_ctx(destroy_ctx_arg& arg) const override;

  std::pair<uint32_t, uint64_t>
  host_bo_alloc(int type, size_t size, uint32_t res_id, uint64_t align) const;

  void
  host_bo_free(uint32_t host_hdl) const;

  void
  create_bo(create_bo_arg& arg) const override;

  void
  destroy_bo(destroy_bo_arg& arg) const override;

  void
  get_info(amdxdna_drm_get_info& arg) const override;

  void
  config_ctx_cu_config(config_ctx_cu_config_arg& arg) const override;

  void
  submit_cmd(submit_cmd_arg& arg) const override;

  void
  wait_cmd_syncobj(wait_cmd_arg& arg) const override;

  void
  export_bo(export_bo_arg& arg) const override;

  void
  import_bo(import_bo_arg& arg) const override;
};

}

#endif

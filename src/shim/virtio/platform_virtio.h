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

  void
  drv_ioctl(drv_ioctl_cmd cmd, void* arg) const override;

private:
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
    uint32_t m_bo = AMDXDNA_INVALID_BO_HANDLE;
    uint32_t m_res = AMDXDNA_INVALID_BO_HANDLE;
    void *m_ptr = nullptr;
  };
  // Setup once and used forever
  mutable std::unique_ptr<response_buffer> m_resp_buf;

  void
  hcall(int dev_fd, void *in_buf, size_t in_size, void *out_buf, size_t out_size) const;
};

}

#endif

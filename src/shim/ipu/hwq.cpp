// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2023-2024, Advanced Micro Devices, Inc. All rights reserved.

#include "bo.h"
#include "hwq.h"

namespace shim_xdna {

hw_q_ipu::
hw_q_ipu(const device& device) : hw_q(device)
{
  shim_debug("Created IPU HW queue");
}

hw_q_ipu::
~hw_q_ipu()
{
  shim_debug("Destroying IPU HW queue");
}

void
hw_q_ipu::
submit_command(xrt_core::buffer_handle *cmd_bo)
{
  auto boh = static_cast<bo*>(cmd_bo);
  int ret = EAGAIN;

  amdxdna_drm_exec_cmd ecmd = {
    .handle = boh->get_drm_bo_handle(),
    .hwctx = m_hwctx->get_slotidx(),
  };

  while (ret == EAGAIN) {
    try {
      m_pdev.ioctl(DRM_IOCTL_AMDXDNA_EXEC_CMD, &ecmd);
      ret = 0;
    }
    catch (const xrt_core::system_error& ex) {
      ret = ex.get_code();
      if (ret != EAGAIN)
        throw;
      amdxdna_drm_wait_cmd wcmd = {
        .hwctx = ecmd.hwctx,
        .timeout = 0, // Infinite waiting
        .seq = AMDXDNA_INVALID_CMD_HANDLE, // Wait for free slot
      };
      m_pdev.ioctl(DRM_IOCTL_AMDXDNA_WAIT_CMD, &wcmd);
    }
  }
  auto id = ecmd.seq;
  boh->set_cmd_id(id);
  shim_debug("Submitted command (%ld)", id);
}

} // shim_xdna

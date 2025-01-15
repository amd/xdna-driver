// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2023-2025, Advanced Micro Devices, Inc. All rights reserved.

#include "bo.h"
#include "hwq.h"

namespace shim_xdna {

hw_q_kmq::
hw_q_kmq(const device& device) : hw_q(device)
{
  shim_debug("Created KMQ HW queue");
}

hw_q_kmq::
~hw_q_kmq()
{
  shim_debug("Destroying KMQ HW queue");
}

void
hw_q_kmq::
issue_command(xrt_core::buffer_handle *cmd_bo)
{
  // Assuming 1024 max args per cmd bo
  const size_t max_arg_bos = 1024;

  uint32_t arg_bo_hdls[max_arg_bos];
  auto boh = static_cast<bo_kmq*>(cmd_bo);
  uint32_t cmd_bo_hdl = boh->get_drm_bo_handle();

  amdxdna_drm_exec_cmd ecmd = {
    .ctx = m_hwctx->get_slotidx(),
    .type = AMDXDNA_CMD_SUBMIT_EXEC_BUF,
    .cmd_handles = cmd_bo_hdl,
    .args = reinterpret_cast<uintptr_t>(arg_bo_hdls),
    .cmd_count = 1,
    .arg_count = static_cast<uint32_t>(boh->get_arg_bo_handles(arg_bo_hdls, max_arg_bos)),
  };
  m_pdev.ioctl(DRM_IOCTL_AMDXDNA_EXEC_CMD, &ecmd);

  auto id = ecmd.seq;
  boh->set_cmd_id(id);
  shim_debug("Submitted command (%ld)", id);
}

void
hw_q_kmq::
bind_hwctx(const hw_ctx *ctx)
{
  // link hwctx by parent class
  hw_q::bind_hwctx(ctx);
}

} // shim_xdna

// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2023-2025, Advanced Micro Devices, Inc. All rights reserved.

#include "hwq.h"

namespace shim_xdna {

hwq_kmq::
hwq_kmq(const device& device) : hwq(device)
{
  shim_debug("Created KMQ HW queue");
}

hwq_kmq::
~hwq_kmq()
{
  shim_debug("Destroying KMQ HW queue");
}

void
hwq_kmq::
issue_command(cmd_buffer *cmd_bo)
{
  // Assuming 1024 max args per cmd bo
  const size_t max_arg_bos = 1024;

  uint32_t arg_bo_hdls[max_arg_bos];
  uint32_t cmd_bo_hdl = cmd_bo->handle();
  auto arg_bos = cmd_bo->get_arg_bo_handles();
  if (arg_bos.size() > max_arg_bos)
    shim_err(EINVAL, "Too many cmd args");

  size_t i = 0;
  for (auto hdl : arg_bos)
    arg_bo_hdls[i++] = hdl;

  submit_cmd_arg ecmd = {
    .ctx_handle = m_ctx_id,
    .cmd_bo = cmd_bo_hdl,
    .arg_bo_handles = arg_bo_hdls,
    .num_arg_bos = arg_bos.size(),
  };
  m_pdev.drv_ioctl(drv_ioctl_cmd::submit_cmd, &ecmd);

  auto id = ecmd.seq;
  cmd_bo->set_cmd_id(id);
  shim_debug("Submitted command (%ld)", id);
}

uint32_t
hwq_kmq::
get_queue_bo() const
{
  return AMDXDNA_INVALID_BO_HANDLE;
}

}

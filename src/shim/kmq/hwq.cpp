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

uint64_t
hwq_kmq::
issue_command(const cmd_buffer *cmd_bo)
{
  submit_cmd_arg ecmd = {
    .ctx_handle = m_ctx->get_slotidx(),
    .cmd_bo = cmd_bo->id(),
    .arg_bos = cmd_bo->get_arg_bo_ids(),
  };
  m_pdev.drv_ioctl(drv_ioctl_cmd::submit_cmd, &ecmd);
  shim_debug("Submitted command (%ld)", ecmd.seq);
  return ecmd.seq;
}

bo_id
hwq_kmq::
get_queue_bo() const
{
  return { AMDXDNA_INVALID_BO_HANDLE, AMDXDNA_INVALID_BO_HANDLE };
}

}

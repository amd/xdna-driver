// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2023-2024, Advanced Micro Devices, Inc. All rights reserved.

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
submit_command(xrt_core::buffer_handle *cmd_bo)
{
  std::vector<xrt_core::buffer_handle *> cmd_bos {cmd_bo};
  return submit_command(cmd_bos);
}

void
hw_q_kmq::
submit_command(const std::vector<xrt_core::buffer_handle *>& cmd_bos)
{
  // Assuming 256 max cmds and 256 max args per cmd bo
  const size_t max_cmd_bos = 256;
  const size_t max_arg_bos = max_cmd_bos << 8;

  auto num_cmd_bos = cmd_bos.size();
  if (num_cmd_bos > max_cmd_bos)
    shim_err(EINVAL, "Too many cmds (%ld) in the list", num_cmd_bos);

  uint32_t cmd_bo_hdls[max_cmd_bos];
  uint32_t arg_bo_hdls[max_arg_bos];
  size_t arg_cnt = 0;

  for (size_t cmd_cnt = 0; cmd_cnt < num_cmd_bos; cmd_cnt++) {
    auto boh = static_cast<bo_kmq*>(cmd_bos[cmd_cnt]);
    cmd_bo_hdls[cmd_cnt] = boh->get_drm_bo_handle();
    auto cur_arg_cnt = boh->get_arg_bo_handles(&arg_bo_hdls[arg_cnt], max_arg_bos - arg_cnt);
    arg_cnt += cur_arg_cnt;
  }

  amdxdna_drm_exec_cmd ecmd = {
    .hwctx = m_hwctx->get_slotidx(),
    .cmd_bo_handles = reinterpret_cast<uintptr_t>(cmd_bo_hdls),
    .arg_bo_handles = reinterpret_cast<uintptr_t>(arg_bo_hdls),
    .cmd_bo_count = static_cast<uint32_t>(num_cmd_bos),
    .arg_bo_count = static_cast<uint32_t>(arg_cnt),
  };

  int ret = EAGAIN;
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

  // All command BOs share the same cmd ID.
  for (size_t cmd_cnt = 0; cmd_cnt < num_cmd_bos; cmd_cnt++) {
    auto boh = static_cast<bo_kmq*>(cmd_bos[cmd_cnt]);
    boh->set_cmd_id(id);
  }
  shim_debug("Submitted command (%ld)", id);
}

void
hw_q_kmq::
map_doorbell(uint32_t doorbell_offset)
{
  //No-op
}

} // shim_xdna

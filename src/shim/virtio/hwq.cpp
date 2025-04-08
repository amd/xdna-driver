// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2025, Advanced Micro Devices, Inc. All rights reserved.

#include "bo.h"
#include "hwq.h"
#include "pcidev.h"
#include "amdxdna_proto.h"

namespace shim_xdna {

hw_q_virtio::
hw_q_virtio(const device& device) : hw_q(device)
{
  shim_debug("Created VIRTIO HW queue");
}

hw_q_virtio::
~hw_q_virtio()
{
  shim_debug("Destroying VIRTIO HW queue");
}

void
hw_q_virtio::
issue_command(xrt_core::buffer_handle *cmd_bo)
{
  auto boh = static_cast<bo_virtio*>(cmd_bo);
  uint32_t cmd_bo_hdl = boh->get_host_bo_handle();
  const shim_xdna::pdev_virtio& vdev = static_cast<const shim_xdna::pdev_virtio&>(m_pdev);

  amdxdna_ccmd_exec_cmd_rsp rsp = {};

  // Get a 64 bit aligned buffer for req
  auto req_sz_in_u64 =
    (sizeof(amdxdna_ccmd_exec_cmd_req) + sizeof(uint64_t)) / sizeof(uint64_t) + 1;
  uint64_t req_buf[req_sz_in_u64];
  auto req = reinterpret_cast<amdxdna_ccmd_exec_cmd_req*>(req_buf);

  req->hdr.cmd = AMDXDNA_CCMD_EXEC_CMD;
  req->hdr.len = sizeof(req);
  req->hdr.rsp_off = 0;
  req->ctx_handle = m_hwctx->get_slotidx();
  req->type = AMDXDNA_CMD_SUBMIT_EXEC_BUF;
  req->cmd_count = 1;
  req->arg_count = 0;
  req->cmds_n_args[0] = cmd_bo_hdl;
  vdev.host_call(&req, sizeof(req), &rsp, sizeof(rsp));

  auto id = rsp.seq;
  boh->set_cmd_id(id);
  shim_debug("Submitted virtio command (%ld)", id);
}

int
hw_q_virtio::
wait_command(xrt_core::buffer_handle *cmd, uint32_t timeout_ms) const
{
  auto boh = static_cast<shim_xdna::bo*>(cmd);
  auto seq = boh->get_cmd_id();

  shim_debug("Waiting for virtio cmd (%ld)...", seq);
  return 1;
}

} // shim_xdna

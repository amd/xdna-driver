// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2023-2025, Advanced Micro Devices, Inc. All rights reserved.

#include "hwq.h"
#include "fence.h"
#include "buffer.h"
#include "shim_debug.h"
#include "core/common/trace.h"

namespace shim_xdna {

hwq::
hwq(const device& device)
  : m_pdev(device.get_pdev())
{
}

hwq::
~hwq()
{
}

void
hwq::
bind_hwctx(const hwctx& ctx)
{
  m_ctx = &ctx;
}

void
hwq::
unbind_hwctx()
{
  m_ctx = nullptr;
}

void
hwq::
submit_command(xrt_core::buffer_handle *cmd)
{
  auto boh = static_cast<cmd_buffer*>(cmd);
  issue_command(boh);
}

int
hwq::
poll_command(xrt_core::buffer_handle *cmd) const
{
  auto boh = static_cast<cmd_buffer*>(cmd);
  auto cmdpkt = reinterpret_cast<ert_packet *>(boh->vaddr());

  if (cmdpkt->state >= ERT_CMD_STATE_COMPLETED) {
    XRT_TRACE_POINT_LOG(poll_command_done);
    return 1;
  }
  return 0;
}

int
hwq::
wait_command(uint64_t seq, uint32_t timeout_ms) const
{
  int ret = 1;

  shim_debug("Waiting for cmd (%ld)...", seq);
  try {
    wait_cmd_arg wcmd = {
      .timeout_ms = timeout_ms,
      .seq = seq,
    };

    auto syncobj = m_ctx->get_syncobj();
    if (syncobj != AMDXDNA_INVALID_FENCE_HANDLE) {
      wcmd.ctx_syncobj_handle = syncobj;
      m_pdev.drv_ioctl(drv_ioctl_cmd::wait_cmd_syncobj, &wcmd);
    } else {
      wcmd.ctx_handle = m_ctx->get_slotidx();
      m_pdev.drv_ioctl(drv_ioctl_cmd::wait_cmd_ioctl, &wcmd);
    }
  }
  catch (const xrt_core::system_error& ex) {
    if (ex.get_code() != ETIME)
      throw;
    else
      ret = 0;
  }
  return ret;
}

int
hwq::
wait_command(xrt_core::buffer_handle *cmd, uint32_t timeout_ms) const
{
  if (poll_command(cmd))
      return 1;

  auto boh = static_cast<cmd_buffer*>(cmd);
  auto seq = boh->get_cmd_seq();
  return wait_command(seq, timeout_ms);
}

void
hwq::
submit_wait(const xrt_core::fence_handle* f)
{
  auto fh = static_cast<const fence*>(f);
  fh->submit_wait(*m_ctx);
}

void
hwq::
submit_signal(const xrt_core::fence_handle* f)
{
  auto fh = static_cast<const fence*>(f);
  fh->submit_signal(*m_ctx);
}

}

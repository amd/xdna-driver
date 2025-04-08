// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2023-2025, Advanced Micro Devices, Inc. All rights reserved.

#include "bo.h"
#include "hwq.h"
#include "fence.h"
#include "shim_debug.h"
#include "core/common/trace.h"

namespace {

uint64_t abs_now_ns()
{
    auto now = std::chrono::high_resolution_clock::now();
    auto now_ns = std::chrono::time_point_cast<std::chrono::nanoseconds>(now);
    return now_ns.time_since_epoch().count();
}

ert_packet *
get_chained_command_pkt(xrt_core::buffer_handle *boh)
{
  auto cmdpkt = reinterpret_cast<ert_packet *>(boh->map(xrt_core::buffer_handle::map_type::write));
  return cmdpkt->opcode == ERT_CMD_CHAIN ? cmdpkt : nullptr;
}

void
wait_cmd_syncobj(const shim_xdna::pdev& pdev, uint32_t syncobj, uint64_t seq, uint32_t timeout_ms)
{
  int64_t timeout = std::numeric_limits<int64_t>::max();

  if (timeout_ms) {
	  timeout = timeout_ms;
	  timeout *= 1000000;
	  timeout += abs_now_ns();
  }
  drm_syncobj_timeline_wait wsobj = {
    .handles = reinterpret_cast<uintptr_t>(&syncobj),
    .points = reinterpret_cast<uintptr_t>(&seq),
    .timeout_nsec = timeout,
    .count_handles = 1,
    .flags = 0,
  };
  pdev.ioctl(DRM_IOCTL_SYNCOBJ_TIMELINE_WAIT, &wsobj);
}

void
wait_cmd_ioctl(const shim_xdna::pdev& pdev, uint32_t ctx_id, uint64_t seq, uint32_t timeout_ms)
{
  amdxdna_drm_wait_cmd wcmd = {
    .ctx = ctx_id,
    .timeout = timeout_ms,
    .seq = seq,
  };
  pdev.ioctl(DRM_IOCTL_AMDXDNA_WAIT_CMD, &wcmd);
}

int
wait_cmd(const shim_xdna::pdev& pdev, const shim_xdna::hw_ctx *ctx,
  xrt_core::buffer_handle *cmd, uint32_t timeout_ms)
{
  int ret = 1;
  auto boh = static_cast<shim_xdna::bo*>(cmd);
  auto syncobj = ctx->get_syncobj();
  auto ctx_id = ctx->get_slotidx();
  auto seq = boh->get_cmd_id();

  shim_debug("Waiting for cmd (%ld)...", seq);
  
  try {
    if (syncobj != AMDXDNA_INVALID_FENCE_HANDLE)
      wait_cmd_syncobj(pdev, syncobj, seq, timeout_ms);
    else
      wait_cmd_ioctl(pdev, ctx_id, seq, timeout_ms);
  }
  catch (const xrt_core::system_error& ex) {
    if (ex.get_code() != ETIME)
      throw;
    else
      ret = 0;
  }
  return ret;
}

}

namespace shim_xdna {

hw_q::
hw_q(const device& device)
  : m_hwctx(nullptr)
  , m_queue_boh(AMDXDNA_INVALID_BO_HANDLE)
  , m_pdev(device.get_pdev())
{
}

void
hw_q::
bind_hwctx(const hw_ctx *ctx)
{
  m_hwctx = ctx;
  shim_debug("Bond HW queue to HW context %d", m_hwctx->get_slotidx());
}

void
hw_q::
unbind_hwctx()
{
  shim_debug("Unbond HW queue from HW context %d", m_hwctx->get_slotidx());
  m_hwctx = nullptr;
}

uint32_t
hw_q::
get_queue_bo()
{
  return m_queue_boh;
}

void
hw_q::
submit_command(xrt_core::buffer_handle *cmd)
{
  issue_command(cmd);
}

int
hw_q::
poll_command(xrt_core::buffer_handle *cmd) const
{
  auto cmdpkt = reinterpret_cast<ert_packet *>(cmd->map(xrt_core::buffer_handle::map_type::write));

  if (cmdpkt->state >= ERT_CMD_STATE_COMPLETED) {
    XRT_TRACE_POINT_LOG(poll_command_done);
    return 1;
  }
  return 0;
}

int
hw_q::
wait_command(xrt_core::buffer_handle *cmd, uint32_t timeout_ms) const
{
  if (poll_command(cmd))
      return 1;
  return wait_cmd(m_pdev, m_hwctx, cmd, timeout_ms);
}

void
hw_q::
submit_wait(const xrt_core::fence_handle* f)
{
  auto fh = static_cast<const fence*>(f);
  fh->submit_wait(m_hwctx);
}

void
hw_q::
submit_wait(const std::vector<xrt_core::fence_handle*>& fences)
{
  fence::submit_wait(m_pdev, m_hwctx, fences);
}

void
hw_q::
submit_signal(const xrt_core::fence_handle* f)
{
  auto fh = static_cast<const fence*>(f);
  fh->submit_signal(m_hwctx);
}

} // shim_xdna

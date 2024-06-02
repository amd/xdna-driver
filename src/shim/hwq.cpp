// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2023-2024, Advanced Micro Devices, Inc. All rights reserved.

#include "bo.h"
#include "hwq.h"
#include "shim_debug.h"

namespace {

ert_packet *
get_chained_command_pkt(xrt_core::buffer_handle *boh)
{
  auto cmdpkt = reinterpret_cast<ert_packet *>(boh->map(xrt_core::buffer_handle::map_type::write));
  return cmdpkt->opcode == ERT_CMD_CHAIN ? cmdpkt : nullptr;
}

int
wait_cmd(const shim_xdna::pdev& pdev, const shim_xdna::hw_ctx *ctx,
  xrt_core::buffer_handle *cmd, uint32_t timeout_ms)
{
  int ret = 1;
  auto boh = static_cast<shim_xdna::bo*>(cmd);
  auto id = boh->get_cmd_id();

  shim_debug("Waiting for cmd (%ld)...", id);

  amdxdna_drm_wait_cmd wcmd = {
    .hwctx = ctx->get_slotidx(),
    .timeout = timeout_ms,
    .seq = boh->get_cmd_id(),
  };

  try {
    pdev.ioctl(DRM_IOCTL_AMDXDNA_WAIT_CMD, &wcmd);
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
  auto pkt = get_chained_command_pkt(cmd);
  if (!m_pdev.is_force_unchained_command() || !pkt) {
    issue_command(cmd);
    return;
  }

  // HACK: Forcibly unchain commands, to be removed later.
  //
  // Forcibly unchain commands and send to driver one by one.
  auto payload = get_ert_cmd_chain_data(pkt);
  for (size_t i = 0; i < payload->command_count; i++) {
    auto boh = reinterpret_cast<xrt_core::buffer_handle*>(
      m_pdev.lookup_hdl_mapping(static_cast<uint32_t>(payload->data[i])));
    issue_command(boh);
  }
}

int
hw_q::
wait_command(xrt_core::buffer_handle *cmd, uint32_t timeout_ms) const
{
  auto pkt = get_chained_command_pkt(cmd);
  if (!m_pdev.is_force_unchained_command() || !pkt)
    return wait_cmd(m_pdev, m_hwctx, cmd, timeout_ms);

  // HACK: handling forcibly unchained commands, to be removed later.
  //
  // Wait for the last unchained command.
  auto payload = get_ert_cmd_chain_data(pkt);
  auto last_boh = reinterpret_cast<xrt_core::buffer_handle*>(
    m_pdev.lookup_hdl_mapping(static_cast<uint32_t>(payload->data[payload->command_count-1])));
  auto ret = wait_cmd(m_pdev, m_hwctx, last_boh, timeout_ms);
  if (ret != 1)
    return ret;

  // Check the state of the last command.
  auto cmdpkt = reinterpret_cast<ert_packet *>(last_boh->map(xrt_core::buffer_handle::map_type::read));
  if (cmdpkt->state == ERT_CMD_STATE_COMPLETED) {
    pkt->state = ERT_CMD_STATE_COMPLETED;
    return 0;
  }

  // Find out the first command failed.
  for (int i = 0; i < payload->command_count; i++) {
    auto boh = reinterpret_cast<xrt_core::buffer_handle*>(
      m_pdev.lookup_hdl_mapping(static_cast<uint32_t>(payload->data[i])));
    cmdpkt = reinterpret_cast<ert_packet *>(boh->map(xrt_core::buffer_handle::map_type::read));
    if (cmdpkt->state != ERT_CMD_STATE_COMPLETED) {
      pkt->state = cmdpkt->state;
      payload->error_index = i;
      break;
    }
  }
  return 0;
}

} // shim_xdna

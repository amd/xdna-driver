// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2025, Advanced Micro Devices, Inc. All rights reserved.

#include "shim_debug.h"
#include "xdna_bo.h"
#include "xdna_hwq.h"

namespace shim_xdna_edge {

xdna_hwq::
xdna_hwq(const device_xdna& device)
  : m_hwctx(nullptr)
  , m_queue_boh(AMDXDNA_INVALID_BO_HANDLE)
  , m_edev(device.get_edev())
{
}

void
xdna_hwq::
bind_hwctx(const xdna_hwctx *ctx)
{
  m_hwctx = ctx;
  shim_debug("Bond HW queue to HW context %d", m_hwctx->get_slotidx());
}

void
xdna_hwq::
unbind_hwctx()
{
  shim_debug("Unbond HW queue from HW context %d", m_hwctx->get_slotidx());
  m_hwctx = nullptr;
}

uint32_t
xdna_hwq::
get_queue_bo()
{
  return m_queue_boh;
}

void
xdna_hwq::
submit_command(xrt_core::buffer_handle *cmd_bo)
{
  shim_debug("Calling %s", __func__);
  const size_t max_arg_bos = 1024;
  uint32_t arg_bo_hdls[max_arg_bos];
  auto boh = static_cast<shim_xdna_edge::xdna_bo*>(cmd_bo);
  uint32_t cmd_bo_hdl = boh->get_drm_bo_handle();

  amdxdna_drm_exec_cmd ecmd = {
    .ctx = m_hwctx->get_slotidx(),
    .cmd_handles = boh->get_drm_bo_handle(),
    .args = reinterpret_cast<uintptr_t>(arg_bo_hdls),
    .cmd_count = 1,
    .arg_count = static_cast<uint32_t>(boh->get_arg_bo_handles(arg_bo_hdls, max_arg_bos)),
  };

  m_edev->ioctl(DRM_IOCTL_AMDXDNA_EXEC_CMD, &ecmd);
  auto id = ecmd.seq;
  boh->set_cmd_id(id);
  shim_debug("Submitted command (%ld)", id);
}

int
xdna_hwq::
wait_command(xrt_core::buffer_handle *cmd_bo, uint32_t timeout_ms) const
{
  int ret = 1;
  auto boh = static_cast<shim_xdna_edge::xdna_bo*>(cmd_bo);
  auto id = boh->get_cmd_id();

  shim_debug("Waiting for cmd (%ld)...", id);
  amdxdna_drm_wait_cmd wcmd = {
    .ctx = m_hwctx->get_slotidx(),
    .timeout = timeout_ms,
    .seq = boh->get_cmd_id(),
  };

  try {
    m_edev->ioctl(DRM_IOCTL_AMDXDNA_WAIT_CMD, &wcmd);
  }
  catch (const xrt_core::system_error& ex) {
    if (ex.get_code() != ETIME)
      throw;
    else
      ret = 0;
  }

  return ret;
}

} // shim_xdna_edge

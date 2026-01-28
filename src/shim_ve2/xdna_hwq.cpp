// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2025, Advanced Micro Devices, Inc. All rights reserved.

#include "shim_debug.h"
#include "xdna_bo.h"
#include "xdna_hwq.h"

namespace shim_xdna_edge {

xdna_hwq::
xdna_hwq(const device_xdna* device)
  : m_hwctx(nullptr)
  , m_queue_boh(AMDXDNA_INVALID_BO_HANDLE)
{
  shim_debug("Created HW queue");
}

void
xdna_hwq::
bind_hwctx(const xdna_hwctx *ctx)
{
  if (m_hwctx)
    shim_err(EINVAL, "HW queue already bound to hwctx %d, cannot bind to another",
             m_hwctx->get_slotidx());
  m_hwctx = const_cast<xdna_hwctx*>(ctx);
  shim_debug("Bound HW queue to hwctx %d", m_hwctx->get_slotidx());
}

void
xdna_hwq::
unbind_hwctx()
{
  if (!m_hwctx) {
    shim_debug("HW queue not bound to any hwctx, skipping unbind");
    return;
  }
  shim_debug("Unbinding HW queue from hwctx %d", m_hwctx->get_slotidx());
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
  const size_t max_arg_bos = 1024;
  uint32_t arg_bo_hdls[max_arg_bos];

  if (!cmd_bo)
    shim_err(EINVAL, "submit_command: cmd_bo is NULL");

  auto boh = static_cast<shim_xdna_edge::xdna_bo*>(cmd_bo);
  uint32_t cmd_bo_hdl = boh->get_drm_bo_handle();

  if (!m_hwctx)
    shim_err(EINVAL, "submit_command: No hwctx bound to HW queue");

  auto hwctx_id = m_hwctx->get_slotidx();
  auto arg_count = static_cast<uint32_t>(boh->get_arg_bo_handles(arg_bo_hdls, max_arg_bos));

  shim_debug("Submitting command: hwctx=%u, cmd_bo_hdl=%u, arg_count=%u",
             hwctx_id, cmd_bo_hdl, arg_count);

  amdxdna_drm_exec_cmd ecmd = {
    .hwctx = hwctx_id,
    .cmd_handles = cmd_bo_hdl,
    .args = reinterpret_cast<uintptr_t>(arg_bo_hdls),
    .cmd_count = 1,
    .arg_count = arg_count,
  };

  try {
    m_hwctx->get_device()->get_edev()->ioctl(DRM_IOCTL_AMDXDNA_EXEC_CMD, &ecmd);
  } catch (const xrt_core::system_error& ex) {
    shim_err(ex.get_code(), "DRM_IOCTL_AMDXDNA_EXEC_CMD failed: hwctx=%u, cmd_bo_hdl=%u",
             hwctx_id, cmd_bo_hdl);
  }

  auto id = ecmd.seq;
  boh->set_cmd_id(id);
  shim_debug("Command submitted: hwctx=%u, seq=%ld", hwctx_id, id);
}

int
xdna_hwq::
wait_command(xrt_core::buffer_handle *cmd_bo, uint32_t timeout_ms) const
{
  int ret = 1;

  if (!cmd_bo)
    shim_err(EINVAL, "wait_command: cmd_bo is NULL");

  auto boh = static_cast<shim_xdna_edge::xdna_bo*>(cmd_bo);
  auto id = boh->get_cmd_id();

  if (!m_hwctx)
    shim_err(EINVAL, "wait_command: No hwctx bound to HW queue");

  auto hwctx_id = m_hwctx->get_slotidx();

  shim_debug("Waiting for command: hwctx=%u, seq=%ld, timeout_ms=%u",
             hwctx_id, id, timeout_ms);

  amdxdna_drm_wait_cmd wcmd = {
    .hwctx = hwctx_id,
    .timeout = timeout_ms,
    .seq = boh->get_cmd_id(),
  };

  try {
    m_hwctx->get_device()->get_edev()->ioctl(DRM_IOCTL_AMDXDNA_WAIT_CMD, &wcmd);
    shim_debug("Command completed: hwctx=%u, seq=%ld", hwctx_id, id);
  }
  catch (const xrt_core::system_error& ex) {
    int err_code = ex.get_code();
    if (err_code == ETIME) {
      shim_debug("Command wait timeout: hwctx=%u, seq=%ld, timeout_ms=%u (err=%d: %s)",
                 hwctx_id, id, timeout_ms, err_code, errno_to_str(err_code));
      ret = 0;
    } else {
      shim_debug("Command wait failed: hwctx=%u, seq=%ld, err=%d: %s (%s)",
                 hwctx_id, id, err_code, errno_to_str(err_code), ex.what());
      throw;
    }
  }

  return ret;
}

} // shim_xdna_edge

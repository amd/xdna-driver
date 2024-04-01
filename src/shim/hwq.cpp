// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2023-2024, Advanced Micro Devices, Inc. All rights reserved.

#include "bo.h"
#include "hwq.h"
#include "shim_debug.h"

namespace shim_xdna {

hw_q::
hw_q(const device& device)
  : m_hwctx(nullptr)
  , m_queue_ptr(nullptr)
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

const void *
hw_q::
get_queue_addr()
{
  return m_queue_ptr;
}

int
hw_q::
wait_command(xrt_core::buffer_handle *cmd, uint32_t timeout_ms) const
{
  int ret = 1;
  auto boh = static_cast<bo*>(cmd);
  auto id = boh->get_cmd_id();

  shim_debug("Waiting for cmd (%ld)...", id);

  amdxdna_drm_wait_cmd wcmd = {
    .hwctx = m_hwctx->get_slotidx(),
    .timeout = timeout_ms,
    .seq = boh->get_cmd_id(),
  };

  try {
    m_pdev.ioctl(DRM_IOCTL_AMDXDNA_WAIT_CMD, &wcmd);
  }
  catch (const xrt_core::system_error& ex) {
    if (ex.get_code() != ETIME)
      throw;
    else
      ret = 0;
  }
  return ret;
}

} // shim_xdna

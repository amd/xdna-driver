// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2025, Advanced Micro Devices, Inc. All rights reserved.

#ifndef XDNA_EDGE_HWQ_H__
#define XDNA_EDGE_HWQ_H__

#include "core/common/shim/hwqueue_handle.h"
#include "shim_debug.h"
#include "xdna_device.h"
#include "xdna_hwctx.h"

namespace shim_xdna_edge {

class xdna_hwq : public xrt_core::hwqueue_handle
{
public:
  xdna_hwq(const device_xdna& device);

  void
  submit_command(xrt_core::buffer_handle *) override;

  int
  wait_command(xrt_core::buffer_handle *, uint32_t timeout_ms) const override;

  // TODO
  void
  submit_wait(const xrt_core::fence_handle*) override
  { shim_not_supported_err(__func__); }

  // TODO
  void
  submit_wait(const std::vector<xrt_core::fence_handle*>&) override
  { shim_not_supported_err(__func__); }

  // TODO
  void
  submit_signal(const xrt_core::fence_handle*) override
  { shim_not_supported_err(__func__); }

  // TODO
  std::unique_ptr<xrt_core::fence_handle>
  import(xrt_core::fence_handle::export_handle) override
  { shim_not_supported_err(__func__); }

public:
  void
  bind_hwctx(const xdna_hwctx *ctx);

  void
  unbind_hwctx();

  uint32_t
  get_queue_bo();

private:
  const xdna_hwctx *m_hwctx;
  std::shared_ptr<xdna_edgedev> m_edev;
  uint32_t m_queue_boh;
};

} // shim_xdna_edge

#endif // __XDNA_EDGE_HWQ_H__

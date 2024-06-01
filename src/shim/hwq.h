// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2023-2024, Advanced Micro Devices, Inc. All rights reserved.

#ifndef _HWQ_XDNA_H_
#define _HWQ_XDNA_H_

#include "fence.h"
#include "hwctx.h"
#include "shim_debug.h"

#include "core/common/shim/hwqueue_handle.h"

namespace shim_xdna {

class hw_q : public xrt_core::hwqueue_handle
{
public:
  hw_q(const device& device);

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
  virtual void
  bind_hwctx(const hw_ctx *ctx) = 0;

  void
  unbind_hwctx();

  uint32_t
  get_queue_bo();

protected:
  virtual void
  issue_command(xrt_core::buffer_handle *) = 0;

  const hw_ctx *m_hwctx;
  const pdev& m_pdev;
  uint32_t m_queue_boh;
};

} // shim_xdna

#endif // _HWQ_XDNA_H_

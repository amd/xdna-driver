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

  void
  submit_command(const std::vector<xrt_core::buffer_handle *>&) override;

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
  bind_hwctx(const hw_ctx *ctx);

  void
  unbind_hwctx();

  uint32_t
  get_queue_bo();

  virtual void
  map_doorbell(uint32_t doorbell_offset)
  {
    // do nothing by default
  }

protected:
  virtual void
  submit_command_list(const std::vector<xrt_core::buffer_handle *>&) = 0;

  const hw_ctx *m_hwctx;
  const pdev& m_pdev;
  uint32_t m_queue_boh;

private:
  bool m_force_unchained_command;
};

} // shim_xdna

#endif // _HWQ_XDNA_H_

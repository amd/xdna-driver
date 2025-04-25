// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2023-2025, Advanced Micro Devices, Inc. All rights reserved.

#ifndef HWQ_XDNA_H
#define HWQ_XDNA_H

#include "fence.h"
#include "hwctx.h"
#include "buffer.h"
#include "core/common/shim/hwqueue_handle.h"

namespace shim_xdna {

class hwq : public xrt_core::hwqueue_handle
{
public:
  hwq(const device& device);
  ~hwq();

  void
  submit_command(xrt_core::buffer_handle *) override;

  int
  poll_command(xrt_core::buffer_handle *) const override;

  int
  wait_command(xrt_core::buffer_handle *, uint32_t timeout_ms) const override;

  void
  submit_wait(const xrt_core::fence_handle*) override;

  void
  submit_wait(const std::vector<xrt_core::fence_handle*>&) override;

  void
  submit_signal(const xrt_core::fence_handle*) override;

  std::unique_ptr<xrt_core::fence_handle>
  import(xrt_core::fence_handle::export_handle) override
  { shim_not_supported_err(__func__); }

public:
  virtual void
  bind_hwctx(const hwctx& ctx);

  virtual void
  unbind_hwctx();

  virtual uint32_t
  get_queue_bo() const = 0;

protected:
  const pdev& m_pdev;
  xrt_core::hwctx_handle::slot_id m_ctx_id = AMDXDNA_INVALID_CTX_HANDLE;

  int
  wait_command(uint64_t seq, uint32_t timeout_ms) const;

private:
  uint32_t m_syncobj = 0;

  virtual void
  issue_command(cmd_buffer *) = 0;
};

}

#endif

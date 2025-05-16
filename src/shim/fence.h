// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2023-2025, Advanced Micro Devices, Inc. All rights reserved.

#ifndef FENCE_XDNA_H
#define FENCE_XDNA_H

#include "hwctx.h"
#include "device.h"
#include "shared.h"
#include "core/common/shim/fence_handle.h"
#include <mutex>

namespace shim_xdna {

class fence : public xrt_core::fence_handle
{
public:
  fence(const device& device);
  fence(const device& device, xrt_core::shared_handle::export_handle ehdl);
  fence(const fence&);
  ~fence() override;

  std::unique_ptr<xrt_core::fence_handle>
  clone() const override;

  std::unique_ptr<xrt_core::shared_handle>
  share() const override;

  void
  wait(uint32_t timeout_ms) const override;

  uint64_t
  get_next_state() const override;

  void
  signal() const override;

public:
  void
  submit_wait(xrt_core::hwctx_handle::slot_id) const;

  void
  submit_signal(xrt_core::hwctx_handle::slot_id) const;

private:
  uint64_t
  wait_next_state() const;

  uint64_t
  signal_next_state() const;

  const pdev& m_pdev;
  const std::unique_ptr<xrt_core::shared_handle> m_import;
  uint32_t m_syncobj_hdl;

  // Protecting below mutables
  mutable std::mutex m_lock;
  // Set once at first signal
  mutable bool m_signaled = false;
  // Ever incrementing at each wait/signal
  static constexpr uint64_t initial_state = 0;
  mutable uint64_t m_state = initial_state;
};

}

#endif

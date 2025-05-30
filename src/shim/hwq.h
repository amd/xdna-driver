// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2023-2025, Advanced Micro Devices, Inc. All rights reserved.

#ifndef HWQ_XDNA_H
#define HWQ_XDNA_H

#include "fence.h"
#include "hwctx.h"
#include "buffer.h"
#include "core/common/shim/hwqueue_handle.h"
#include <thread>

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
  submit_signal(const xrt_core::fence_handle*) override;

  std::unique_ptr<xrt_core::fence_handle>
  import(xrt_core::fence_handle::export_handle) override
  { shim_not_supported_err(__func__); }

public:
  virtual void
  bind_hwctx(const hwctx& ctx);

  virtual void
  unbind_hwctx();

  virtual bo_id
  get_queue_bo() const = 0;

protected:
  const pdev& m_pdev;
  const hwctx* m_ctx = nullptr;

  int
  wait_command(uint64_t seq, uint32_t timeout_ms) const;

private:
  enum class pending_cmd_type
  {
    io,
    signal,
    wait,
  };
  struct pending_cmd {
    pending_cmd_type m_type;
    const void* m_cmd = nullptr;
    uint64_t m_fence_state;
    uint64_t m_last_seq;
  };

  virtual uint64_t
  issue_command(const cmd_buffer *) = 0;

  bool
  pending_queue_empty() const;

  bool
  pending_queue_full() const;

  uint64_t
  pending_queue_consumer_idx() const;

  uint64_t
  pending_queue_producer_idx() const;

  void
  process_pending_queue();

  void
  push_to_pending_queue(std::unique_lock<std::mutex>& lock,
    const void *cmd, uint64_t fence_state, pending_cmd_type type);

  std::mutex m_mutex;
  const uint64_t INVALID_SEQ = 0xffffffffffffffff;
  uint64_t m_last_seq = INVALID_SEQ;

  bool m_pending_thread_stop = false;
  std::array<pending_cmd, 1> m_pending;
  std::condition_variable m_pending_producer_cv;
  std::condition_variable m_pending_consumer_cv;
  uint64_t m_pending_consumer = 0;
  uint64_t m_pending_producer = 0;
  std::thread m_pending_thread;
};

}

#endif

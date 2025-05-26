// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2023-2025, Advanced Micro Devices, Inc. All rights reserved.

#include "hwq.h"
#include "fence.h"
#include "buffer.h"
#include "shim_debug.h"
#include "core/common/trace.h"

namespace shim_xdna {

hwq::
hwq(const device& device)
  : m_pdev(device.get_pdev())
  , m_pending_thread{&hwq::process_pending_queue, this}
{
}

hwq::
~hwq()
{
  {
    std::unique_lock<std::mutex> lock(m_mutex);
    m_pending_thread_stop = true;
  }
  m_pending_consumer_cv.notify_all();
  m_pending_thread.join();
}

void
hwq::
bind_hwctx(const hwctx& ctx)
{
  m_ctx = &ctx;
}

void
hwq::
unbind_hwctx()
{
  m_ctx = nullptr;
}

int
hwq::
poll_command(xrt_core::buffer_handle *cmd) const
{
  auto boh = static_cast<cmd_buffer*>(cmd);
  auto cmdpkt = reinterpret_cast<ert_packet *>(boh->vaddr());

  if (cmdpkt->state >= ERT_CMD_STATE_COMPLETED) {
    XRT_TRACE_POINT_LOG(poll_command_done);
    return 1;
  }
  return 0;
}

int
hwq::
wait_command(uint64_t seq, uint32_t timeout_ms) const
{
  int ret = 1;

  shim_debug("Waiting for cmd (%ld)...", seq);
  try {
    wait_cmd_arg wcmd = {
      .timeout_ms = timeout_ms,
      .seq = seq,
    };

    auto syncobj = m_ctx->get_syncobj();
    if (syncobj != AMDXDNA_INVALID_FENCE_HANDLE) {
      wcmd.ctx_syncobj_handle = syncobj;
      m_pdev.drv_ioctl(drv_ioctl_cmd::wait_cmd_syncobj, &wcmd);
    } else {
      wcmd.ctx_handle = m_ctx->get_slotidx();
      m_pdev.drv_ioctl(drv_ioctl_cmd::wait_cmd_ioctl, &wcmd);
    }
  }
  catch (const xrt_core::system_error& ex) {
    if (ex.get_code() != ETIME)
      throw;
    else
      ret = 0;
  }
  return ret;
}

int
hwq::
wait_command(xrt_core::buffer_handle *cmd, uint32_t timeout_ms) const
{
  if (poll_command(cmd))
      return 1;

  auto boh = static_cast<cmd_buffer*>(cmd);
  auto seq = boh->wait_for_submitted();
  return wait_command(seq, timeout_ms);
}

void
hwq::
push_to_pending_queue(std::unique_lock<std::mutex>& lock,
  const void *cmd, pending_cmd_type type)
{
  m_pending_producer_cv.wait(lock, [this]() { return !pending_queue_full(); });
  pending_cmd& c = m_pending[pending_queue_producer_idx()];
  c.m_type = type;
  c.m_cmd = cmd;
  c.m_last_seq = m_last_seq;
  m_pending_producer++;
  m_pending_consumer_cv.notify_all();
}

void
hwq::
submit_command(xrt_core::buffer_handle *cmd)
{
  std::unique_lock<std::mutex> lock(m_mutex);
  ++m_last_seq;
  auto boh = static_cast<cmd_buffer*>(cmd);
  shim_debug("Enqueuing command (%ld)", m_last_seq);
  push_to_pending_queue(lock, boh, pending_cmd_type::io);
  boh->enqueued(m_last_seq);
}

void
hwq::
submit_wait(const xrt_core::fence_handle* f)
{
  std::unique_lock<std::mutex> lock(m_mutex);
  auto fh = static_cast<const fence*>(f);
  shim_debug("Enqueuing wait fence %s", fh->describe().c_str());
  push_to_pending_queue(lock, fh, pending_cmd_type::wait);
}

void
hwq::
submit_signal(const xrt_core::fence_handle* f)
{
  std::unique_lock<std::mutex> lock(m_mutex);
  auto fh = static_cast<const fence*>(f);
  shim_debug("Enqueuing signal fence %s", fh->describe().c_str());
  push_to_pending_queue(lock, fh, pending_cmd_type::signal);
}

bool
hwq::
pending_queue_empty() const
{
  return m_pending_consumer == m_pending_producer;
}

bool
hwq::
pending_queue_full() const
{
  return (m_pending_producer - m_pending_consumer) == m_pending.size();
}

uint64_t
hwq::
pending_queue_consumer_idx() const
{
  return (m_pending_consumer & (m_pending.size() - 1));
}

uint64_t
hwq::
pending_queue_producer_idx() const
{
  return (m_pending_producer & (m_pending.size() - 1));
}

void
hwq::
process_pending_queue()
{
  shim_debug("Pending queue thread started!");

  std::unique_lock<std::mutex> lock(m_mutex);

  while (!m_pending_thread_stop) {

    // Process all pending commands in queued order.
    while (!pending_queue_empty()) {
      // Releasing the lock, allow others to add to the pending queue while
      // it is being processed. The pending cmd is processed in this single
      // thread, so no need for any locking.
      lock.unlock();

      pending_cmd& c = m_pending[pending_queue_consumer_idx()];
      switch (c.m_type) {
      case pending_cmd_type::io: {
        auto boh = reinterpret_cast<const cmd_buffer*>(c.m_cmd);
        auto seq = issue_command(boh);
        boh->submitted(seq);
        break;
      }
      case pending_cmd_type::signal: {
        auto fh = reinterpret_cast<const xrt_core::fence_handle*>(c.m_cmd);
        if (c.m_last_seq != INVALID_SEQ)
          wait_command(c.m_last_seq, 0);
        fh->signal();
        break;
      }
      case pending_cmd_type::wait: {
        auto fh = reinterpret_cast<const xrt_core::fence_handle*>(c.m_cmd);
        fh->wait(0);
        break;
      }
      default:
        shim_err(EINVAL, "Bad pending cmd!");
      }

      // Acquiring the lock before publishing pending queue processing progress.
      lock.lock();
      m_pending_consumer++;
    }
    // In case someone is waiting for adding more cmds.
    m_pending_producer_cv.notify_all();

    // Wait for new pending commands or quit indicator.
    m_pending_consumer_cv.wait(lock,
      [this]() { return m_pending_thread_stop || !pending_queue_empty(); });
  }

  shim_debug("Pending queue thread stopped!");
}

}

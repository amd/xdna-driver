// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2024-2025, Advanced Micro Devices, Inc. All rights reserved.

#include "fence.h"
#include "drm_local/amdxdna_accel.h"
#include <limits>

namespace {

uint32_t
create_syncobj(const shim_xdna::pdev& dev)
{
  drm_syncobj_create csobj = {
    .handle = AMDXDNA_INVALID_FENCE_HANDLE,
    .flags = 0
  };
  dev.ioctl(DRM_IOCTL_SYNCOBJ_CREATE, &csobj);
  return csobj.handle;
}

void
destroy_syncobj(const shim_xdna::pdev& dev, uint32_t hdl)
{
  drm_syncobj_destroy dsobj = {
    .handle = hdl
  };
  dev.ioctl(DRM_IOCTL_SYNCOBJ_DESTROY, &dsobj);
}

uint64_t
query_syncobj_timeline(const shim_xdna::pdev& dev, uint32_t sobj_hdl)
{
  uint64_t point = 0;
  drm_syncobj_timeline_array sobjs = {
    .handles = reinterpret_cast<uintptr_t>(&sobj_hdl),
    .points = reinterpret_cast<uintptr_t>(&point),
    .count_handles = 1,
    .flags = 0
  };
  dev.ioctl(DRM_IOCTL_SYNCOBJ_QUERY, &sobjs);
  return point;
}

int
export_syncobj(const shim_xdna::pdev& dev, uint32_t sobj_hdl)
{
  drm_syncobj_handle esobj = {
    .handle = sobj_hdl,
    .flags = 0,
    .fd = -1,
  };
  dev.ioctl(DRM_IOCTL_SYNCOBJ_HANDLE_TO_FD, &esobj);
  return esobj.fd;
}

uint32_t
import_syncobj(const shim_xdna::pdev& dev, int fd)
{
  drm_syncobj_handle isobj = {
    .handle = AMDXDNA_INVALID_FENCE_HANDLE,
    .flags = 0,
    .fd = fd,
  };
  dev.ioctl(DRM_IOCTL_SYNCOBJ_FD_TO_HANDLE, &isobj);
  return isobj.handle;
}

void
signal_syncobj(const shim_xdna::pdev& dev, uint32_t sobj_hdl, uint64_t timepoint)
{
  drm_syncobj_timeline_array sobjs = {
    .handles = reinterpret_cast<uintptr_t>(&sobj_hdl),
    .points = reinterpret_cast<uintptr_t>(&timepoint),
    .count_handles = 1,
    .flags = 0
  };
  dev.ioctl(DRM_IOCTL_SYNCOBJ_TIMELINE_SIGNAL, &sobjs);
}

void
wait_syncobj_done(const shim_xdna::pdev& dev, uint32_t sobj_hdl, uint64_t timepoint)
{
  drm_syncobj_timeline_wait wsobj = {
    .handles = reinterpret_cast<uintptr_t>(&sobj_hdl),
    .points = reinterpret_cast<uintptr_t>(&timepoint),
    .timeout_nsec = std::numeric_limits<int64_t>::max(), /* wait forever */
    .count_handles = 1,
    .flags = DRM_SYNCOBJ_WAIT_FLAGS_WAIT_FOR_SUBMIT,
  };
  dev.ioctl(DRM_IOCTL_SYNCOBJ_TIMELINE_WAIT, &wsobj);
}

void
wait_syncobj_available(const shim_xdna::pdev& dev,
  const uint32_t* sobj_hdls, const uint64_t* timepoints, uint32_t num)
{
  drm_syncobj_timeline_wait wsobj = {
    .handles = reinterpret_cast<uintptr_t>(sobj_hdls),
    .points = reinterpret_cast<uintptr_t>(timepoints),
    .timeout_nsec = std::numeric_limits<int64_t>::max(), /* wait forever */
    .count_handles = num,
    .flags = DRM_SYNCOBJ_WAIT_FLAGS_WAIT_ALL |
             DRM_SYNCOBJ_WAIT_FLAGS_WAIT_FOR_SUBMIT |
             DRM_SYNCOBJ_WAIT_FLAGS_WAIT_AVAILABLE,
  };
  dev.ioctl(DRM_IOCTL_SYNCOBJ_TIMELINE_WAIT, &wsobj);
}

void
submit_wait_syncobjs(const shim_xdna::pdev& dev, const shim_xdna::hw_ctx *ctx,
  const uint32_t* sobj_hdls, const uint64_t* points, uint32_t num)
{
  wait_syncobj_available(dev, sobj_hdls, points, num);

  amdxdna_drm_exec_cmd ecmd = {
    .ctx = ctx->get_slotidx(),
    .type = AMDXDNA_CMD_SUBMIT_DEPENDENCY,
    .cmd_handles = reinterpret_cast<uintptr_t>(sobj_hdls),
    .args = reinterpret_cast<uintptr_t>(points),
    .cmd_count = num,
    .arg_count = num,
  };
  dev.ioctl(DRM_IOCTL_AMDXDNA_EXEC_CMD, &ecmd);
}

void
submit_signal_syncobj(const shim_xdna::pdev& dev, const shim_xdna::hw_ctx *ctx,
  uint32_t sobj_hdl, uint64_t point)
{
  amdxdna_drm_exec_cmd ecmd = {
    .ctx = ctx->get_slotidx(),
    .type = AMDXDNA_CMD_SUBMIT_SIGNAL,
    .cmd_handles = sobj_hdl,
    .args = point,
    .cmd_count = 1,
    .arg_count = 1,
  };
  dev.ioctl(DRM_IOCTL_AMDXDNA_EXEC_CMD, &ecmd);
}

}

namespace shim_xdna {

fence::
fence(const device& device)
  : m_pdev(device.get_pdev())
  , m_import(std::make_unique<shared>(-1))
  , m_syncobj_hdl(create_syncobj(m_pdev))
{
  shim_debug("Fence allocated: %d@%d", m_syncobj_hdl, m_state);
}

fence::
fence(const device& device, xrt_core::shared_handle::export_handle ehdl)
  : m_pdev(device.get_pdev())
  , m_import(std::make_unique<shared>(ehdl))
  , m_syncobj_hdl(import_syncobj(m_pdev, m_import->get_export_handle()))
{
  shim_debug("Fence imported: %d@%ld", m_syncobj_hdl, m_state);
}

fence::
fence(const fence& f)
  : m_pdev(f.m_pdev)
  , m_import(f.share())
  , m_syncobj_hdl(import_syncobj(m_pdev, m_import->get_export_handle()))
  , m_state{f.m_state}
  , m_signaled{f.m_signaled}
{
  shim_debug("Fence cloned: %d@%ld", m_syncobj_hdl, m_state);
}

fence::
~fence()
{
  shim_debug("Fence going away: %d@%ld", m_syncobj_hdl, m_state);
  try {
    destroy_syncobj(m_pdev, m_syncobj_hdl);
  } catch (const xrt_core::system_error& e) {
    shim_debug("Failed to destroy fence");
  }
}

std::unique_ptr<xrt_core::shared_handle>
fence::
share() const
{
  if (m_state != initial_state)
    shim_err(-EINVAL, "Can't share fence not at initial state.");

  return std::make_unique<shared>(export_syncobj(m_pdev, m_syncobj_hdl));
}

uint64_t
fence::
get_next_state() const
{
  return m_state + 1;
}

std::unique_ptr<xrt_core::fence_handle>
fence::
clone() const
{
  return std::make_unique<fence>(*this);
}

uint64_t
fence::
wait_next_state() const
{
  std::lock_guard<std::mutex> guard(m_lock);

  if (m_state != initial_state && m_signaled)
    shim_err(-EINVAL, "Can't wait on fence that has been signaled before.");
  return ++m_state;
}

// Timeout value is ignored for now.
void
fence::
wait(uint32_t timeout_ms) const
{
  auto st = signal_next_state();
  shim_debug("Waiting for command fence %d@%ld", m_syncobj_hdl, st);
  wait_syncobj_done(m_pdev, m_syncobj_hdl, st);
}

void
fence::
submit_wait(const hw_ctx *ctx) const
{
  auto st = signal_next_state();
  shim_debug("Submitting wait for command fence %d@%ld", m_syncobj_hdl, st);
  submit_wait_syncobjs(m_pdev, ctx, &m_syncobj_hdl, &st, 1);
}

uint64_t
fence::
signal_next_state() const
{
  std::lock_guard<std::mutex> guard(m_lock);

  if (m_state != initial_state && !m_signaled)
    shim_err(-EINVAL, "Can't signal fence that has been waited before.");
  if (m_state == initial_state)
    m_signaled = true;
  return ++m_state;
}

void
fence::
signal() const
{
  auto st = signal_next_state();
  shim_debug("Signaling command fence %d@%ld", m_syncobj_hdl, st);
  signal_syncobj(m_pdev, m_syncobj_hdl, st);
}

void
fence::
submit_signal(const hw_ctx *ctx) const
{
  auto st = signal_next_state();
  shim_debug("Submitting signal command fence %d@%ld", m_syncobj_hdl, st);
  submit_signal_syncobj(m_pdev, ctx, m_syncobj_hdl, st);
}

void
fence::
submit_wait(const pdev& dev, const hw_ctx *ctx, const std::vector<xrt_core::fence_handle*>& fences)
{
  constexpr int max_fences = 1024;
  uint32_t hdls[max_fences];
  uint64_t pts[max_fences];
  int i = 0;

  if (fences.size() > max_fences)
    shim_err(-EINVAL, "Too many fences in one submit: %d", fences.size());

  for (auto f : fences) {
    auto fh = static_cast<const fence*>(f);
    auto st = fh->wait_next_state();
    shim_debug("Waiting for command fence %d@%ld", fh->m_syncobj_hdl, st);
    hdls[i] = fh->m_syncobj_hdl;
    pts[i] = st;
    i++;
  }
  submit_wait_syncobjs(dev, ctx, hdls, pts, i);
}

} // shim_xdna

// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2024-2025, Advanced Micro Devices, Inc. All rights reserved.

#include "fence.h"

namespace {

using namespace shim_xdna;

uint32_t
create_syncobj(const shim_xdna::pdev& dev)
{
  create_destroy_syncobj_arg csobj = {
    .handle = AMDXDNA_INVALID_FENCE_HANDLE,
  };
  dev.drv_ioctl(drv_ioctl_cmd::create_syncobj, &csobj);
  return csobj.handle;
}

void
destroy_syncobj(const shim_xdna::pdev& dev, uint32_t hdl)
{
  create_destroy_syncobj_arg dsobj = {
    .handle = hdl
  };
  dev.drv_ioctl(drv_ioctl_cmd::destroy_syncobj, &dsobj);
}

int
export_syncobj(const shim_xdna::pdev& dev, uint32_t sobj_hdl)
{
  export_import_syncobj_arg esobj = {
    .handle = sobj_hdl,
    .fd = -1,
  };
  dev.drv_ioctl(drv_ioctl_cmd::export_syncobj, &esobj);
  return esobj.fd;
}

uint32_t
import_syncobj(const shim_xdna::pdev& dev, int fd)
{
  export_import_syncobj_arg isobj = {
    .handle = AMDXDNA_INVALID_FENCE_HANDLE,
    .fd = fd,
  };
  dev.drv_ioctl(drv_ioctl_cmd::import_syncobj, &isobj);
  return isobj.handle;
}

void
signal_syncobj(const shim_xdna::pdev& dev, uint32_t sobj_hdl, uint64_t timepoint)
{
  signal_syncobj_arg sobjs = {
    .handle = sobj_hdl,
    .timepoint = timepoint,
  };
  dev.drv_ioctl(drv_ioctl_cmd::signal_syncobj, &sobjs);
}

void
wait_syncobj_done(const shim_xdna::pdev& dev, uint32_t sobj_hdl, uint64_t timepoint)
{
  wait_syncobj_arg wsobj = {
    .handle = sobj_hdl,
    .timeout_ms = 0, /* wait forever */
    .timepoint = timepoint,
  };
  dev.drv_ioctl(drv_ioctl_cmd::wait_syncobj, &wsobj);
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
  std::lock_guard<std::mutex> guard(m_lock);

  if (m_state != initial_state)
    shim_err(EINVAL, "Can't share fence not at initial state.");

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
next_wait_state() const
{
  std::lock_guard<std::mutex> guard(m_lock);

  if (m_state != initial_state && m_signaled)
    shim_err(EINVAL, "Can't wait on fence that has been signaled before.");
  return ++m_state;
}

void
fence::
wait(uint64_t state) const
{
  shim_debug("Waiting for command fence %d@%ld", m_syncobj_hdl, state);
  wait_syncobj_done(m_pdev, m_syncobj_hdl, state);
}

// Timeout value is ignored for now.
void
fence::
wait(uint32_t timeout_ms) const
{
  wait(next_wait_state());
}

uint64_t
fence::
next_signal_state() const
{
  std::lock_guard<std::mutex> guard(m_lock);

  if (m_state != initial_state && !m_signaled)
    shim_err(EINVAL, "Can't signal fence that has been waited before.");
  if (m_state == initial_state)
    m_signaled = true;
  return ++m_state;
}

void
fence::
signal(uint64_t state) const
{
  shim_debug("Signaling command fence %d@%ld", m_syncobj_hdl, state);
  signal_syncobj(m_pdev, m_syncobj_hdl, state);
}

void
fence::
signal() const
{
  signal(next_signal_state());
}

const std::string
fence::
describe() const
{
  return std::to_string(m_syncobj_hdl) + "@" + std::to_string(get_next_state());
}

}

// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2025, Advanced Micro Devices, Inc. All rights reserved.

#include "shim_debug.h"
#include "xdna_bo.h"
#include "xdna_hwq.h"

namespace shim_xdna_edge {

xdna_hwq::
xdna_hwq(const device_xdna* device)
  : m_hwctx(nullptr)
  , m_queue_boh(AMDXDNA_INVALID_BO_HANDLE)
{
  shim_debug("Created HW queue");
}

void
xdna_hwq::
bind_hwctx(const xdna_hwctx *ctx)
{
  if (m_hwctx)
    shim_err(EINVAL, "HW queue already bound to hwctx %d, cannot bind to another",
             m_hwctx->get_slotidx());
  m_hwctx = const_cast<xdna_hwctx*>(ctx);
  shim_debug("Bound HW queue to hwctx %d", m_hwctx->get_slotidx());
}

void
xdna_hwq::
unbind_hwctx()
{
  if (!m_hwctx) {
    shim_debug("HW queue not bound to any hwctx, skipping unbind");
    return;
  }
  shim_debug("Unbinding HW queue from hwctx %d", m_hwctx->get_slotidx());
  m_hwctx = nullptr;
}

uint32_t
xdna_hwq::
get_queue_bo()
{
  return m_queue_boh;
}

void
xdna_hwq::
submit_command(xrt_core::buffer_handle *cmd_bo)
{
  const size_t max_arg_bos = 1024;
  uint32_t arg_bo_hdls[max_arg_bos];

  if (!cmd_bo)
    shim_err(EINVAL, "submit_command: cmd_bo is NULL");

  auto boh = static_cast<shim_xdna_edge::xdna_bo*>(cmd_bo);
  uint32_t cmd_bo_hdl = boh->get_drm_bo_handle();

  if (!m_hwctx)
    shim_err(EINVAL, "submit_command: No hwctx bound to HW queue");

  auto hwctx_id = m_hwctx->get_slotidx();
  auto arg_count = static_cast<uint32_t>(boh->get_arg_bo_handles(arg_bo_hdls, max_arg_bos));

  shim_debug("Submitting command: hwctx=%u, cmd_bo_hdl=%u, arg_count=%u",
             hwctx_id, cmd_bo_hdl, arg_count);

  /*
   * Flush the SHIM-internal command BO before handing it to the kernel.
   *
   * Rationale: the cmd BO (AMDXDNA_BO_CMD) is XRT-owned (from bo_cache
   * + xrt_kernel.cpp) and is mmaped *cached* into userspace by the
   * driver (amdxdna_cmabuf_mmap()), so the ert_packet bytes XRT just
   * wrote sit in CPU cache.  Without this sync_bo(host2device), CERT
   * reads stale DDR via DMA and the cmd never executes, surfacing as
   * state==ERT_CMD_STATE_NEW (1) in the wait completion path.
   *
   * NOTE — split of responsibility vs the modern (src/shim) path:
   *   For aie4-class devices the equivalent cmd-BO flush has been
   *   pushed into the kernel driver itself (see commit 160ae98:
   *   "driver/amdxdna: aie4_hwctx: take ownership of cmd BO cache sync
   *   in KMS", which adds dma_sync_*(DMA_TO_DEVICE) inside
   *   aie4_submit_one_cmd() / aie4_submit_job()).  The shim half was
   *   correspondingly dropped in commit bea37cf ("shim: hand cmd-BO
   *   cache sync to the driver in KMS; aie2ps-only coherency").
   *
   *   src/shim_ve2 keeps the sync here because the VE2 kernel ops
   *   (ve2_cmd_submit / ve2_cmd_wait in src/driver/amdxdna/ve2_hwctx.c)
   *   do NOT yet mirror that kernel-side flush.  Until they do, the
   *   shim must continue to own this side of the cache maintenance.
   *
   * The driver's DRM_IOCTL_AMDXDNA_SYNC_BO short-circuits on
   * cache-coherent devices (dev_is_dma_coherent() in
   * amdxdna_gem_sync_range()), so this call is effectively free on
   * platforms that do not need it.
   */
  try {
    boh->sync(xrt_core::buffer_handle::direction::host2device,
              boh->get_properties().size, 0);
  } catch (const std::exception& e) {
    shim_debug("submit_command: cmd_bo sync to device failed: %s", e.what());
    throw;
  }

  amdxdna_drm_exec_cmd ecmd = {
    .hwctx = hwctx_id,
    .cmd_handles = cmd_bo_hdl,
    .args = reinterpret_cast<uintptr_t>(arg_bo_hdls),
    .cmd_count = 1,
    .arg_count = arg_count,
  };

  try {
    m_hwctx->get_device()->get_edev()->ioctl(DRM_IOCTL_AMDXDNA_EXEC_CMD, &ecmd);
  } catch (const xrt_core::system_error& ex) {
    int err_code = ex.get_code();

    if (err_code == EINVAL) {
      shim_err(err_code, "Command submission failed: Invalid command or arguments. "
               "hwctx=%u, cmd_bo=%u. Check command buffer format and arguments.",
               hwctx_id, cmd_bo_hdl);
    } else if (err_code == EBUSY) {
      shim_err(err_code, "Command submission failed: Command queue full or context busy. "
               "hwctx=%u, cmd_bo=%u. Wait for pending commands to complete.",
               hwctx_id, cmd_bo_hdl);
    } else if (err_code == ENODEV) {
      shim_err(err_code, "Command submission failed: Context destroyed or device unavailable. "
               "hwctx=%u, cmd_bo=%u",
               hwctx_id, cmd_bo_hdl);
    } else if (err_code == ETIME || err_code == ETIMEDOUT) {
      shim_err(err_code, "Command submission failed: Timeout waiting for submission. "
               "hwctx=%u, cmd_bo=%u",
               hwctx_id, cmd_bo_hdl);
    } else if (err_code == ENOSPC) {
      shim_err(err_code, "Command submission failed: No space in queue. "
               "hwctx=%u, cmd_bo=%u. Reduce command submission rate.",
               hwctx_id, cmd_bo_hdl);
    } else {
      shim_err(err_code, "Command submission failed: hwctx=%u, cmd_bo=%u - %s",
               hwctx_id, cmd_bo_hdl, ex.what());
    }
  }

  auto id = ecmd.seq;
  boh->set_cmd_id(id);
  shim_debug("Command submitted: hwctx=%u, seq=%ld", hwctx_id, id);
}

int
xdna_hwq::
wait_command(xrt_core::buffer_handle *cmd_bo, uint32_t timeout_ms) const
{
  int ret = 1;

  if (!cmd_bo)
    shim_err(EINVAL, "wait_command: cmd_bo is NULL");

  auto boh = static_cast<shim_xdna_edge::xdna_bo*>(cmd_bo);
  auto id = boh->get_cmd_id();

  if (!m_hwctx)
    shim_err(EINVAL, "wait_command: No hwctx bound to HW queue");

  auto hwctx_id = m_hwctx->get_slotidx();

  shim_debug("Waiting for command: hwctx=%u, seq=%ld, timeout_ms=%u",
             hwctx_id, id, timeout_ms);

  amdxdna_drm_wait_cmd wcmd = {
    .hwctx = hwctx_id,
    .timeout = timeout_ms,
    .seq = boh->get_cmd_id(),
  };

  try {
    m_hwctx->get_device()->get_edev()->ioctl(DRM_IOCTL_AMDXDNA_WAIT_CMD, &wcmd);
    shim_debug("Command completed: hwctx=%u, seq=%ld", hwctx_id, id);
  }
  catch (const xrt_core::system_error& ex) {
    int err_code = ex.get_code();
    if (err_code == ETIME) {
      shim_debug("Command wait timeout: hwctx=%u, seq=%ld, timeout_ms=%u (err=%d: %s)",
                 hwctx_id, id, timeout_ms, err_code, errno_to_str(err_code));
      ret = 0;
    } else {
      shim_debug("Command wait failed: hwctx=%u, seq=%ld, err=%d: %s (%s)",
                 hwctx_id, id, err_code, errno_to_str(err_code), ex.what());
      throw;
    }
  }

  /*
   * Invalidate the SHIM-internal command BO so XRT's get_state_raw()
   * observes the value placed by CERT (success path) or the driver
   * (timeout / abort path) rather than the stale ERT_CMD_STATE_NEW that
   * still sits in this process's cached mapping from the pre-submit
   * write.
   *
   * NOTE — split of responsibility vs the modern (src/shim) path:
   *   For aie4-class devices, the equivalent invalidate has been moved
   *   into the kernel driver (commit 160ae98 adds
   *   aie4_cmd_bo_sync_for_cpu() in aie4_job_done(), which performs
   *   dma_sync_*(DMA_FROM_DEVICE) on the cmd BO and any chained
   *   sub-cmds *before* the completion fence is signaled).  The
   *   matching shim sync was correspondingly removed in commit
   *   bea37cf, with the device2host invalidate now gated on the
   *   user-mode-submission (UMS) path only.
   *
   *   src/shim_ve2 keeps the sync here because the VE2 kernel ops
   *   (ve2_cmd_wait / its job-done equivalent in
   *   src/driver/amdxdna/ve2_hwctx.c) do NOT yet mirror that
   *   kernel-side invalidate.  Until they do, the shim must continue
   *   to own this side of the cache maintenance.
   *
   *   The kernel-side flush in amdxdna_cmd_set_state() (PR4) already
   *   protects the timeout / abort path on both shims since both share
   *   the same DRM driver.
   *
   * Skip on timeout (ret==0): amdxdna_cmd_set_state() has already
   * drained any state update the driver wrote on its way out; if the
   * driver took no action, there is nothing fresh in DDR to fetch.
   */
  if (ret) {
    try {
      boh->sync(xrt_core::buffer_handle::direction::device2host,
                boh->get_properties().size, 0);
    } catch (const std::exception& e) {
      shim_debug("wait_command: cmd_bo sync from device failed: %s", e.what());
      throw;
    }
  }

  return ret;
}

} // shim_xdna_edge

// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2023-2026, Advanced Micro Devices, Inc. All rights reserved.

#include "hwctx.h"
#include "hwq.h"
#include "../platform.h"
#include "core/common/config_reader.h"
#include <filesystem>

namespace shim_xdna {

// Map XRT/AMDXDNA priority (0x100,0x180,0x200,0x280) to AIE4 band index (0-3).
// Matches Windows: IDLE=0, NORMAL=1, FOCUS=2, REAL_TIME=3.
static uint32_t
qos_priority_to_band_index(uint32_t priority)
{
  switch (priority) {
  case 0x280u: return 0; /* IDLE */
  case 0x200u: return 1; /* NORMAL */
  case 0x180u: return 2; /* FOCUS */
  case 0x100u: return 3; /* REAL_TIME */
  default:     return 1; /* NORMAL */
  }
}

// Allow at least one runlist (24 sub-cms) plus a few single cmds.
const size_t total_queue_slots = 32;

hwctx_umq::
hwctx_umq(const device& device, const xrt::xclbin& xclbin, const qos_type& qos)
  : hwctx(device, qos, xclbin, std::make_unique<hwq_umq>(device, total_queue_slots))
  , m_pdev(device.get_pdev())
{
  shim_debug("Created UMQ HW context (%d)", get_slotidx());
  xclbin_parser xp(xclbin);
  m_col_cnt = xp.get_column_cnt();

  auto path = xrt_core::config::get_dtrace_control_file_path();
  if (std::filesystem::exists(path))
  { //tcp server is running only when we run dtrace
    init_tcp_server(device);
    tcp_server_running = true;
  }
}

hwctx_umq::
hwctx_umq(const device& device, uint32_t partition_size)
  : hwctx(device, partition_size, std::make_unique<hwq_umq>(device, total_queue_slots))
  , m_pdev(device.get_pdev())
{
  m_col_cnt = partition_size;

  auto path = xrt_core::config::get_dtrace_control_file_path();
  if (std::filesystem::exists(path))
  {
    init_tcp_server(device);
    tcp_server_running = true;
  }
  shim_debug("Created UMQ HW context (%d)", get_slotidx());
}

hwctx_umq::
~hwctx_umq()
{
  shim_debug("Destroying UMQ HW context (%d)...", get_slotidx());
  if (tcp_server_running)
  {
    fini_tcp_server();
  }
}

void
hwctx_umq::
update_qos(const qos_type& qos)
{
  // If only perf_pref or priority is updated, only update priority band (match Windows fast path).
  if (qos.size() == 1u) {
    auto it_perf = qos.find("perf_pref");
    auto it_prio = qos.find("priority");
    if (it_perf != qos.end()) {
      uint32_t band = (it_perf->second == 0u) ? 1u : 0u; /* 0=normal, 1=idle */
      config_ctx_priority_band_arg arg = { .ctx_handle = m_handle, .priority_band = band };
      m_device.get_pdev().drv_ioctl(drv_ioctl_cmd::config_ctx_priority_band, &arg);
      if (band == 1u)
        m_qos.priority = 0x200u;
      else
        m_qos.priority = 0x280u;
      return;
    }
    if (it_prio != qos.end()) {
      m_qos.priority = it_prio->second;
      uint32_t band = qos_priority_to_band_index(m_qos.priority);
      config_ctx_priority_band_arg arg = { .ctx_handle = m_handle, .priority_band = band };
      m_device.get_pdev().drv_ioctl(drv_ioctl_cmd::config_ctx_priority_band, &arg);
      return;
    }
  }

  bool priority_updated = (qos.find("priority") != qos.end());

  for (auto& [key, value] : qos) {
    if (key == "gops" || key == "egops")
      m_qos.gops = value;
    else if (key == "fps")
      m_qos.fps = value;
    else if (key == "dma_bandwidth" || key == "data_movement")
      m_qos.dma_bandwidth = value;
    else if (key == "latency")
      m_qos.latency = value * 1000u;  /* ms -> us (match Windows) */
    else if (key == "latency_in_us")
      m_qos.latency = value;
    else if (key == "frame_execution_time")
      m_qos.frame_exec_time = value;
    else if (key == "priority")
      m_qos.priority = value;
  }

  config_ctx_dpm_arg arg = {
    .ctx_handle = m_handle,
    .qos = m_qos,
  };
  m_device.get_pdev().drv_ioctl(drv_ioctl_cmd::config_ctx_dpm, &arg);

  if (priority_updated) {
    uint32_t band = qos_priority_to_band_index(m_qos.priority);
    config_ctx_priority_band_arg parg = { .ctx_handle = m_handle, .priority_band = band };
    m_device.get_pdev().drv_ioctl(drv_ioctl_cmd::config_ctx_priority_band, &parg);
  }
}

void
hwctx_umq::
init_tcp_server(const device& dev)
{
  //TODO:check xrt.ini to start tcp server
  m_tcp_server = std::make_unique<tcp_server>(dev, this);
  m_thread_ = std::thread([&] () { m_tcp_server->start(); });
}

void
hwctx_umq::
fini_tcp_server()
{
  if (m_thread_.joinable())
  {
    shim_debug("Kill TCP server...");
    pthread_kill(m_thread_.native_handle(), SIGUSR1);
    m_thread_.join();
  }
}

} // shim_xdna

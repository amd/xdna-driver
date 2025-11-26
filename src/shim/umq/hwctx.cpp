// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2023-2025, Advanced Micro Devices, Inc. All rights reserved.

#include "hwctx.h"
#include "hwq.h"
#include "core/common/config_reader.h"
#include <filesystem>

namespace shim_xdna {

hwctx_umq::
hwctx_umq(const device& device, const xrt::xclbin& xclbin, const qos_type& qos)
  : hwctx(device, qos, xclbin, std::make_unique<hwq_umq>(device, 8))
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
  : hwctx(device, partition_size, std::make_unique<hwq_umq>(device, 8))
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

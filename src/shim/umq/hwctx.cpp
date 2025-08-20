// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2023-2025, Advanced Micro Devices, Inc. All rights reserved.

#include "hwctx.h"
#include "hwq.h"
#include "core/common/config_reader.h"
#include <fstream>
#include <string>

namespace shim_xdna {

hwctx_umq::
hwctx_umq(const device& device, const xrt::xclbin& xclbin, const qos_type& qos)
  : hwctx(device, qos, xclbin, std::make_unique<hwq_umq>(device, 8))
  , m_pdev(device.get_pdev())
{
  shim_debug("Created UMQ HW context (%d)", get_slotidx());
  xclbin_parser xp(xclbin);
  m_uc_cnt = xp.get_column_cnt() * 2; //so far single-app mode only

  init_tcp_server(device);
  init_log_buf();
}

hwctx_umq::
hwctx_umq(const device& device, uint32_t partition_size)
  : hwctx(device, partition_size, std::make_unique<hwq_umq>(device, 8))
  , m_pdev(device.get_pdev())
{
  m_uc_cnt = partition_size * 2;

  init_tcp_server(device);
  init_log_buf();
  // TODO: configure log BO on the hwctx
  shim_debug("Created UMQ HW context (%d)", get_slotidx());
}

hwctx_umq::
~hwctx_umq()
{
  shim_debug("Destroying UMQ HW context (%d)...", get_slotidx());
  fini_tcp_server();
  // TODO: unconfigure log BO on the hwctx
  fini_log_buf();
}

void
hwctx_umq::
init_log_buf()
{
  //PoC to control log buf size and filename from xrt.ini
  //this setting should be in xrt so it works for all platform
  //this code will be gone once the support in xrt is ready	
  //auto column_size = xrt_core::config::get_cert_log_buffer_size();
  auto column_size = 4096;
  // make sure size is multiple of 32B
  //column_size = (column_size + 31) & (~31);
  m_log_buf_size = m_uc_cnt * column_size;
  m_log_bo = std::make_unique<uc_dbg_buffer>
    (m_pdev, m_log_buf_size, AMDXDNA_BO_CMD);
  m_log_buf = m_log_bo->vaddr();
  std::memset(m_log_buf, 0, m_log_buf_size);

  auto f = xcl_bo_flags{0};
  f.use = XRT_BO_USE_LOG;
  f.flags = XRT_BO_FLAGS_CACHEABLE;
  f.access = XRT_BO_ACCESS_LOCAL;
  f.dir = XRT_BO_ACCESS_READ_WRITE;

  m_log_bo->set_flags(f.all);

  std::map<uint32_t,size_t> buf_sizes;
  set_metadata(buf_sizes, m_uc_cnt, column_size);
  shim_debug("cert log uc_cnt: %d size: %d", m_uc_cnt, column_size);
  
  // TODO: configure log BO on the hwctx once driver and fw support it
  // we may use xrt.ini to control the config
  m_log_bo->config(this, buf_sizes);
}

void
hwctx_umq::
fini_log_buf(void)
{
#if 0
  //PoC to support log buffer setting in xrt.ini
  auto path = xrt_core::config::get_cert_log_file_path();
  if (path.empty()) {
    shim_debug("Skip saving cert log");
    return;
  }

  std::ofstream outf(path, std::ios::binary);
  if (!outf) {
    shim_debug("Error opening cert log file: %s", path.c_str());
    return;
  }
  outf.write(static_cast<const char*>(m_log_buf), m_log_buf_size);
  outf.close();
  shim_debug("cert log saved to %s", path.c_str());
#endif
}

void
hwctx_umq::
set_metadata(std::map<uint32_t, size_t>& buf_sizes, int num_ucs, size_t size)
{
  for (int i = 0; i < num_ucs; i++) {
    buf_sizes[i] = size;
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

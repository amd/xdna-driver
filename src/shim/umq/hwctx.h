// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2023-2025, Advanced Micro Devices, Inc. All rights reserved.

#ifndef HWCTX_UMQ_H
#define HWCTX_UMQ_H

#include <thread>
#include <signal.h>
#include <functional>
#include <map>
#include "../hwctx.h"
#include "../buffer.h"
#include "tcp_server.h"
#include "drm_local/amdxdna_accel.h"

namespace shim_xdna {

class hwctx_umq : public hwctx {
public:
  hwctx_umq(const device& device, const xrt::xclbin& xclbin, const qos_type& qos);
  hwctx_umq(const device& device, uint32_t partition_size);
  ~hwctx_umq();

private:
  const pdev& m_pdev;
  uint32_t m_col_cnt = 0;
  std::unique_ptr<tcp_server> m_tcp_server;
  std::thread m_thread_;

  void init_tcp_server(const device& dev);
  void fini_tcp_server();
};

}

#endif

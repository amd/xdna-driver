// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2023-2025, Advanced Micro Devices, Inc. All rights reserved.

#ifndef HWCTX_UMQ_H
#define HWCTX_UMQ_H

#include <thread>
#include <signal.h>
#include <functional>
#include "../hwctx.h"
#include "../buffer.h"
#include "tcp_server.h"
#include "fw_buf_metadata.h"

namespace shim_xdna {

class hwctx_umq : public hwctx {
public:
  hwctx_umq(const device& device, const xrt::xclbin& xclbin, const qos_type& qos);
  ~hwctx_umq();

private:
  std::unique_ptr<buffer> m_log_bo;
  uint32_t m_col_cnt = 0;

  umq_fw_metadata m_log_metadata;
  void *m_log_buf = nullptr;

  std::unique_ptr<tcp_server> m_tcp_server;
  std::thread m_thread_;

  void init_tcp_server(const device& dev);
  void fini_tcp_server();

  void init_log_buf();
  void fini_log_buf();
  void set_metadata(int num_cols, size_t size, uint64_t bo_paddr, enum umq_fw_flag flag);
};

}

#endif

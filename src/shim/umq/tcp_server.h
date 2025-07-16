// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2025, Advanced Micro Devices, Inc. All rights reserved.

#ifndef TCP_SERVER_H
#define TCP_SERVER_H

#include "dbg_hwq.h"
#include "../buffer.h"
#include "../hwctx.h"
#include <csignal>

namespace shim_xdna {

class tcp_server {
public:
  tcp_server(const device& dev, hwctx* hwctx);
  ~tcp_server();
  void start();

private:
  dbg_hwq_umq m_dbg_umq;
  uint32_t m_def_size;
  std::unique_ptr<buffer> m_data_bo;
  volatile void *m_data_buf;
  uint64_t m_data_paddr;
  std::unique_ptr<buffer> m_ctrl_bo;
  volatile void *m_ctrl_buf;
  uint64_t m_ctrl_paddr;
  bool m_aie_attached;
  hwctx* m_hwctx;
  const pdev& m_pdev;
  static inline volatile std::sig_atomic_t m_srv_stop;

  std::unique_ptr<std::vector<uint32_t>>
  handle_read_mem(uint32_t addr, uint32_t length);
  uint32_t handle_write_mem(uint32_t addr, std::vector<uint32_t> &data);
  void buffer_extend(size_t new_size);
  uint32_t handle_attach(uint32_t);
  void handle_detach();
  static void sigusr1_handler(int sig);
};

}

#endif

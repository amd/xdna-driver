// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2025, Advanced Micro Devices, Inc. All rights reserved.

#ifndef TCP_SERVER_H
#define TCP_SERVER_H

#include "dbg_hwq.h"
#include "../buffer.h"

namespace shim_xdna {

class tcp_server {
public:
  tcp_server();
  ~tcp_server();

private:
  dbg_hwq_umq m_dbg_umq;
  uint32_t m_def_size;
  std::unique_ptr<buffer> m_def_bo;
  volatile void *m_def_buf;
  uint64_t m_def_addr;
  bool m_aie_attached;
};

}

#endif

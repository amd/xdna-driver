// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2025, Advanced Micro Devices, Inc. All rights reserved.

#ifndef DBG_HWQ_UMQ_H
#define DBG_HWQ_UMQ_H

#include "host_queue.h"
#include "dbg_cmd.h"
#include "aiedbg.h"

namespace shim_xdna {

class dbg_hwq_umq
{
public:
  dbg_hwq_umq(const device& device);
  ~dbg_hwq_umq();

private:
  const pdev& m_pdev;
  void *m_dbg_umq_bo_buf;
  uint64_t m_dbg_umq_addr;
  volatile struct host_queue_header *m_dbg_umq_hdr = nullptr;
  volatile struct host_queue_packet *m_dbg_umq_pkt = nullptr;
  uint64_t m_dbg_umq_comp;
  volatile uint32_t *m_dbg_umq_comp_ptr = nullptr;

  uint32_t issue_exit_cmd();
  uint32_t issue_rw_cmd(struct rw_mem &data, uint16_t opcode);
  uint32_t submit();
};

}

#endif

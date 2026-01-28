// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2023-2026, Advanced Micro Devices, Inc. All rights reserved.

#ifndef HWQ_UMQ_H
#define HWQ_UMQ_H

#include "../hwq.h"
#include "host_queue.h"

namespace shim_xdna {

class hwq_umq : public hwq
{
public:
  hwq_umq(const device& device, size_t nslots);
  ~hwq_umq();

  void
  bind_hwctx(const hwctx& ctx) override;

  void
  unbind_hwctx() override;

  bo_id
  get_queue_bo() const override;

  int
  wait_command(xrt_core::buffer_handle *, uint32_t timeout_ms) const override;

private:
  std::unique_ptr<buffer> m_umq_bo;
  void *m_umq_bo_buf;
  volatile struct host_queue_header *m_umq_hdr = nullptr;
  volatile struct host_queue_packet *m_umq_pkt = nullptr;
  volatile struct host_indirect_data *m_umq_indirect_buf = nullptr;
  uint64_t m_indirect_paddr;
  volatile uint32_t *m_mapped_doorbell = nullptr;

  uint64_t
  issue_command(const cmd_buffer *cmd_bo) override;

  void
  dump() const;

  void
  dump_raw() const;

  uint32_t
  get_next_avail_slot();

  volatile struct host_queue_packet *
  get_pkt(uint32_t index);

  void
  fill_direct_exec_buf(uint32_t idx, ert_dpu_data *dpu);

  void 
  fill_indirect_exec_buf(uint32_t idx, ert_dpu_data *dpu);

  uint64_t
  issue_single_exec_buf(const cmd_buffer *cmd_bo, bool last_of_chain);

  bool
  is_driver_cmd_submission() const;
};

}

#endif

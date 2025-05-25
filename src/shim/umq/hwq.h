// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2023-2025, Advanced Micro Devices, Inc. All rights reserved.

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

private:
  struct host_indirect_data {
    struct common_header	header;
    struct exec_buf		payload;
  };

  std::unique_ptr<cmd_buffer> m_umq_bo;
  void *m_umq_bo_buf;
  volatile struct host_queue_header *m_umq_hdr = nullptr;
  volatile struct host_queue_packet *m_umq_pkt = nullptr;
  volatile struct host_indirect_data *m_umq_indirect_buf = nullptr;
  uint64_t m_indirect_paddr;

  volatile uint32_t *m_mapped_doorbell = nullptr;

  uint64_t
  issue_command(const cmd_buffer *) override;

  void
  dump() const;

  void
  dump_raw() const;

  volatile struct host_queue_header *
  get_header_ptr() const;

  uint64_t
  reserve_slot();

  int
  get_pkt_idx(uint64_t index);

  volatile struct host_queue_packet *
  get_pkt(uint64_t index);

  void
  init_indirect_buf(volatile struct host_indirect_data *indirect_buf, int size);

  size_t
  fill_direct_exec_buf(uint16_t cu_idx,
    volatile struct host_queue_packet *pkt, ert_dpu_data *dpu);

  size_t 
  fill_indirect_exec_buf(uint64_t idx, uint16_t cu_idx,
    volatile struct host_queue_packet *pkt, ert_dpu_data *dpu);

  void
  fill_slot_and_send(volatile struct host_queue_packet *pkt, size_t size);

  uint64_t
  issue_exec_buf(uint16_t cu_idx, ert_dpu_data *dpu_data, uint64_t comp);

  void
  map_doorbell(uint32_t doorbell_offset);
};

}

#endif

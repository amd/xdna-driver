// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2023-2024, Advanced Micro Devices, Inc. All rights reserved.

#ifndef _HWQ_UMQ_H_
#define _HWQ_UMQ_H_

#include "../hwq.h"

#include "ert.h"
#include "host_queue.h"

namespace shim_xdna {

class hw_q_umq : public hw_q
{
public:
  hw_q_umq(const device& device, size_t nslots);

  ~hw_q_umq();

  void
  dump() const;

  void
  dump_raw() const;

  void
  bind_hwctx(const hw_ctx *ctx);

  volatile host_queue_header_t *
  get_header_ptr() const;

protected:
  void
  submit_command_list(const xrt_core::span<xrt_core::buffer_handle *>& cmd_bos) override;

private:
  std::unique_ptr<xrt_core::buffer_handle> m_umq_bo;
  void *m_umq_bo_buf;
  volatile host_queue_header_t *m_umq_hdr = nullptr;
  volatile host_queue_packet_t *m_umq_pkt = nullptr;

  volatile uint32_t *m_mapped_doorbell = nullptr;

  std::mutex m_mutex;

  uint64_t
  reserve_slot();

  volatile host_queue_packet_t *
  get_slot(uint64_t index);

  void
  fill_slot_and_send(volatile host_queue_packet_t *pkt, void *payload, size_t size);

  uint64_t
  issue_exec_buf(uint16_t cu_idx, ert_dpu_data *dpu_data, uint64_t comp);

  void
  map_doorbell(uint32_t doorbell_offset);
};

} // shim_xdna

#endif // _HWQ_UMQ_H_

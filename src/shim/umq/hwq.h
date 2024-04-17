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
  void
  submit_command(xrt_core::buffer_handle *) override;

  void
  submit_command(const std::vector<xrt_core::buffer_handle *>&) override;

public:
  hw_q_umq(const device& device, size_t nslots);

  ~hw_q_umq();

  void
  dump() const;

  void
  dump_raw() const;

  void
  map_doorbell(uint32_t doorbell_offset);

  volatile host_queue_header_t *
  get_header_ptr() const;

private:
  std::unique_ptr<xrt_core::buffer_handle> umq_bo;
  void *umq_bo_buf;
  volatile host_queue_header_t *umq_hdr = nullptr;
  volatile host_queue_packet_t *umq_pkt = nullptr;

  volatile uint32_t *mapped_doorbell = nullptr;

  std::mutex m_mutex;

  uint64_t
  reserve_slot();

  volatile host_queue_packet_t *
  get_slot(uint64_t index);

  void
  fill_slot_and_send(volatile host_queue_packet_t *pkt, void *payload, size_t size);

  uint64_t
  issue_exec_buf(uint16_t cu_idx, ert_dpu_data *dpu_data, uint64_t comp);

};

} // shim_xdna

#endif // _HWQ_UMQ_H_

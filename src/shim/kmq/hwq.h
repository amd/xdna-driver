// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2023-2024, Advanced Micro Devices, Inc. All rights reserved.

#ifndef _HWQ_KMQ_H_
#define _HWQ_KMQ_H_

#include "../hwq.h"

namespace shim_xdna {

class hw_q_kmq : public hw_q
{
public:
  hw_q_kmq(const device& device);

  ~hw_q_kmq();

  void
  map_doorbell(uint32_t doorbell_offset);

protected:
  void
  submit_command_list(const std::vector<xrt_core::buffer_handle *>&) override;
};

} // shim_xdna

#endif // _HWQ_KMQ_H_

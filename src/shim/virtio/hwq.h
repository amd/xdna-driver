// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2025, Advanced Micro Devices, Inc. All rights reserved.

#ifndef _HWQ_VIRTIO_H_
#define _HWQ_VIRTIO_H_

#include "../hwq.h"

namespace shim_xdna {

class hw_q_virtio : public hw_q
{
public:
  hw_q_virtio(const device& device);

  ~hw_q_virtio();

  int
  wait_command(xrt_core::buffer_handle *, uint32_t timeout_ms) const override;

  void
  issue_command(xrt_core::buffer_handle *) override;
};

} // shim_xdna

#endif // _HWQ_VIRTIO_H_

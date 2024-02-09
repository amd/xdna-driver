// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2023-2024, Advanced Micro Devices, Inc. All rights reserved.

#ifndef _HWQ_NPU_H_
#define _HWQ_NPU_H_

#include "../hwq.h"

namespace shim_xdna {

class hw_q_npu : public hw_q
{
public:
  hw_q_npu(const device& device);

  ~hw_q_npu();

  void
  submit_command(xrt_core::buffer_handle *) override;
};

} // shim_xdna

#endif // _HWQ_NPU_H_

// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2023-2024, Advanced Micro Devices, Inc. All rights reserved.

#ifndef _HWCTX_NPU_H_
#define _HWCTX_NPU_H_

#include "../hwctx.h"

namespace shim_xdna {

class hw_ctx_npu : public hw_ctx {
public:
  hw_ctx_npu(const device& dev, const xrt::xclbin& xclbin, const qos_type& qos);

  ~hw_ctx_npu();

private:
  void
  init_cu_info(const void *cu_idx_buf);

  void
  create_ctx(const device& dev, const xrt::xclbin& xclbin);

  void
  create_ctx_unsecure(const device& dev, const xrt::xclbin& xclbin);
};

} // shim_xdna

#endif // _HWCTX_NPU_H_

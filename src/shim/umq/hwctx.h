// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2023-2024, Advanced Micro Devices, Inc. All rights reserved.

#ifndef _HWCTX_UMQ_H_
#define _HWCTX_UMQ_H_

#include "../hwctx.h"

namespace shim_xdna {

class hw_ctx_umq : public hw_ctx {
public:
  hw_ctx_umq(const device& dev, const xrt::xclbin& xclbin, const qos_type& qos);

  ~hw_ctx_umq();

  std::unique_ptr<xrt_core::buffer_handle>
  alloc_bo(void* userptr, size_t size, uint64_t flags) override;

};

} // shim_xdna

#endif // _HWCTX_UMQ_H_

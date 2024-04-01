// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2023-2024, Advanced Micro Devices, Inc. All rights reserved.

#ifndef _HWCTX_KMQ_H_
#define _HWCTX_KMQ_H_

#include "../hwctx.h"

namespace shim_xdna {

class hw_ctx_kmq : public hw_ctx {
public:
  hw_ctx_kmq(const device& dev, const xrt::xclbin& xclbin, const qos_type& qos);

  ~hw_ctx_kmq();

  std::unique_ptr<xrt_core::buffer_handle>
  alloc_bo(void* userptr, size_t size, uint64_t flags) override;

private:
  std::vector< std::unique_ptr<xrt_core::buffer_handle> > m_pdi_bos;
};

} // shim_xdna

#endif // _HWCTX_KMQ_H_

// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2023-2025, Advanced Micro Devices, Inc. All rights reserved.

#ifndef HWCTX_KMQ_H_
#define HWCTX_KMQ_H_

#include "../hwctx.h"
#include "../buffer.h"

namespace shim_xdna {

class hwctx_kmq : public hwctx {
public:
  hwctx_kmq(const device& dev, const xrt::xclbin& xclbin, const qos_type& qos);
  ~hwctx_kmq();

private:
  std::vector< std::unique_ptr<buffer> > m_pdi_bos;
};

}

#endif

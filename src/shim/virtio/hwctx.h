// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2025, Advanced Micro Devices, Inc. All rights reserved.

#ifndef _HWCTX_VIRTIO_H_
#define _HWCTX_VIRTIO_H_

#include "bo.h"
#include "../hwctx.h"

namespace shim_xdna {

class hw_ctx_virtio : public hw_ctx {
public:
  hw_ctx_virtio(const device& dev, const xrt::xclbin& xclbin, const qos_type& qos);

  ~hw_ctx_virtio();

  std::unique_ptr<xrt_core::buffer_handle>
  alloc_bo(void* userptr, size_t size, uint64_t flags) override;

private:
  std::vector< std::unique_ptr<xrt_core::buffer_handle> > m_pdi_bos;

  void
  create_ctx_on_device() override;

  void
  delete_ctx_on_device() override;
};

} // shim_xdna

#endif // _HWCTX_VIRTIO_H_

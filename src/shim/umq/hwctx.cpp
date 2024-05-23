// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2023-2024, Advanced Micro Devices, Inc. All rights reserved.

#include "hwctx.h"
#include "hwq.h"

#include "core/common/config_reader.h"
#include "core/common/memalign.h"

namespace shim_xdna {

hw_ctx_umq::
hw_ctx_umq(const device& device, const xrt::xclbin& xclbin, const xrt::hw_context::qos_type& qos)
  : hw_ctx(device, qos, std::make_unique<hw_q_umq>(device, 8), xclbin)
{
  hw_ctx::init_log_buf();
  hw_ctx::create_ctx_on_device();

  shim_debug("Created UMQ HW context (%d)", get_slotidx());
}

hw_ctx_umq::
~hw_ctx_umq()
{
  shim_debug("Destroying UMQ HW context (%d)...", get_slotidx());
}

std::unique_ptr<xrt_core::buffer_handle>
hw_ctx_umq::
alloc_bo(void* userptr, size_t size, uint64_t flags)
{
  // const_cast: alloc_bo() is not const yet in device class
  auto& dev = const_cast<device&>(get_device());

  return dev.alloc_bo(userptr, AMDXDNA_INVALID_CTX_HANDLE, size, flags);
}

} // shim_xdna

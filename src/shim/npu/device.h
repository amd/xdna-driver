// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2023-2024, Advanced Micro Devices, Inc. All rights reserved.

#ifndef _DEVICE_NPU_H_
#define _DEVICE_NPU_H_

#include "../device.h"
#include "core/common/memalign.h"

namespace shim_xdna {

class device_npu : public device {
public:
  device_npu(const pdev& pdev, handle_type shim_handle, id_type device_id);

  ~device_npu();

  std::unique_ptr<xrt_core::buffer_handle>
  alloc_bo(void* userptr, xrt_core::hwctx_handle::slot_id ctx_id,
    size_t size, uint64_t flags) override;

protected:
  std::unique_ptr<xrt_core::hwctx_handle>
  create_hw_context(const device& dev, const xrt::xclbin& xclbin,
    const xrt::hw_context::qos_type& qos) const override;

private:
  std::unique_ptr<xrt_core::buffer_handle> m_dev_heap_bo;
};

} // namespace shim_xdna

#endif // _DEVICE_NPU_H_

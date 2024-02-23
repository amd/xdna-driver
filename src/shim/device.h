// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2022-2024, Advanced Micro Devices, Inc. All rights reserved.

#ifndef PCIE_DEVICE_LINUX_XDNA_H
#define PCIE_DEVICE_LINUX_XDNA_H

#include "pcidev.h"
#include "shim.h"
#include "shim_debug.h"

#include "core/pcie/linux/device_linux.h"

namespace shim_xdna {

class device : public xrt_core::device_linux
{
private:
  // Private look up function for concrete query::request
  const xrt_core::query::request&
  lookup_query(xrt_core::query::key_type query_key) const override;

  const pdev& m_pdev; // The pcidev that this device object is derived from

protected:
  virtual std::unique_ptr<xrt_core::hwctx_handle>
  create_hw_context(const device& dev,
    const xrt::xclbin& xclbin, const xrt::hw_context::qos_type& qos) const = 0;

public:
  device(const pdev& pdev, handle_type shim_handle, id_type device_id);

  ~device();

  const pdev&
  get_pdev() const;

  virtual std::unique_ptr<xrt_core::buffer_handle>
  alloc_bo(void* userptr, xrt_core::hwctx_handle::slot_id ctx_id,
    size_t size, uint64_t flags) = 0;

// ISHIM APIs supported are listed below
public:
  void
  close_device() override;

  std::unique_ptr<xrt_core::buffer_handle>
  alloc_bo(size_t size, uint64_t flags) override;

  virtual std::unique_ptr<xrt_core::buffer_handle>
  alloc_bo(void* userptr, size_t size, uint64_t flags) override;

  std::unique_ptr<xrt_core::hwctx_handle>
  create_hw_context(const xrt::uuid& xclbin_uuid, const xrt::hw_context::qos_type& qos,
    xrt::hw_context::access_mode mode) const override;

  void
  register_xclbin(const xrt::xclbin& xclbin) const override;
};

} // namespace shim_xdna

#endif

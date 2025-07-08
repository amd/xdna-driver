// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2022-2025, Advanced Micro Devices, Inc. All rights reserved.

#ifndef DEVICE_XDNA_H
#define DEVICE_XDNA_H

#include "shim.h"
#include "pcidev.h"
#include "shim_debug.h"
#include "core/common/ishim.h"

namespace shim_xdna {

class device : public xrt_core::noshim<xrt_core::device_pcie>
{
private:
  const pdev& m_pdev; // The pcidev that this device object is created from

  // The shared pointer to the pcidev which this device is created from
  // Hold the shared pointer in this object to make sure the underline pdev
  // will not be released until this object is released.
  std::shared_ptr<xrt_core::pci::dev> m_pcidev_handle;

  // Private look up function for concrete query::request
  const xrt_core::query::request&
  lookup_query(xrt_core::query::key_type query_key) const override;

public:
  device(const pdev& pdev, handle_type shim_handle, id_type device_id);
  ~device();

  const pdev&
  get_pdev() const;

// ISHIM APIs supported are listed below
public:
  void
  close_device() override;

  std::unique_ptr<xrt_core::buffer_handle>
  alloc_bo(size_t size, uint64_t flags) override;

  virtual std::unique_ptr<xrt_core::buffer_handle>
  alloc_bo(void* userptr, size_t size, uint64_t flags) override;

  std::unique_ptr<xrt_core::buffer_handle>
  import_bo(pid_t, xrt_core::shared_handle::export_handle) override;

  std::unique_ptr<xrt_core::hwctx_handle>
  create_hw_context(const xrt::uuid& xclbin_uuid, const xrt::hw_context::qos_type& qos,
    xrt::hw_context::access_mode mode) const override;

  std::unique_ptr<xrt_core::hwctx_handle>
  create_hw_context(uint32_t partition_size,
                    const xrt::hw_context::cfg_param_type& cfg,
                    xrt::hw_context::access_mode mode) const override;

  void
  register_xclbin(const xrt::xclbin& xclbin) const override;

  void
  open_aie_context(xrt::aie::access_mode) override;

  std::vector<char>
  read_aie_mem(uint16_t col, uint16_t row, uint32_t offset, uint32_t size) override;

  size_t
  write_aie_mem(uint16_t col, uint16_t row, uint32_t offset, const std::vector<char>& buf) override;

  uint32_t
  read_aie_reg(uint16_t col, uint16_t row, uint32_t reg_addr) override;

  bool
  write_aie_reg(uint16_t col, uint16_t row, uint32_t reg_addr, uint32_t reg_val) override;

  std::unique_ptr<xrt_core::fence_handle>
  create_fence(xrt::fence::access_mode) override;

  std::unique_ptr<xrt_core::fence_handle>
  import_fence(pid_t, xrt_core::shared_handle::export_handle) override;
};

}

#endif

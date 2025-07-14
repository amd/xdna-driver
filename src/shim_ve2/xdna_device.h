// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2025, Advanced Micro Devices, Inc. All rights reserved.

#ifndef XDNA_EDGE_DEVICE_H__
#define XDNA_EDGE_DEVICE_H__

#include "core/common/shim/buffer_handle.h"
#include "core/edge/common/device_edge.h"
#include "core/common/shim/hwctx_handle.h"
#include "core/common/ishim.h"
#include "core/common/shim/shared_handle.h"
#include "shim_debug.h"
#include "xdna_edgedev.h"
#include "xdna_aie_array.h"
#include "xdna_shim.h"

namespace shim_xdna_edge {

class xdna_hwctx;

// concrete class derives from device_edge, but mixes in
// shim layer functions for access through base class
class device_xdna : public xrt_core::noshim<xrt_core::device_edge>
{
  static const int BUFFER_ALIGNMENT = 0x80; // TODO: UKP
public:
  device_xdna(handle_type device_handle, id_type device_id);

  ~device_xdna();

  std::unique_ptr<xrt_core::hwctx_handle>
  create_hw_context(const xrt::uuid& xclbin_uuid,
		    const xrt::hw_context::qos_type& qos,
		    xrt::hw_context::access_mode mode) const override;

  std::unique_ptr<xrt_core::hwctx_handle>
  create_hw_context(uint32_t partition_size,
                    const xrt::hw_context::qos_type& qos,
                    xrt::hw_context::access_mode mode) const override;

  virtual void
  open_aie_context(xrt::aie::access_mode)
  {}

  std::shared_ptr<xdna_edgedev>
  get_edev() const;

  std::unique_ptr<xrt_core::buffer_handle>
  alloc_bo(size_t size, uint64_t flags) override;

  virtual std::unique_ptr<xrt_core::buffer_handle>
  alloc_bo(void* userptr, size_t size, uint64_t flags) override;

  void close_device() override;

  void
  open_context(const xrt::uuid&, unsigned int, bool) override
  {
    //currently this is a no-op
  }

  void
  register_xclbin(const xrt::xclbin& xclbin) const override
  {
    //currently this is a no-op
  }

  std::unique_ptr<xrt_core::buffer_handle>
  alloc_bo(void* userptr, xrt_core::hwctx_handle::slot_id ctx_id,
	   size_t size, uint64_t flags);

  std::unique_ptr<xrt_core::buffer_handle>
  import_bo(pid_t pid, xrt_core::shared_handle::export_handle ehdl) override;

  virtual std::vector<char>
  read_aie_mem(uint16_t /*col*/, uint16_t /*row*/, uint32_t /*offset*/, uint32_t /*size*/) override;

  virtual size_t
  write_aie_mem(uint16_t /*col*/, uint16_t /*row*/, uint32_t /*offset*/, const std::vector<char>& /*data*/) override;

  virtual uint32_t
  read_aie_reg(uint16_t /*col*/, uint16_t /*row*/, uint32_t /*reg_addr*/) override;

  virtual bool
  write_aie_reg(uint16_t /*col*/, uint16_t /*row*/, uint32_t /*reg_addr*/, uint32_t /*reg_val*/) override;

  int
  get_info(xclDeviceInfo2 *info) const;

  std::shared_ptr<xdna_aie_array> 
  get_aie_array();

  void 
  register_aie_array(const xdna_hwctx* hwctx_obj);

  bool 
  is_aie_registered();

  std::string
  get_uuid() const
  {
    return m_uuid;
  }

private:
  std::shared_ptr<xdna_edgedev> m_edev; // The xdna_edgedev that this device object is derived from

  // Private look up function for concrete query::request
  const xrt_core::query::request&
  lookup_query(xrt_core::query::key_type query_key) const override;
  std::shared_ptr<xdna_aie_array> m_aie_array;
  mutable std::string m_uuid;

};

}

#endif /* XDNA_EDGE_DEVICE_H */

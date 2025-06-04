// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2025, Advanced Micro Devices, Inc. All rights reserved.

#ifndef XDNA_EDGE_HWCTX_H__
#define XDNA_EDGE_HWCTX_H__

#include "drm_local/amdxdna_accel.h"
#include "core/common/shim/buffer_handle.h"
#include "core/common/shim/fence_handle.h"
#include "core/common/shim/hwctx_handle.h"
#include "shim_debug.h"
#include "xdna_device.h"

namespace shim_xdna_edge {

struct partition_info
{
  uint32_t start_column;
  uint32_t num_columns;
  uint32_t partition_id;
  uint64_t base_address;
};

class xdna_hwq; // forward declaration

class xdna_hwctx : public xrt_core::hwctx_handle
{
public:
  xdna_hwctx(const device_xdna& dev, const xrt::xclbin& xclbin, const xrt::hw_context::qos_type& qos);

  xdna_hwctx(const device_xdna& dev, uint32_t partition_size, const xrt::hw_context::qos_type& qos);

  ~xdna_hwctx();

  // TODO
  void
  update_qos(const qos_type&) override
  { shim_not_supported_err(__func__); }

  void
  update_access_mode(access_mode) override
  { shim_not_supported_err(__func__); }

  slot_id
  get_slotidx() const override;

  xrt_core::hwqueue_handle*
  get_hw_queue() override;

  partition_info
  get_partition_info() const
  {
    return m_info;
  }

  std::unique_ptr<xrt_core::buffer_handle>
  alloc_bo(void* userptr, size_t size, uint64_t flags) override;

  std::unique_ptr<xrt_core::buffer_handle>
  alloc_bo(size_t size, uint64_t flags) override;

  std::unique_ptr<xrt_core::buffer_handle>
  import_bo(pid_t, xrt_core::shared_handle::export_handle) override;

  xrt_core::cuidx_type
  open_cu_context(const std::string& cuname) override;

  void
  close_cu_context(xrt_core::cuidx_type cuidx) override;

  void
  exec_buf(xrt_core::buffer_handle *) override
  { shim_not_supported_err(__func__); }

public:
  uint32_t
  get_doorbell() const;

  xrt::uuid
  get_xclbin_uuid() const
  {
    return m_uuid;
  }

  std::shared_ptr<xdna_aie_array>
  get_aie_array();

protected:
  const device_xdna&
  get_device();

  struct cu_info {
    std::string m_name;
    size_t m_func;
    std::vector<uint8_t> m_pdi;
  };

  const std::vector<cu_info>&
  get_cu_info() const;

  void
  set_slotidx(slot_id id);

  void
  set_doorbell(uint32_t db);

  void
  init_log_buf();

  void
  fini_log_buf();

private:
  const device_xdna& m_device;
  slot_id m_handle = AMDXDNA_INVALID_CTX_HANDLE;
  amdxdna_qos_info m_qos = {};
  std::vector<cu_info> m_cu_info;
  std::unique_ptr<xdna_hwq> m_hwq;
  uint32_t m_ops_per_cycle;
  uint32_t m_num_cols;
  uint32_t m_doorbell;
  std::unique_ptr<xrt_core::buffer_handle> m_log_bo;
  std::shared_ptr<xdna_aie_array> m_aie_array;
  void *m_log_buf;
  xrt::uuid m_uuid;
  partition_info m_info;

  void
  init_qos_info(const qos_type& qos);

  void
  parse_xclbin(const xrt::xclbin& xclbin);

  void
  print_xclbin_info();
};

} // shim_xdna_edge

#endif // __XDNA_EDGE_HWCTX_H__

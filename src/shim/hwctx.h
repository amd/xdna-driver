// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2022-2025, Advanced Micro Devices, Inc. All rights reserved.

#ifndef HWCTX_XDNA_H
#define HWCTX_XDNA_H

#include "device.h"
#include "core/common/xclbin_parser.h"
#include "core/common/shim/buffer_handle.h"
#include "core/common/shim/hwctx_handle.h"

namespace shim_xdna {

class hwq; // forward declaration

class xclbin_parser {
public:
  xclbin_parser(const xrt::xclbin& xclbin);
  ~xclbin_parser();

  uint32_t
  get_column_cnt() const;

  uint32_t
  get_ops_per_cycle() const;

  int
  get_num_cus() const;

  const std::string&
  get_cu_name(int idx) const;

  size_t
  get_cu_func(int idx) const;

  const std::vector<uint8_t>&
  get_cu_pdi(int idx) const;

private:
  struct cu_info {
    std::string m_name;
    size_t m_func;
    std::vector<uint8_t> m_pdi;
  };
  std::vector<cu_info> m_cus;
  uint32_t m_column_cnt;
  uint32_t m_ops_per_cycle;

  std::vector<uint8_t>
  get_pdi(const xrt_core::xclbin::aie_partition_obj& aie, uint16_t kernel_id) const;

  void
  print_info() const;
};

class hwctx : public xrt_core::hwctx_handle
{
public:
  hwctx(const device& dev, const qos_type& qos, const xrt::xclbin& xclbin,
    std::unique_ptr<hwq> queue);
  hwctx(const device& dev, uint32_t partition_size, std::unique_ptr<hwq> queue);
  ~hwctx();

  slot_id
  get_slotidx() const override;

  xrt_core::hwqueue_handle*
  get_hw_queue() override;

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

  uint32_t
  get_syncobj() const;

private:
  const device& m_device;
  slot_id m_handle = AMDXDNA_INVALID_CTX_HANDLE;
  std::vector<std::string> m_cu_names;
  uint32_t m_doorbell = 0;
  uint32_t m_syncobj = AMDXDNA_INVALID_FENCE_HANDLE;
  uint32_t m_col_cnt = 0;
  uint32_t m_ops_per_cycle = 0;
  std::unique_ptr<hwq> m_q;
  amdxdna_qos_info m_qos = {};

  void
  create_ctx_on_device();

  void
  delete_ctx_on_device();

  void
  init_qos_info(const qos_type& qos);
};

}

#endif

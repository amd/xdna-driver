// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2022-2024, Advanced Micro Devices, Inc. All rights reserved.

#ifndef _HWCTX_XDNA_H_
#define _HWCTX_XDNA_H_

#include "device.h"
#include "shim_debug.h"

#include "core/common/shim/buffer_handle.h"
#include "core/common/shim/fence_handle.h"
#include "core/common/shim/hwctx_handle.h"
#include "drm_local/amdxdna_accel.h"

namespace shim_xdna {

class hw_q; // forward declaration

class hw_ctx : public xrt_core::hwctx_handle
{
public:
  hw_ctx(const device& dev, const qos_type& qos, std::unique_ptr<hw_q> q, const xrt::xclbin& xclbin);

  ~hw_ctx();

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

  std::unique_ptr<xrt_core::buffer_handle>
  alloc_bo(void* userptr, size_t size, uint64_t flags) override = 0;

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

protected:
  const device&
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
  set_syncobj(uint32_t syncobj);

  void
  create_ctx_on_device();

  void
  init_log_buf();

  void
  fini_log_buf();

private:
  const device& m_device;
  slot_id m_handle = AMDXDNA_INVALID_CTX_HANDLE;
  amdxdna_qos_info m_qos = {};
  std::vector<cu_info> m_cu_info;
  std::unique_ptr<hw_q> m_q;
  uint32_t m_ops_per_cycle;
  uint32_t m_num_cols;
  uint32_t m_doorbell;
  uint32_t m_syncobj;
  std::unique_ptr<xrt_core::buffer_handle> m_log_bo;
  void *m_log_buf;

  void
  delete_ctx_on_device();

  void
  init_qos_info(const qos_type& qos);

  void
  parse_xclbin(const xrt::xclbin& xclbin);

  void
  print_xclbin_info();
};

} // shim_xdna

#endif // _HWCTX_XDNA_H_

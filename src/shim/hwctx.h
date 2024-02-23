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

namespace {

const xrt_core::hwctx_handle::slot_id INVALID_CTX_HANDLE = -1;

}

namespace shim_xdna {

class hw_q; // forward declaration

class hw_ctx : public xrt_core::hwctx_handle
{
public:
  hw_ctx(const device& dev, const qos_type& qos, std::unique_ptr<hw_q> q);

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

  xrt_core::cuidx_type
  open_cu_context(const std::string& cuname) override;

  void
  close_cu_context(xrt_core::cuidx_type cuidx) override;

  void
  exec_buf(xrt_core::buffer_handle *) override
  { shim_not_supported_err(__func__); }

protected:
  std::map< std::string, std::pair<xrt_core::cuidx_type, std::vector<uint8_t>> > m_cu_info;

  const amdxdna_qos_info *
  get_qos_info() const;

  void
  set_slotidx(slot_id id);

  void
  print_cu_info();

  const device& m_device;

private:
  slot_id m_handle = INVALID_CTX_HANDLE;
  amdxdna_qos_info m_qos = {};
  std::unique_ptr<hw_q> m_q;
};

} // shim_xdna

#endif // _HWCTX_XDNA_H_

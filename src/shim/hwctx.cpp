// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2022-2024, Advanced Micro Devices, Inc. All rights reserved.

#include "bo.h"
#include "hwctx.h"
#include "hwq.h"

namespace {

void
init_qos_info(const xrt::hw_context::qos_type& qos, amdxdna_qos_info& drv_qos)
{
  for (auto& [key, value] : qos) {
    if (key == "gops")
      drv_qos.gops = value;
    else if (key == "fps")
      drv_qos.fps = value;
    else if (key == "dma_bandwidth")
      drv_qos.dma_bandwidth = value;
    else if (key == "latency")
      drv_qos.latency = value;
    else if (key == "frame_execution_time")
      drv_qos.frame_exec_time = value;
    else if (key == "priority")
      drv_qos.priority = value;
  }
}

}

namespace shim_xdna {

hw_ctx::
hw_ctx(const device& dev, const xrt::hw_context::qos_type& qos, std::unique_ptr<hw_q> q)
  : m_device(dev), m_q(std::move(q))
{
  shim_debug("Creating HW context...");
  init_qos_info(qos, m_qos);
}

hw_ctx::
~hw_ctx()
{
  if (m_handle == INVALID_CTX_HANDLE)
    return;
  shim_debug("Destroyed HW context (%d)...", m_handle);
}

hw_ctx::slot_id
hw_ctx::
get_slotidx() const
{
  return m_handle;
}

void
hw_ctx::
set_slotidx(slot_id id)
{
  m_handle = id;
}

xrt_core::cuidx_type
hw_ctx::
open_cu_context(const std::string& cu_name)
{
  auto it = m_cu_info.find(cu_name);
  if (it == m_cu_info.end())
    shim_err(ENOENT, "CU name (%s) not found", cu_name.c_str());
  return it->second.first;
}

void
hw_ctx::
close_cu_context(xrt_core::cuidx_type cuidx)
{
  // Nothing to be done
}

std::unique_ptr<xrt_core::buffer_handle>
hw_ctx::
alloc_bo(void* userptr, size_t size, uint64_t flags)
{
  // const_cast: alloc_bo() is not const yet in device class
  return const_cast<device&>(m_device).alloc_bo(userptr, size, flags);
}

std::unique_ptr<xrt_core::buffer_handle>
hw_ctx::
alloc_bo(size_t size, uint64_t flags)
{
  return alloc_bo(nullptr, size, flags);
}

xrt_core::hwqueue_handle*
hw_ctx::
get_hw_queue()
{
  return m_q.get();
}

const amdxdna_qos_info *
hw_ctx::
get_qos_info() const
{
  return &m_qos;
}

// For debugging only
void
hw_ctx::
print_cu_info()
{
  if (m_cu_info.empty()) {
    shim_debug("CU INFO MAP is empty");
    return;
  }

  for (auto it = m_cu_info.begin(); it != m_cu_info.end(); it++) {
    shim_debug("CU name=%s, index=%d, pdi(p=%p, sz=%ld)",
      it->first.c_str(), it->second.first.index, it->second.second.data(), it->second.second.size());
  }
}

} // shim_xdna

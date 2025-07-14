// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2022-2025, Advanced Micro Devices, Inc. All rights reserved.

#include "buffer.h"
#include "hwctx.h"
#include "hwq.h"

#include "core/common/query_requests.h"
#include "core/common/api/xclbin_int.h"

namespace shim_xdna {

//
// Implementation of xclbin_parser
//

xclbin_parser::
xclbin_parser(const xrt::xclbin& xclbin)
{
  auto axlf = xclbin.get_axlf();
  auto aie_partition = xrt_core::xclbin::get_aie_partition(axlf);

  for (const auto& k : xclbin.get_kernels()) {
    auto& props = xrt_core::xclbin_int::get_properties(k);
    try {
      for (const auto& cu : k.get_cus()) {
        m_cus.push_back( {
          .m_name = cu.get_name(),
          .m_func = props.functional,
          .m_pdi = get_pdi(aie_partition, props.kernel_id) } );
      }
    } catch (xrt_core::system_error &ex) {
      if (ex.get_code() != ENOENT)
        throw;
      shim_debug("%s", ex.what());
      continue;
    }
  }

  if (m_cus.empty())
    shim_err(EINVAL, "No valid DPU kernel found in xclbin");
  m_ops_per_cycle = aie_partition.ops_per_cycle;
  m_column_cnt = aie_partition.ncol;
  //print_info();
}

xclbin_parser::
~xclbin_parser()
{
  // Nothing to do
}

std::vector<uint8_t>
xclbin_parser::
get_pdi(const xrt_core::xclbin::aie_partition_obj& aie, uint16_t kernel_id) const
{
  for (auto& pdi : aie.pdis) {
    for (auto& cdo : pdi.cdo_groups) {
      for (auto kid : cdo.kernel_ids) {
        if (kid == kernel_id)
          return pdi.pdi;
      }
    }
  }
  shim_err(ENOENT, "PDI for kernel ID 0x%x not found", kernel_id);
}

void
xclbin_parser::
print_info() const
{
  if (m_cus.empty()) {
    shim_debug("CU INFO is empty");
    return;
  }

  for (int idx = 0; idx < m_cus.size(); idx++) {
    auto& e = m_cus[idx];
    shim_debug("index=%d, name=%s, func=%d, pdi(p=%p, sz=%ld)",
      idx, e.m_name.c_str(), e.m_func, e.m_pdi.data(), e.m_pdi.size());
  }
  shim_debug("col cnt: %d", m_column_cnt);
  shim_debug("OPs/cycle: %d", m_ops_per_cycle);
}

uint32_t
xclbin_parser::
get_column_cnt() const
{
  return m_column_cnt;
}

uint32_t
xclbin_parser::
get_ops_per_cycle() const
{
  return m_ops_per_cycle;
}

int
xclbin_parser::
get_num_cus() const
{
  return m_cus.size();
}

const std::string&
xclbin_parser::
get_cu_name(int idx) const
{
  return m_cus[idx].m_name;
}

size_t
xclbin_parser::
get_cu_func(int idx) const
{
  return m_cus[idx].m_func;
}

const std::vector<uint8_t>&
xclbin_parser::
get_cu_pdi(int idx) const
{
  return m_cus[idx].m_pdi;
}

//
// Implementation of hwctx
//

hwctx::
hwctx(const device& dev, const qos_type& qos, const xrt::xclbin& xclbin,
  std::unique_ptr<hwq> queue)
  : m_device(dev)
  , m_q(std::move(queue))
{
  xclbin_parser xp(xclbin);

  m_col_cnt = xp.get_column_cnt();
  m_ops_per_cycle = xp.get_ops_per_cycle();
  auto n_cu = xp.get_num_cus();
  for (int i = 0; i < n_cu; i++)
    m_cu_names.push_back(xp.get_cu_name(i));

  init_qos_info(qos);

  create_ctx_on_device();
}

hwctx::
hwctx(const device& dev, uint32_t partition_size, std::unique_ptr<hwq> queue)
  : m_device(dev)
  , m_q(std::move(queue))
{
  m_col_cnt = partition_size;
  m_ops_per_cycle = 0;

  create_ctx_on_device();
}

hwctx::
~hwctx()
{
  try {
    delete_ctx_on_device();
  } catch (const xrt_core::system_error& e) {
    shim_debug("Failed to delete context on device: %s", e.what());
  }
}

hwctx::slot_id
hwctx::
get_slotidx() const
{
  return m_handle;
}

xrt_core::cuidx_type
hwctx::
open_cu_context(const std::string& cu_name)
{
  for (uint32_t i = 0; i < m_cu_names.size(); i++) {
    auto& name = m_cu_names[i];
    if (name == cu_name)
      return xrt_core::cuidx_type{ .index = i };
  }
  shim_err(ENOENT, "CU name (%s) not found", cu_name.c_str());
}

void
hwctx::
close_cu_context(xrt_core::cuidx_type cuidx)
{
  // Nothing to be done
}

std::unique_ptr<xrt_core::buffer_handle>
hwctx::
alloc_bo(size_t size, uint64_t flags)
{
  return alloc_bo(nullptr, size, flags);
}

std::unique_ptr<xrt_core::buffer_handle>
hwctx::
alloc_bo(void* userptr, size_t size, uint64_t flags)
{
  // const_cast: alloc_bo() is not const yet in device class
  auto& dev = const_cast<device&>(m_device);
  auto boh = dev.alloc_bo(userptr, size, flags);
  auto bo = dynamic_cast<buffer*>(boh.get());
  bo->bind_hwctx(*this);
  return boh;
}

std::unique_ptr<xrt_core::buffer_handle>
hwctx::
import_bo(pid_t pid, xrt_core::shared_handle::export_handle ehdl)
{
  // const_cast: import_bo() is not const yet in device class
  auto& dev = const_cast<device&>(m_device);
  return dev.import_bo(pid, ehdl);
}

xrt_core::hwqueue_handle*
hwctx::
get_hw_queue()
{
  return m_q.get();
}

void
hwctx::
init_qos_info(const qos_type& qos)
{
  for (auto& [key, value] : qos) {
    if (key == "gops" && value && !m_qos.gops)
      m_qos.gops = value;
    if (key == "egops" && value)
      m_qos.gops = value;
    else if (key == "fps")
      m_qos.fps = value;
    else if (key == "dma_bandwidth")
      m_qos.dma_bandwidth = value;
    else if (key == "latency")
      m_qos.latency = value;
    else if (key == "frame_execution_time")
      m_qos.frame_exec_time = value;
    else if (key == "priority")
      m_qos.priority = value;
  }
}

void
hwctx::
create_ctx_on_device()
{
  create_ctx_arg arg = {
    .qos = m_qos,
    .umq_bo = m_q->get_queue_bo(),
    .log_buf_bo = { AMDXDNA_INVALID_BO_HANDLE, AMDXDNA_INVALID_BO_HANDLE },
    .max_opc = m_ops_per_cycle,
    .num_tiles = m_col_cnt * xrt_core::device_query<xrt_core::query::aie_tiles_stats>(&m_device).core_rows,
  };
  m_device.get_pdev().drv_ioctl(drv_ioctl_cmd::create_ctx, &arg);

  m_handle = arg.ctx_handle;
  m_doorbell = arg.umq_doorbell;
  m_syncobj = arg.syncobj_handle;
  m_q->bind_hwctx(*this);
}

void
hwctx::
delete_ctx_on_device()
{
  if (m_handle == AMDXDNA_INVALID_CTX_HANDLE)
    return;

  m_q->unbind_hwctx();
  struct destroy_ctx_arg arg = {
    .ctx_handle = m_handle,
    .syncobj_handle = m_syncobj,
  };
  m_device.get_pdev().drv_ioctl(drv_ioctl_cmd::destroy_ctx, &arg);
}

uint32_t
hwctx::
get_doorbell() const
{
  return m_doorbell;
}

uint32_t
hwctx::
get_syncobj() const
{
  return m_syncobj;
}

} // shim_xdna

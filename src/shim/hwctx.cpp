// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2022-2024, Advanced Micro Devices, Inc. All rights reserved.

#include "bo.h"
#include "hwctx.h"
#include "hwq.h"

#include "core/common/xclbin_parser.h"
#include "core/common/query_requests.h"

namespace {

std::vector<uint8_t>
get_pdi(const xrt_core::xclbin::aie_partition_obj& aie, uint16_t kernel_id)
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

}
namespace shim_xdna {

hw_ctx::
hw_ctx(const device& dev, const qos_type& qos, std::unique_ptr<hw_q> q, const xrt::xclbin& xclbin)
  : m_device(dev), m_q(std::move(q))
{
  shim_debug("Creating HW context...");
  init_qos_info(qos);
  parse_xclbin(xclbin);
}

hw_ctx::
~hw_ctx()
{
  delete_ctx_on_device();
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
  for (uint32_t i = 0; i < m_cu_info.size(); i++) {
    auto& ci = m_cu_info[i];
    if (ci.m_name == cu_name)
      return xrt_core::cuidx_type{ .index = i };
  }

  shim_err(ENOENT, "CU name (%s) not found", cu_name.c_str());
}

void
hw_ctx::
close_cu_context(xrt_core::cuidx_type cuidx)
{
  // Nothing to be done
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

void
hw_ctx::
init_qos_info(const qos_type& qos)
{
  for (auto& [key, value] : qos) {
    if (key == "gops")
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
hw_ctx::
print_xclbin_info()
{
  if (m_cu_info.empty()) {
    shim_debug("CU INFO is empty");
    return;
  }

  for (int idx = 0; idx < m_cu_info.size(); idx++) {
    auto& e = m_cu_info[idx];
    shim_debug("index=%d, name=%s, func=%d, pdi(p=%p, sz=%ld)",
      idx, e.m_name.c_str(), e.m_func, e.m_pdi.data(), e.m_pdi.size());
  }
  shim_debug("OPs/cycle: %d", m_ops_per_cycle);
}

void
hw_ctx::
parse_xclbin(const xrt::xclbin& xclbin)
{
  auto axlf = xclbin.get_axlf();
  auto aie_partition = xrt_core::xclbin::get_aie_partition(axlf);
  auto ips = xrt_core::xclbin::axlf_section_type<const ip_layout*>::get(
    axlf, axlf_section_kind::IP_LAYOUT);

  for (uint32_t idx = 0; idx < ips->m_count; idx++) {
    auto ip = &ips->m_ip_data[idx];
    if (ip->m_type != IP_PS_KERNEL || ip->ps_kernel.m_subtype != ST_DPU)
      continue;

    //xrt_core::cuidx_type cuidx = { .index = idx, };
    try {
      auto pdi = get_pdi(aie_partition, ip->ps_kernel.m_kernel_id);
      auto cuname = std::string(reinterpret_cast<const char*>(ip->m_name));
      m_cu_info.push_back( {
        .m_name = cuname,
        .m_func = static_cast<uint8_t>(ip->ps_kernel.m_functional),
        .m_pdi = pdi } );
    } catch (xrt_core::system_error &ex) {
      if (ex.get_code() != ENOENT)
        throw;
      shim_debug("%s", ex.what());
      continue;
    }
  }

  if (m_cu_info.empty())
    shim_err(EINVAL, "No valid DPU kernel found in xclbin");

  m_ops_per_cycle = aie_partition.ops_per_cycle;
  m_num_cols = aie_partition.ncol;
}

const device&
hw_ctx::
get_device()
{
  return m_device;
}

const std::vector<hw_ctx::cu_info>&
hw_ctx::
get_cu_info() const
{
  return m_cu_info;
}

void
hw_ctx::
create_ctx_on_device()
{
  amdxdna_drm_create_hwctx arg = {};
  arg.qos_p = reinterpret_cast<uintptr_t>(&m_qos);
  arg.umq_bo = m_q->get_queue_bo();
  arg.max_opc = m_ops_per_cycle;
  arg.num_tiles = m_num_cols * xrt_core::device_query<xrt_core::query::aie_tiles_stats>(&m_device).core_rows;
  arg.log_buf_bo = init_log_buf();
  m_device.get_pdev().ioctl(DRM_IOCTL_AMDXDNA_CREATE_HWCTX, &arg);

  set_slotidx(arg.handle);
  set_doorbell(arg.umq_doorbell);

  m_q->bind_hwctx(this);
}

void
hw_ctx::
delete_ctx_on_device()
{
  if (m_handle == INVALID_CTX_HANDLE)
    return;

  m_q->unbind_hwctx();
  struct amdxdna_drm_destroy_hwctx arg = {};
  arg.handle = m_handle;
  m_device.get_pdev().ioctl(DRM_IOCTL_AMDXDNA_DESTROY_HWCTX, &arg);

  fini_log_buf();
}

uint32_t
hw_ctx::
init_log_buf()
{
  m_log_buf_size = m_num_cols * 1024;
  m_log_bo = alloc_bo(nullptr, m_log_buf_size, XCL_BO_FLAGS_EXECBUF);
  m_log_buf = m_log_bo->map(bo::map_type::write);
  std::memset(m_log_buf, 0, m_log_buf_size);

  return static_cast<bo*>(m_log_bo.get())->get_drm_bo_handle();
}

void
hw_ctx::
fini_log_buf(void)
{
  m_log_bo->unmap(m_log_buf);
}

void
hw_ctx::
set_doorbell(uint32_t db)
{
  m_doorbell = db;
}

uint32_t
hw_ctx::
get_doorbell() const
{
  return m_doorbell;
}

} // shim_xdna

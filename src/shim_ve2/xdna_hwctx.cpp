// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2025, Advanced Micro Devices, Inc. All rights reserved.

#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp>
#include <boost/optional.hpp>

#include "core/edge/common/aie_parser.h"
#include "core/common/config_reader.h"
#include "core/common/query_requests.h"
#include "core/common/api/xclbin_int.h"
#include "core/common/xclbin_parser.h"
#include "xdna_bo.h"
#include "xdna_hwctx.h"
#include "xdna_hwq.h"

namespace shim_xdna_edge {

namespace pt = boost::property_tree;

void read_aie_metadata_hw(const char* data, size_t size, pt::ptree& aie_project)
{
  std::stringstream aie_stream;
  aie_stream.write(data,size);
  pt::read_json(aie_stream,aie_project);
}

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
  shim_err(ENOENT, "PDI for kernel ID %d not found", kernel_id);
}

partition_info
get_partition_info_main(const xrt_core::device* device,const pt::ptree& aie_meta, uint32_t hw_context_id)
{
  partition_info info;
  info.start_column = 0;
  info.base_address = aie_meta.get<uint64_t>("aie_metadata.driver_config.base_address");

  bool partinfo_found = false;
  auto data = xrt_core::device_query_default<xrt_core::query::aie_partition_info>(device, {});
  
  for (const auto& entry : data) {
    if ( std::stoi(entry.metadata.id) == hw_context_id) {
      info.num_columns = entry.num_cols;
      info.start_column = entry.start_col;
      info.partition_id = (entry.num_cols << 8U) | (entry.start_col & 0xffU);
      partinfo_found = true;
      break;
    }
  }

  if(partinfo_found == false)
    throw xrt_core::error(-EINVAL, "partition info not found");

  return info;
}

partition_info
get_partition_info_hw(const xrt_core::device* device, const xrt::uuid xclbin_uuid, uint32_t hw_context_id)
{
  auto data = device->get_axlf_section(AIE_TRACE_METADATA, xclbin_uuid);
  if (!data.first || !data.second)
    return {};

  pt::ptree aie_meta;
  read_aie_metadata_hw(data.first, data.second, aie_meta);
  return get_partition_info_main(device,aie_meta, hw_context_id);
}

xdna_hwctx::
xdna_hwctx(const device_xdna& dev, const xrt::xclbin& xclbin, const xrt::hw_context::qos_type& qos)
  : m_device(dev), 
    m_doorbell(0), 
    m_log_buf(nullptr), 
    m_uuid(xclbin.get_uuid())
{
  m_hwq = std::make_unique<xdna_hwq>(m_device);
  init_qos_info(qos);
  parse_xclbin(xclbin);
  amdxdna_drm_create_ctx arg = {};
  arg.qos_p = reinterpret_cast<uintptr_t>(&m_qos);
  arg.num_tiles = m_num_cols;
  // TODO: Need to use correct field once available in amdxdna_drm_create_ctx
  // making use of umq_bo field for now.
  arg.umq_bo = xrt_core::config::get_privileged_context();

  // FIXME
#if 0
  // Not supported yet
  arg.umq_bo = m_q->get_queue_bo();
  arg.max_opc = m_ops_per_cycle;
  arg.num_tiles = m_num_cols * xrt_core::device_query<xrt_core::query::aie_tiles_stats>(&m_device).core_rows;
  arg.log_buf_bo = m_log_bo ?
	  static_cast<bo*>(m_log_bo.get())->get_drm_bo_handle() :
	  AMDXDNA_INVALID_BO_HANDLE;
#endif
  m_device.get_edev()->ioctl(DRM_IOCTL_AMDXDNA_CREATE_CTX, &arg);

  set_slotidx(arg.handle);
  m_info = get_partition_info_hw(&m_device, xclbin.get_uuid(), arg.handle);
  set_doorbell(arg.umq_doorbell);

  auto data = m_device.get_axlf_section(AIE_TRACE_METADATA, xclbin.get_uuid());
  if (data.first && data.second)
    m_aie_array = std::make_shared<xdna_aie_array>(&m_device, this);

  m_hwq->bind_hwctx(this);
}

xdna_hwctx::
xdna_hwctx(const device_xdna& dev, uint32_t partition_size, const xrt::hw_context::qos_type& qos)
  : m_device(dev)
  , m_hwq{ std::make_unique<xdna_hwq>(m_device) }
  , m_num_cols(partition_size)
  , m_doorbell(0)
  , m_log_buf(nullptr)
{
  init_qos_info(qos);

  amdxdna_drm_create_ctx arg = {};
  arg.qos_p = reinterpret_cast<uintptr_t>(&m_qos);
  arg.num_tiles = m_num_cols;
  // TODO: Need to use correct field once available in amdxdna_drm_create_ctx
  // making use of umq_bo field for now.
  arg.umq_bo = xrt_core::config::get_privileged_context();

  m_device.get_edev()->ioctl(DRM_IOCTL_AMDXDNA_CREATE_CTX, &arg);

  set_slotidx(arg.handle);
  set_doorbell(arg.umq_doorbell);

  // TODO : create xdna_aie_array object after ELF has AIE_METADATA, AIE_PARTITION
  // sections added

  m_hwq->bind_hwctx(this);
}

xdna_hwctx::
~xdna_hwctx()
{
  try {
    if (m_handle == AMDXDNA_INVALID_CTX_HANDLE)
      return;

    m_hwq->unbind_hwctx();
    struct amdxdna_drm_destroy_ctx arg = {};
    arg.handle = m_handle;
    m_device.get_edev()->ioctl(DRM_IOCTL_AMDXDNA_DESTROY_CTX, &arg);
#if 0
    // Not supported yet
    fini_log_buf();
#endif
  } catch (const xrt_core::system_error& e) {
    shim_debug("Failed to delete context on device: %s", e.what());
  }
  shim_debug("Destroyed HW context (%d)...", m_handle);
}

std::shared_ptr<xdna_aie_array>
xdna_hwctx::
get_aie_array()
{
  return m_aie_array;
}

xdna_hwctx::slot_id
xdna_hwctx::
get_slotidx() const
{
  return m_handle;
}

void
xdna_hwctx::
set_slotidx(slot_id id)
{
  m_handle = id;
}

xrt_core::cuidx_type
xdna_hwctx::
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
xdna_hwctx::
close_cu_context(xrt_core::cuidx_type cuidx)
{
  // Nothing to be done
}

std::unique_ptr<xrt_core::buffer_handle>
xdna_hwctx::
alloc_bo(size_t size, uint64_t flags)
{
  return alloc_bo(nullptr, size, flags);
}

std::unique_ptr<xrt_core::buffer_handle>
xdna_hwctx::
alloc_bo(void* userptr, size_t size, uint64_t flags)
{
  // const_cast: alloc_bo() is not const yet in device class
  auto& dev = const_cast<device_xdna&>(get_device());

  // Debug or dtrace buffers are specific to context.
  if (xcl_bo_flags{flags}.use == XRT_BO_USE_DEBUG || xcl_bo_flags{flags}.use == XRT_BO_USE_DTRACE ||
      xcl_bo_flags{flags}.use == XRT_BO_USE_LOG || xcl_bo_flags{flags}.use == XRT_BO_USE_UC_DEBUG)
    return dev.alloc_bo(userptr, get_slotidx(), size, flags);

  // Other BOs are shared across all contexts.
  return dev.alloc_bo(userptr, AMDXDNA_INVALID_CTX_HANDLE, size, flags);
}

std::unique_ptr<xrt_core::buffer_handle>
xdna_hwctx::
import_bo(pid_t pid, xrt_core::shared_handle::export_handle ehdl)
{
  // const_cast: import_bo() is not const yet in device class
  auto& dev = const_cast<device_xdna&>(get_device());
  return dev.import_bo(pid, ehdl);
}

xrt_core::hwqueue_handle*
xdna_hwctx::
get_hw_queue()
{
  return m_hwq.get();
}

void
xdna_hwctx::
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
xdna_hwctx::
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
xdna_hwctx::
parse_xclbin(const xrt::xclbin& xclbin)
{
  auto axlf = xclbin.get_axlf();
  auto aie_partition = xrt_core::xclbin::get_aie_partition(axlf);

  for (const auto& k : xclbin.get_kernels()) {
    auto& props = xrt_core::xclbin_int::get_properties(k);
    try {
      for (const auto& cu : k.get_cus()) {
        m_cu_info.push_back( {
          .m_name = cu.get_name(),
          .m_func = props.functional,
          // TODO FIXME : May not required
	  //.m_pdi = get_pdi(aie_partition, props.kernel_id)
	  } );
      }
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
  print_xclbin_info();
}

const device_xdna&
xdna_hwctx::
get_device()
{
  return m_device;
}

const std::vector<xdna_hwctx::cu_info>&
xdna_hwctx::
get_cu_info() const
{
  return m_cu_info;
}

void
xdna_hwctx::
init_log_buf()
{
  // TODO FIXME 
#if 0
  auto log_buf_size = m_num_cols * 1024;
  m_log_bo = alloc_bo(nullptr, log_buf_size, XCL_BO_FLAGS_EXECBUF);
  m_log_buf = m_log_bo->map(bo::map_type::write);
  std::memset(m_log_buf, 0, log_buf_size);
#endif
}

void
xdna_hwctx::
fini_log_buf(void)
{
  // TODO FIXME 
#if 0
  if (m_log_bo)
    m_log_bo->unmap(m_log_buf);
#endif
}

void
xdna_hwctx::
set_doorbell(uint32_t db)
{
  m_doorbell = db;
}

uint32_t
xdna_hwctx::
get_doorbell() const
{
  return m_doorbell;
}

} // shim_xdna_edge

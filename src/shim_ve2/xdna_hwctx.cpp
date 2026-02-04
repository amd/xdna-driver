// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2025, Advanced Micro Devices, Inc. All rights reserved.

#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp>
#include <boost/optional.hpp>

#include "core/edge/common/aie_parser.h"
#include "core/common/config_reader.h"
#include "core/common/query_requests.h"
#include "core/common/api/xclbin_int.h"
#include "core/common/message.h"
#include "core/common/xclbin_parser.h"

#include "xdna_bo.h"
#include "xdna_hwctx.h"
#include "xdna_hwq.h"

namespace shim_xdna_edge {

namespace pt = boost::property_tree;

// Minimum column alignment required by the driver (must be a multiple of this value)
constexpr uint32_t MIN_COL_SUPPORT = 4;

// Maximum number of CMA memory regions supported by the driver.
// This must match MAX_MEM_REGIONS in kernel (amdxdna_drm.h).
constexpr uint32_t MAX_MEM_REGIONS = 16;

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
  info.base_address = aie_meta.get<uint64_t>("aie_metadata.driver_config.base_address", 0);
  auto column_shift = aie_meta.get<uint8_t>("aie_metadata.driver_config.column_shift", 0);

  bool partinfo_found = false;
  pid_t pid = getpid();
  auto data = xrt_core::device_query_default<xrt_core::query::aie_partition_info>(device, {});
  
  for (const auto& entry : data) {
    if (entry.pid == pid && std::stoi(entry.metadata.id) == hw_context_id) {
      info.num_columns = entry.num_cols;
      info.start_column = entry.start_col;
      info.partition_id = (entry.num_cols << 8U) | (entry.start_col & 0xffU);
      info.base_address += (info.start_column << column_shift);
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
  pt::ptree aie_meta;
  if (data.first && data.second)
    read_aie_metadata_hw(data.first, data.second, aie_meta);

  return get_partition_info_main(device,aie_meta, hw_context_id);
}

xdna_hwctx::
xdna_hwctx(const device_xdna* dev, const xrt::xclbin& xclbin, const xrt::hw_context::qos_type& qos)
   : m_device(const_cast<device_xdna*>(dev)),
    m_hwq(std::make_unique<xdna_hwq>(m_device)),
    m_doorbell(0),
    m_log_buf(nullptr)
{
  shim_debug("Creating hwctx with xclbin");

  std::memcpy((&m_uuid), xclbin.get_uuid().get(), sizeof(xuid_t));
  init_qos_info(qos);
  parse_xclbin(xclbin);

  amdxdna_drm_create_hwctx arg = {};
  arg.qos_p = reinterpret_cast<uintptr_t>(&m_qos);
  arg.num_tiles = m_num_cols;
  // TODO: Need to use correct field once available in amdxdna_drm_create_hwctx
  // making use of umq_bo field for now.
  arg.umq_bo = xrt_core::config::get_privileged_context();

  shim_debug("Calling DRM_IOCTL_AMDXDNA_CREATE_HWCTX: num_tiles=%u, qos_p=0x%lx, user_start_col=%u",
             arg.num_tiles, arg.qos_p, m_qos.user_start_col);

  try {
    m_device->get_edev()->ioctl(DRM_IOCTL_AMDXDNA_CREATE_HWCTX, &arg);
  } catch (const xrt_core::system_error& ex) {
    int err_code = ex.get_code();
    // Provide context-specific error messages based on driver error codes
    if (err_code == EINVAL && m_qos.user_start_col != USER_START_COL_NOT_REQUESTED) {
      shim_err(err_code, "DRM_IOCTL_AMDXDNA_CREATE_HWCTX failed: user_start_col=%u is invalid "
               "(must be a multiple of 4, valid values: 0, 4, 8, ...)", m_qos.user_start_col);
    } else if (err_code == ERANGE && m_qos.user_start_col != USER_START_COL_NOT_REQUESTED) {
      shim_err(err_code, "DRM_IOCTL_AMDXDNA_CREATE_HWCTX failed: user_start_col=%u exceeds "
               "available columns on device", m_qos.user_start_col);
    } else if (err_code == ENODEV) {
      shim_err(err_code, "DRM_IOCTL_AMDXDNA_CREATE_HWCTX failed: no free partition available "
               "(num_tiles=%u, user_start_col=%u)", arg.num_tiles, m_qos.user_start_col);
    } else if (err_code == EBUSY) {
      shim_err(err_code, "DRM_IOCTL_AMDXDNA_CREATE_HWCTX failed: requested partition is busy "
               "(num_tiles=%u, user_start_col=%u)", arg.num_tiles, m_qos.user_start_col);
    } else {
      shim_err(err_code, "DRM_IOCTL_AMDXDNA_CREATE_HWCTX failed: num_tiles=%u, user_start_col=%u",
               arg.num_tiles, m_qos.user_start_col);
    }
  }

  set_slotidx(arg.handle);
  shim_debug("HW context created with handle=%u", arg.handle);

  // Query the auto-selected mem_index from the driver
  query_mem_index();

  try {
    m_info = get_partition_info_hw(m_device, xclbin.get_uuid(), arg.handle);
  } catch (const xrt_core::error& ex) {
    shim_debug("Failed to get partition info: %s", ex.what());
    // Cleanup the created context before re-throwing
    struct amdxdna_drm_destroy_hwctx destroy_arg = {};
    destroy_arg.handle = arg.handle;
    try {
      m_device->get_edev()->ioctl(DRM_IOCTL_AMDXDNA_DESTROY_HWCTX, &destroy_arg);
    } catch (...) {
      shim_debug("Failed to cleanup hwctx during error recovery");
    }
    throw;
  }

  std::stringstream ss;
  ss << "Partition Created with start_col "<<m_info.start_column
          <<" num_columns "<<m_info.num_columns
          <<" partition_id "<<m_info.partition_id;
  xrt_core::message::send( xrt_core::message::severity_level::debug, "xrt_xdna", ss.str());

  set_doorbell(arg.umq_doorbell);

  auto data = m_device->get_axlf_section(AIE_TRACE_METADATA, xclbin.get_uuid());
  if (data.first && data.second)
    m_aie_array = std::make_shared<xdna_aie_array>(m_device, this);

  m_hwq->bind_hwctx(this);

  u32 op_timeout = xrt_core::config::get_cert_timeout();
  amdxdna_drm_config_hwctx adbo;
  adbo.handle = arg.handle;
  adbo.param_val = (__u64)(uintptr_t)&op_timeout;
  adbo.param_val_size = sizeof(u64);
  adbo.param_type = DRM_AMDXDNA_HWCTX_CONFIG_OPCODE_TIMEOUT;

  shim_debug("Configuring hwctx opcode timeout: handle=%u, timeout=%u", arg.handle, op_timeout);

  try {
    m_device->get_edev()->ioctl(DRM_IOCTL_AMDXDNA_CONFIG_HWCTX, &adbo);
  } catch (const xrt_core::system_error& ex) {
    shim_debug("DRM_IOCTL_AMDXDNA_CONFIG_HWCTX failed (non-fatal): %s (err=%d: %s)",
               ex.what(), ex.get_code(), errno_to_str(ex.get_code()));
    // This is non-fatal, continue with context creation
  }

  shim_debug("HW context initialization completed: handle=%u", m_handle);
}

xdna_hwctx::
xdna_hwctx(const device_xdna* dev, uint32_t partition_size, const xrt::hw_context::qos_type& qos)
  : m_device(const_cast<device_xdna*>(dev))
  , m_hwq{ std::make_unique<xdna_hwq>(m_device) }
  , m_num_cols(partition_size)
  , m_doorbell(0)
  , m_log_buf(nullptr)
{
  shim_debug("Creating hwctx with partition_size=%u", partition_size);

  init_qos_info(qos);

  amdxdna_drm_create_hwctx arg = {};
  arg.qos_p = reinterpret_cast<uintptr_t>(&m_qos);
  arg.num_tiles = m_num_cols;
  // TODO: Need to use correct field once available in amdxdna_drm_create_hwctx
  // making use of umq_bo field for now.
  arg.umq_bo = xrt_core::config::get_privileged_context();

  shim_debug("Calling DRM_IOCTL_AMDXDNA_CREATE_HWCTX: num_tiles=%u, qos_p=0x%lx, user_start_col=%u",
             arg.num_tiles, arg.qos_p, m_qos.user_start_col);

  try {
    m_device->get_edev()->ioctl(DRM_IOCTL_AMDXDNA_CREATE_HWCTX, &arg);
  } catch (const xrt_core::system_error& ex) {
    int err_code = ex.get_code();
    // Provide context-specific error messages based on driver error codes
    if (err_code == EINVAL && m_qos.user_start_col != USER_START_COL_NOT_REQUESTED) {
      shim_err(err_code, "DRM_IOCTL_AMDXDNA_CREATE_HWCTX failed: user_start_col=%u is invalid "
               "(must be a multiple of 4, valid values: 0, 4, 8, ...)", m_qos.user_start_col);
    } else if (err_code == ERANGE && m_qos.user_start_col != USER_START_COL_NOT_REQUESTED) {
      shim_err(err_code, "DRM_IOCTL_AMDXDNA_CREATE_HWCTX failed: user_start_col=%u exceeds "
               "available columns on device", m_qos.user_start_col);
    } else if (err_code == ENODEV) {
      shim_err(err_code, "DRM_IOCTL_AMDXDNA_CREATE_HWCTX failed: no free partition available "
               "(partition_size=%u, user_start_col=%u)", partition_size, m_qos.user_start_col);
    } else if (err_code == EBUSY) {
      shim_err(err_code, "DRM_IOCTL_AMDXDNA_CREATE_HWCTX failed: requested partition is busy "
               "(partition_size=%u, user_start_col=%u)", partition_size, m_qos.user_start_col);
    } else {
      shim_err(err_code, "DRM_IOCTL_AMDXDNA_CREATE_HWCTX failed: partition_size=%u, user_start_col=%u",
               partition_size, m_qos.user_start_col);
    }
  }

  set_slotidx(arg.handle);
  set_doorbell(arg.umq_doorbell);
  shim_debug("HW context created: handle=%u, doorbell=%u", arg.handle, arg.umq_doorbell);

  // Query the auto-selected mem_index from the driver
  query_mem_index();

  // TODO : create xdna_aie_array object after ELF has AIE_METADATA, AIE_PARTITION
  // sections added

  m_hwq->bind_hwctx(this);
  shim_debug("HW context initialization completed: handle=%u", m_handle);
}

void
xdna_hwctx::
query_mem_index()
{
  uint32_t mem_index = 0;

  amdxdna_drm_get_array array_args = {};
  array_args.param = DRM_AMDXDNA_HWCTX_MEM_INDEX;
  array_args.element_size = m_handle;  // Pass context_id via element_size
  array_args.num_element = 1;
  array_args.buffer = reinterpret_cast<uint64_t>(&mem_index);

  try {
    m_device->get_edev()->ioctl(DRM_IOCTL_AMDXDNA_GET_ARRAY, &array_args);
    m_mem_index = mem_index;
    shim_debug("Queried mem_index=%u for hwctx handle=%u", m_mem_index, m_handle);
  } catch (const xrt_core::system_error& ex) {
    // Query failed, use MAX_MEM_REGIONS as invalid value
    m_mem_index = MAX_MEM_REGIONS;
    shim_debug("Failed to query mem_index (using MAX_MEM_REGIONS): %s (err=%d: %s)",
               ex.what(), ex.get_code(), errno_to_str(ex.get_code()));
  }
}

xdna_hwctx::
~xdna_hwctx()
{
  shim_debug("Destroying hwctx: handle=%d", m_handle);

  try {
    if (m_handle == AMDXDNA_INVALID_CTX_HANDLE) {
      shim_debug("HW context handle is invalid, nothing to destroy");
      return;
    }

    m_hwq->unbind_hwctx();

    // Explicitly destroy the aie_array before destroying the hw context
    if (m_aie_array) {
      shim_debug("Releasing AIE array for hwctx %d", m_handle);
      m_aie_array.reset();
    }

    struct amdxdna_drm_destroy_hwctx arg = {};
    arg.handle = m_handle;

    shim_debug("Calling DRM_IOCTL_AMDXDNA_DESTROY_HWCTX: handle=%u", m_handle);
    m_device->get_edev()->ioctl(DRM_IOCTL_AMDXDNA_DESTROY_HWCTX, &arg);

#if 0
    // Not supported yet
    fini_log_buf();
#endif
  } catch (const xrt_core::system_error& e) {
    // Log error but don't re-throw in destructor
    shim_debug("Failed to destroy hwctx %d: %s (err=%d: %s)",
               m_handle, e.what(), e.get_code(), errno_to_str(e.get_code()));
  }
  shim_debug("Destroyed HW context: handle=%d", m_handle);
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

size_t
xdna_hwctx::
get_num_uc() const
{
  return m_num_cols;
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
  auto dev = const_cast<device_xdna*>(get_device());

  // Inject hwctx's mem_index (queried from driver) into BO flags
  // This ensures BOs are allocated from the correct CMA region
  xcl_bo_flags xflags{flags};
  if (m_mem_index < MAX_MEM_REGIONS)
    xflags.bank = m_mem_index & 0xFF;  // Lower 8 bits
  uint64_t corrected_flags = xflags.all;

  // Debug or dtrace buffers are specific to context.
  if (xflags.use == XRT_BO_USE_DEBUG || xflags.use == XRT_BO_USE_DTRACE ||
      xflags.use == XRT_BO_USE_LOG || xflags.use == XRT_BO_USE_UC_DEBUG)
    return dev->alloc_bo(userptr, get_slotidx(), size, corrected_flags);

  // Other BOs are shared across all contexts, but use hwctx's mem_index for region selection
  return dev->alloc_bo(userptr, AMDXDNA_INVALID_CTX_HANDLE, size, corrected_flags);
}

std::unique_ptr<xrt_core::buffer_handle>
xdna_hwctx::
import_bo(pid_t pid, xrt_core::shared_handle::export_handle ehdl)
{
  // const_cast: import_bo() is not const yet in device class
  auto dev = const_cast<device_xdna*>(get_device());
  return dev->import_bo(pid, ehdl);
}

xrt_core::hwqueue_handle*
xdna_hwctx::
get_hw_queue()
{
  return m_hwq.get();
}

int
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
    else if (key == "start_col")
      m_qos.user_start_col = value;
  }

  if (m_qos.user_start_col != USER_START_COL_NOT_REQUESTED) {
    shim_debug("QoS user_start_col requested: %u", m_qos.user_start_col);
  }

  return 0;
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

device_xdna*
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

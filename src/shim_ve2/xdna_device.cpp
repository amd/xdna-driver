// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2025, Advanced Micro Devices, Inc. All rights reserved.

#include <boost/format.hpp>
#include <boost/tokenizer.hpp>
#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp>
#include <fcntl.h>
#include <map>
#include <memory>
#include <string>
#include <sys/syscall.h>
#include <unistd.h>

#include "core/common/query_requests.h"
#include "smi_ve2.h"
#include "xdna_bo.h"
#include "xdna_device.h"
#include "xdna_edgedev.h"
#include "xdna_hwctx.h"
#include "xdna_shim.h"

namespace {

namespace query = xrt_core::query;
using key_type = query::key_type;

uint32_t
flag_to_type(uint64_t bo_flags)
{
  auto flags = xcl_bo_flags{bo_flags};
  auto boflags = (static_cast<uint32_t>(flags.boflags) << 24);
  switch (boflags) {
  case XCL_BO_FLAGS_NONE:
  case XCL_BO_FLAGS_HOST_ONLY:
    return AMDXDNA_BO_SHARE;
  case XCL_BO_FLAGS_CACHEABLE:
    return AMDXDNA_BO_DEV;
  case XCL_BO_FLAGS_EXECBUF:
    return AMDXDNA_BO_CMD;
  default:
    break;
  }
  return AMDXDNA_BO_INVALID;
}

static std::map<query::key_type, std::unique_ptr<query::request>> query_tbl;

static std::shared_ptr<shim_xdna_edge::xdna_edgedev>
get_edgedev(const xrt_core::device* device)
{
  //return shim_xdna_edge::device_xdna::get_edev();
  // Assuming you have an instance of device_xdna
  const auto* dev_xdna = dynamic_cast<const shim_xdna_edge::device_xdna*>(device);
  if (dev_xdna) {
    return dev_xdna->get_edev();
  }

  return nullptr;
}

struct bdf
{
  using result_type = query::pcie_bdf::result_type;

  static result_type
  get(const xrt_core::device* device, key_type)
  {
    return std::make_tuple(0,0,0,device->get_device_id());
  }

};

struct board_name
{
  using result_type = query::board_name::result_type;

  static result_type
  get(const xrt_core::device* device, key_type)
  {
    result_type deviceName("edge_xdna");
#if 0
    std::ifstream VBNV("/etc/xocl.txt");
    if (VBNV.is_open()) {
      VBNV >> deviceName;
    }
    VBNV.close();
#endif
    return deviceName;
  }
};

static xclDeviceInfo2
init_device_info(const xrt_core::device* device)
{
  const auto* dev_xdna = dynamic_cast<const shim_xdna_edge::device_xdna*>(device);
  xclDeviceInfo2 dinfo;
  dev_xdna->get_info(&dinfo);
  return dinfo;
}

struct dev_info
{
  static std::any
  get(const xrt_core::device* device, key_type key)
  {
    auto edev = get_edgedev(device);
    static std::map<const xrt_core::device*, xclDeviceInfo2> infomap;
    auto it = infomap.find(device);
    if (it == infomap.end()) {
      auto ret = infomap.emplace(device, init_device_info(device));
      it = ret.first;
    }

    auto& deviceInfo = (*it).second;
    switch (key) {
    case key_type::edge_vendor:
      return deviceInfo.mVendorId;
    case key_type::rom_vbnv:
      return std::string(deviceInfo.mName);
    case key_type::rom_ddr_bank_size_gb:
    {
      static const uint32_t BYTES_TO_GBYTES = 30;
      return (deviceInfo.mDDRSize >> BYTES_TO_GBYTES);
    }
    case key_type::rom_ddr_bank_count_max:
      return static_cast<uint64_t>(deviceInfo.mDDRBankCount);
    case key_type::clock_freqs_mhz:
    {
      std::vector<std::string> clk_freqs;
      for(int i = 0; i < sizeof(deviceInfo.mOCLFrequency)/sizeof(deviceInfo.mOCLFrequency[0]); i++)
        clk_freqs.push_back(std::to_string(deviceInfo.mOCLFrequency[i]));
      return clk_freqs;
    }
    case key_type::rom_time_since_epoch:
      return static_cast<uint64_t>(deviceInfo.mTimeStamp);
    case key_type::device_class:
      return xrt_core::query::device_class::type::ryzen;
    default:
      throw query::no_such_key(key);
    }
  }
};

struct xclbin_uuid
{

  using result_type = query::xclbin_uuid::result_type;

  static result_type
  get(const xrt_core::device* device, key_type)
  {
    using tokenizer = boost::tokenizer< boost::char_separator<char> >;
    std::vector<std::string> xclbin_info;
    std::string errmsg;
    auto edev = get_edgedev(device);
    edev->sysfs_get("xclbinid", errmsg, xclbin_info);
    if (!errmsg.empty())
      throw xrt_core::query::sysfs_error(errmsg);

    // xclbin_uuid e.g.
    // <slot_id> <uuid_slot_0>
    //     0     <uuid_slot_0>
    //     1     <uuid_slot_1>
    for (auto& line : xclbin_info) {
      boost::char_separator<char> sep(" ");
      tokenizer tokens(line, sep);

      if (std::distance(tokens.begin(), tokens.end()) != 2)
        throw xrt_core::query::sysfs_error("xclbinid sysfs node corrupted");

      tokenizer::iterator tok_it = tokens.begin();
      unsigned int slot_index = std::stoi(std::string(*tok_it++));
      //return the first slot uuid always for backward compatibility
      return std::string(*tok_it);
    }

    return "";
  }
};
//Implement xrt_smi_config query
struct xrt_smi_config
{
  using result_type = std::any;
  static result_type
  get(const xrt_core::device* device, key_type key, const std::any& reqType)
  {
    if (key != key_type::xrt_smi_config)
      throw xrt_core::query::no_such_key(key, "Not implemented");
    std::string xrt_smi_config;
    const auto xrt_smi_config_type = std::any_cast<xrt_core::query::xrt_smi_config::type>(reqType);
    switch (xrt_smi_config_type) {
    case xrt_core::query::xrt_smi_config::type::options_config:
      xrt_smi_config = shim_telluride::smi::get_smi_config();
      break;
    default:
      throw xrt_core::query::no_such_key(key, "Not implemented");
    }
    return xrt_smi_config;
  }
};
//Implementation of xrt_smi_lists quer//Implementation of xrt_smi_lists queryy
struct xrt_smi_lists
{
  using result_type = std::any;

  static result_type
  get(const xrt_core::device* /*device*/, key_type key)
  {
    throw xrt_core::query::no_such_key(key, "Not implemented");
  }

  static result_type
  get(const xrt_core::device* /*device*/, key_type key, const std::any& reqType)
  {
    if (key != key_type::xrt_smi_lists)
      throw xrt_core::query::no_such_key(key, "Not implemented");

    const auto xrt_smi_lists_type = std::any_cast<xrt_core::query::xrt_smi_lists::type>(reqType);
    switch (xrt_smi_lists_type) {
    case xrt_core::query::xrt_smi_lists::type::examine_reports:
      return xrt_core::smi::get_list("examine", "report");
    default:
      throw xrt_core::query::no_such_key(key, "Not implemented");
    }
  }
};
//Implement aie_partition_info query
struct partition_info
{
  using result_type = std::any;

  static result_type
  get(const xrt_core::device* device, key_type key)
  {
    if (key != key_type::aie_partition_info)
      throw xrt_core::query::no_such_key(key, "Not implemented");

    amdxdna_drm_query_ctx* data;
    const uint32_t output_size = 32 * sizeof(*data);
    std::vector<char> payload(output_size);

    amdxdna_drm_get_info arg = {
      .param = DRM_AMDXDNA_QUERY_HW_CONTEXTS,
      .buffer_size = output_size,
      .buffer = reinterpret_cast<uintptr_t>(payload.data())
    };

    auto edev = get_edgedev(device);
    edev->ioctl(DRM_IOCTL_AMDXDNA_GET_INFO, &arg);

    uint32_t data_size = arg.buffer_size / sizeof(*data);
    data = reinterpret_cast<decltype(data)>(payload.data());

    query::aie_partition_info::result_type output;
    for (uint32_t i = 0; i < data_size; i++) {
      const auto& entry = data[i];
      xrt_core::query::aie_partition_info::data new_entry{};
      new_entry.metadata.id = std::to_string(entry.context_id);
      new_entry.metadata.xclbin_uuid = "N/A";
      new_entry.start_col = entry.start_col;
      new_entry.num_cols = entry.num_col;
      new_entry.pid = entry.pid;
      new_entry.command_submissions = entry.command_submissions;
      new_entry.command_completions = entry.command_completions;
      new_entry.migrations = entry.migrations;
      new_entry.preemptions = entry.preemptions;
      new_entry.errors = entry.errors;
      new_entry.qos.priority = 0x200;
      output.push_back(new_entry);
    }

    return output;
  }
};
//Implement uc firmware verison query
struct firmware_version
{
  using result_type = query::firmware_version::result_type;

  static std::any
  get(const xrt_core::device* /*device*/, key_type key)
  {
    throw xrt_core::query::no_such_key(key, "Not implemented");
  }

  static result_type
  get(const xrt_core::device* device, key_type,
		  const std::any& req_type)
  {
    const auto fw_type = std::any_cast<query::firmware_version::firmware_type>(req_type);
    if (fw_type != query::firmware_version::firmware_type::uc_firmware)
       throw std::runtime_error("NPU firmware query not supported in this context");

    amdxdna_drm_query_ve2_firmware_version fw_version{};
    amdxdna_drm_get_info arg = {
      .param = DRM_AMDXDNA_QUERY_VE2_FIRMWARE_VERSION,
      .buffer_size = sizeof(fw_version),
      .buffer = reinterpret_cast<uintptr_t>(&fw_version)
    };

    auto edev = get_edgedev(device);
    edev->ioctl(DRM_IOCTL_AMDXDNA_GET_INFO, &arg);

    result_type output;
    output.major = static_cast<int>(fw_version.major);
    output.minor = static_cast<int>(fw_version.minor);
    output.patch = 0;
    output.build = 0;
    output.git_hash = std::string(reinterpret_cast<char*>(fw_version.git_hash));
    output.date = std::string(reinterpret_cast<char*>(fw_version.date));

    return output;
  }
};

struct total_cols
{
  using result_type = query::total_cols::result_type;

  static result_type
  get(const xrt_core::device* device, key_type)
  {
    amdxdna_drm_query_aie_metadata aie_metadata = {};

    amdxdna_drm_get_info arg = {
      .param = DRM_AMDXDNA_QUERY_AIE_METADATA,
      .buffer_size = sizeof(aie_metadata),
      .buffer = reinterpret_cast<uintptr_t>(&aie_metadata)
    };

    auto edev = get_edgedev(device);
    edev->ioctl(DRM_IOCTL_AMDXDNA_GET_INFO, &arg);

    return aie_metadata.cols;                                                          
  }
};

struct xclbin_slots
{
  using result_type = query::xclbin_slots::result_type;
  using slot_info = query::xclbin_slots::slot_info;
  using slot_id = query::xclbin_slots::slot_id;

  static result_type
  get(const xrt_core::device* device, key_type)
  {
    using tokenizer = boost::tokenizer< boost::char_separator<char> >;
    std::vector<std::string> xclbin_info;
    std::string errmsg;
    auto edev = get_edgedev(device);
    edev->sysfs_get("xclbinid", errmsg, xclbin_info);

    result_type xclbin_data;
    if (!errmsg.empty()) { // driver support for xclbinslots is not there
      const auto* dev_xdna = dynamic_cast<const shim_xdna_edge::device_xdna*>(device);
      slot_info data {};
      data.slot = 0;
      data.uuid = dev_xdna->get_uuid();
      xclbin_data.push_back(std::move(data));
    }
    else
    {
      // xclbin_uuid e.g.
      // 0 <uuid_slot_0>
      // 1 <uuid_slot_1>
      for (auto& line : xclbin_info) {
        boost::char_separator<char> sep(" ");
        tokenizer tokens(line, sep);

        if (std::distance(tokens.begin(), tokens.end()) != 2)
          throw xrt_core::query::sysfs_error("xclbinid sysfs node corrupted");

        slot_info data {};
        tokenizer::iterator tok_it = tokens.begin();
        data.slot = std::stoi(std::string(*tok_it++));
        data.uuid = std::string(*tok_it++);

        xclbin_data.push_back(std::move(data));
      }
    }
    //slot_info data {};
    //data.uuid = "393ef246-8fca-29b2-2085-ab98489b3c87";
    //xclbin_data.push_back(std::move(data));
    return xclbin_data;
  }
};

// Specialize for other value types.
template <typename ValueType>
struct sysfs_fcn
{
  static ValueType
  get(shim_xdna_edge::xdna_edgedev* dev, const char* entry)
  {
    std::string err;
    ValueType value;
    dev->sysfs_get(entry, err, value, static_cast<ValueType>(-1));
    if (!err.empty())
      throw xrt_core::query::sysfs_error(err);

    return value;
  }
};

template <>
struct sysfs_fcn<std::string>
{
  static std::string
  get(shim_xdna_edge::xdna_edgedev* dev, const char* entry)
  {
    std::string err;
    std::string value;
    dev->sysfs_get(entry, err, value);
    if (!err.empty())
      throw xrt_core::query::sysfs_error(err);

    return value;
  }
};

template <typename VectorValueType>
struct sysfs_fcn<std::vector<VectorValueType>>
{
  //using ValueType = std::vector<std::string>;
  using ValueType = std::vector<VectorValueType>;

  static ValueType
  get(std::shared_ptr<shim_xdna_edge::xdna_edgedev> dev, const char* entry)
  {
    std::string err;
    ValueType value;
    dev->sysfs_get(entry, err, value);
    if (!err.empty())
      throw xrt_core::query::sysfs_error(err);

    return value;
  }
};

template <typename QueryRequestType>
struct sysfs_get : QueryRequestType
{
  const char* entry;

  sysfs_get(const char* e)
    : entry(e)
  {}

  std::any
  get(const xrt_core::device* device) const
  {
    return sysfs_fcn<typename QueryRequestType::result_type>
      ::get(get_edgedev(device), entry);
  }
};

template <typename QueryRequestType, typename Getter>
struct function0_get : QueryRequestType
{
  std::any
  get(const xrt_core::device* device) const
  {
    auto k = QueryRequestType::key;
    return Getter::get(device, k);
  }
};

template <typename QueryRequestType, typename Getter>
struct function1_get : function0_get<QueryRequestType, Getter>
{
  std::any
  get(const xrt_core::device* device, const std::any& param) const
  {
    if (auto uhdl = device->get_user_handle())
      return Getter::get(device, QueryRequestType::key, param);
    else
      throw xrt_core::internal_error("No device handle");
  }
};

template <typename QueryRequestType, typename Getter>
struct function2_get : QueryRequestType
{
  std::any
  get(const xrt_core::device* device, const std::any& arg1, const std::any& arg2) const
  {
    auto k = QueryRequestType::key;
    return Getter::get(device, k, arg1, arg2);
  }
};

template <typename QueryRequestType, typename Getter>
struct function3_get : QueryRequestType
{
  std::any
  get(const xrt_core::device* device, const std::any& arg1, const std::any& arg2, const std::any& arg3) const
  {
    auto k = QueryRequestType::key;
    return Getter::get(device, k, arg1, arg2, arg3);
  }
};

template <typename QueryRequestType, typename Getter>
struct function4_get : virtual QueryRequestType
{
  std::any
  get(const xrt_core::device* device, const std::any& arg1) const
  {
    auto k = QueryRequestType::key;
    return Getter::get(device, k, arg1);
  }
};

template <typename QueryRequestType>
static void
emplace_sysfs_get(const char* entry)
{
  auto x = QueryRequestType::key;
  query_tbl.emplace(x, std::make_unique<sysfs_get<QueryRequestType>>(entry));
}

template <typename QueryRequestType, typename Getter>
static void
emplace_func0_request()
{
  auto k = QueryRequestType::key;
  query_tbl.emplace(k, std::make_unique<function0_get<QueryRequestType, Getter>>());
}

template <typename QueryRequestType, typename Getter>
static void
emplace_func1_request()
{
  auto k = QueryRequestType::key;
  query_tbl.emplace(k, std::make_unique<function1_get<QueryRequestType, Getter>>());
}

template <typename QueryRequestType, typename Getter>
static void
emplace_func2_request()
{
  auto k = QueryRequestType::key;
  query_tbl.emplace(k, std::make_unique<function2_get<QueryRequestType, Getter>>());
}

template <typename QueryRequestType, typename Getter>
static void
emplace_func3_request()
{
  auto k = QueryRequestType::key;
  query_tbl.emplace(k, std::make_unique<function3_get<QueryRequestType, Getter>>());
}

template <typename QueryRequestType, typename Getter>
static void
emplace_func4_request()
{
  auto k = QueryRequestType::key;
  query_tbl.emplace(k, std::make_unique<function4_get<QueryRequestType, Getter>>());
}

static void
initialize_query_table()
{
  emplace_func0_request<query::xclbin_uuid,             xclbin_uuid>();
  emplace_func0_request<query::aie_partition_info,      partition_info>();
  emplace_func0_request<query::xclbin_slots,            xclbin_slots>();
  emplace_func0_request<query::pcie_bdf,                bdf>();
  emplace_func0_request<query::rom_vbnv,                dev_info>();
  emplace_func0_request<query::device_class,            dev_info>();
  emplace_func0_request<query::total_cols,              total_cols>();
  emplace_func1_request<query::firmware_version,        firmware_version>();
  emplace_func4_request<query::xrt_smi_config,          xrt_smi_config>();
  emplace_func4_request<query::xrt_smi_lists,           xrt_smi_lists>();
}

struct X { X() { initialize_query_table(); } };
static X x;

}

namespace shim_xdna_edge {

const xrt_core::query::request&
device_xdna::
lookup_query(xrt_core::query::key_type query_key) const
{
  auto it = query_tbl.find(query_key);
  if (it == query_tbl.end()) {
    shim_debug("query key (%d) is not supported", query_key);
    throw query::no_such_key(query_key);
  }

  return *(it->second);
}

device_xdna::
device_xdna(handle_type device_handle, id_type device_id)
  : noshim<device_edge>(device_handle, device_id, true /* is user */)
{
  m_edev = xdna_edgedev::get_edgedev();
  m_edev->open();
}

device_xdna::
~device_xdna()
{
  m_edev->close();
}


////////////////////////////////////////////////////////////////
// Custom ishim implementation
// Redefined from xrt_core::ishim for functions that are not
// universally implemented by all shims
////////////////////////////////////////////////////////////////

void
device_xdna::
close_device()
{
  auto s = reinterpret_cast<shim_xdna_edge::shim*>(get_device_handle());
  if (s)
    delete s;
}

/*
 * Define priority in application's QoS.
 * AMDXDNA_QOS_REALTIME_PRIORITY: Real time hwctx. It's consider as an exclusive ctx
 * AMDXDNA_QOS_NORMAL_PRIORITY: This will consider as a shared ctx
 */
std::unique_ptr<xrt_core::hwctx_handle>
device_xdna::
create_hw_context(const xrt::uuid& xclbin_uuid, const xrt::hw_context::qos_type& qos,
		  xrt::hw_context::access_mode mode) const
{
  m_uuid = xclbin_uuid.to_string(); // maintaining uuid in device class
  auto mutable_qos = qos; // Create a local copy

  if (mode == xrt::hw_context::access_mode::exclusive)
    mutable_qos["priority"] = AMDXDNA_QOS_REALTIME_PRIORITY;
  else
    mutable_qos["priority"] = AMDXDNA_QOS_NORMAL_PRIORITY;

  auto hwctx_obj = std::make_unique<xdna_hwctx>(*this, get_xclbin(xclbin_uuid), mutable_qos);

  auto data = get_axlf_section(AIE_METADATA, xclbin_uuid);

  if (data.first && data.second)
  {
    device_xdna* non_const_this = const_cast<device_xdna*>(this); 
    non_const_this->register_aie_array(hwctx_obj.get());
  }
  return hwctx_obj;
}

std::unique_ptr<xrt_core::hwctx_handle>
device_xdna::
create_hw_context(uint32_t partition_size,
                  const xrt::hw_context::qos_type& qos,
                  xrt::hw_context::access_mode mode) const
{
  auto mutable_qos = qos; // Create a local copy

  if (mode == xrt::hw_context::access_mode::exclusive)
    mutable_qos["priority"] = AMDXDNA_QOS_REALTIME_PRIORITY;
  else
    mutable_qos["priority"] = AMDXDNA_QOS_NORMAL_PRIORITY;

  auto hwctx_obj = std::make_unique<xdna_hwctx>(*this, partition_size, mutable_qos);
  // TODO : Get AIE_METADATA info from ELF and register aie array

  return hwctx_obj;
}

std::unique_ptr<xrt_core::buffer_handle>
device_xdna::
alloc_bo(size_t size, uint64_t flags)
{
  return alloc_bo(nullptr, size, flags);
}

std::unique_ptr<xrt_core::buffer_handle>
device_xdna::
alloc_bo(void* userptr, size_t size, uint64_t flags)
{
  return alloc_bo(userptr, AMDXDNA_INVALID_CTX_HANDLE, size, flags);
}

std::unique_ptr<xrt_core::buffer_handle>
device_xdna::
alloc_bo(void* userptr, xrt_core::hwctx_handle::slot_id ctx_id,
  size_t size, uint64_t flags)
{
  if (userptr)
    shim_not_supported_err("User ptr BO");;

  // TODO:
  // For now, debug BO is just a normal device BO. Let's associate all device
  // BO with a HW CTX (if not passed in) since we can't tell if it is a
  // debug BO or not.
  auto f = xcl_bo_flags{flags};
  if ((ctx_id == AMDXDNA_INVALID_CTX_HANDLE) && !!(f.flags & XRT_BO_FLAGS_CACHEABLE))
    ctx_id = f.slot;

  return std::make_unique<xdna_bo>(*this, ctx_id, size, flags, flag_to_type(flags));
}

std::shared_ptr<xdna_edgedev>
device_xdna::
get_edev() const
{
  return m_edev;
}

std::unique_ptr<xrt_core::buffer_handle>
device_xdna::
import_bo(pid_t pid, xrt_core::shared_handle::export_handle ehdl)
{
  if (pid == 0 || getpid() == pid)
     return std::make_unique<xdna_bo>(*this, ehdl);
  
#if defined(SYS_pidfd_open) && defined(SYS_pidfd_getfd)
  auto pidfd = syscall(SYS_pidfd_open, pid, 0);
  if (pidfd < 0)
    throw xrt_core::system_error(errno, "pidfd_open failed");

  auto bofd = syscall(SYS_pidfd_getfd, pidfd, ehdl, 0);
  if (bofd < 0)
    throw xrt_core::system_error
      (errno, "pidfd_getfd failed, check that ptrace access mode "
       "allows PTRACE_MODE_ATTACH_REALCREDS.  For more details please "
       "check /etc/sysctl.d/10-ptrace.conf");

  return std::make_unique<xdna_bo>(*this, bofd);
#else
  throw xrt_core::system_error
    (std::errc::not_supported,
     "Importing buffer object from different process requires XRT "
     " built and installed on a system with 'pidfd' kernel support");
#endif
}

std::vector<char>
device_xdna::
read_aie_mem(uint16_t col, uint16_t row, uint32_t offset, uint32_t size)
{
  std::vector<char> payload(size);
  amdxdna_drm_aie_mem mem;

  mem.col = col;
  mem.row = row;
  mem.addr = offset;
  mem.size = size;
  mem.buf_p = reinterpret_cast<uintptr_t>(payload.data());

  amdxdna_drm_get_info arg = {
    .param = DRM_AMDXDNA_READ_AIE_MEM,
    .buffer_size = sizeof(mem),
    .buffer = reinterpret_cast<uintptr_t>(&mem)
  };

  get_edev()->ioctl(DRM_IOCTL_AMDXDNA_GET_INFO, &arg);
  return payload;
}

size_t
device_xdna::
write_aie_mem(uint16_t col, uint16_t row, uint32_t offset, const std::vector<char>& buf)
{
  amdxdna_drm_aie_mem mem;
  uint32_t size = static_cast<uint32_t>(buf.size());

  mem.col = col;
  mem.row = row;
  mem.addr = offset;
  mem.size = size;
  mem.buf_p = reinterpret_cast<uintptr_t>(buf.data());

  amdxdna_drm_get_info arg = {
    .param = DRM_AMDXDNA_WRITE_AIE_MEM,
    .buffer_size = sizeof(mem),
    .buffer = reinterpret_cast<uintptr_t>(&mem)
  };

  get_edev()->ioctl(DRM_IOCTL_AMDXDNA_SET_STATE, &arg);

  return size;
}

uint32_t
device_xdna::
read_aie_reg(uint16_t col, uint16_t row, uint32_t reg_addr)
{
  amdxdna_drm_aie_reg reg;

  reg.col = col;
  reg.row = row;
  reg.addr = reg_addr;
  reg.val = 0;

  amdxdna_drm_get_info arg = {
    .param = DRM_AMDXDNA_READ_AIE_REG,
    .buffer_size = sizeof(reg),
    .buffer = reinterpret_cast<uintptr_t>(&reg)
  };

  get_edev()->ioctl(DRM_IOCTL_AMDXDNA_GET_INFO, &arg);

  return reg.val;
}

bool
device_xdna::
write_aie_reg(uint16_t col, uint16_t row, uint32_t reg_addr, uint32_t reg_val)
{
  amdxdna_drm_aie_reg reg = {};

  reg.col = col;
  reg.row = row;
  reg.addr = reg_addr;
  reg.val = reg_val;

  amdxdna_drm_get_info arg = {
    .param = DRM_AMDXDNA_WRITE_AIE_REG,
    .buffer_size = sizeof(reg),
    .buffer = reinterpret_cast<uintptr_t>(&reg)
  };

  get_edev()->ioctl(DRM_IOCTL_AMDXDNA_SET_STATE, &arg);
  return true;
}

int
device_xdna::
get_info(xclDeviceInfo2 *info) const
{
  std::memset(info, 0, sizeof(xclDeviceInfo2));

  info->mMagic = 0X586C0C6C;
  info->mHALMajorVersion = XCLHAL_MAJOR_VER;
  info->mHALMajorVersion = XCLHAL_MINOR_VER;
  info->mMinTransferSize = 32;
  info->mVendorId = 0x10ee;   // TODO: UKP
  info->mDeviceId = 0xffff;   // TODO: UKP
  info->mSubsystemId = 0xffff;
  info->mSubsystemVendorId = 0xffff;
  info->mDeviceVersion = 0xffff;

  info->mDDRSize = 4;
  info->mDataAlignment = BUFFER_ALIGNMENT;  //TODO:UKP

  info->mDDRBankCount = 1;
  info->mOCLFrequency[0] = 0;
  info->mTimeStamp = 0;

#if defined(__aarch64__)
  info->mNumCDMA = 1;
#else
  info->mNumCDMA = 0;
#endif

  std::string deviceName("Telluride");
  std::size_t length = deviceName.copy(info->mName, deviceName.length(),0);
  info->mName[length] = '\0';
  return 0;
}

std::shared_ptr<xdna_aie_array>
device_xdna::
get_aie_array()
{
  return m_aie_array;
}

void
device_xdna::
register_aie_array(const xdna_hwctx* hwctx_obj)
{
  if(!m_aie_array)
      m_aie_array = std::make_shared<xdna_aie_array>(this, hwctx_obj);
}

bool
device_xdna::
is_aie_registered()
{
  return (m_aie_array != nullptr);
}
}

// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2022-2024, Advanced Micro Devices, Inc. - All rights reserved

#include "bo.h"
#include "device.h"
#include "hwctx.h"

#include "core/common/query_requests.h"

#include <filesystem>

namespace {

namespace query = xrt_core::query;
using key_type = query::key_type;

inline std::shared_ptr<xrt_core::pci::dev>
get_pcidev(const xrt_core::device* device)
{
  auto pdev = xrt_core::pci::get_dev(device->get_device_id(), device->is_userpf());
  if (!pdev)
    throw xrt_core::error("Invalid device handle");
  return pdev;
}

inline const shim_xdna::pdev&
get_pcidev_impl(const xrt_core::device* device)
{
  auto device_impl = dynamic_cast<const shim_xdna::device*>(device);
  return device_impl->get_pdev();
}

template <typename ValueType>
struct sysfs_fcn
{
  static ValueType
  get(const std::shared_ptr<xrt_core::pci::dev>& dev, const std::string& entry)
  {
    return get(dev, "", entry.c_str());
  }

  static ValueType
  get(const std::shared_ptr<xrt_core::pci::dev>& dev, const char* subdev, const char* entry)
  {
    std::string err;
    ValueType value;
    dev->sysfs_get(subdev, entry, err, value, static_cast<ValueType>(-1));
    if (!err.empty())
      throw xrt_core::query::sysfs_error(err);

    return value;
  }

  static void
  put(const std::shared_ptr<xrt_core::pci::dev>& dev, const char* subdev, const char* entry, ValueType value)
  {
    std::string err;
    dev->sysfs_put(subdev, entry, err, value);
    if (!err.empty())
      throw xrt_core::query::sysfs_error(err);
  }
};

template <>
struct sysfs_fcn<std::string>
{
  using ValueType = std::string;

  static std::string
  get(const std::shared_ptr<xrt_core::pci::dev>& dev, const std::string& entry)
  {
    return get(dev, "", entry.c_str());
  }

  static std::string
  get(const std::shared_ptr<xrt_core::pci::dev>& dev, const std::string& subdev, const std::string& entry)
  {
    std::string err;
    std::string value;
    dev->sysfs_get(subdev, entry, err, value);
    if (!err.empty())
      throw xrt_core::query::sysfs_error(err);

    return value;
  }

  static void
  put(const std::shared_ptr<xrt_core::pci::dev>& dev, const std::string& subdev, const std::string& entry, const ValueType& value)
  {
    std::string err;
    dev->sysfs_put(subdev, entry, err, value);
    if (!err.empty())
      throw xrt_core::query::sysfs_error(err);
  }
};

struct aie_info
{
  using result_type = std::any;

  static result_type
  get(const xrt_core::device* device, key_type key)
  {
    switch (key) {
    case key_type::aie_status_version:
    {
      amdxdna_drm_query_aie_version aie_version = {
        .major = 0,
        .minor = 0,
      };

      amdxdna_drm_get_info arg = {
        .param = DRM_AMDXDNA_QUERY_AIE_VERSION,
        .buffer_size = sizeof(aie_version),
        .buffer = reinterpret_cast<uintptr_t>(&aie_version)
      };

      auto& pci_dev_impl = get_pcidev_impl(device);
      pci_dev_impl.ioctl(DRM_IOCTL_AMDXDNA_GET_INFO, &arg);

      query::aie_status_version::result_type output;
      output.major = aie_version.major;
      output.minor = aie_version.minor;
      return output;
    }
    case key_type::aie_tiles_stats:
    {
      amdxdna_drm_query_aie_metadata aie_metadata;

      amdxdna_drm_get_info arg = {
        .param = DRM_AMDXDNA_QUERY_AIE_METADATA,
        .buffer_size = sizeof(aie_metadata),
        .buffer = reinterpret_cast<uintptr_t>(&aie_metadata)
      };

      auto& pci_dev_impl = get_pcidev_impl(device);
      pci_dev_impl.ioctl(DRM_IOCTL_AMDXDNA_GET_INFO, &arg);

      query::aie_tiles_stats::result_type output;
      output.col_size = aie_metadata.col_size;
      output.major = aie_metadata.version.major;
      output.minor = aie_metadata.version.minor;
      output.cols = aie_metadata.cols;
      output.rows = aie_metadata.rows;

      output.core_rows = aie_metadata.core.row_count;
      output.core_row_start = aie_metadata.core.row_start;
      output.core_dma_channels = aie_metadata.core.dma_channel_count;
      output.core_locks = aie_metadata.core.lock_count;
      output.core_events = aie_metadata.core.event_reg_count;

      output.mem_rows = aie_metadata.mem.row_count;
      output.mem_row_start = aie_metadata.mem.row_start;
      output.mem_dma_channels = aie_metadata.mem.dma_channel_count;
      output.mem_locks = aie_metadata.mem.lock_count;
      output.mem_events = aie_metadata.mem.event_reg_count;

      output.shim_rows = aie_metadata.shim.row_count;
      output.shim_row_start = aie_metadata.shim.row_start;
      output.shim_dma_channels = aie_metadata.shim.dma_channel_count;
      output.shim_locks = aie_metadata.shim.lock_count;
      output.shim_events = aie_metadata.shim.event_reg_count;
      return output;
    }
    default:
      throw xrt_core::query::no_such_key(key, "Not implemented");
    }
  }
  static result_type
  get(const xrt_core::device* device, key_type key, const std::any& param)
  {
    switch (key) {
    case key_type::aie_tiles_status_info:
    {
      query::aie_tiles_status_info::parameters query_param = std::any_cast<query::aie_tiles_status_info::parameters>(param);

      const uint32_t output_size = query_param.col_size * query_param.max_num_cols;

      std::vector<char> payload(output_size);

      amdxdna_drm_query_aie_status aie_status = {
        .start_col = 0,
        .num_cols = query_param.max_num_cols,
        .buffer_size = output_size,
        .buffer = reinterpret_cast<uintptr_t>(payload.data())
      };

      amdxdna_drm_get_info arg = {
        .param = DRM_AMDXDNA_QUERY_AIE_STATUS,
        .buffer_size = sizeof(aie_status),
        .buffer = reinterpret_cast<uintptr_t>(&aie_status)
      };

      auto& pci_dev_impl = get_pcidev_impl(device);
      pci_dev_impl.ioctl(DRM_IOCTL_AMDXDNA_GET_INFO, &arg);

      query::aie_tiles_status_info::result_type output;
      output.buf = payload;
      output.cols_filled = aie_status.cols_filled;
      return output;
    }
    default:
      throw xrt_core::query::no_such_key(key, "Not implemented");
    }
  }
};

struct bdf
{
  using result_type = query::pcie_bdf::result_type;

  static result_type
  get(const xrt_core::device* device, key_type)
  {
    auto pdev = get_pcidev(device);
    return std::make_tuple(pdev->m_domain, pdev->m_bus, pdev->m_dev, pdev->m_func);
  }
};

struct clock_topology
{
  using result_type = query::clock_freq_topology_raw::result_type;

  static result_type
  get(const xrt_core::device* device, key_type)
  {
    amdxdna_drm_query_clock_metadata clock_metadata;

    amdxdna_drm_get_info arg = {
      .param = DRM_AMDXDNA_QUERY_CLOCK_METADATA,
      .buffer_size = sizeof(clock_metadata),
      .buffer = reinterpret_cast<uintptr_t>(&clock_metadata)
    };

    auto& pci_dev_impl = get_pcidev_impl(device);
    pci_dev_impl.ioctl(DRM_IOCTL_AMDXDNA_GET_INFO, &arg);

    std::vector<clock_freq> clocks;
    clock_freq mp_npu_clock;
    strcpy(mp_npu_clock.m_name, reinterpret_cast<const char*>(clock_metadata.mp_npu_clock.name));
    mp_npu_clock.m_type = CT_SYSTEM;
    mp_npu_clock.m_freq_Mhz = clock_metadata.mp_npu_clock.freq_mhz;
    clocks.push_back(mp_npu_clock);

    clock_freq h_clock;
    strcpy(h_clock.m_name, reinterpret_cast<const char*>(clock_metadata.h_clock.name));
    h_clock.m_type = CT_SYSTEM;
    h_clock.m_freq_Mhz = clock_metadata.h_clock.freq_mhz;
    clocks.push_back(h_clock);

    std::vector<char> payload(sizeof(int16_t) + (clocks.size() * sizeof(struct clock_freq)));
    auto data = reinterpret_cast<struct clock_freq_topology*>(payload.data());
    data->m_count = clocks.size();
    memcpy(data->m_clock_freq, clocks.data(), (clocks.size() * sizeof(struct clock_freq)));

    return payload;
  }
};

struct default_value
{

  static std::any
  get(const xrt_core::device* device, key_type key)
  {
    switch (key) {
    case key_type::device_class:
      return xrt_core::query::device_class::type::ryzen;
    case key_type::is_ready:
      return xrt_core::query::is_ready::result_type(true);
    case key_type::is_versal:
      return xrt_core::query::is_versal::result_type(false);
    case key_type::logic_uuids:
      return xrt_core::query::logic_uuids::result_type({std::string(32, '0'), std::string(32, '0')});
    case key_type::rom_ddr_bank_size_gb:
      return xrt_core::query::rom_ddr_bank_size_gb::result_type(0);
    case key_type::rom_ddr_bank_count_max:
      return xrt_core::query::rom_ddr_bank_count_max::result_type(0);
    default:
      throw xrt_core::query::no_such_key(key);
    }
    throw xrt_core::query::no_such_key(key);
  }

};

struct instance
{
  using result_type = query::instance::result_type;

  static result_type
  get(const xrt_core::device* device, key_type)
  {
    return get_pcidev(device)->m_instance;
  }

};

template <typename QueryRequestType>
struct sysfs_get : virtual QueryRequestType
{
  const char* subdev;
  const char* entry;

  sysfs_get(const char* s, const char* e)
    : subdev(s), entry(e)
  {}

  std::any
  get(const xrt_core::device* device) const
  {
    return sysfs_fcn<typename QueryRequestType::result_type>
      ::get(get_pcidev(device), subdev, entry);
  }

  std::any
  get(const xrt_core::device* device, query::request::modifier m, const std::string& v) const
  {
    auto ms = (m == query::request::modifier::subdev) ? v.c_str() : subdev;
    auto me = (m == query::request::modifier::entry) ? v.c_str() : entry;
    return sysfs_fcn<typename QueryRequestType::result_type>
      ::get(get_pcidev(device), ms, me);
  }
};

template <typename QueryRequestType, typename Getter>
struct function0_get : virtual QueryRequestType
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

static std::map<xrt_core::query::key_type, std::unique_ptr<query::request>> query_tbl;

template <typename QueryRequestType>
static void
emplace_sysfs_get(const char* subdev, const char* entry)
{
  auto x = QueryRequestType::key;
  query_tbl.emplace(x, std::make_unique<sysfs_get<QueryRequestType>>(subdev, entry));
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

static void
initialize_query_table()
{
  emplace_func0_request<query::aie_status_version,             aie_info>();
  emplace_func0_request<query::aie_tiles_stats,                aie_info>();
  emplace_func1_request<query::aie_tiles_status_info,          aie_info>();
  emplace_func0_request<query::clock_freq_topology_raw,        clock_topology>();
  emplace_func0_request<query::device_class,                   default_value>();
  emplace_func0_request<query::instance,                       instance>();
  emplace_func0_request<query::is_ready,                       default_value>();
  emplace_func0_request<query::is_versal,                      default_value>();
  emplace_func0_request<query::logic_uuids,                    default_value>();
  emplace_func0_request<query::pcie_bdf,                       bdf>();
  emplace_sysfs_get<query::pcie_device>                        ("", "device");
  emplace_sysfs_get<query::pcie_express_lane_width>            ("", "link_width");
  emplace_sysfs_get<query::pcie_express_lane_width_max>        ("", "link_width_max");
  emplace_sysfs_get<query::pcie_link_speed>                    ("", "link_speed");
  emplace_sysfs_get<query::pcie_link_speed_max>                ("", "link_speed_max");
  emplace_sysfs_get<query::pcie_subsystem_id>                  ("", "subsystem_device");
  emplace_sysfs_get<query::pcie_subsystem_vendor>              ("", "subsystem_vendor");
  emplace_sysfs_get<query::pcie_vendor>                        ("", "vendor");
  emplace_func0_request<query::rom_ddr_bank_count_max,         default_value>();
  emplace_func0_request<query::rom_ddr_bank_size_gb,           default_value>();
  emplace_sysfs_get<query::rom_vbnv>                           ("", "vbnv");
}

struct X { X() { initialize_query_table(); }};
static X x;

}

namespace shim_xdna {

const query::request&
device::
lookup_query(query::key_type query_key) const
{
  auto it = query_tbl.find(query_key);

  if (it == query_tbl.end())
    throw query::no_such_key(query_key);

  return *(it->second);
}

device::
device(const pdev& pdev, handle_type shim_handle, id_type device_id)
  : device_linux(shim_handle, device_id, !pdev.m_is_mgmt), m_pdev(pdev)
{
}

device::
~device()
{
}


const pdev&
device::
get_pdev() const
{
  return m_pdev;
}

void
device::
close_device()
{
  auto s = reinterpret_cast<shim_xdna::shim*>(get_device_handle());
  if (s)
    delete s;
  // When shim is gone, the last ref to this device object will be removed
  // which will cause this object to be destruted. We're essentially committing
  // suicide here. Do not touch anything in this device object after this.
}

void
device::
register_xclbin(const xrt::xclbin& xclbin) const
{
  // Do not throw here, just do nothing.
  // xclbins are registered with xrt coreutil and
  // loaded by create_hw_context
}

std::unique_ptr<xrt_core::hwctx_handle>
device::
create_hw_context(const xrt::uuid& xclbin_uuid, const xrt::hw_context::qos_type& qos,
  xrt::hw_context::access_mode mode) const
{
  return create_hw_context(*this, get_xclbin(xclbin_uuid), qos);
}

std::unique_ptr<xrt_core::buffer_handle>
device::
alloc_bo(size_t size, uint64_t flags)
{
  return alloc_bo(nullptr, size, flags);
}

std::unique_ptr<xrt_core::buffer_handle>
device::
alloc_bo(void* userptr, size_t size, uint64_t flags)
{
  return alloc_bo(userptr, INVALID_CTX_HANDLE, size, flags);
}

} // namespace shim_xdna

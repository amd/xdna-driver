// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2022-2025, Advanced Micro Devices, Inc. - All rights reserved

#include "bo.h"
#include "device.h"
#include "hwctx.h"
#include "fence.h"
#include "smi_xdna.h"

#include "core/common/query_requests.h"

#include <any>
#include <filesystem>
#include <sys/syscall.h>
#include <unistd.h>

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
  if (!device_impl)
    throw xrt_core::error("Invalid device handle");
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
      static std::map<const xrt_core::device *, query::aie_tiles_stats::result_type> cache;

      auto iter = cache.find(device);
      if (iter != cache.end())
        return cache.at(device);

      {
        static std::mutex lock; // Usually there is only one device was referenced, not per device lock..
        std::lock_guard L(lock);

        auto iter = cache.find(device);
        if (iter != cache.end())
          return cache.at(device);

        amdxdna_drm_query_aie_metadata aie_metadata = {};

        amdxdna_drm_get_info arg = {
          .param = DRM_AMDXDNA_QUERY_AIE_METADATA,
          .buffer_size = sizeof(aie_metadata),
          .buffer = reinterpret_cast<uintptr_t>(&aie_metadata)
        };

        auto& pci_dev_impl = get_pcidev_impl(device);
        pci_dev_impl.ioctl(DRM_IOCTL_AMDXDNA_GET_INFO, &arg);

        query::aie_tiles_stats::result_type output = {};
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

        cache.emplace(device, output);
        return output;
      }
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
        .buffer = reinterpret_cast<uintptr_t>(payload.data()),
        .buffer_size = output_size,
      };

      amdxdna_drm_get_info arg = {
        .param = DRM_AMDXDNA_QUERY_AIE_STATUS,
        .buffer_size = sizeof(aie_status),
        .buffer = reinterpret_cast<uintptr_t>(&aie_status)
      };

      auto& pci_dev_impl = get_pcidev_impl(device);
      pci_dev_impl.ioctl(DRM_IOCTL_AMDXDNA_GET_INFO, &arg);

      query::aie_tiles_status_info::result_type output;
      output.buf = std::move(payload);
      output.cols_filled = aie_status.cols_filled;
      return output;
    }
    default:
      throw xrt_core::query::no_such_key(key, "Not implemented");
    }
  }
};

struct partition_info
{
  using result_type = std::any;

  static result_type
  get(const xrt_core::device* device, key_type key)
  {
    if (key != key_type::aie_partition_info)
      throw xrt_core::query::no_such_key(key, "Not implemented");

    amdxdna_drm_query_ctx* data;
    const uint32_t output_size = 256 * sizeof(*data);

    std::vector<char> payload(output_size);
    amdxdna_drm_get_info arg = {
      .param = DRM_AMDXDNA_QUERY_HW_CONTEXTS,
      .buffer_size = output_size,
      .buffer = reinterpret_cast<uintptr_t>(payload.data())
    };

    auto& pci_dev_impl = get_pcidev_impl(device);
    pci_dev_impl.ioctl(DRM_IOCTL_AMDXDNA_GET_INFO, &arg);

    if (output_size < arg.buffer_size) {
      throw xrt_core::query::exception(
        boost::str(boost::format("DRM_AMDXDNA_QUERY_HW_CONTEXTS - Insufficient buffer size. Need: %u") % arg.buffer_size));
    }

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
      new_entry.qos.priority = entry.priority;
      output.push_back(std::move(new_entry));
    }
    return output;
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

struct pcie_id
{
  using result_type = query::pcie_id::result_type;

  static result_type
  get(const xrt_core::device* device, key_type)
  {
    result_type pcie_id;

    const auto pdev = get_pcidev(device);

    pcie_id.device_id = sysfs_fcn<uint16_t>::get(pdev, "", "device");
    pcie_id.revision_id = sysfs_fcn<uint8_t>::get(pdev, "", "revision");

    return pcie_id;
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

    auto& pci_dev_impl = get_pcidev_impl(device);
    pci_dev_impl.ioctl(DRM_IOCTL_AMDXDNA_GET_INFO, &arg);

    return aie_metadata.cols;
  }
};

struct performance_mode
{
  using result_type = query::performance_mode::result_type;

  static result_type
  get(const xrt_core::device* device, key_type)
  {
    amdxdna_drm_get_power_mode state;

    amdxdna_drm_get_info arg = {
        .param = DRM_AMDXDNA_GET_POWER_MODE,
        .buffer_size = sizeof(state),
        .buffer = reinterpret_cast<uintptr_t>(&state)
    };

    auto& pci_dev_impl = get_pcidev_impl(device);
    pci_dev_impl.ioctl(DRM_IOCTL_AMDXDNA_GET_INFO, &arg);

    return state.power_mode;
  }

  static void
  put(const xrt_core::device* device, key_type key, const std::any& any)
  {
    amdxdna_drm_set_power_mode state;
    state.power_mode = static_cast<int>(std::any_cast<xrt_core::query::performance_mode::power_type>(any));

    amdxdna_drm_set_state arg = {
      .param = DRM_AMDXDNA_SET_POWER_MODE,
      .buffer_size = sizeof(state),
      .buffer = reinterpret_cast<uintptr_t>(&state)
    };

    auto& pci_dev_impl = get_pcidev_impl(device);
    pci_dev_impl.ioctl(DRM_IOCTL_AMDXDNA_SET_STATE, &arg);
  }
};

struct preemption
{
  using result_type = query::preemption::result_type;

  static result_type
  get(const xrt_core::device* device, key_type)
  {
    amdxdna_drm_get_force_preempt_state force;

    amdxdna_drm_get_info arg = {
      .param = DRM_AMDXDNA_GET_FORCE_PREEMPT_STATE,
      .buffer_size = sizeof(force),
      .buffer = reinterpret_cast<uintptr_t>(&force)
    };

    auto& pci_dev_impl = get_pcidev_impl(device);
    pci_dev_impl.ioctl(DRM_IOCTL_AMDXDNA_GET_INFO, &arg);

    return force.state;
  }

  static void
  put(const xrt_core::device* device, key_type key, const std::any& any)
  {
    amdxdna_drm_set_force_preempt_state force;
    force.state = std::any_cast<uint32_t>(any);

    amdxdna_drm_set_state arg = {
      .param = DRM_AMDXDNA_SET_FORCE_PREEMPT,
      .buffer_size = sizeof(force),
      .buffer = reinterpret_cast<uintptr_t>(&force)
    };

    auto& pci_dev_impl = get_pcidev_impl(device);
    pci_dev_impl.ioctl(DRM_IOCTL_AMDXDNA_SET_STATE, &arg);
  }
};

struct telemetry
{
  static constexpr uint32_t NPU_RTOS_MAX_USER_ID_COUNT = 16;
  static constexpr uint32_t NPU_MAX_STREAM_BUFFER_COUNT = 8;
  static constexpr uint32_t NPU_MAX_SLEEP_COUNT = 9;
  static constexpr uint32_t NPU_MAX_OPCODE_COUNT = 30;
  static constexpr uint32_t NPU_MAX_DTLB_COUNT = 12;
  static constexpr uint16_t NPU4_DEVICE_ID = 0x17f0;

  struct amdxdna_drm_query_telemetry {
    uint32_t major;
    uint32_t minor;
    uint64_t l1_interrupts;
    uint64_t context_started_count[NPU_RTOS_MAX_USER_ID_COUNT];
    uint64_t scheduled_count[NPU_RTOS_MAX_USER_ID_COUNT];
    uint64_t syscall_count[NPU_RTOS_MAX_USER_ID_COUNT];
    uint64_t dma_access_count[NPU_RTOS_MAX_USER_ID_COUNT];
    uint64_t resource_acquisition_count[NPU_RTOS_MAX_USER_ID_COUNT];
    uint64_t sb_tokens[NPU_MAX_STREAM_BUFFER_COUNT];
    uint64_t deep_sleep_count[NPU_MAX_SLEEP_COUNT];
    uint64_t trace_opcode[NPU_MAX_OPCODE_COUNT];
    uint64_t dtlb_misses[NPU_RTOS_MAX_USER_ID_COUNT][NPU_MAX_DTLB_COUNT];
    uint64_t reserved[32];
    uint64_t layer_boundary_count[NPU_RTOS_MAX_USER_ID_COUNT];
    uint64_t frame_boundary_count[NPU_RTOS_MAX_USER_ID_COUNT];
    uint64_t reserved1[126];
  };

  using result_type = std::any;

  static result_type
  get(const xrt_core::device* device, key_type key)
  {
    switch (key) {
    case key_type::aie_telemetry:
    {
      query::aie_telemetry::result_type output;

      amdxdna_drm_query_telemetry telemetry{};

      amdxdna_drm_get_info query_telemetry = {
        .param = DRM_AMDXDNA_QUERY_TELEMETRY,
        .buffer_size = sizeof(telemetry),
        .buffer = reinterpret_cast<uintptr_t>(&telemetry)
      };

      auto& pci_dev_impl = get_pcidev_impl(device);
      pci_dev_impl.ioctl(DRM_IOCTL_AMDXDNA_GET_INFO, &query_telemetry);

      for (auto i = 0; i < NPU_MAX_SLEEP_COUNT; i++) {
        query::aie_telemetry::data task;
        task.deep_sleep_count = telemetry.deep_sleep_count[i];
        output.push_back(std::move(task));
      }
      return output;
    }
    case key_type::misc_telemetry:
    {
      query::misc_telemetry::result_type output;

      amdxdna_drm_query_telemetry telemetry{};

      amdxdna_drm_get_info query_telemetry = {
        .param = DRM_AMDXDNA_QUERY_TELEMETRY,
        .buffer_size = sizeof(telemetry),
        .buffer = reinterpret_cast<uintptr_t>(&telemetry)
      };

      auto& pci_dev_impl = get_pcidev_impl(device);
      pci_dev_impl.ioctl(DRM_IOCTL_AMDXDNA_GET_INFO, &query_telemetry);

      output.l1_interrupts = telemetry.l1_interrupts;
      return output;
    }
    case key_type::opcode_telemetry:
    {
      query::opcode_telemetry::result_type output;

      amdxdna_drm_query_telemetry telemetry{};

      amdxdna_drm_get_info query_telemetry = {
        .param = DRM_AMDXDNA_QUERY_TELEMETRY,
        .buffer_size = sizeof(telemetry),
        .buffer = reinterpret_cast<uintptr_t>(&telemetry)
      };

      auto& pci_dev_impl = get_pcidev_impl(device);
      pci_dev_impl.ioctl(DRM_IOCTL_AMDXDNA_GET_INFO, &query_telemetry);

      for (auto i = 0; i < NPU_MAX_OPCODE_COUNT; i++) {
        query::opcode_telemetry::data task;
        task.count = telemetry.trace_opcode[i];
        output.push_back(std::move(task));
      }
      return output;
    }
    case key_type::rtos_telemetry:
    {
      amdxdna_drm_query_ctx* data;
      const uint32_t output_size = 256 * sizeof(*data);
      query::rtos_telemetry::result_type output;

      auto device_id = sysfs_fcn<uint16_t>::get(get_pcidev(device), "", "device");
      if (device_id != NPU4_DEVICE_ID)
        return output;

      std::vector<char> payload(output_size);
      amdxdna_drm_get_info query_ctx = {
        .param = DRM_AMDXDNA_QUERY_HW_CONTEXTS,
        .buffer_size = output_size,
        .buffer = reinterpret_cast<uintptr_t>(payload.data())
      };

      auto& pci_dev_impl = get_pcidev_impl(device);
      pci_dev_impl.ioctl(DRM_IOCTL_AMDXDNA_GET_INFO, &query_ctx);

      if (output_size < query_ctx.buffer_size) {
        throw xrt_core::query::exception(
          boost::str(boost::format("DRM_AMDXDNA_QUERY_HW_CONTEXTS - Insufficient buffer size. Need: %u") % query_ctx.buffer_size));
      }

      uint32_t data_size = query_ctx.buffer_size / sizeof(*data);
      data = reinterpret_cast<decltype(data)>(payload.data());

      std::array<uint32_t, NPU_RTOS_MAX_USER_ID_COUNT> ctx_map{};
      for (uint32_t i = 0; i < data_size; i++) {
        const auto& entry = data[i];

        if (entry.hwctx_id >= NPU_RTOS_MAX_USER_ID_COUNT) {
          throw xrt_core::query::exception(
            boost::str(boost::format("DRM_AMDXDNA_QUERY_HW_CONTEXTS - Invalid hw ctx ID: %u") % entry.hwctx_id));
        }

        ctx_map[entry.hwctx_id] = entry.context_id;
      }

      amdxdna_drm_query_telemetry telemetry{};

      amdxdna_drm_get_info query_telemetry = {
        .param = DRM_AMDXDNA_QUERY_TELEMETRY,
        .buffer_size = sizeof(telemetry),
        .buffer = reinterpret_cast<uintptr_t>(&telemetry)
      };

      pci_dev_impl.ioctl(DRM_IOCTL_AMDXDNA_GET_INFO, &query_telemetry);

      for (auto i = 0; i < NPU_RTOS_MAX_USER_ID_COUNT; i++) {
        query::rtos_telemetry::data task;

        task.context_starts = telemetry.context_started_count[i];
        task.schedules = telemetry.scheduled_count[i];
        task.syscalls = telemetry.syscall_count[i];
        task.dma_access = telemetry.dma_access_count[i];
        task.resource_acquisition = telemetry.resource_acquisition_count[i];

        std::vector<query::rtos_telemetry::dtlb_data> dtlbs;
        for (auto j = 0; j < NPU_MAX_DTLB_COUNT; j++) {
          query::rtos_telemetry::dtlb_data dtlb = {
            .misses = telemetry.dtlb_misses[i][j]
          };
          dtlbs.push_back(std::move(dtlb));
        }
        task.dtlbs = std::move(dtlbs);

        task.preemption_data.slot_index = ctx_map[i];
        task.preemption_data.preemption_checkpoint_event = telemetry.layer_boundary_count[i];
        task.preemption_data.preemption_frame_boundary_events = telemetry.frame_boundary_count[i];
        output.push_back(std::move(task));
      }
      return output;
    }
    case key_type::stream_buffer_telemetry:
    {
      query::stream_buffer_telemetry::result_type output;

      amdxdna_drm_query_telemetry telemetry{};

      amdxdna_drm_get_info query_telemetry = {
        .param = DRM_AMDXDNA_QUERY_TELEMETRY,
        .buffer_size = sizeof(telemetry),
        .buffer = reinterpret_cast<uintptr_t>(&telemetry)
      };

      auto& pci_dev_impl = get_pcidev_impl(device);
      pci_dev_impl.ioctl(DRM_IOCTL_AMDXDNA_GET_INFO, &query_telemetry);

      for (auto i = 0; i < NPU_MAX_STREAM_BUFFER_COUNT; i++) {
        query::stream_buffer_telemetry::data task;
        task.tokens = telemetry.sb_tokens[i];
        output.push_back(std::move(task));
      }
      return output;
    }
    default:
      throw xrt_core::query::no_such_key(key, "Not implemented");
    }
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

struct resource_info
{
  using result_type = query::xrt_resource_raw::result_type;

  static result_type
  get(const xrt_core::device* device, key_type)
  {
    amdxdna_drm_get_resource_info resource_info;

    amdxdna_drm_get_info arg = {
      .param = DRM_AMDXDNA_QUERY_RESOURCE_INFO,
      .buffer_size = sizeof(resource_info),
      .buffer = reinterpret_cast<uintptr_t>(&resource_info),
    };

    auto& pci_dev_impl = get_pcidev_impl(device);
    pci_dev_impl.ioctl(DRM_IOCTL_AMDXDNA_GET_INFO, &arg);

    std::vector<xrt_core::query::xrt_resource_raw::xrt_resource_query> info_items(5);
    info_items[0].type = xrt_core::query::xrt_resource_raw::resource_type::ipu_clk_max;
    info_items[0].data_uint64 = resource_info.npu_clk_max;
    info_items[1].type = xrt_core::query::xrt_resource_raw::resource_type::ipu_tops_max;
    info_items[1].data_double = resource_info.npu_tops_max;
    info_items[2].type = xrt_core::query::xrt_resource_raw::resource_type::ipu_task_max;
    info_items[2].data_uint64 = resource_info.npu_task_max;
    info_items[3].type = xrt_core::query::xrt_resource_raw::resource_type::ipu_tops_curr;
    info_items[3].data_double = resource_info.npu_tops_curr;
    info_items[4].type = xrt_core::query::xrt_resource_raw::resource_type::ipu_task_curr;
    info_items[4].data_uint64 = resource_info.npu_task_curr;

    return info_items;
  }
};

struct firmware_version
{
  using result_type = query::firmware_version::result_type;

  static result_type
  get(const xrt_core::device* device, key_type)
  {
    amdxdna_drm_query_firmware_version fw_version{};

    amdxdna_drm_get_info arg = {
      .param = DRM_AMDXDNA_QUERY_FIRMWARE_VERSION,
      .buffer_size = sizeof(fw_version),
      .buffer = reinterpret_cast<uintptr_t>(&fw_version)
    };

    auto& pci_dev_impl = get_pcidev_impl(device);
    pci_dev_impl.ioctl(DRM_IOCTL_AMDXDNA_GET_INFO, &arg);

    result_type output;
    output.major = fw_version.major;
    output.minor = fw_version.minor;
    output.patch = fw_version.patch;
    output.build = fw_version.build;
    return output;
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

struct sensor_info
{
  static std::any
  get(const xrt_core::device* /*device*/, key_type key)
  {
    throw xrt_core::query::no_such_key(key, "Not implemented");
  }

  static bool
  validate_sensor_type(const std::any& param, const amdxdna_drm_query_sensor& sensor)
  {
    switch (std::any_cast<xrt_core::query::sdm_sensor_info::sdr_req_type>(param)) {
    case xrt_core::query::sdm_sensor_info::sdr_req_type::power:
      return sensor.type == AMDXDNA_SENSOR_TYPE_POWER;
    // At the moment no sensors are expected for IPU other than power
    case xrt_core::query::sdm_sensor_info::sdr_req_type::current:
    case xrt_core::query::sdm_sensor_info::sdr_req_type::mechanical:
    case xrt_core::query::sdm_sensor_info::sdr_req_type::thermal:
    case xrt_core::query::sdm_sensor_info::sdr_req_type::voltage:
      return false;
    }
    return false;
  }

  static amdxdna_drm_get_info
  get_sensor_data(const xrt_core::device* device)
  {
    static std::map<const xrt_core::device*, std::vector<char>> data_map;

    // If an entry does not exist for the current device, query the driver for sensor data
    if (data_map.find(device) == data_map.end()) {
      const uint32_t output_size = sizeof(amdxdna_drm_query_sensor);

      std::vector<char> payload(output_size);
      amdxdna_drm_get_info arg = {
        .param = DRM_AMDXDNA_QUERY_SENSORS,
        .buffer_size = output_size,
        .buffer = reinterpret_cast<uintptr_t>(payload.data())
      };

      auto& pci_dev_impl = get_pcidev_impl(device);
      pci_dev_impl.ioctl(DRM_IOCTL_AMDXDNA_GET_INFO, &arg);

      if (output_size < arg.buffer_size) {
        throw xrt_core::query::exception(
          boost::str(boost::format("DRM_AMDXDNA_QUERY_SENSORS - Insufficient buffer size. Need: %u") % arg.buffer_size));
      }

      payload.resize(arg.buffer_size);
      data_map.emplace(device, payload);
    }

    auto& payload = data_map.at(device);
    amdxdna_drm_get_info output = {
      .param = DRM_AMDXDNA_QUERY_SENSORS,
      .buffer_size = static_cast<uint32_t>(payload.size()),
      .buffer = reinterpret_cast<uintptr_t>(payload.data())
    };
    return output;
  }

  static std::any
  get(const xrt_core::device* device, key_type key, const std::any& param)
  {
    if (key != key_type::sdm_sensor_info)
      throw xrt_core::query::no_such_key(key, "Not implemented");

    amdxdna_drm_get_info arg = get_sensor_data(device);

    amdxdna_drm_query_sensor* drv_sensors;
    const uint32_t drv_sensor_count = arg.buffer_size / sizeof(*drv_sensors);
    drv_sensors = reinterpret_cast<decltype(drv_sensors)>(arg.buffer);

    // Parse the received sensor info into the user facing struct
    xrt_core::query::sdm_sensor_info::result_type sensors;
    for (uint32_t i = 0; i < drv_sensor_count; i++) {
      const auto& drv_sensor = drv_sensors[i];
      if (!validate_sensor_type(param, drv_sensor))
        continue;

      xrt_core::query::sdm_sensor_info::data_type sensor;
      sensor.label = std::string(reinterpret_cast<const char*>(drv_sensor.label));
      sensor.input = drv_sensor.input;
      sensor.max = drv_sensor.max;
      sensor.average = drv_sensor.average;
      sensor.highest = drv_sensor.highest;
      sensor.status = std::string(reinterpret_cast<const char*>(drv_sensor.status));
      sensor.units = std::string(reinterpret_cast<const char*>(drv_sensor.units));
      sensor.unitm = drv_sensor.unitm;
      sensors.push_back(std::move(sensor));
    }
    return sensors;
  }
};

/* This structure can be extended to provide
*  other configurations supporting xrt-smi
*/
struct xrt_smi_config
{
  static std::any
  get(const xrt_core::device* /*device*/, key_type key)
  {
    throw xrt_core::query::no_such_key(key, "Not implemented");
  }

  static std::any
  get(const xrt_core::device* device, key_type key, const std::any& param)
  {
    if (key != key_type::xrt_smi_config)
      throw xrt_core::query::no_such_key(key, "Not implemented");

    const auto& pcie_id = xrt_core::device_query<xrt_core::query::pcie_id>(device);

    std::string xrt_smi_config;
    const auto xrt_smi_config_type = std::any_cast<xrt_core::query::xrt_smi_config::type>(param);
    switch (xrt_smi_config_type) {
    case xrt_core::query::xrt_smi_config::type::options_config:
      return shim_xdna::smi::get_smi_config();
    default:
      throw xrt_core::query::no_such_key(key, "Not implemented");
    }

    return xrt_smi_config;
  }
};

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
    case xrt_core::query::xrt_smi_lists::type::validate_tests:
      return xrt_core::smi::get_list("validate", "run");
    case xrt_core::query::xrt_smi_lists::type::examine_reports:
      return xrt_core::smi::get_list("examine", "report");
    default:
      throw xrt_core::query::no_such_key(key, "Not implemented");
    }
  }
};

struct xclbin_name
{
  static std::any
  get(const xrt_core::device* /*device*/, key_type key)
  {
    throw xrt_core::query::no_such_key(key, "Not implemented");
  }

  static std::any
  get(const xrt_core::device* device, key_type key, const std::any& param)
  {
    if (key != key_type::xclbin_name)
      throw xrt_core::query::no_such_key(key, "Not implemented");

    const auto& pcie_id = xrt_core::device_query<xrt_core::query::pcie_id>(device);

    std::string xclbin_name;
    const auto xclbin_type = std::any_cast<xrt_core::query::xclbin_name::type>(param);
    switch (xclbin_type) {
    case xrt_core::query::xclbin_name::type::validate:
      xclbin_name = "validate.xclbin";
      break;
    case xrt_core::query::xclbin_name::type::validate_elf:
      xclbin_name = "validate_elf.xclbin";
      break;
    // case xrt_core::query::xclbin_name::type::gemm:
    //   xclbin_name = "gemm.xclbin";
    //   break;
    // case xrt_core::query::xclbin_name::type::gemm_elf:
    //   xclbin_name = "gemm_elf.xclbin";
    //   break; 
    }

    return boost::str(boost::format("bins/%04x_%02x/%s")
      % pcie_id.device_id
      % static_cast<uint16_t>(pcie_id.revision_id)
      % xclbin_name);
  }
};

struct sequence_name
{
  static std::any
  get(const xrt_core::device* /*device*/, key_type key)
  {
    throw xrt_core::query::no_such_key(key, "Not implemented");
  }

  static std::any
  get(const xrt_core::device* device, key_type key, const std::any& param)
  {
    if (key != key_type::sequence_name)
      throw xrt_core::query::no_such_key(key, "Not implemented");

    auto fmt = boost::format("bins/dpu_sequence/%s");

    std::string seq_name;
    switch (std::any_cast<xrt_core::query::sequence_name::type>(param)) {
    case xrt_core::query::sequence_name::type::df_bandwidth:
      seq_name = "df_bw.txt";
      break;
    case xrt_core::query::sequence_name::type::tct_one_column:
      seq_name = "tct_1col.txt";
      break;
    case xrt_core::query::sequence_name::type::tct_all_column:
      seq_name = "tct_4col.txt";
      break;
    // case xrt_core::query::sequence_name::type::gemm_int8: 
    //   seq_name = "gemm_int8.txt";
    //   break;
    }

    return boost::str(fmt % seq_name);
  }
};

struct elf_name
{
  static std::any
  get(const xrt_core::device* /*device*/, key_type key)
  {
    throw xrt_core::query::no_such_key(key, "Not implemented");
  }

  static std::any
  get(const xrt_core::device* device, key_type key, const std::any& param)
  {
    if (key != key_type::elf_name)
      throw xrt_core::query::no_such_key(key, "Not implemented");

    const auto& pcie_id = xrt_core::device_query<xrt_core::query::pcie_id>(device);

    std::string elf_file;
    switch (std::any_cast<xrt_core::query::elf_name::type>(param)) {
    case xrt_core::query::elf_name::type::nop:
      elf_file = "nop.elf";
      break;
    case xrt_core::query::elf_name::type::df_bandwidth:
      elf_file = "df_bw.elf";
      break;
    case xrt_core::query::elf_name::type::tct_one_column:
      elf_file = "tct_1col.elf";
      break;
    case xrt_core::query::elf_name::type::tct_all_column:
      elf_file = "tct_4col.elf";
      break;
    case xrt_core::query::elf_name::type::aie_reconfig_overhead: 
      elf_file = "aie_reconfig_overhead.elf";
      break;
    // case xrt_core::query::elf_name::type::gemm_int8:
    //   elf_file = "gemm_int8.elf";
    //   break;
    }

    return boost::str(boost::format("bins/%04x_%02x/%s")
      % pcie_id.device_id
      % static_cast<uint16_t>(pcie_id.revision_id)
      % elf_file);
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

template <typename QueryRequestType, typename Putter>
struct function_putter : virtual QueryRequestType
{
  void
  put(const xrt_core::device* device, const std::any& any) const
  {
    if (auto uhdl = device->get_user_handle())
      Putter::put(device, QueryRequestType::key, any);
    else
      throw xrt_core::internal_error("No device handle");
  }
};

template <typename QueryRequestType, typename GetPut>
struct function0_getput : function0_get<QueryRequestType, GetPut>, function_putter<QueryRequestType, GetPut>
{};

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

template <typename QueryRequestType, typename GetPut>
static void
emplace_func0_getput()
{
  auto k = QueryRequestType::key;
  query_tbl.emplace(k, std::make_unique<function0_getput<QueryRequestType, GetPut>>());
}

static void
initialize_query_table()
{
  emplace_func0_request<query::aie_partition_info,             partition_info>();
  emplace_func0_request<query::aie_status_version,             aie_info>();
  emplace_func0_request<query::aie_tiles_stats,                aie_info>();
  emplace_func1_request<query::aie_tiles_status_info,          aie_info>();
  emplace_func0_request<query::clock_freq_topology_raw,        clock_topology>();
  emplace_func0_request<query::xrt_resource_raw,               resource_info>();
  emplace_func0_request<query::device_class,                   default_value>();
  emplace_func0_request<query::instance,                       instance>();
  emplace_func0_request<query::is_ready,                       default_value>();
  emplace_func0_request<query::is_versal,                      default_value>();
  emplace_func0_request<query::logic_uuids,                    default_value>();
  emplace_func0_request<query::pcie_bdf,                       bdf>();
  emplace_func0_request<query::pcie_id,                        pcie_id>();
  emplace_func0_request<query::total_cols,                     total_cols>();
  emplace_sysfs_get<query::pcie_device>                        ("", "device");
  emplace_sysfs_get<query::pcie_express_lane_width>            ("", "link_width");
  emplace_sysfs_get<query::pcie_express_lane_width_max>        ("", "link_width_max");
  emplace_sysfs_get<query::pcie_link_speed>                    ("", "link_speed");
  emplace_sysfs_get<query::pcie_link_speed_max>                ("", "link_speed_max");
  emplace_sysfs_get<query::pcie_subsystem_id>                  ("", "subsystem_device");
  emplace_sysfs_get<query::pcie_subsystem_vendor>              ("", "subsystem_vendor");
  emplace_sysfs_get<query::pcie_vendor>                        ("", "vendor");

  emplace_func0_getput<query::performance_mode,                performance_mode>();
  emplace_func0_getput<query::preemption,                      preemption>();
  emplace_func0_request<query::aie_telemetry,                  telemetry>();
  emplace_func0_request<query::misc_telemetry,                 telemetry>();
  emplace_func0_request<query::opcode_telemetry,               telemetry>();
  emplace_func0_request<query::rtos_telemetry,                 telemetry>();
  emplace_func0_request<query::stream_buffer_telemetry,        telemetry>();

  emplace_func0_request<query::rom_ddr_bank_count_max,         default_value>();
  emplace_func0_request<query::rom_ddr_bank_size_gb,           default_value>();
  emplace_sysfs_get<query::rom_vbnv>                           ("", "vbnv");
  emplace_func1_request<query::sdm_sensor_info,                sensor_info>();
  emplace_func1_request<query::sequence_name,                  sequence_name>();
  emplace_func1_request<query::elf_name,                       elf_name>();
  emplace_func1_request<query::xclbin_name,                    xclbin_name>();
  emplace_func1_request<query::xrt_smi_config,                 xrt_smi_config>();
  emplace_func1_request<query::xrt_smi_lists,                  xrt_smi_lists>();
  emplace_func0_request<query::firmware_version,               firmware_version>();
}

struct X { X() { initialize_query_table(); }};
static X x;

int
import_fd(pid_t pid, int ehdl)
{
  if (pid == 0 || getpid() == pid)
    return ehdl;

#if defined(SYS_pidfd_open) && defined(SYS_pidfd_getfd)
  auto pidfd = syscall(SYS_pidfd_open, pid, 0);
  if (pidfd < 0)
    throw xrt_core::system_error(errno, "pidfd_open failed");

  auto fd = syscall(SYS_pidfd_getfd, pidfd, ehdl, 0);
  if (fd < 0) {
    if (errno == EPERM) {
      throw xrt_core::system_error
        (errno, "pidfd_getfd failed, check that ptrace access mode "
        "allows PTRACE_MODE_ATTACH_REALCREDS.  For more details please "
        "check /etc/sysctl.d/10-ptrace.conf");
    } else {
      throw xrt_core::system_error(errno, "pidfd_getfd failed");
    }
  }
  return fd;
#else
  throw xrt_core::system_error
    (std::errc::not_supported,
     "Importing buffer object from different process requires XRT "
     " built and installed on a system with 'pidfd' kernel support");
  return -1;
#endif
}

}

namespace shim_xdna {

const query::request&
device::
lookup_query(query::key_type query_key) const
{
  auto it = query_tbl.find(query_key);

  if (it == query_tbl.end()) {
    shim_debug("query key (%d) is not supported", query_key);
    throw query::no_such_key(query_key);
  }

  return *(it->second);
}

device::
device(const pdev& pdev, handle_type shim_handle, id_type device_id)
  : noshim<xrt_core::device_pcie>{shim_handle, device_id, !pdev.m_is_mgmt}
  , m_pdev(pdev)
{
  m_pdev.open();
}

device::
~device()
{
  m_pdev.close();
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
  return alloc_bo(userptr, AMDXDNA_INVALID_CTX_HANDLE, size, flags);
}

std::unique_ptr<xrt_core::buffer_handle>
device::
import_bo(pid_t pid, xrt_core::shared_handle::export_handle ehdl)
{
  return import_bo(import_fd(pid, ehdl));
}

std::unique_ptr<xrt_core::fence_handle>
device::
create_fence(xrt::fence::access_mode)
{
  return std::make_unique<fence>(*this);
}

std::unique_ptr<xrt_core::fence_handle>
device::
import_fence(pid_t pid, xrt_core::shared_handle::export_handle ehdl)
{
  return std::make_unique<fence>(*this, import_fd(pid, ehdl));
}

} // namespace shim_xdna

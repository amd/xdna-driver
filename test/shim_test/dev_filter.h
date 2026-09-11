// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2022-2026, Advanced Micro Devices, Inc. All rights reserved.

#ifndef _SHIMTEST_DEV_FILTER_H_
#define _SHIMTEST_DEV_FILTER_H_

#include "dev_info.h"

#include "core/common/device.h"
#include "core/common/query_requests.h"

#include <filesystem>
#include <iterator>
#include <stdexcept>
#include <string>
#include <vector>

using namespace xrt_core;

// Hardware platform and driver type enums for test case filtering.
// Any device can belong to only 1 hw_type, no overlap.
enum hw_type {
  non_npu,  // non-xdna device
  npu1,     // AIE2, device_id 0x1502
  npu4,     // AIE2, device_id 0x17f0
  npu3,     // AIE4 classic, device_id 0x17f1 / 0x1b0a (classic only)
  npu3vf,   // AIE4 VF, device_id 0x17f3 / 0x1b0c (SRIOV VF only)
  ve2,      // VE2 edge, device_id 0xb052
};

enum drv_type {
  amdxdna,  // native amdxdna kernel driver
};

// Per-enum hw filter entry: nullptr check for non_npu (special case)
struct hw_filter_entry {
  hw_type hw;
  bool (*check)(device::id_type, device*);
};

struct drv_filter_entry {
  drv_type drv;
  bool (*check)(device::id_type, device*);
};

// Per-enum hw check functions — implement device ID logic directly
inline bool
dev_filter_is_npu1(device::id_type id, device* dev)
{
  return device_query<query::pcie_device>(dev) == npu1_device_id;
}

inline bool
dev_filter_is_npu4(device::id_type id, device* dev)
{
  return device_query<query::pcie_device>(dev) == npu4_device_id;
}

inline bool
dev_filter_is_npu3(device::id_type id, device* dev)
{
  auto device_id = device_query<query::pcie_device>(dev);
  return device_id == npu3_device_id || device_id == npu3a_device_id;
}

inline bool
dev_filter_is_npu3vf(device::id_type id, device* dev)
{
  auto device_id = device_query<query::pcie_device>(dev);
  return device_id == npu3_device_id1 || device_id == npu3a_device_id1;
}

// Classic AIE4 userpf or SRIOV VF (npu3 / npu3a).
inline bool
dev_filter_is_aie4(device::id_type id, device* dev)
{
  return dev_filter_is_npu3(id, dev) || dev_filter_is_npu3vf(id, dev);
}

inline bool
dev_filter_is_ve2(device::id_type id, device* dev)
{
  return device_query<query::pcie_device>(dev) == npu_ve2_device_id;
}

// hw_filter_table: non_npu is entry 0 with nullptr check (special case handled by
// dev_filter_is_non_npu). All other entries have a dedicated check function.
// When adding a new hw_type, add it here and dev_filter_is_non_npu auto-updates.
inline const hw_filter_entry hw_filter_table[] = {
  { non_npu, nullptr              },
  { npu1,    dev_filter_is_npu1   },
  { npu4,    dev_filter_is_npu4   },
  { npu3,    dev_filter_is_npu3   },
  { npu3vf,  dev_filter_is_npu3vf},
  { ve2,     dev_filter_is_ve2    },
};

// driver checker
inline bool
drv_filter_is_amdxdna(device::id_type id, device* dev)
{
  query::sub_device_path::args query_arg = {std::string(""), 0};
  auto sysfs = device_query<query::sub_device_path>(dev, query_arg);
  auto drv_path = std::filesystem::read_symlink(sysfs + "/driver");
  return drv_path.filename() == "amdxdna";
}

inline const drv_filter_entry drv_filter_table[] = {
  { amdxdna, drv_filter_is_amdxdna },
};

// dev_filter_is_non_npu: iterates hw_filter_table from entry 1 onward,
// returns true if none of the known NPU checkers match.
inline bool
dev_filter_is_non_npu(device::id_type id, device* dev)
{
  for (size_t i = 1; i < std::size(hw_filter_table); i++) {
    if (hw_filter_table[i].check(id, dev))
      return false;
  }
  return true;
}

inline bool
match_hw(const std::vector<hw_type>& hw_list, device::id_type id, device* dev)
{
  if (hw_list.empty())
    throw std::runtime_error("match_hw: hw_list must not be empty");
  for (auto hw : hw_list) {
    if (hw == non_npu) {
      if (dev_filter_is_non_npu(id, dev))
        return true;
      continue;
    }
    for (const auto& entry : hw_filter_table) {
      if (entry.hw == hw && entry.check(id, dev))
        return true;
    }
  }
  return false;
}

inline bool
match_drv(const std::vector<drv_type>& drv_list, device::id_type id, device* dev)
{
  if (drv_list.empty())
    return true;
  for (auto drv : drv_list) {
    for (const auto& entry : drv_filter_table) {
      if (entry.drv == drv && entry.check(id, dev))
        return true;
    }
  }
  return false;
}

#endif // _SHIMTEST_DEV_FILTER_H_

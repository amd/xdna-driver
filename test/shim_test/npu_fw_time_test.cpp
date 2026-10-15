// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026, Advanced Micro Devices, Inc. All rights reserved.

#include "dev_info.h"
#include "core/common/query_requests.h"

#include <chrono>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <stdexcept>
#include <string>
#include <thread>

// Reads the aie4 "npu_fw_time" debugfs node (GET_NPUFW_TIME, fw op 0x10011)
// twice and asserts the firmware timestamp advances, proving the round-trip.

namespace {
namespace fs = std::filesystem;

// Node is /sys/kernel/debug/accel/<dir>/npu_fw_time, where <dir> is the PCI BDF
// on some kernels and accel<N> on others; return whichever exists for this dev.
std::string npu_fw_time_node(device* dev)
{
  query::sub_device_path::args arg{std::string(""), 0};
  const std::string sysfs = device_query<query::sub_device_path>(dev, arg);
  for (const auto& d : fs::directory_iterator("/sys/kernel/debug/accel")) {
    const std::string name = d.path().filename().string();
    if (fs::exists(d.path() / "npu_fw_time") &&
        (name == fs::path(sysfs).filename().string() ||
         fs::exists(sysfs + "/accel/" + name)))
      return (d.path() / "npu_fw_time").string();
  }
  throw std::runtime_error("npu_fw_time debugfs node not found for device");
}

uint64_t read_fw_time_ns(const std::string& node)
{
  uint64_t ns = 0;
  if (!(std::ifstream(node) >> ns))
    throw std::runtime_error("cannot read " + node + " (run as root?)");
  return ns;
}

}

void
TEST_npu_fw_time_monotonic(device::id_type, std::shared_ptr<device>& sdev, arg_type&)
{
  const std::string node = npu_fw_time_node(sdev.get());

  const uint64_t t1 = read_fw_time_ns(node);
  std::this_thread::sleep_for(std::chrono::milliseconds(50));
  const uint64_t t2 = read_fw_time_ns(node);

  if (t2 <= t1)
    throw std::runtime_error("npu_fw_time did not advance: " +
                             std::to_string(t1) + " -> " + std::to_string(t2));
}

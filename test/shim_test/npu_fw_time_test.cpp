// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026, Advanced Micro Devices, Inc. All rights reserved.

#include "dev_info.h"

#include "core/common/query_requests.h"

#include <chrono>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>
#include <thread>

// Shim-level test for the aie4 "npu_fw_time" debugfs node
// (AIE4_MSG_OP_GET_NPUFW_TIME, firmware opcode 0x10011).
//
// The node is a read-only file created under the DRM accel debugfs root:
//
//     /sys/kernel/debug/accel/<accelN>/npu_fw_time
//
// Reading it issues a GET_NPUFW_TIME management message to firmware and
// returns the current NPU firmware timestamp in nanoseconds. The test
// reads the node twice and asserts the counter advances, which proves the
// firmware round-trip actually happened (a stubbed/stuck path would return
// a constant or zero).

namespace {

namespace fs = std::filesystem;

// Resolve /sys/kernel/debug/accel/<accelN>/npu_fw_time for @dev by walking
// from the device's PCI sysfs directory to its DRM accel node name.
std::string
npu_fw_time_node(device* dev)
{
  query::sub_device_path::args path_arg = {std::string(""), 0};
  const std::string dev_sysfs = device_query<query::sub_device_path>(dev, path_arg);

  const fs::path accel_dir = fs::path(dev_sysfs) / "accel";
  std::error_code ec;
  if (!fs::is_directory(accel_dir, ec))
    throw std::runtime_error("accel sysfs dir not found: " + accel_dir.string());

  for (const auto& entry : fs::directory_iterator(accel_dir, ec)) {
    const std::string name = entry.path().filename().string();
    if (name.rfind("accel", 0) == 0)  // e.g. "accel0"
      return "/sys/kernel/debug/accel/" + name + "/npu_fw_time";
  }

  throw std::runtime_error("no accel<N> node under " + accel_dir.string());
}

uint64_t
read_fw_time_ns(const std::string& node)
{
  std::ifstream f(node);
  if (!f.is_open())
    throw std::runtime_error("cannot open " + node + " (run as root; feature/device present?)");

  uint64_t ns = 0;
  f >> ns;
  if (f.fail())
    throw std::runtime_error("failed to read a timestamp from " + node +
                             " (firmware GET_NPUFW_TIME error?)");
  return ns;
}

}

void
TEST_npu_fw_time_monotonic(device::id_type id, std::shared_ptr<device>& sdev, arg_type& arg)
{
  const std::string node = npu_fw_time_node(sdev.get());

  const uint64_t t1 = read_fw_time_ns(node);
  std::this_thread::sleep_for(std::chrono::milliseconds(50));
  const uint64_t t2 = read_fw_time_ns(node);

  std::cout << "  " << node << ": " << t1 << " -> " << t2 << " ns" << std::endl;

  if (t2 < t1)
    throw std::runtime_error("npu_fw_time went backwards: " + std::to_string(t1) +
                             " -> " + std::to_string(t2));
  if (t2 == t1)
    throw std::runtime_error("npu_fw_time did not advance (" + std::to_string(t1) +
                             "); firmware counter stuck or read stubbed");

  std::cout << "  npu_fw_time advanced by " << (t2 - t1) << " ns" << std::endl;
}

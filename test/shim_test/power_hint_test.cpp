// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026, Advanced Micro Devices, Inc. All rights reserved.

#include "dev_info.h"
#include "core/common/query_requests.h"

#include <cstdint>
#include <filesystem>
#include <fstream>
#include <stdexcept>
#include <string>

// Exercises the aie4 "power_hint" debugfs node (POWER_HINT, fw op 0x3000A):
// every valid hint (0..7) must round-trip through firmware, and an
// out-of-range value must be rejected.

namespace {
namespace fs = std::filesystem;

// Node is /sys/kernel/debug/accel/<dir>/power_hint, where <dir> is the PCI BDF
// on some kernels and accel<N> on others; return whichever exists for this dev.
std::string power_hint_node(device* dev)
{
  query::sub_device_path::args arg{std::string(""), 0};
  const std::string sysfs = device_query<query::sub_device_path>(dev, arg);
  for (const auto& d : fs::directory_iterator("/sys/kernel/debug/accel")) {
    const std::string name = d.path().filename().string();
    if (fs::exists(d.path() / "power_hint") &&
        (name == fs::path(sysfs).filename().string() ||
         fs::exists(sysfs + "/accel/" + name)))
      return (d.path() / "power_hint").string();
  }
  throw std::runtime_error("power_hint debugfs node not found for device");
}

uint64_t read_hint(const std::string& node)
{
  uint64_t v = 0;
  if (!(std::ifstream(node) >> v))
    throw std::runtime_error("cannot read " + node + " (run as root?)");
  return v;
}

bool write_hint(const std::string& node, uint64_t v)
{
  std::ofstream f(node);
  f << v << std::flush;
  return f.good();
}

}

void
TEST_power_hint_set_get(device::id_type, std::shared_ptr<device>& sdev, arg_type&)
{
  const std::string node = power_hint_node(sdev.get());
  const uint64_t original = read_hint(node);

  for (uint64_t v = 0; v < 8; v++)  // 0..7 are the valid aie4_msg_power_hint values
    if (!write_hint(node, v) || read_hint(node) != v)
      throw std::runtime_error("power_hint round-trip failed for " + std::to_string(v));

  if (write_hint(node, 8))  // out-of-range must be rejected (-EINVAL)
    throw std::runtime_error("out-of-range power_hint 8 was not rejected");

  write_hint(node, original);
}

// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026, Advanced Micro Devices, Inc. All rights reserved.

#include "dev_info.h"
#include "core/common/query_requests.h"

#include <cstdint>
#include <filesystem>
#include <fstream>
#include <stdexcept>
#include <string>

// Exercises the aie4 "ctx_switch_hysteresis_us" debugfs node, which drives
// SET_RUNTIME_CONFIG / GET_RUNTIME_CONFIG (fw ops 0x10007/0x10008). A written
// timeout must round-trip through the firmware read path, and an out-of-range
// value must be rejected.

namespace {
namespace fs = std::filesystem;

// Node is /sys/kernel/debug/accel/<dir>/ctx_switch_hysteresis_us, where <dir>
// is the PCI BDF on some kernels and accel<N> on others; return whichever
// exists for this device.
std::string ctx_hysteresis_node(device* dev)
{
  query::sub_device_path::args arg{std::string(""), 0};
  const std::string sysfs = device_query<query::sub_device_path>(dev, arg);
  for (const auto& d : fs::directory_iterator("/sys/kernel/debug/accel")) {
    const std::string name = d.path().filename().string();
    if (fs::exists(d.path() / "ctx_switch_hysteresis_us") &&
        (name == fs::path(sysfs).filename().string() ||
         fs::exists(sysfs + "/accel/" + name)))
      return (d.path() / "ctx_switch_hysteresis_us").string();
  }
  throw std::runtime_error("ctx_switch_hysteresis_us debugfs node not found for device");
}

uint64_t read_us(const std::string& node)
{
  uint64_t v = 0;
  if (!(std::ifstream(node) >> v))
    throw std::runtime_error("cannot read " + node + " (run as root?)");
  return v;
}

bool write_us(const std::string& node, uint64_t v)
{
  std::ofstream f(node);
  f << v << std::flush;
  return f.good();
}

}

void
TEST_ctx_hysteresis_set_get(device::id_type, std::shared_ptr<device>& sdev, arg_type&)
{
  const std::string node = ctx_hysteresis_node(sdev.get());
  const uint64_t original = read_us(node);

  for (uint64_t v : {uint64_t{0}, uint64_t{500}, uint64_t{1000}, uint64_t{100000}})
    if (!write_us(node, v) || read_us(node) != v)
      throw std::runtime_error("ctx_switch_hysteresis_us round-trip failed for " +
                               std::to_string(v));

  if (write_us(node, uint64_t{UINT32_MAX} + 1))  // out-of-range must be rejected (-EINVAL)
    throw std::runtime_error("out-of-range ctx_switch_hysteresis_us was not rejected");

  write_us(node, original);
}

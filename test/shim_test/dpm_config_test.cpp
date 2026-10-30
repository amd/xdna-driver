// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026, Advanced Micro Devices, Inc. All rights reserved.

#include "dev_info.h"
#include "core/common/query_requests.h"

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cstdint>
#include <filesystem>
#include <fstream>
#include <map>
#include <sstream>
#include <stdexcept>
#include <string>
#include <system_error>
#include <vector>

// Reads the aie4 "dpm_config" debugfs node (GET_RUNTIME_CONFIG for the DPM
// compute and BW configs) and checks it is read-only and reports a complete,
// well-formed set of fields for each config firmware supports.

namespace {
namespace fs = std::filesystem;

const std::vector<std::string> dpm_compute_keys = {
  "active_hysteresis_ms", "sampling_window_ms", "up_threshold",
  "down_threshold", "compute_sys_efficiency_percent", "bw_sys_efficiency_percent",
};

const std::vector<std::string> dpm_bw_keys = {
  "bw_high_cac_threshold", "bw_low_cac_threshold", "bw_sampling_window_ms",
};

// Node is /sys/kernel/debug/accel/<dir>/dpm_config, where <dir> is the device
// name (e.g. PCI BDF) on newer kernels and the bare accel minor <N> (sysfs
// accel/accel<N>) on older ones; return whichever matches this device.
std::string dpm_config_node(device* dev)
{
  query::sub_device_path::args arg{std::string(""), 0};
  const std::string sysfs = device_query<query::sub_device_path>(dev, arg);
  std::error_code ec;
  fs::directory_iterator it("/sys/kernel/debug/accel", ec);
  if (ec)
    throw std::runtime_error("cannot open /sys/kernel/debug/accel (debugfs mounted, run as root?): " +
                             ec.message());
  for (const auto& d : it) {
    const std::string name = d.path().filename().string();
    if (fs::exists(d.path() / "dpm_config") &&
        (name == fs::path(sysfs).filename().string() ||
         fs::exists(sysfs + "/accel/accel" + name)))
      return (d.path() / "dpm_config").string();
  }
  throw std::runtime_error("dpm_config debugfs node not found for device");
}

std::map<std::string, uint64_t> read_dpm_config(const std::string& node)
{
  std::ifstream in(node);
  if (!in)
    throw std::runtime_error("cannot read " + node + " (run as root?)");

  std::map<std::string, uint64_t> fields;
  std::string line;
  while (std::getline(in, line)) {
    std::istringstream ls(line);
    std::string key;
    uint64_t val;
    if (!(ls >> key >> val) || key.empty() || key.back() != ':')
      throw std::runtime_error("malformed dpm_config line: '" + line + "'");
    key.pop_back();
    if (!fields.emplace(key, val).second)
      throw std::runtime_error("duplicate dpm_config key: " + key);
  }
  return fields;
}

// Returns true if all @keys are present, false if none are; throws on a partial set.
bool has_config(const std::map<std::string, uint64_t>& fields,
                const std::vector<std::string>& keys, const char* what)
{
  size_t found = 0;
  for (const auto& k : keys)
    found += fields.count(k);
  if (found && found != keys.size())
    throw std::runtime_error(std::string("incomplete ") + what + " fields in dpm_config");
  return found;
}

}

void
TEST_dpm_config_read(device::id_type, std::shared_ptr<device>& sdev, arg_type&)
{
  const std::string node = dpm_config_node(sdev.get());

  struct stat st;
  if (stat(node.c_str(), &st))
    throw std::system_error(errno, std::generic_category(), "stat " + node);
  if ((st.st_mode & 0777) != 0400)
    throw std::runtime_error("dpm_config mode is not 0400");

  // Root bypasses the mode bits, so also check the node itself rejects writes.
  int fd = open(node.c_str(), O_WRONLY);
  if (fd >= 0) {
    const ssize_t n = write(fd, "1", 1);
    close(fd);
    if (n >= 0)
      throw std::runtime_error("write to dpm_config unexpectedly succeeded");
  }

  const auto fields = read_dpm_config(node);
  const bool compute = has_config(fields, dpm_compute_keys, "DPM compute");
  const bool bw = has_config(fields, dpm_bw_keys, "DPM BW");

  if (!compute && !bw)
    throw std::runtime_error("dpm_config reports no DPM config");
  if (fields.size() != (compute ? dpm_compute_keys.size() : 0) + (bw ? dpm_bw_keys.size() : 0))
    throw std::runtime_error("unexpected keys in dpm_config");

  if (compute && fields.at("up_threshold") <= fields.at("down_threshold"))
    throw std::runtime_error("DPM up_threshold " + std::to_string(fields.at("up_threshold")) +
                             " is not above down_threshold " +
                             std::to_string(fields.at("down_threshold")));
  if (bw && fields.at("bw_high_cac_threshold") <= fields.at("bw_low_cac_threshold"))
    throw std::runtime_error("DPM BW high CAC threshold is not above the low one");
}

// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2024-2026, Advanced Micro Devices, Inc. All rights reserved.

#ifndef _SHIMTEST_DEV_INFO_H_
#define _SHIMTEST_DEV_INFO_H_

#include <cstdint>
#include <map>
#include <vector>
#include "core/common/device.h"
#include "core/common/query_requests.h"

using namespace xrt_core;

using arg_type = const std::vector<uint64_t>;

enum flow_type {
  LEGACY = 0,
  PARTIAL_ELF,
  PREEMPT_PARTIAL_ELF,
  FULL_ELF,
  PREEMPT_FULL_ELF,
};

struct binary_info {
  const char* tag;  /* tag for test lookup, e.g. "nop", "bad", "good" */
  const uint16_t device;     /* PCI parts: pcie device id (0 for a platform part) */
  const bool platform = false;  /* true: npu12-family (platform) entry; false: PCI */
  const uint16_t revision_id;
  const std::map<const char*, cuidx_type> ip_name2idx;
  const std::string path;
  const std::string data;
  const std::map<std::string, std::string> extra = {};  /* e.g. elf_name, exp_status, exp_val */
  const flow_type flow;
};

const uint16_t npu1_device_id = 0x1502;
const uint16_t npu1_device_id1 = 0x1050;
const uint16_t npu3_device_id = 0x17f1;
const uint16_t npu3_pf_device_id = 0x17f2;
const uint16_t npu3_device_id1 = 0x17f3;
const uint16_t npu3a_device_id = 0x1b0a;
const uint16_t npu3a_pf_device_id = 0x1b0b;
const uint16_t npu3a_device_id1 = 0x1b0c;
// npu12: platform (non-PCI) aie2ps part. It has no PCI device id; the shim
// identifies it by the "amd,xdna-<part>" device-tree compatible, exposed as
// query::device_id_str. The aie2ps/npu12 SKUs (T50/T20/T10) share the same
// shim-test ELFs, so the shim test treats them as one family (see is_npu12) and
// marks their ELF entries with binary_info::platform instead of a PCI device id.
const uint16_t npu_ve2_device_id = 0xb052;
const uint16_t npu4_device_id = 0x17f0;
const uint16_t npu_any_revision_id = 0xffff;
const uint16_t npu1_revision_id = 0x0;
const uint16_t npu1_revision_id1 = 0x1;
const uint16_t npu4_revision_id = 0x10;
const uint16_t npu5_revision_id = 0x11;
const uint16_t npu6_revision_id = 0x20;

// Test ELFs are keyed by classic AIE4 PCI ids; map VF ids for lookup only.
inline uint16_t
aie4_binary_device_id(uint16_t device_id)
{
  switch (device_id) {
  case npu3_device_id1:
    return npu3_device_id;
  case npu3a_device_id1:
    return npu3a_device_id;
  default:
    return device_id;
  }
}

// VE2 is the auxiliary device xilinx_aie.amdxdna. It reports the same board
// part string as an npu12 SKU, but it is not the platform npu12 device.
inline bool
is_ve2_aux(device* dev)
{
  try {
    query::sub_device_path::args query_arg = {std::string(""), 0};
    auto sysfs = device_query<query::sub_device_path>(dev, query_arg);
    return sysfs.find("xilinx_aie.amdxdna") != std::string::npos;
  }
  catch (const query::exception&) {
    return false;
  }
}

// Any platform (non-PCI) part reports a device-tree part string (query::
// device_id_str) and has no PCI id. This covers every aie2ps/npu12 SKU, not just
// the one the shim test has binaries for. The VE2 auxiliary device also reports
// a part string; callers that mean the platform npu12 part use is_npu12.
inline bool
is_platform_part(device* dev)
{
  return !device_query_default<query::device_id_str>(dev, std::string{}).empty();
}

// The aie2ps/npu12 SKUs the shim test ships ELF binaries for, identified by their
// device-tree part string. All three SKUs share the same ELFs, so they are one
// family here.
inline bool
is_npu12(device* dev)
{
  if (is_ve2_aux(dev))
    return false;
  const auto part = device_query_default<query::device_id_str>(dev, std::string{});
  return part == "xc2ve3858"   // T50
      || part == "xc2ve3558"   // T20
      || part == "xc2ve3358";  // T10
}

// Real pcie device id used for ELF lookup and hw filtering, or 0 for a part that
// legitimately has none: a device whose pcie_device query is unsupported (non-xdna
// edge device) or any platform part (which has no "device" sysfs node). A sysfs
// read failure on an actual PCI device is a real error and propagates.
inline uint16_t
test_device_id(device* dev)
{
  try {
    return device_query<query::pcie_device>(dev);
  }
  catch (const query::no_such_key&) {
    return 0;
  }
  catch (const query::sysfs_error&) {
    if (is_platform_part(dev))
      return 0;
    throw;
  }
}

// A device is a shim_test target if it has a known PCI id, is the npu12 part,
// or is the VE2 auxiliary device.
inline bool
is_shimtest_target(device* dev)
{
  return test_device_id(dev) != 0 || is_npu12(dev) || is_ve2_aux(dev);
}

const binary_info& get_binary_info(device* dev, const char* tag = nullptr, const flow_type* flow = nullptr);
std::string get_binary_path(device* dev, const char* tag = nullptr, const flow_type* flow = nullptr);
std::string get_kernel_name(device* dev, const char* tag, const flow_type* flow = nullptr);
flow_type get_flow_type(device* dev, const char* tag, const flow_type* flow = nullptr);
std::string get_binary_data(device* dev, const char* tag = nullptr, const flow_type* flow = nullptr);
const std::map<const char*, cuidx_type>& get_binary_ip_name2index(device* dev, const char* tag = nullptr, const flow_type* flow = nullptr);

#endif // _SHIMTEST_DEV_INFO_H_

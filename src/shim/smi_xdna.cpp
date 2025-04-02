// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2025 Advanced Micro Devices, Inc. All rights reserved.
#include "smi_xdna.h"

namespace shim_xdna::smi {

smi_xdna::
smi_xdna() : smi_base( 
  {
    {"all", "All applicable validate tests will be executed (default)", "common"},
    {"cmd-chain-latency", "Run end-to-end latency test using command chaining", "hidden"},
    {"cmd-chain-throughput", "Run end-to-end throughput test using command chaining", "hidden"},
    {"df-bw", "Run bandwidth test on data fabric", "hidden"},
    {"latency", "Run end-to-end latency test", "common"},
    {"quick", "Run a subset of four tests: \n1. latency \n2. throughput \n3. cmd-chain-latency \n4. cmd-chain-throughput", "hidden"},
    {"spatial-sharing-overhead", "Run Spatial Sharing Overhead Test", "hidden"},
    {"tct-all-col", "Measure average TCT processing time for all columns", "hidden"},
    {"tct-one-col", "Measure average TCT processing time for one column", "hidden"},
    {"temporal-sharing-overhead", "Run Temporal Sharing Overhead Test", "hidden"},
    {"throughput", "Run end-to-end throughput test", "common"}
  },
  {
    {"aie-partitions", "AIE partition information", "common"},
    {"host", "Host information", "common"},
    {"platform", "Platforms flashed on the device", "common"},
    {"telemetry", "Telemetry data for the device", "hidden"},
    {"preemption", "Preemption telemetry data for the device", "hidden"},
    {"clocks", "Clock frequency information", "hidden"}
  },
  {
    {"device", "d", "The Bus:Device.Function (e.g., 0000:d8:00.0) device of interest", "common", "", "string"},
    {"help", "h", "Help to use this sub-command", "common", "", "none"}
  })
{}

static shim_xdna::smi::smi_xdna smi_instance;

std::string
get_smi_config()
{
  // Call the get_smi_config method
  return smi_instance.build_smi_config();
}

const xrt_core::smi::tuple_vector&
get_validate_tests()
{
  // Call the get_validate_tests method
  return smi_instance.get_validate_tests();
}

const xrt_core::smi::tuple_vector&
get_examine_reports()
{
  // Call the get_examine_reports method
  return smi_instance.get_examine_reports();
}

} // namespace shim_xdna::smi

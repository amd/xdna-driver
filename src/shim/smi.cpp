// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2025 Advanced Micro Devices, Inc. All rights reserved.
#include "smi.h"

namespace shim_xdna::smi {

smi_xdna::
smi_xdna() : smi_base() 
{
  // Filter validate_test_desc to include only relevant entries
  validate_test_desc = {
    {"aie-reconfig-overhead", "Run end-to-end array reconfiguration overhead through shim DMA", "hidden"},
    {"all", "All applicable validate tests will be executed (default)", "common"},
    {"cmd-chain-latency", "Run end-to-end latency test using command chaining", "hidden"},
    {"cmd-chain-throughput", "Run end-to-end throughput test using command chaining", "hidden"},
    {"df-bw", "Run bandwidth test on data fabric", "hidden"},
    {"gemm", "Measure the TOPS value of GEMM operations", "common"},
    {"latency", "Run end-to-end latency test", "common"},
    {"quick", "Run a subset of four tests: \n1. latency \n2. throughput \n3. cmd-chain-latency \n4. cmd-chain-throughput", "hidden"},
    {"spatial-sharing-overhead", "Run Spatial Sharing Overhead Test", "hidden"},
    {"tct-all-col", "Measure average TCT processing time for all columns", "hidden"},
    {"tct-one-col", "Measure average TCT processing time for one column", "hidden"},
    {"temporal-sharing-overhead", "Run Temporal Sharing Overhead Test", "hidden"},
    {"throughput", "Run end-to-end throughput test", "common"}
  };

  // Filter examine_report_desc to include only relevant entries
  examine_report_desc = {
    {"aie-partitions", "AIE partition information", "common"},
    {"host", "Host information", "common"},
    {"platform", "Platforms flashed on the device", "common"},
    {"telemetry", "Telemetry data for the device", "hidden"},
    {"preemption", "Preemption telemetry data for the device", "hidden"},
    {"clocks", "Clock frequency information", "hidden"}
  };
}
  
static shim_xdna::smi::smi_xdna smi_instance;

std::string
get_smi_config()
{
  // Call the get_smi_config method
  return smi_instance.get_smi_config();
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

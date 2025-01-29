// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2025 Advanced Micro Devices, Inc. All rights reserved.
#include "smi.h"

namespace shim_xdna::smi {

const std::vector<std::tuple<std::string, std::string, std::string>>& 
smi_xdna::
get_validate_test_desc() const 
{
  static const std::vector<std::tuple<std::string, std::string, std::string>> validate_test_desc = {
    {"aie-reconfig-overhead", "Run end-to-end array reconfiguration overhead through shim DMA", "hidden"},
    {"all", "All applicable validate tests will be executed (default)", "common"},
    {"cmd-chain-latency", "Run end-to-end latency test using command chaining", "common"},
    {"cmd-chain-throughput", "Run end-to-end throughput test using command chaining", "common"},
    {"df-bw", "Run bandwidth test on data fabric", "common"},
    {"gemm", "Measure the TOPS value of GEMM operations", "common"},
    {"latency", "Run end-to-end latency test", "common"},
    {"quick", "Run a subset of four tests: \n1. latency \n2. throughput \n3. cmd-chain-latency \n4. cmd-chain-throughput", "common"},
    {"spatial-sharing-overhead", "Run Spatial Sharing Overhead Test", "hidden"},
    {"tct-all-col", "Measure average TCT processing time for all columns", "common"},
    {"tct-one-col", "Measure average TCT processing time for one column", "common"},
    {"temporal-sharing-overhead", "Run Temporal Sharing Overhead Test", "hidden"},
    {"throughput", "Run end-to-end throughput test", "common"}
  };
  return validate_test_desc;
}

const std::vector<std::tuple<std::string, std::string, std::string>>& 
smi_xdna::
get_examine_report_desc() const 
{
  static const std::vector<std::tuple<std::string, std::string, std::string>> examine_report_desc = {
    {"aie-partitions", "AIE partition information", "common"},
    {"host", "Host information", "common"},
    {"platform", "Platforms flashed on the device", "common"},
    {"telemetry", "Telemetry data for the device", "common"}
  };
  return examine_report_desc;
}

std::string
get_smi_config()
{
  // Create an instance of the derived class
  shim_xdna::smi::smi_xdna smi_instance;

  // Call the get_smi_config method
  return smi_instance.get_smi_config();
}
} // namespace shim_xdna::smi

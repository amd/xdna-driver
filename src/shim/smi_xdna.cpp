// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2025 Advanced Micro Devices, Inc. All rights reserved.

#include "smi_xdna.h"
using namespace xrt_core::smi;

namespace shim_xdna::smi {

  // Function to create the "validate" subcommand
subcommand 
config_gen_xdna::create_validate_subcommand()
{
  std::vector<basic_option> validate_test_desc = {
    {"aie-reconfig-overhead", "Run end-to-end array reconfiguration overhead through shim DMA", "hidden"},
    {"all", "All applicable validate tests will be executed (default)", "common"},
    {"cmd-chain-latency", "Run end-to-end latency test using command chaining", "hidden"},
    {"cmd-chain-throughput", "Run end-to-end throughput test using command chaining", "hidden"},
    {"df-bw", "Run bandwidth test on data fabric", "hidden"},
    {"gemm", "Measure the TOPS value of GEMM INT8operations", "common"},
    {"latency", "Run end-to-end latency test", "common"},
    {"quick", "Run a subset of four tests: \n1. latency \n2. throughput \n3. cmd-chain-latency \n4. cmd-chain-throughput", "hidden"},
    {"tct-all-col", "Measure average TCT processing time for all columns", "hidden"},
    {"tct-one-col", "Measure average TCT processing time for one column", "hidden"},
    {"throughput", "Run end-to-end throughput test", "common"},
    {"temporal-sharing-overhead", "Run end-to-end temporal sharing overhead test", "hidden"},
    {"preemption-overhead", "Measure preemption overhead at noop and memtile levels", "hidden"},
  };

  std::map<std::string, std::shared_ptr<option>> validate_suboptions;
  validate_suboptions.emplace("device", std::make_shared<option>("device", "d", "The Bus:Device.Function (e.g., 0000:d8:00.0) device of interest", "common", "", "string"));
  validate_suboptions.emplace("format", std::make_shared<option>("format", "f", "Report output format. Valid values are:\n"
                                "\tJSON        - Latest JSON schema\n"
                                "\tJSON-2020.2 - JSON 2020.2 schema", "common", "JSON", "string"));
  validate_suboptions.emplace("output", std::make_shared<option>("output", "o", "Direct the output to the given file", "common", "", "string"));
  validate_suboptions.emplace("help", std::make_shared<option>("help", "h", "Help to use this sub-command", "common", "", "none"));
  validate_suboptions.emplace("run", std::make_shared<listable_description_option>("run", "r", "Run a subset of the test suite. Valid options are:\n",
                              "common", "",  "array", validate_test_desc));
  validate_suboptions.emplace("path", std::make_shared<option>("path", "p", "Path to the directory containing validate xclbins", "hidden", "", "string"));
  validate_suboptions.emplace("param", std::make_shared<option>("param", "", "Extended parameter for a given test. Format: <test-name>:<key>:<value>", "param", "", "string"));
  validate_suboptions.emplace("pmode", std::make_shared<option>("pmode", "", "Specify which power mode to run the benchmarks in. Note: Some tests might be unavailable for some modes", "hidden", "", "string")); 
  validate_suboptions.emplace("elf", std::make_shared<option>("elf", "", "Run the test in ELF mode", "hidden", "", "none"));

  return {"validate", "Validates the given device by executing the platform's validate executable", "common", std::move(validate_suboptions)};
}

// Function to create the "examine" subcommand
subcommand 
config_gen_xdna::create_examine_subcommand()
{
  std::vector<basic_option> examine_report_desc = {
    {"aie-partitions", "AIE partition information", "common"},
    {"all", "All known reports are produced", "common"},
    {"host", "Host information", "common"},
    {"platform", "Platforms flashed on the device", "common"},
    {"telemetry", "Telemetry data for the device", "hidden"},
    {"preemption", "Preemption telemetry data for the device", "hidden"},
    {"clocks", "Clock frequency information", "hidden"}
  };

  std::map<std::string, std::shared_ptr<option>> examine_suboptions; 
  examine_suboptions.emplace("device", std::make_shared<option>("device", "d", "The Bus:Device.Function (e.g., 0000:d8:00.0) device of interest", "common", "", "string"));
  examine_suboptions.emplace("format", std::make_shared<option>("format", "f", "Report output format. Valid values are:\n"
                                "\tJSON        - Latest JSON schema\n"
                                "\tJSON-2020.2 - JSON 2020.2 schema", "common", "JSON", "string"));
  examine_suboptions.emplace("output", std::make_shared<option>("output", "o", "Direct the output to the given file", "common", "", "string"));
  examine_suboptions.emplace("help", std::make_shared<option>("help", "h", "Help to use this sub-command", "common", "", "none"));
  examine_suboptions.emplace("report", std::make_shared<listable_description_option>("report", "r", "The type of report to be produced. Reports currently available are:\n", "common", "", "array", examine_report_desc));
  examine_suboptions.emplace("element", std::make_shared<option>("element", "e", "Filters individual elements(s) from the report. Format: '/<key>/<key>/...'", "hidden", "", "array"));

  return {"examine", "This command will 'examine' the state of the system/device and will generate a report of interest in a text or JSON format.", "common", std::move(examine_suboptions)};
}

// Function to create the "configure" subcommand
subcommand 
config_gen_xdna::create_configure_subcommand()
{
  std::map<std::string, std::shared_ptr<option>> configure_suboptions;
  configure_suboptions.emplace("device", std::make_shared<option>("device", "d", "The Bus:Device.Function (e.g., 0000:d8:00.0) device of interest", "common", "", "string"));
  configure_suboptions.emplace("help", std::make_shared<option>("help", "h", "Help to use this sub-command", "common", "", "none"));
  configure_suboptions.emplace("pmode", std::make_shared<option>("pmode", "", "Modes: default, powersaver, balanced, performance, turbo", "common", "", "string", true));
  configure_suboptions.emplace("force-preemption", std::make_shared<option>("force-preemption", "", "Force enable|disable and see status of preemption", "hidden", "", "string", true));

  return {"configure", "Device and host configuration", "common", std::move(configure_suboptions)};
}

void 
populate_smi_instance(xrt_core::smi::smi* smi_instance, const xrt_core::device* device)
{
  smi_hardware_config smi_hrdw;
  const auto pcie_id = xrt_core::device_query<xrt_core::query::pcie_id>(device); 
  auto hardware_type = smi_hrdw.get_hardware_type(pcie_id);

  // Retrieve the appropriate config generator based on hardware type
  std::shared_ptr<config_generator> generator;

  switch (hardware_type) {
  case smi_hardware_config::hardware_type::phx:
  case smi_hardware_config::hardware_type::stxA0:
  case smi_hardware_config::hardware_type::stxB0:
  case smi_hardware_config::hardware_type::stxH:
  case smi_hardware_config::hardware_type::krk1:
  {
    generator = std::make_shared<config_gen_strix>();
    break;
  }
  case smi_hardware_config::hardware_type::npu3_f1:
  case smi_hardware_config::hardware_type::npu3_f2:
  case smi_hardware_config::hardware_type::npu3_f3:
  {
    generator = std::make_shared<config_gen_npu3>();
    break;
  }
  default:
  // Failsafe case for unknown hardware types for now. This should be changed to an error.
    generator = std::make_shared<config_gen_strix>();
    break;
  }

  if (generator) {
    smi_instance->add_subcommand("validate",  generator->create_validate_subcommand());
    smi_instance->add_subcommand("examine",  generator->create_examine_subcommand());
    smi_instance->add_subcommand("configure",  generator->create_configure_subcommand());
  }
}
std::string
get_smi_config(const xrt_core::device* device)
{

  // Get the singleton instance
  auto smi_instance = xrt_core::smi::instance();

  populate_smi_instance(smi_instance, device);

  return smi_instance->build_json();
}

} // namespace shim_xdna::smi

// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2025 Advanced Micro Devices, Inc. All rights reserved.

#include "smi_ve2.h"

namespace shim_telluride::smi {

xrt_core::smi::subcommand
create_validate_subcommand()
{
  std::vector<xrt_core::smi::basic_option> validate_test_desc = {
   {"all", "All applicable validate tests will be executed (default)", "common"},
   {"cmd-chain-latency", "Run end-to-end latency test using command chaining", "hidden"},
   {"cmd-chain-throughput", "Run end-to-end throughput test using command chaining", "hidden"},
   {"latency", "Run end-to-end latency test", "common"},
   {"throughput", "Run end-to-end throughput test", "common"}
  };

  std::map<std::string, std::shared_ptr<xrt_core::smi::option>> validate_suboptions;
  validate_suboptions.emplace("device", std::make_shared<xrt_core::smi::option>("device", "d", "The Bus:Device.Function (e.g., 0000:d8:00.0) device of interest", "common", "", "string"));
  validate_suboptions.emplace("format", std::make_shared<xrt_core::smi::option>("format", "f", "Report output format. Valid values are:\n"
                                "\tJSON        - Latest JSON schema\n"
                                "\tJSON-2020.2 - JSON 2020.2 schema", "common", "JSON", "string"));
  validate_suboptions.emplace("output", std::make_shared<xrt_core::smi::option>("output", "o", "Direct the output to the given file", "common", "", "string"));
  validate_suboptions.emplace("help", std::make_shared<xrt_core::smi::option>("help", "h", "Help to use this sub-command", "common", "", "none"));
  validate_suboptions.emplace("run", std::make_shared<xrt_core::smi::listable_description_option>("run", "r", "Run a subset of the test suite. Valid options are:\n",
                              "common", "",  "array", validate_test_desc));
  validate_suboptions.emplace("path", std::make_shared<xrt_core::smi::option>("path", "p", "Path to the directory containing validate xclbins", "hidden", "", "string"));
  validate_suboptions.emplace("param", std::make_shared<xrt_core::smi::option>("param", "", "Extended parameter for a given test. Format: <test-name>:<key>:<value>", "param", "", "string"));
  validate_suboptions.emplace("elf", std::make_shared<xrt_core::smi::option>("elf", "", "Run the test in ELF mode", "hidden", "", "none"));

  return {"validate", "Validates the given device by executing the platform's validate executable", "common", std::move(validate_suboptions)};
}

xrt_core::smi::subcommand
create_examine_subcommand()
{
    std::vector<xrt_core::smi::basic_option> examine_report_desc = {
      {"all", "All known reports are produced", "common"},
      {"aie", "AIE metadata in xclbin", "common"},
      {"aiemem", "AIE memory tile information", "common"},
      {"aieshim", "AIE shim tile status", "common"},
      {"aie-partitions", "AIE partition information", "common"},
      {"host", "Host information", "common"},
      {"clocks", "Clock frequency information", "hidden"},
      {"platform", "Platforms flashed on the device", "common"}
    };
    
    std::map<std::string, std::shared_ptr<xrt_core::smi::option>> examine_suboptions;
    examine_suboptions.emplace("device", std::make_shared<xrt_core::smi::option>("device", "d", "The Bus:Device.Function (e.g., 0000:d8:00.0) device of interest", "common", "", "string"));
    examine_suboptions.emplace("format", std::make_shared<xrt_core::smi::option>("format", "f", "Report output format. Valid values are:\n"
                                "\tJSON        - Latest JSON schema\n"
                                "\tJSON-2020.2 - JSON 2020.2 schema", "common", "JSON", "string"));
    examine_suboptions.emplace("output", std::make_shared<xrt_core::smi::option>("output", "o", "Direct the output to the given file", "common", "", "string"));
    examine_suboptions.emplace("help", std::make_shared<xrt_core::smi::option>("help", "h", "Help to use this sub-command", "common", "", "none"));
    examine_suboptions.emplace("report", std::make_shared<xrt_core::smi::listable_description_option>("report", "r", "The type of report to be produced. Reports currently available are:\n", "common", "", "array", examine_report_desc));
    examine_suboptions.emplace("element", std::make_shared<xrt_core::smi::option>("element", "e", "Filters individual elements(s) from the report. Format: '/<key>/<key>/...'", "hidden", "", "array"));

  return {"examine", "This command will 'examine' the state of the system/device and will generate a report of interest in a text or JSON format.", "common", std::move(examine_suboptions)};
}
std::string
get_smi_config()
{
  // Get the singleton instance
  auto smi_instance = xrt_core::smi::instance();

  // Add subcommands
  smi_instance->add_subcommand("validate", create_validate_subcommand());
  smi_instance->add_subcommand("examine", create_examine_subcommand());

  return smi_instance->build_json();
}

}

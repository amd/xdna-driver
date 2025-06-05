// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2025 Advanced Micro Devices, Inc. All rights reserved.

#include <string>
#include "core/common/smi.h"
#include "core/common/device.h"

namespace shim_xdna::smi {
// class : config_generator
//
// This class is responsible for generating configuration subcommands for the xrt-smi.
// Any behavior specific to windows platform should be defined here.
class config_gen_xdna : public xrt_core::smi::config_generator {
public:
  xrt_core::smi::subcommand
  create_validate_subcommand() override;

  xrt_core::smi::subcommand
  create_examine_subcommand() override;

  xrt_core::smi::subcommand
  create_configure_subcommand() override;

};

// class : config_gen_strix
// This class is a specific implementation of config_gen_mcdm for Strix hardware.
// Any xrt-smi configuration specific to Strix hardware should be defined here.
class config_gen_strix : public config_gen_xdna {

};

// class : config_gen_npu3
// This class is a specific implementation of config_gen_mcdm for NPU3 hardware.
// Any xrt-smi configuration specific to NPU3 hardware should be defined here.
class config_gen_npu3 : public config_gen_xdna {

};

std::string 
get_smi_config(const xrt_core::device* device);  

} // namespace shim_xdna::smi

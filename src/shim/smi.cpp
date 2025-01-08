// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2025 Advanced Micro Devices, Inc. All rights reserved.
#include "smi.h"

namespace shim_xdna::smi {
std::string 
get_smi_config()
{
  return std::string(xrt_smi_config);
}
} // namespace shim_xdna::smi

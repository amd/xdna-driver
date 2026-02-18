// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2024-2026, Advanced Micro Devices, Inc. All rights reserved.

#ifndef _SHIMTEST_HWCTX_H_
#define _SHIMTEST_HWCTX_H_

#include <iostream>

#include "dev_info.h"

#include "core/common/shim/hwctx_handle.h"
#include "core/common/device.h"

using namespace xrt_core;

class hw_ctx {
public:
  hw_ctx(device* dev, const char *tag = nullptr, const flow_type* flow = nullptr)
  {
    hw_ctx_init(dev, tag, flow);
  }

  hwctx_handle *
  get()
  {
    return m_handle.get();
  }

private:
  std::unique_ptr<hwctx_handle> m_handle;

  void
  hw_ctx_init(device* dev, const char *tag, const flow_type* flow)
  {
    xrt::xclbin xclbin;
    xrt::elf elf;
    auto resolved_flow = get_flow_type(dev, tag, flow);
    auto is_full_elf = (resolved_flow == PREEMPT_FULL_ELF || resolved_flow == FULL_ELF);
    auto path = get_binary_path(dev, tag, flow);

    try {
      if (is_full_elf)
        elf = xrt::elf(path);
      else
        xclbin = xrt::xclbin(path);
    } catch (...) {
      throw std::runtime_error(
        path + " not found?\n"
        "specify xclbin path or run \"build.sh -xclbin_only\" to download them");
    }

    xrt::hw_context::qos_type qos{ {"gops", 100}, {"priority", 0x180} };
    xrt::hw_context::access_mode mode = xrt::hw_context::access_mode::shared;
    if (is_full_elf) {
      m_handle = dev->create_hw_context(elf.get_partition_size(), qos, mode);
    } else {
      dev->record_xclbin(xclbin);
      auto xclbin_uuid = xclbin.get_uuid();
      m_handle = dev->create_hw_context(xclbin_uuid, qos, mode);
    }

    std::cout << "loaded " << path << std::endl;
  }
};

#endif // _SHIMTEST_HWCTX_H_

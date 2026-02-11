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
  hw_ctx(device* dev, const char *xclbin_name=nullptr)
  {
    hw_ctx_init(dev, xclbin_name);
  }

  hwctx_handle *
  get()
  {
    return m_handle.get();
  }

private:
  std::unique_ptr<hwctx_handle> m_handle;

  void
  hw_ctx_init(device* dev, const char *xclbin_name)
  {
    xrt::xclbin xclbin;
    xrt::elf elf;
    auto kernel_type = get_kernel_type(dev, xclbin_name);
    auto is_full_elf = (kernel_type == KERNEL_TYPE_TXN_FULL_ELF_PREEMPT ||
		        kernel_type == KERNEL_TYPE_TXN_FULL_ELF);
    auto path = get_xclbin_path(dev, xclbin_name);

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

// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2024, Advanced Micro Devices, Inc. All rights reserved.

#ifndef _SHIMTEST_HWCTX_H_
#define _SHIMTEST_HWCTX_H_

#include "dev_info.h"

#include "core/common/shim/hwctx_handle.h"
#include "core/common/device.h"

using namespace xrt_core;

class hw_ctx {
public:
  hw_ctx(device* dev, const char *xclbin_name=nullptr)
  {
    auto path = get_xclbin_path(dev, xclbin_name);
    hw_ctx_init(dev, path);
  }

  hwctx_handle *
  get()
  {
    return m_handle.get();
  }

private:
  std::unique_ptr<hwctx_handle> m_handle;

  void
  hw_ctx_init(device* dev, const std::string& xclbin_path)
  {
    xrt::xclbin xclbin;

    try {
      xclbin = xrt::xclbin(xclbin_path);
    } catch (...) {
      throw std::runtime_error(
        xclbin_path + " not found?\n"
        "specify xclbin path or run \"build.sh -xclbin_only\" to download them");
    }
    dev->record_xclbin(xclbin);
    auto xclbin_uuid = xclbin.get_uuid();
    xrt::hw_context::qos_type qos{ {"gops", 100}, {"priority", 0x180} };
    xrt::hw_context::access_mode mode = xrt::hw_context::access_mode::shared;

    m_handle = dev->create_hw_context(xclbin_uuid, qos, mode);
    std::cout << "loaded " << xclbin_path << std::endl;
  }
};

#endif // _SHIMTEST_HWCTX_H_

// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026, Advanced Micro Devices, Inc. All rights reserved.

#ifndef _SHIMTEST_PM_H_
#define _SHIMTEST_PM_H_

#include "speed.h"

#include "core/common/device.h"
#include "core/common/query_requests.h"

#include <chrono>
#include <fstream>
#include <stdexcept>
#include <string>
#include <thread>

/*
 * Wait out the auto-suspend and fail unless the device actually got there.
 * Every suspend/restore test needs the device genuinely suspended, otherwise it
 * would pass without exercising anything.
 */
static inline void
require_runtime_suspend(xrt_core::device* dev)
{
  using namespace xrt_core;

  query::sub_device_path::args query_arg = {std::string(""), 0};
  const std::string sysfs = device_query<query::sub_device_path>(dev, query_arg);
  const auto deadline = clk::now() + std::chrono::seconds(30);
  std::string status;

  for (;;) {
    std::ifstream ifs(sysfs + "/power/runtime_status");
    std::getline(ifs, status);
    if (status == "suspended" || status.empty() || clk::now() >= deadline)
      break;
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
  }

  if (status.empty())
    throw std::runtime_error("runtime PM status unavailable, cannot exercise the restore path");
  if (status != "suspended")
    throw std::runtime_error("device did not auto-suspend, runtime_status=\"" + status + "\"");
}

#endif // _SHIMTEST_PM_H_

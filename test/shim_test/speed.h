// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2024, Advanced Micro Devices, Inc. All rights reserved.

#ifndef _SHIMTEST_SPEED_H_
#define _SHIMTEST_SPEED_H_

#include <chrono>

using clk = std::chrono::high_resolution_clock;
using ms_t = std::chrono::milliseconds;
using us_t = std::chrono::microseconds;
using ns_t = std::chrono::nanoseconds;

static inline int
get_speed_and_print(std::string prefix, size_t size, clk::time_point &start, clk::time_point &end)
{
  std::ios_base::fmtflags f(std::cout.flags());

  auto dur = std::chrono::duration_cast<ns_t>(end - start).count();
  int speed = (size * 1000000000.0) / dur / 1024 / 1024.0;
  auto prec = std::cout.precision();

  std::cout << "\t" + prefix + " 0x" << std::hex << size << std::dec << " bytes in "
            << dur << " ns, " << std::setprecision(0) << std::fixed
            << "speed " << speed << " MB/sec"
            << std::setprecision(prec) << std::endl;

  std::cout.flags(f);
  return speed;
}

#endif // _SHIMTEST_SPEED_H_

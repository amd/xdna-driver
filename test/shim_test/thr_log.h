// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026, Advanced Micro Devices, Inc. All rights reserved.

#ifndef _SHIMTEST_THR_LOG_H_
#define _SHIMTEST_THR_LOG_H_

#include <iostream>
#include <mutex>
#include <string>

/*
 * Print "  [<thr>] <msg>" as one line. Safe to call from several threads of a
 * test at once: lines from different threads never interleave.
 */
inline void
thr_log(const char *thr, const std::string& msg)
{
  static std::mutex lock;
  std::lock_guard<std::mutex> lg(lock);
  std::cout << "  [" << thr << "] " << msg << std::endl;
}

#endif

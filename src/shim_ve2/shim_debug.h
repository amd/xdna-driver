// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2025, Advanced Micro Devices, Inc. All rights reserved.
//
#ifndef SHIM_DEBUG_H__
#define SHIM_DEBUG_H__

#include <cstdio>
#include <memory>

#include "core/common/debug.h"
#include "core/common/error.h"
#include "core/common/ishim.h"

#ifndef __counted_by
#define __counted_by(m)
#endif

namespace {

template <typename ...Args>
[[ noreturn ]] void
shim_err(int err, const char* fmt, Args&&... args)
{
  std::string format = std::string(fmt);
  format += " (err=%d)";
  int sz = std::snprintf(nullptr, 0, format.c_str(), args ..., err) + 1;
  if(sz <= 0)
    throw xrt_core::system_error(sz, "could not format error string");

  auto size = static_cast<size_t>(sz);
  std::unique_ptr<char[]> buf(new char[size]);
  std::snprintf(buf.get(), size, format.c_str(), args ..., err);
  throw xrt_core::system_error(err, std::string(buf.get()));
}

[[ noreturn ]] inline void
shim_not_supported_err(const char* msg)
{
  shim_err(ENOTSUP, msg);
}

template <typename ...Args>
void
shim_debug(const char* fmt, Args&&... args)
{
#ifdef AIE_SHIM_DEBUG
  std::string format = std::string(fmt);
  format += "\n";
  XRT_PRINTF(format.c_str(), std::forward<Args>(args)...);
#endif
}

}

#endif // SHIM_DEBUG_H

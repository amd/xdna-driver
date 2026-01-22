// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2025, Advanced Micro Devices, Inc. All rights reserved.
//
#ifndef SHIM_DEBUG_H__
#define SHIM_DEBUG_H__

#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <memory>

#include "core/common/config_reader.h"
#include "core/common/debug.h"
#include "core/common/error.h"
#include "core/common/ishim.h"

#ifndef __counted_by
#define __counted_by(m)
#endif

namespace {

/**
 * is_shim_debug_enabled - Check if shim debug logging is enabled
 *
 * Runtime control for shim debug logging. Can be enabled via:
 *   1. xrt.ini file: [Debug] shim_debug = true
 *   2. Environment variable: XRT_SHIM_DEBUG=1
 *   3. Compile-time: -DAIE_SHIM_DEBUG (always enabled, no runtime check)
 *
 * Returns true if shim debug is enabled, false otherwise.
 */
inline bool
is_shim_debug_enabled()
{
#ifdef AIE_SHIM_DEBUG
  // Compile-time enabled - always return true for zero-overhead when disabled
  return true;
#else
  // Runtime check - cached on first call for performance
  static bool enabled = xrt_core::config::detail::get_bool_value("Debug.shim_debug", false)
                        || (std::getenv("XRT_SHIM_DEBUG") != nullptr);
  return enabled;
#endif
}

/**
 * errno_to_str - Convert errno value to human-readable string
 * @err: errno value to convert
 *
 * Returns a human-readable description of the errno value.
 * This is useful for debug/error logging.
 */
inline const char*
errno_to_str(int err)
{
  switch (err) {
  case EINVAL:     return "Invalid argument";
  case ENOENT:     return "No such file or directory";
  case ENOMEM:     return "Out of memory";
  case EBUSY:      return "Device or resource busy";
  case EAGAIN:     return "Resource temporarily unavailable";
  case ETIMEDOUT:  return "Connection timed out";
  case ETIME:      return "Timer expired";
  case EPERM:      return "Operation not permitted";
  case EACCES:     return "Permission denied";
  case ENODEV:     return "No such device";
  case EFAULT:     return "Bad address";
  case ENOSPC:     return "No space left on device";
  case EOPNOTSUPP: return "Operation not supported";  // Same as ENOTSUP on Linux
  case ERANGE:     return "Result too large";
  case EEXIST:     return "File exists";
  case ENOBUFS:    return "No buffer space available";
  case E2BIG:      return "Argument list too long";
  case EBADF:      return "Bad file descriptor";
  case EIO:        return "Input/output error";
  case ENXIO:      return "No such device or address";
  case ENOTTY:     return "Inappropriate ioctl for device";
  case ENOSYS:     return "Function not implemented";
  default:         return "Unknown error";
  }
}

/**
 * shim_err - Throw system error with formatted message
 * @err: errno value
 * @fmt: printf-style format string
 * @args: format arguments
 *
 * Note: xrt_core::system_error::what() automatically appends the system
 * error string (e.g., ": Invalid argument"), so we only include the
 * error code number in our message to avoid duplication.
 */
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

/**
 * shim_debug - Print debug message if shim debug is enabled
 * @fmt: printf-style format string
 * @args: format arguments
 *
 * Debug logging for shim layer. Messages are only printed when
 * shim debug is enabled via runtime configuration or compile-time.
 *
 * Enable via:
 *   - xrt.ini: [Debug] shim_debug = true
 *   - Environment: export XRT_SHIM_DEBUG=1
 *   - Compile-time: -DAIE_SHIM_DEBUG
 */
template <typename ...Args>
void
shim_debug(const char* fmt, Args&&... args)
{
  if (!is_shim_debug_enabled())
    return;

  std::string format = std::string("[SHIM_DEBUG] ");
  format += fmt;
  format += "\n";
  XRT_PRINTF(format.c_str(), std::forward<Args>(args)...);
}

}

#endif // SHIM_DEBUG_H

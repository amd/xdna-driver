// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026, Advanced Micro Devices, Inc. All rights reserved.

#ifndef _SHIMTEST_FW_TRACE_H_
#define _SHIMTEST_FW_TRACE_H_

#include "core/common/device.h"

#include <cerrno>
#include <csignal>
#include <cstdint>
#include <cstring>
#include <functional>
#include <stdexcept>
#include <string>
#include <vector>
#include <sys/ioctl.h>
#include <unistd.h>

// FIXME
#include "../../src/include/uapi/drm_local/amdxdna_accel.h"
// end of FIXME

// Defined in shim_test.cpp.
template <typename T>
T
fork_query(xrt_core::device* dev, const std::function<T(int fd)>& op);

// Firmware trace categories. GPU_VIEW is the only one an SR-IOV VF may enable.
constexpr uint32_t FW_TRACE_CAT_GPU_VIEW = 0x800;
constexpr uint32_t FW_TRACE_CAT_ALL = 0xffffffff;

// Large enough for the whole 4 MiB trace ring.
constexpr uint32_t FW_TRACE_READ_SIZE = 4 * 1024 * 1024 + sizeof(amdxdna_dpt_metadata);

struct fw_trace_read_result {
  int err;
  uint32_t size;
  uint64_t offset;
};

// Start (categories != 0) or stop firmware tracing. Returns 0 or errno.
inline int
fw_trace_set(int fd, uint32_t categories)
{
  amdxdna_drm_set_dpt_state state = {
    .action = categories ? 1U : 0U,
    .config = categories,
  };
  amdxdna_drm_set_state arg = {
    .param = DRM_AMDXDNA_SET_FW_TRACE_STATE,
    .buffer_size = sizeof(state),
    .buffer = reinterpret_cast<uintptr_t>(&state),
  };

  return ::ioctl(fd, DRM_IOCTL_AMDXDNA_SET_STATE, &arg) ? errno : 0;
}

// Starts firmware tracing and stops it when the test leaves, pass or fail.
struct fw_trace_session {
  xrt_core::device* dev;

  fw_trace_session(xrt_core::device* d, uint32_t categories) : dev(d)
  {
    int err = fork_query<int>(dev, [categories](int fd) {
      return fw_trace_set(fd, categories);
    });
    if (err)
      throw std::runtime_error("failed to start fw trace: " + std::string(std::strerror(err)));
  }

  ~fw_trace_session()
  {
    try {
      fork_query<int>(dev, [](int fd) { return fw_trace_set(fd, 0); });
    } catch (...) {
    }
  }

  fw_trace_session(const fw_trace_session&) = delete;
  fw_trace_session& operator=(const fw_trace_session&) = delete;
};

inline void
fw_trace_alarm(int)
{
}

// Read the trace ring from offset once. With watch_secs > 0 the kernel waits
// for new data, up to watch_secs, and an expired wait reports EINTR.
inline fw_trace_read_result
fw_trace_read(int fd, uint64_t offset, unsigned int watch_secs = 0)
{
  std::vector<uint8_t> buf(FW_TRACE_READ_SIZE);
  auto md = reinterpret_cast<amdxdna_dpt_metadata *>(buf.data() + buf.size() -
                                                 sizeof(amdxdna_dpt_metadata));
  md->offset = offset;
  md->watch = watch_secs ? 1 : 0;

  amdxdna_drm_get_array arg = {
    .param = DRM_AMDXDNA_FW_TRACE,
    .element_size = static_cast<uint32_t>(buf.size()),
    .num_element = 1,
    .buffer = reinterpret_cast<uintptr_t>(buf.data()),
  };

  // No SA_RESTART, so the alarm interrupts the waiting ioctl.
  struct sigaction sa = {};
  sa.sa_handler = fw_trace_alarm;
  sigaction(SIGALRM, &sa, nullptr);
  alarm(watch_secs);

  fw_trace_read_result r{};
  r.err = ::ioctl(fd, DRM_IOCTL_AMDXDNA_GET_ARRAY, &arg) ? errno : 0;
  alarm(0);
  r.size = md->size;
  r.offset = md->offset;
  return r;
}

#endif // _SHIMTEST_FW_TRACE_H_

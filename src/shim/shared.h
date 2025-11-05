// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2023-2025, Advanced Micro Devices, Inc. All rights reserved.

#ifndef SHARED_XDNA_H
#define SHARED_XDNA_H

#include "core/common/shim/shared_handle.h"
#include "shim_debug.h"

namespace shim_xdna {

class shared : public xrt_core::shared_handle
{
public:
  shared(int fd) : m_fd(fd)
  {}

  ~shared() override
  {
    if (m_fd != -1) {
      shim_debug("Closing exported fd %d", m_fd);
      close(m_fd);
    }
  }

  export_handle
  get_export_handle() const override
  { return m_fd; }

private:
  const int m_fd;
};

}

#endif

// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2023-2024, Advanced Micro Devices, Inc. All rights reserved.

#ifndef _SHARED_XDNA_H_
#define _SHARED_XDNA_H_

#include "shim_debug.h"
#include "core/common/shim/shared_handle.h"
#include <unistd.h>

namespace shim_xdna {

class shared : public xrt_core::shared_handle
{
public:
  shared(int fd) : m_fd(fd)
  {}

  ~shared() override
  { close(m_fd); }

  export_handle
  get_export_handle() const override
  { return m_fd; }

private:
  const int m_fd;
};

} // shim_xdna

#endif // _SHARED_XDNA_H_

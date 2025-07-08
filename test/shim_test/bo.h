// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2024, Advanced Micro Devices, Inc. All rights reserved.

#ifndef _SHIMTEST_BO_H_
#define _SHIMTEST_BO_H_

#include "core/common/shim/buffer_handle.h"
#include "core/common/device.h"

namespace {

using namespace xrt_core;

uint64_t
get_bo_flags(uint32_t flags, uint32_t ext_flags)
{
  xcl_bo_flags f = {};

  f.flags = flags;
  f.extension = ext_flags;
  return f.all;
}

}

class bo {
public:
  bo(device* dev, size_t size, uint32_t boflags, uint32_t ext_boflags)
    : bo(dev, nullptr, size, boflags, ext_boflags)
  {
  }

  bo(device* dev, void *uptr, size_t size, uint32_t boflags, uint32_t ext_boflags)
    : m_dev(dev)
  {
    m_handle = m_dev->alloc_bo(uptr, size, get_bo_flags(boflags, ext_boflags));
    map_and_chk();
  }

  bo(device* dev, size_t size, uint32_t xcl_boflags)
    : bo(dev, size, xcl_boflags, 0)
  {
  }

  bo(device* dev, size_t size)
    : bo(dev, size, XCL_BO_FLAGS_HOST_ONLY, 0)
  {
  }

  bo(device* dev, void *ubuf, size_t size)
    : bo(dev, ubuf, size, XCL_BO_FLAGS_HOST_ONLY, 0)
  {
  }

  bo(device* dev, pid_t pid, shared_handle::export_handle ehdl)
    : m_dev(dev)
  {
    m_handle = m_dev->import_bo(pid, ehdl);
    map_and_chk();
  }

  bo(bo&& rbo)
    : m_dev(rbo.m_dev)
    , m_handle(rbo.m_handle.release())
    , m_bop(rbo.m_bop)
    , m_no_unmap(rbo.m_no_unmap)
  {
  }

  ~bo()
  {
    if (!m_no_unmap)
      m_handle->unmap(m_bop);
  }

  buffer_handle *
  get()
  { return m_handle.get(); }

  int *
  map()
  { return m_bop; }

  void
  set_no_unmap()
  { m_no_unmap = true; }

  size_t
  size()
  { return m_handle->get_properties().size; }

  uint64_t
  paddr()
  { return m_handle->get_properties().paddr; }

private:
  device* m_dev;
  std::unique_ptr<buffer_handle> m_handle;
  int *m_bop = nullptr;
  bool m_no_unmap = false;

  int *
  map_and_chk()
  {
    m_bop = reinterpret_cast<int *>(m_handle->map(buffer_handle::map_type::write));
    if (!m_bop)
      throw std::runtime_error("map bo of " + std::to_string(size()) + "bytes failed");
    return m_bop;
  }
};

#endif // _SHIMTEST_BO_H_

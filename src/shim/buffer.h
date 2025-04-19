// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2025, Advanced Micro Devices, Inc. All rights reserved.

#ifndef BUFFER_XDNA_H_
#define BUFFER_XDNA_H_

#include "pcidev.h"
#include "shared.h"
#include "core/common/shim/hwctx_handle.h"
#include "core/common/shim/buffer_handle.h"
#include <set>

namespace shim_xdna {

class mmap_ptr {
public:
  mmap_ptr(size_t size);
  mmap_ptr(const pdev *dev, void *addr, uint64_t offset, size_t size);
  ~mmap_ptr();

  void *
  get() const;

private:
  const pdev* m_dev = nullptr;
  void *m_ptr = nullptr;
  size_t m_size = 0;
};

class drm_bo {
public:
  drm_bo(const pdev& pdev, size_t size, int type);
  drm_bo(const pdev& pdev, xrt_core::shared_handle::export_handle ehdl);
  ~drm_bo();

  int m_type = AMDXDNA_BO_INVALID;
  size_t m_size = 0;
  bo_id m_id = { AMDXDNA_INVALID_BO_HANDLE, AMDXDNA_INVALID_BO_HANDLE };
  uint64_t m_paddr = AMDXDNA_INVALID_ADDR;
  void *m_vaddr = nullptr;
  uint64_t m_map_offset = 0;

private:
  const pdev& m_pdev;
};

class buffer : public xrt_core::buffer_handle
{
public:
  buffer(const pdev& pdev, size_t size, int type);
  buffer(const pdev& pdev, xrt_core::shared_handle::export_handle ehdl);
  virtual ~buffer();

  void*
  map(map_type) override;

  void
  unmap(void* addr) override;

  properties
  get_properties() const override;

  std::unique_ptr<xrt_core::shared_handle>
  share() const override;

  void
  sync(direction, size_t size, size_t offset) override;

  void
  bind_at(size_t pos, const buffer_handle* bh, size_t offset, size_t size) override;

public:
  void*
  map() const;

  uint32_t
  handle() const;

  uint64_t
  paddr() const;

  virtual void
  attach_to_ctx(const xrt_core::hwctx_handle& hwctx);

  // Save flags in buffer which later returns via get_properties()
  void
  set_flags(uint64_t flags);

  virtual std::set<uint32_t>
  get_arg_bo_handles() const;

protected:
  std::string
  describe() const;

  const pdev& m_pdev;

private:
  void
  mmap_drm_bo(); // Obtain void* through mmap()

  uint64_t m_flags = 0;
  std::unique_ptr<mmap_ptr> m_range_addr = nullptr;
  std::unique_ptr<mmap_ptr> m_addr = nullptr;
  std::unique_ptr<drm_bo> m_bo = nullptr;
};

class cmd_buffer : public buffer
{
public:
  using buffer::buffer;

  void
  bind_at(size_t pos, const buffer_handle* bh, size_t offset, size_t size) override;

public:
  void
  set_cmd_id(uint64_t id);

  uint64_t
  get_cmd_id() const;

  std::set<uint32_t>
  get_arg_bo_handles() const override;

private:
  uint64_t m_cmd_id = 0;
  std::map< size_t, std::set<uint32_t> > m_args_map;
  mutable std::mutex m_args_map_lock;
};

class dbg_buffer : public buffer
{
public:
  using buffer::buffer;
  ~dbg_buffer();

  virtual void
  attach_to_ctx(const xrt_core::hwctx_handle& hwctx);

private:
  void
  config_debug_bo(bool is_attach);

  xrt_core::hwctx_handle::slot_id m_ctx_id = AMDXDNA_INVALID_CTX_HANDLE;
};

}

#endif

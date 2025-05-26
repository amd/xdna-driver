// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2025, Advanced Micro Devices, Inc. All rights reserved.

#ifndef BUFFER_XDNA_H
#define BUFFER_XDNA_H

#include "pcidev.h"
#include "shared.h"
#include "hwctx.h"
#include "shim_debug.h"
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
  bo_id m_id;
  uint64_t m_xdna_addr = AMDXDNA_INVALID_ADDR;
  uint64_t m_map_offset = AMDXDNA_INVALID_ADDR;

private:
  const pdev& m_pdev;
};

class buffer : public xrt_core::buffer_handle
{
public:
  buffer(const pdev& dev, size_t size, int type);
  buffer(const pdev& dev, xrt_core::shared_handle::export_handle ehdl);
  virtual ~buffer();

  void
  copy(const xrt_core::buffer_handle* src, size_t size, size_t dst_offset, size_t src_offset) override
  { shim_not_supported_err(__func__); }

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
  vaddr() const;

  bo_id
  id() const;

  uint64_t
  paddr() const;

  size_t
  size() const;

  virtual void
  bind_hwctx(const hwctx& hwctx);

  // Save flags in buffer which later returns via get_properties()
  void
  set_flags(uint64_t flags);

  virtual std::set<bo_id>
  get_arg_bo_ids() const;

protected:
  const pdev& m_pdev;

private:
  std::string
  describe() const;

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
  // Today, sequence order is decided once enqueued.
  void
  enqueued(uint64_t seq);

  // Passing in sequence number in HW queue.
  // Should be the same as seq when enqueued.
  void
  submitted(uint64_t seq) const;

  // Returning final sequence number in HW queue, which can be waited on.
  uint64_t
  wait_for_submitted() const;

  std::set<bo_id>
  get_arg_bo_ids() const override;

private:
  uint64_t m_cmd_seq = 0;
  std::map< size_t, std::set<bo_id> > m_args_map;
  mutable std::mutex m_args_map_lock;

  mutable std::mutex m_submission_lock;
  // Changed only once in the life time of cmd BO.
  mutable bool m_submitted = false;
  // Changed only once in the life time of cmd BO.
  mutable std::condition_variable m_submission_cv;
};

class dbg_buffer : public buffer
{
public:
  using buffer::buffer;
  ~dbg_buffer();

  void
  bind_hwctx(const hwctx& hwctx) override;

private:
  void
  config_debug_bo(bool is_detach);

  xrt_core::hwctx_handle::slot_id m_ctx_id = AMDXDNA_INVALID_CTX_HANDLE;
};

}

#endif

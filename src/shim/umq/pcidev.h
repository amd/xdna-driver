// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2022-2025, Advanced Micro Devices, Inc. All rights reserved.

#ifndef PCIDEV_UMQ_H
#define PCIDEV_UMQ_H

#include "../pcidev.h"

// DMA cache-coherency policy for UMQ devices, resolved at build time.
//
// UMQ parts are cache-coherent by default.  Define XDNA_UMQ_CACHE_NONCOHERENT
// (e.g. for the aie2ps platform npu12, a non-coherent aarch64 DMA master) so
// is_cache_coherent() reports false and buffer::sync() does real cache
// maintenance instead of skipping it.

namespace shim_xdna {

class pdev_umq : public pdev
{
public:
  using pdev::pdev;

public:
  bool
  is_cache_coherent() const override;

  uint64_t
  get_heap_paddr() const override;

  void *
  get_heap_vaddr() const override;

  bool
  is_umq() const override;

  void
  create_drm_bo(bo_info *arg) const override;

private:
  virtual void
  on_first_open() const override;

  virtual void
  on_last_close() const override;
};

class pdev_pf : public pdev_umq
{
public:
  pdev_pf(std::shared_ptr<const platform_drv>& driver,
          const std::string& sysfs_name);

  bool
  is_umq() const override;

  void
  create_drm_bo(bo_info *arg) const override;
};

}

#endif

// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2022-2025, Advanced Micro Devices, Inc. All rights reserved.

#ifndef PCIDEV_UMQ_H
#define PCIDEV_UMQ_H

#include "../pcidev.h"

// DMA cache-coherency behavior for UMQ devices is fixed by the device class,
// selected from the kernel driver's device_type sysfs at device creation.
// AMDXDNA_DEV_TYPE_UMQ maps to the coherent pdev_umq (sync_bo no-ops);
// AMDXDNA_DEV_TYPE_UMQ_NONCOHERENT maps to pdev_umq_nc (sync_bo via driver).

namespace shim_xdna {

class pdev_umq : public pdev
{
public:
  using pdev::pdev;

public:
  // Coherent: hardware keeps caches in sync, nothing to do.
  void
  sync_bo(buffer& bo, xrt_core::buffer_handle::direction dir,
          size_t size, size_t offset) const override
  {}

  uint64_t
  get_heap_paddr() const override;

  void *
  get_heap_vaddr() const override;

  bool
  is_umq() const override;

  void
  create_drm_bo(bo_info *arg) const override;

private:
  void
  on_first_open() const override
  {}

  void
  on_last_close() const override
  {}
};

// Non-coherent UMQ part (the aarch64 platform): the CPU and device caches are
// not kept in sync by hardware. Driver-allocated BOs are backed by coherent
// (non-cacheable) DMA memory, so xrt::bo::sync() is a no-op (inherited from
// pdev_umq). An imported cacheable dmabuf cannot be cache-maintained by the
// kernel either, so importing one is warned about rather than synced.
class pdev_umq_nc : public pdev_umq
{
public:
  using pdev_umq::pdev_umq;

  // Non-coherent: the kernel cannot maintain caches for an imported cacheable
  // dmabuf, so xrt::bo::sync() on an imported BO is a no-op. Warn once per
  // imported BO unless XRT_NO_WARN_IMPORT_BO_CREATION is set.
  void
  warn_imported_bo() const override;
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

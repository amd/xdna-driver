// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2022-2025, Advanced Micro Devices, Inc. All rights reserved.

#include "pcidev.h"

namespace shim_xdna {

void
pdev_umq::
on_first_open() const
{
  // do nothing
}

void
pdev_umq::
on_last_close() const
{
  // do nothing
}

bool
pdev_umq::
is_cache_coherent() const
{
  // The UMQ shim subclass binds to several silicon variants: NPU3 PCIe
  // (Strix), NPU7/8/9/10 PCIe (AIE4 Medusa & friends) - all
  // cache-coherent - and npu3_aie2ps on the embedded VEK385 / T20-class
  // SoC, which is NOT coherent because there is no PCIe / IOMMU
  // upstream and the AIE engine talks to DDR via a separate fabric.
  //
  // Treat aie2ps as the single non-coherent case; everything else
  // skips the SYNC_BO ioctl path.  Detection is by sysfs prefix in
  // pdev::is_npu3_aie2ps() and assumes the historical 1:1 mapping
  // (only aie2ps is platform-attached).  Note that the kernel side
  // amdxdna_gem_sync_range() additionally re-checks via the DMA API,
  // so a stricter / different runtime answer in the kernel cannot
  // produce a stale-cache bug here, only at worst a redundant ioctl.
  return !is_npu3_aie2ps();
}

void *
pdev_umq::
get_heap_vaddr() const
{
  return nullptr;
}

uint64_t
pdev_umq::
get_heap_paddr() const
{
  return AMDXDNA_INVALID_ADDR;
}

bool
pdev_umq::
is_umq() const
{
  return true;
}

void
pdev_umq::
create_drm_bo(bo_info *arg) const
{
  drv_ioctl(drv_ioctl_cmd::create_bo, arg);
}

}


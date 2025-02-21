// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2025, Advanced Micro Devices, Inc. All rights reserved.

#ifndef _PCIDRV_VIRTIO_XDNA_H_
#define _PCIDRV_VIRTIO_XDNA_H_

#include "pcidev.h"

#include "core/pcie/linux/pcidrv.h"

#include <string>

namespace shim_xdna {

class drv_virtio : public xrt_core::pci::drv
{
public:
  std::string
  name() const override;

  bool
  is_user() const override;

  std::string
  dev_node_prefix() const override;

  std::string
  dev_node_dir() const override;

  std::string
  sysfs_dev_node_dir() const override;

private:
  std::shared_ptr<xrt_core::pci::dev>
  create_pcidev(const std::string& sysfs) const override;
};

} // namespace shim_xdna

#endif

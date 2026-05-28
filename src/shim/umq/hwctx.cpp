// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2023-2026, Advanced Micro Devices, Inc. All rights reserved.

#include "hwctx.h"
#include "hwq.h"
#include "core/common/config_reader.h"
#include <filesystem>

namespace shim_xdna {

// Allow at least one runlist (24 sub-cms) plus a few single cmds.
const size_t total_queue_slots = 32;

hwctx_umq::
hwctx_umq(const device& device, const xrt::xclbin& xclbin, const qos_type& qos)
  : hwctx(device, qos, xclbin, std::make_unique<hwq_umq>(device, total_queue_slots))
  , m_pdev(device.get_pdev())
{
  shim_debug("Created UMQ HW context (%d)", get_slotidx());
  xclbin_parser xp(xclbin);
  m_col_cnt = xp.get_column_cnt();
}

hwctx_umq::
hwctx_umq(const device& device, uint32_t partition_size)
  : hwctx(device, partition_size, std::make_unique<hwq_umq>(device, total_queue_slots))
  , m_pdev(device.get_pdev())
{
  m_col_cnt = partition_size;

  shim_debug("Created UMQ HW context (%d)", get_slotidx());
}

hwctx_umq::
~hwctx_umq()
{
  shim_debug("Destroying UMQ HW context (%d)...", get_slotidx());
}

} // shim_xdna

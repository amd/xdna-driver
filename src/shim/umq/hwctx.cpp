// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2023-2025, Advanced Micro Devices, Inc. All rights reserved.

#include "hwctx.h"
#include "hwq.h"

namespace shim_xdna {

hwctx_umq::
hwctx_umq(const device& device, const xrt::xclbin& xclbin, const qos_type& qos)
  : hwctx(device, qos, xclbin, std::make_unique<hwq_umq>(device, 8))
  , m_metadata()
{
  xclbin_parser xp(xclbin);
  m_col_cnt = xp.get_column_cnt();

  init_log_buf();
  // TODO: configure log BO on the hwctx
  shim_debug("Created UMQ HW context (%d)", get_slotidx());
}

hwctx_umq::
hwctx_umq(const device& device, uint32_t partition_size)
  : hwctx(device, partition_size, std::make_unique<hwq_umq>(device, 8))
  , m_metadata()
{
  m_col_cnt = partition_size;

  init_log_buf();
  // TODO: configure log BO on the hwctx
  shim_debug("Created UMQ HW context (%d)", get_slotidx());
}

hwctx_umq::
~hwctx_umq()
{
  shim_debug("Destroying UMQ HW context (%d)...", get_slotidx());
  // TODO: unconfigure log BO on the hwctx
  fini_log_buf();
}

void
hwctx_umq::
init_log_buf()
{
  size_t column_size = 1024;
  auto log_buf_size = m_col_cnt * column_size + sizeof(m_metadata);
  auto log_bo = alloc_bo(log_buf_size, XCL_BO_FLAGS_EXECBUF);
  m_log_bo = std::unique_ptr<buffer>(static_cast<buffer*>(log_bo.release()));
  m_log_buf = m_log_bo->vaddr();
  uint64_t bo_paddr = m_log_bo->paddr();
  set_metadata(m_col_cnt, column_size, bo_paddr, UMQ_LOG_BUFFER);
  std::memset(m_log_buf, 0, log_buf_size);
  std::memcpy(m_log_buf, &m_metadata, sizeof(m_metadata));
}

void
hwctx_umq::
fini_log_buf(void)
{
  // Nothing to do.
}

void
hwctx_umq::
set_metadata(int num_ucs, size_t size, uint64_t bo_paddr, enum umq_log_flag flag)
{
  const uint32_t LOG_MAGIC_NO = 0x43455254;
  m_metadata.magic_no = LOG_MAGIC_NO;
  m_metadata.major = 0;
  m_metadata.minor = 1;
  m_metadata.umq_log_flag = flag;
  m_metadata.num_ucs = num_ucs;
  for (int i = 0; i < num_ucs; i++) {
    m_metadata.uc_paddr[i] = bo_paddr + size * i + sizeof(m_metadata);
    m_metadata.uc_size[i] = size;
  }
}

} // shim_xdna

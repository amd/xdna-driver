// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2025, Advanced Micro Devices, Inc. All rights reserved.

#include "dbg_hwq.h"

namespace shim_xdna {

dbg_hwq_umq::
dbg_hwq_umq(const device& dev)
  : m_pdev(dev.get_pdev())
{
  const size_t header_sz = sizeof(struct host_queue_header);
  const size_t queue_sz = sizeof(struct host_queue_packet);
  const size_t comp_sz = sizeof(uint32_t);

  const size_t umq_sz = header_sz + queue_sz + comp_sz;

  shim_debug("dbg umq sz %ld", umq_sz);

  m_dbg_umq_bo = std::make_unique<uc_dbg_buffer>(m_pdev, umq_sz, AMDXDNA_BO_CMD);
  m_dbg_umq_bo_buf = m_dbg_umq_bo->vaddr();
  m_dbg_umq_hdr =
    reinterpret_cast<volatile struct host_queue_header *>(m_dbg_umq_bo_buf);
  m_dbg_umq_pkt = reinterpret_cast<volatile struct host_queue_packet *>
    ((char *)m_dbg_umq_bo_buf + header_sz);
  m_dbg_umq_comp = m_dbg_umq_bo->paddr() + header_sz + queue_sz;
  m_dbg_umq_comp_ptr = reinterpret_cast<volatile uint32_t *>
    ((char *)m_dbg_umq_bo_buf + header_sz + queue_sz);

  // set all mapped memory to 0 
  std::memset(m_dbg_umq_bo_buf, 0, umq_sz);
  m_dbg_umq_pkt->xrt_header.completion_signal = m_dbg_umq_comp;
  
  m_dbg_umq_pkt->xrt_header.common_header.type =
    HOST_QUEUE_PACKET_TYPE_VENDOR_SPECIFIC;
  m_dbg_umq_hdr->capacity = 1;
  m_dbg_umq_hdr->data_address = m_dbg_umq_bo->paddr() + header_sz;

  shim_debug("Created DBG UMQ HW queue");
}

dbg_hwq_umq::
~dbg_hwq_umq()
{
  shim_debug("Destroying DBG UMA HW queue");
}

uint32_t
dbg_hwq_umq::
issue_exit_cmd()
{
  auto hdr = &m_dbg_umq_pkt->xrt_header;
  // always case 1
  auto ehp = &m_dbg_umq_pkt->xrt_header;
  ehp->common_header.opcode = DBG_CMD_EXIT;
  ehp->common_header.count = 0;

  shim_debug("dbg umq: issue exit cmd");
  return submit();
}

uint32_t
dbg_hwq_umq::
issue_rw_cmd(struct rw_mem &data, uint16_t opcode)
{ 
  auto hdr = &m_dbg_umq_pkt->xrt_header;
  // always case 1
  auto ehp = &m_dbg_umq_pkt->xrt_header;
  ehp->common_header.opcode = opcode;
  ehp->common_header.count = sizeof (struct rw_mem);

  struct rw_mem *rwp = reinterpret_cast<struct rw_mem *>
    (const_cast<uint32_t *>(m_dbg_umq_pkt->data));
  std::memcpy(rwp, &data, sizeof(struct rw_mem));

  shim_debug("dbg umq: issue rw cmd");
  return submit();
}

buffer*
dbg_hwq_umq::
get_dbg_umq_bo() const
{
  return m_dbg_umq_bo.get();
}

uint32_t
dbg_hwq_umq::
submit()
{
  *m_dbg_umq_comp_ptr = 0;

  /* Issue mfence instruction to make sure all writes to the slot before is done */
  std::atomic_thread_fence(std::memory_order::memory_order_seq_cst);
  m_dbg_umq_hdr->write_index++;

  shim_debug("dbg umq: submit cmd widx: %lu ridx: %lu",
    m_dbg_umq_hdr->write_index,
    m_dbg_umq_hdr->read_index);
  shim_debug("dbg umq: cmd opcode: %d count: %d",
    m_dbg_umq_pkt->xrt_header.common_header.opcode,
    m_dbg_umq_pkt->xrt_header.common_header.count);

  while (1)
  {
    if (*m_dbg_umq_comp_ptr &&
        m_dbg_umq_hdr->write_index == m_dbg_umq_hdr->read_index)
    {
      return (*m_dbg_umq_comp_ptr);
    }
  }
}

} // shim_xdna

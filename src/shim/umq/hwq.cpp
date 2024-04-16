// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2023-2024, Advanced Micro Devices, Inc. All rights reserved.

#include "bo.h"
#include "hwq.h"

namespace {

inline void
mark_slot_invalid(volatile host_queue_packet_t *pkt)
{
  pkt->xrt_header.common_header.type = HOST_QUEUE_PACKET_TYPE_INVALID;
}

inline void
mark_slot_valid(volatile host_queue_packet_t *pkt)
{
  /* Issue mfence instruction to make sure all writes to the slot before is done */
  std::atomic_thread_fence(std::memory_order::memory_order_seq_cst);
  pkt->xrt_header.common_header.type = HOST_QUEUE_PACKET_TYPE_VENDOR_SPECIFIC;
}

inline bool
is_slot_valid(volatile host_queue_packet_t *pkt)
{
  return pkt->xrt_header.common_header.type == HOST_QUEUE_PACKET_TYPE_VENDOR_SPECIFIC;
}

}

namespace shim_xdna {

hw_q_umq::
hw_q_umq(const device& dev, size_t nslots) : hw_q(dev)
{
#ifdef UMQ_HELLO_TEST
  const size_t header_sz = (2 << 20); // Hard code to 2MB
  const size_t queue_sz = 0;
#else
  const size_t header_sz = sizeof(host_queue_header_t);
  const size_t queue_sz = sizeof(host_queue_packet_t) * nslots;
#endif
  const size_t umq_sz = header_sz + queue_sz;

  umq_bo = const_cast<device &>(dev).alloc_bo(umq_sz, XCL_BO_FLAGS_EXECBUF);
  umq_bo_buf = umq_bo->map(bo::map_type::write);
  umq_hdr = reinterpret_cast<volatile host_queue_header_t *>(umq_bo_buf);
  umq_pkt = reinterpret_cast<volatile host_queue_packet_t *>
    ((char *)umq_bo_buf + header_sz);

  // set all mapped memory to 0 
  std::memset(umq_bo_buf, 0, umq_sz);
  
  for (int i = 0; i < nslots; i++)
    mark_slot_invalid(&umq_pkt[i]);

  umq_hdr->capacity = nslots;
  // data_address starts after header
  umq_hdr->data_address = umq_bo->get_properties().paddr + header_sz;

  // this is the bo handler defined in parent class
  m_queue_boh = static_cast<bo_umq*>(umq_bo.get())->get_drm_bo_handle();

  shim_debug("Created UMQ HW queue");
}

hw_q_umq::
~hw_q_umq()
{
  shim_debug("Destroying UMA HW queue");

  umq_bo->unmap(umq_bo_buf);
  m_pdev.munmap(const_cast<uint32_t*>(mapped_doorbell), sizeof(uint32_t));
}

void
hw_q_umq::
map_doorbell(uint32_t doorbell_offset)
{ 
  mapped_doorbell = reinterpret_cast<volatile uint32_t *>(
    m_pdev.mmap(sizeof(uint32_t), PROT_WRITE, MAP_SHARED, doorbell_offset));
}

volatile host_queue_header_t *
hw_q_umq::
get_header_ptr() const
{ 
  return reinterpret_cast<volatile host_queue_header_t *>(umq_bo_buf);
}

void
hw_q_umq::
dump() const
{ 
  auto h = get_header_ptr();
  shim_debug("Dumping UMQ queue header @%p:", h);
  shim_debug("\tRead Index:\t0x%lx", h->read_index);
  shim_debug("\tWrite Index:\t0x%lx", h->write_index);
  shim_debug("\tCapacity:\t%d", h->capacity);
  shim_debug("\tData Addr:\t%p", h->data_address);

  shim_debug("Dumping UMQ queue slot @%p:", umq_pkt);
  for (int i = 0; i < h->capacity; i++) {
    auto pkt = &umq_pkt[i];
    shim_debug("==========slot %d==========", i);
    shim_debug("\ttype:\t\t%u", static_cast<uint16_t>(pkt->xrt_header.common_header.type));
    shim_debug("\tbarrier:\t%u", static_cast<uint16_t>(pkt->xrt_header.common_header.barrier));
    shim_debug("\tacquire:\t%u", static_cast<uint16_t>(pkt->xrt_header.common_header.acquire_fence_scope));
    shim_debug("\trelease:\t%u", static_cast<uint16_t>(pkt->xrt_header.common_header.release_fence_scope));
    shim_debug("\topcode:\t\t%u", pkt->xrt_header.common_header.opcode);
    shim_debug("\tcount:\t\t%u", pkt->xrt_header.common_header.count);
    shim_debug("\tdistribute:\t%u", pkt->xrt_header.common_header.distribute);
    shim_debug("\tindirect:\t%u", pkt->xrt_header.common_header.indirect);
    shim_debug("\tcomplete addr:\t%p", pkt->xrt_header.completion_signal);
    for (int j = 0; j < sizeof(pkt->data) / sizeof(pkt->data[0]); j++)
      shim_debug("\tdata[%d]:\t0x%08x", j, pkt->data[j]);
  }
}

void
hw_q_umq::
dump_raw() const
{
  auto d = reinterpret_cast<volatile uint32_t *>(umq_pkt);
  auto sz = get_header_ptr()->capacity * sizeof(host_queue_packet_t) / sizeof(uint32_t);
  shim_debug("Dumping raw UMQ queue slot data @%p, len=%ld WORDs:", umq_pkt, sz);
  for (int i = 0; i < sz; i++)
    shim_debug("0x%08x", d[i]);
}

uint64_t
hw_q_umq::
reserve_slot()
{
  uint64_t cur_slot = 0;
  bool queue_full = false;
  auto h = get_header_ptr();

  std::unique_lock<std::mutex> lock(m_mutex);
  if (h->write_index < h->read_index) {
    shim_err(EINVAL, "Queue read before write! read_index=0x%lx, write_index=0x%lx",
      h->read_index, h->write_index);
    dump();
  } else if ((h->write_index - h->read_index) < h->capacity) {
    cur_slot = h->write_index;
    h->write_index++;
  } else {
    queue_full = true;
  }
  lock.unlock();

  if (queue_full)
    shim_err(ENOSPC, "Queue is full");

  return cur_slot;
}

volatile host_queue_packet_t *
hw_q_umq::
get_slot(uint64_t index)
{
  auto pkt = &umq_pkt[index & (get_header_ptr()->capacity - 1)];
  if (is_slot_valid(pkt)) {
    shim_err(EINVAL, "Slot is ready before use! index=0x%lx", index);
    dump();
  }
  return pkt;
}

uint64_t
hw_q_umq::
issue_exec_buf(uint16_t cu_idx, ert_dpu_data *dpu, uint64_t comp)
{
  auto idx = reserve_slot();
  auto pkt = get_slot(idx);
  auto hdr = &pkt->xrt_header;
  hdr->common_header.opcode = HOST_QUEUE_PACKET_EXEC_BUF;
  hdr->common_header.distribute = 0;
  hdr->common_header.indirect = 0;
  hdr->completion_signal = comp;

  exec_buf_t payload = {};
  payload.cu_index = cu_idx;
  payload.dpu_control_code_host_addr_low = static_cast<uint32_t>(dpu->instruction_buffer);
  payload.dpu_control_code_host_addr_high = static_cast<uint32_t>(dpu->instruction_buffer >> 32);

  fill_slot_and_send(pkt, &payload, sizeof(payload));
  return idx;
}

void
hw_q_umq::
fill_slot_and_send(volatile host_queue_packet_t *pkt, void *payload, size_t size)
{
  if (size > sizeof(pkt->data))
    shim_err(EINVAL, "HSA packet payload too big, size=0x%lx", size);

  auto hdr = &pkt->xrt_header;
  hdr->common_header.count = size;

  auto data = const_cast<uint32_t *>(pkt->data);
  std::memcpy(data, payload, size);
  /* Always done as last step. */
  mark_slot_valid(pkt);
  /* Wake up CERT */
  *mapped_doorbell = 0;
}

void
hw_q_umq::
submit_command(xrt_core::buffer_handle *cmd_bo)
{
  std::vector<xrt_core::buffer_handle *> cmd_bos {cmd_bo};
  return submit_command(cmd_bos);
}

void
hw_q_umq::
submit_command(std::vector<xrt_core::buffer_handle *>& cmd_bos)
{
  if (cmd_bos.size() > 1)
    shim_err(EINVAL, "Do not support more than 1 cmd");

  auto boh = static_cast<bo*>(cmd_bos[0]);
  auto cmd = reinterpret_cast<ert_start_kernel_cmd *>(boh->map(bo::map_type::write));

  // Sanity check
  auto dpu_data = get_ert_dpu_data(cmd);
  if (!dpu_data) {
    // For debugging: dumping out at most 6 words in case count is insanely large
    const uint32_t max_dump_word = std::min(cmd->count + 1, 6);
    shim_debug("Dumping first %d words out of %d words:", max_dump_word, cmd->count + 1);
    for (uint32_t i = 0; i < max_dump_word; i++)
      shim_debug("EXEC_BUF[%d]: 0x%x", i, (reinterpret_cast<uint32_t *>(cmd))[i]);

    shim_err(EINVAL, "No dpu data, invalid exec buf");
  }

  if (get_ert_dpu_data_next(dpu_data))
    shim_err(EOPNOTSUPP, "chained dpu data is not supported yet");

  // Completion signal area has to be a full WORD
  uint64_t comp = boh->get_properties().paddr + offsetof(ert_start_kernel_cmd, header);

  auto id = issue_exec_buf(ffs(cmd->cu_mask) - 1, dpu_data, comp);
  boh->set_cmd_id(id);
  shim_debug("Submitted command (%ld)", id);
}

} // shim_xdna

// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2023-2025, Advanced Micro Devices, Inc. All rights reserved.

#include "hwq.h"

namespace {

void
init_indirect_buf(volatile struct host_indirect_data *indirect_buf, int size)
{
  for (int i = 0; i < size; i++) {
    indirect_buf[i].header.type = HOST_QUEUE_PACKET_TYPE_VENDOR_SPECIFIC;
    indirect_buf[i].header.opcode = HOST_QUEUE_PACKET_EXEC_BUF;
    indirect_buf[i].header.count = sizeof(struct exec_buf);
    indirect_buf[i].header.distribute = 1;
    indirect_buf[i].header.indirect = 0;
  }
}

volatile uint32_t *
map_doorbell(const shim_xdna::pdev& pdev, uint32_t doorbell_offset)
{
  return reinterpret_cast<volatile uint32_t *>(
    pdev.mmap(0, sizeof(uint32_t), PROT_WRITE, MAP_SHARED, doorbell_offset)
    );
}

}

namespace shim_xdna {

hwq_umq::
hwq_umq(const device& dev, size_t nslots) : hwq(dev)
{
  // host queue layout:
  //   host_queue_header_t
  //   host_queue_packet_t [nslots]
  //   indirect [4 * indirect_buffer * nslots]
  const size_t header_sz = sizeof(struct host_queue_header);
  const size_t queue_sz = sizeof(struct host_queue_packet) * nslots;
  const size_t indirect_sz = (sizeof(struct host_indirect_data) * HSA_MAX_LEVEL1_INDIRECT_ENTRIES) * nslots;

#ifdef UMQ_HELLO_TEST
  const size_t umq_sz = 0x200000;
#else
  const size_t umq_sz = header_sz + queue_sz + indirect_sz;
#endif

  shim_debug("Creating UMQ HW queue of size %ld", umq_sz);

  m_umq_bo = std::make_unique<buffer>(m_pdev, umq_sz, AMDXDNA_BO_CMD);
  m_umq_bo_buf = m_umq_bo->vaddr();
  std::memset(m_umq_bo_buf, 0, umq_sz);

  m_umq_hdr = reinterpret_cast<volatile struct host_queue_header *>(m_umq_bo_buf);
  m_umq_pkt = reinterpret_cast<volatile struct host_queue_packet *>
    (reinterpret_cast<uintptr_t>(m_umq_bo_buf) + header_sz);
  m_umq_indirect_buf = reinterpret_cast<volatile struct host_indirect_data *>
    (reinterpret_cast<uintptr_t>(m_umq_bo_buf) + header_sz + queue_sz);

  // init slots and indirect buf
  for (int i = 0; i < nslots; i++)
    init_indirect_buf(&m_umq_indirect_buf[i * HSA_MAX_LEVEL1_INDIRECT_ENTRIES], HSA_MAX_LEVEL1_INDIRECT_ENTRIES);

  m_umq_hdr->capacity = nslots;
  // data_address starts after header
  m_umq_hdr->data_address = m_umq_bo->get_properties().paddr + header_sz;
  // indirect buf starts after queue
  m_indirect_paddr = m_umq_hdr->data_address + queue_sz;

  shim_debug("Created UMQ HW queue");
}

hwq_umq::
~hwq_umq()
{
  shim_debug("Destroying UMA HW queue");
}

void
hwq_umq::
dump() const
{
  auto h = m_umq_hdr;
  shim_debug("Dumping UMQ queue header @%p:", h);
  shim_debug("\tRead Index:\t0x%lx", h->read_index);
  shim_debug("\tWrite Index:\t0x%lx", h->write_index);
  shim_debug("\tCapacity:\t%d", h->capacity);
  shim_debug("\tData Addr:\t%p", h->data_address);

  shim_debug("Dumping UMQ queue slot @%p:", m_umq_pkt);
  for (int i = 0; i < h->capacity; i++) {
    auto pkt = &m_umq_pkt[i];
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
    if (pkt->xrt_header.common_header.indirect == 0) {
      volatile struct exec_buf *ebp =
        reinterpret_cast<volatile struct exec_buf *>(pkt->data);

      shim_debug("\tdpu: [0x%x 0x%x]",
        ebp->dpu_control_code_host_addr_high,
        ebp->dpu_control_code_host_addr_low);
    } else {
      volatile struct host_indirect_packet_entry *hp =
        reinterpret_cast<volatile struct host_indirect_packet_entry *>(pkt->data);

      for (int i = 0; i < HSA_MAX_LEVEL1_INDIRECT_ENTRIES; i++, hp++) {
        uint32_t hi = hp->host_addr_high;
        uint32_t lo = hp->host_addr_low;
        shim_debug("\thost addr: [0x%x 0x%x]", hi, lo);

        volatile struct host_indirect_data *data =
        reinterpret_cast<volatile struct host_indirect_data *>(m_umq_indirect_buf);
        shim_debug("\t\th:distribute:\t%d", data[i].header.distribute);
        shim_debug("\t\th:indirect:\t%d", data[i].header.indirect);
        shim_debug("\t\tp:dpu: [0x%x 0x%x]",
          data[i].payload.dpu_control_code_host_addr_high,
          data[i].payload.dpu_control_code_host_addr_low);
      }
    }
  }
  shim_debug("Finished dumping UMQ\r\n");
}

void
hwq_umq::
dump_raw() const
{
  auto d = reinterpret_cast<volatile uint32_t *>(m_umq_pkt);
  auto sz = m_umq_hdr->capacity * sizeof(struct host_queue_packet) / sizeof(uint32_t);
  shim_debug("Dumping raw UMQ queue slot data @%p, len=%ld WORDs:", m_umq_pkt, sz);
  for (int i = 0; i < sz; i++)
    shim_debug("0x%08x", d[i]);
  shim_debug("Finished dumping raw UMQ queue slot data\r\n");
}

uint32_t
hwq_umq::
get_next_avail_slot()
{
  uint64_t cur_slot = 0;
  auto h = m_umq_hdr;

  do {
    // Take a snapshot of read and write index in case they changes while being processed here
    uint64_t wi = h->write_index;
    uint64_t ri = h->read_index;

    if (wi < ri) {
      // Invalid queue.
      dump();
      shim_err(EINVAL, "UMQ was read before written! read_index=0x%lx, write_index=0x%lx", ri, wi);
    } else if ((wi - ri) < h->capacity) {
      // Found a slot.
      cur_slot = wi;
      break;
    } else {
      shim_debug("Queue is full, wait for next available slot");
      // The ri is the first available slot.
      wait_command(ri, 0);
    }
  } while (true);

  return cur_slot & (h->capacity - 1);
}

volatile struct host_queue_packet *
hwq_umq::
get_pkt(uint32_t index)
{
  return &m_umq_pkt[index];
}

uint64_t
hwq_umq::
issue_single_exec_buf(const cmd_buffer *cmd_bo, bool last_of_chain)
{
  auto cmd = reinterpret_cast<ert_start_kernel_cmd *>(cmd_bo->vaddr());
  auto dpu = get_ert_dpu_data(cmd);

  // Sanity check
  if (!dpu) {
    // For debugging: dumping out at most 6 words in case count is insanely large
    const uint32_t max_dump_word = std::min(cmd->count + 1, 6);
    shim_debug("Dumping first %d words out of %d words:", max_dump_word, cmd->count + 1);
    for (uint32_t i = 0; i < max_dump_word; i++)
      shim_debug("EXEC_BUF[%d]: 0x%x", i, (reinterpret_cast<uint32_t *>(cmd))[i]);

    shim_err(EINVAL, "No dpu data, invalid exec buf");
  }

  auto slot_idx = get_next_avail_slot();

  if (get_ert_dpu_data_next(dpu))
    fill_indirect_exec_buf(slot_idx, dpu);
  else
    fill_direct_exec_buf(slot_idx, dpu); 

  auto pkt = get_pkt(slot_idx);
  auto hdr = &pkt->xrt_header;
  hdr->common_header.opcode = HOST_QUEUE_PACKET_EXEC_BUF;
  // Completion signal area has to be a full WORD, we utilize the command_bo header.
  hdr->completion_signal = cmd_bo->paddr() + offsetof(ert_start_kernel_cmd, header);
  // TODO: remove once uC stops looking at this field.
  hdr->common_header.type = HOST_QUEUE_PACKET_TYPE_VENDOR_SPECIFIC;

  // Issue mfence instruction to make sure all writes to the slot before is done.
  std::atomic_thread_fence(std::memory_order::memory_order_seq_cst);
  // Indicates the slot is ready for processing by uC.
  // Must be the last step after pkt is filled up.
  uint64_t wi = m_umq_hdr->write_index++;

  // Wake up uC in case it is sleeping and waiting.
  *m_mapped_doorbell = 0;

  shim_debug("Submitted %s-uC %scommand (%ld)",
    get_ert_dpu_data_next(dpu) ? "multi" : "single",
    last_of_chain ? "last-of-chain " : "",
    wi);
  return wi;
}

void
hwq_umq::
fill_indirect_exec_buf(uint32_t slot_idx, ert_dpu_data *dpu)
{
  auto pkt = get_pkt(slot_idx);
  auto pkt_size = (dpu->chained + 1) * sizeof(struct host_indirect_packet_entry);

  if (dpu->chained + 1 >= HSA_MAX_LEVEL1_INDIRECT_ENTRIES)
    shim_err(EINVAL, "unsupported indirect number %d, valid number <= %d",
      dpu->chained + 1, HSA_MAX_LEVEL1_INDIRECT_ENTRIES);

  if (pkt_size > sizeof(pkt->data))
    shim_err(EINVAL, "dpu pkt_size=0x%zx > pkt_data max size=0x%zx",
      pkt_size, sizeof(pkt->data));

  // no need to memset to zero, all buffer will be set
  volatile struct host_indirect_packet_entry *hp =
    reinterpret_cast<volatile struct host_indirect_packet_entry *>(pkt->data);

  for (int i = 0; dpu; i++, hp++, dpu = get_ert_dpu_data_next(dpu)) {
    auto data_size = sizeof(struct host_indirect_data) * HSA_MAX_LEVEL1_INDIRECT_ENTRIES;
    auto prefix_off = slot_idx * data_size;
    auto prefix_idx = slot_idx * HSA_MAX_LEVEL1_INDIRECT_ENTRIES;
    auto buf_paddr = m_indirect_paddr + prefix_off +
       sizeof(struct host_indirect_data) * i;

    hp->host_addr_low = static_cast<uint32_t>(buf_paddr);
    hp->host_addr_high = static_cast<uint32_t>(buf_paddr >> 32);
    hp->uc_index = dpu->uc_index;

    auto cebp = &m_umq_indirect_buf[prefix_idx + i];
    // do not zero this buffer, the cebp->header is pre-set 
    // set every cebp->payload field in case of garbage data
    cebp->payload.dpu_control_code_host_addr_low =
      static_cast<uint32_t>(dpu->instruction_buffer);
    cebp->payload.dpu_control_code_host_addr_high =
      static_cast<uint32_t>(dpu->instruction_buffer >> 32);
    cebp->payload.args_len = 0;
    cebp->payload.args_host_addr_low = 0;
    cebp->payload.args_host_addr_high = 0;
  }

  auto hdr = &pkt->xrt_header;
  hdr->common_header.distribute = 1;
  hdr->common_header.indirect = 1;
  hdr->common_header.count = pkt_size;
}

void
hwq_umq::
fill_direct_exec_buf(uint32_t slot_idx, ert_dpu_data *dpu)
{
  auto pkt = get_pkt(slot_idx);
  auto pkt_size = sizeof(struct exec_buf);

  if (pkt_size > sizeof(pkt->data))
    shim_err(EINVAL, "dpu pkt_size=0x%lx > pkt_data max size=%x%lx",
      pkt_size, sizeof(pkt->data));
  
  // zero this buffer
  auto data = const_cast<uint32_t *>(pkt->data);
  std::memset(data, 0, pkt_size);
  // set correct dpu control code
  volatile struct exec_buf *ebp = reinterpret_cast<volatile struct exec_buf *>(pkt->data);
  ebp->dpu_control_code_host_addr_low = static_cast<uint32_t>(dpu->instruction_buffer);
  ebp->dpu_control_code_host_addr_high = static_cast<uint32_t>(dpu->instruction_buffer >> 32);

  auto hdr = &pkt->xrt_header;
  hdr->common_header.distribute = 0;
  hdr->common_header.indirect = 0;
  hdr->common_header.count = pkt_size;
}

uint64_t
hwq_umq::
issue_command(const cmd_buffer *cmd_bo)
{
  auto cmd = reinterpret_cast<ert_packet *>(cmd_bo->vaddr());
  auto& subcmds = cmd_bo->get_subcmd_list();
  subcmds.clear();

  // Single command submission.
  if (cmd->opcode != ERT_CMD_CHAIN)
    return issue_single_exec_buf(cmd_bo, true);

  // Runlist command submission.
  auto payload = get_ert_cmd_chain_data(cmd);
  if (payload->command_count == 0 || payload->command_count > 100)
    shim_err(EINVAL, "Runlist exec buf with bad num of subcmds: %zx", payload->command_count);

  if (subcmds.capacity() < payload->command_count)
    subcmds.reserve(payload->command_count);

  uint64_t seq = 0;
  for (size_t i = 0; i < payload->command_count; i++) {
    auto subcmd = static_cast<const cmd_buffer *>(m_pdev.find_bo_by_handle(payload->data[i]));
    seq = issue_single_exec_buf(subcmd, i == payload->command_count - 1);
    subcmds.push_back(subcmd);
  }
  return seq;
}

void
hwq_umq::
bind_hwctx(const hwctx& ctx)
{
  // link hwctx by parent class
  hwq::bind_hwctx(ctx);
  // setup doorbell mapping by child class
  m_mapped_doorbell = map_doorbell(m_pdev, ctx.get_doorbell());
}

void
hwq_umq::
unbind_hwctx()
{
  // unlink hwctx by parent class
  hwq::unbind_hwctx();
  // teardown doorbell mapping by child class
  m_pdev.munmap(const_cast<uint32_t*>(m_mapped_doorbell), sizeof(uint32_t));
}

bo_id
hwq_umq::
get_queue_bo() const
{
  return m_umq_bo->id();
}

} // shim_xdna

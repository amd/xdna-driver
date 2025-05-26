// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2023-2025, Advanced Micro Devices, Inc. All rights reserved.

#include "hwq.h"

namespace {

inline void
mark_slot_invalid(volatile struct host_queue_packet *pkt)
{
  pkt->xrt_header.common_header.type = HOST_QUEUE_PACKET_TYPE_INVALID;
}

inline void
mark_slot_valid(volatile struct host_queue_packet *pkt)
{
  /* Issue mfence instruction to make sure all writes to the slot before is done */
  std::atomic_thread_fence(std::memory_order::memory_order_seq_cst);
  pkt->xrt_header.common_header.type = HOST_QUEUE_PACKET_TYPE_VENDOR_SPECIFIC;
}

inline bool
is_slot_valid(volatile struct host_queue_packet *pkt)
{
  return pkt->xrt_header.common_header.type == HOST_QUEUE_PACKET_TYPE_VENDOR_SPECIFIC;
}

}

namespace shim_xdna {

void
hwq_umq::
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
  const size_t umq_sz = 0x8000; // 32k, current cmd_bo max size
  //const size_t umq_sz = 0x200000; // 2M, lift the cmd_bo max size to enable this
#else
  const size_t umq_sz = header_sz + queue_sz + indirect_sz;
#endif

  shim_debug("umq sz %ld", umq_sz);

  m_umq_bo = std::make_unique<cmd_buffer>(m_pdev, umq_sz, AMDXDNA_BO_CMD);
  m_umq_bo_buf = m_umq_bo->vaddr();
  m_umq_hdr = reinterpret_cast<volatile struct host_queue_header *>(m_umq_bo_buf);
  m_umq_pkt = reinterpret_cast<volatile struct host_queue_packet *>
    ((char *)m_umq_bo_buf + header_sz);
  m_umq_indirect_buf = reinterpret_cast<volatile struct host_indirect_data *>
    ((char *)m_umq_bo_buf + header_sz + queue_sz);

  // set all mapped memory to 0 
  std::memset(m_umq_bo_buf, 0, umq_sz);
  
  // init slots and indirect buf
  for (int i = 0; i < nslots; i++) {
    mark_slot_invalid(&m_umq_pkt[i]);
    init_indirect_buf(&m_umq_indirect_buf[i * HSA_MAX_LEVEL1_INDIRECT_ENTRIES], HSA_MAX_LEVEL1_INDIRECT_ENTRIES);
  }

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
map_doorbell(uint32_t doorbell_offset)
{
  m_mapped_doorbell = reinterpret_cast<volatile uint32_t *>(
    m_pdev.mmap(0, sizeof(uint32_t), PROT_WRITE, MAP_SHARED, doorbell_offset));
}

volatile struct host_queue_header *
hwq_umq::
get_header_ptr() const
{
  return reinterpret_cast<volatile struct host_queue_header *>(m_umq_bo_buf);
}

void
hwq_umq::
dump() const
{
  auto h = get_header_ptr();
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

      shim_debug("\tcu_index:\t%d", ebp->cu_index);
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
	shim_debug("\t\tp:cu_index:\t%d", data[i].payload.cu_index);
	shim_debug("\t\tp:dpu: [0x%x 0x%x]",
          data[i].payload.dpu_control_code_host_addr_high,
          data[i].payload.dpu_control_code_host_addr_low);
      }
    }
  }
  shim_debug("dump finished\r\n");
}

void
hwq_umq::
dump_raw() const
{
  auto d = reinterpret_cast<volatile uint32_t *>(m_umq_pkt);
  auto sz = get_header_ptr()->capacity * sizeof(struct host_queue_packet) / sizeof(uint32_t);
  shim_debug("Dumping raw UMQ queue slot data @%p, len=%ld WORDs:", m_umq_pkt, sz);
  for (int i = 0; i < sz; i++)
    shim_debug("0x%08x", d[i]);
}

uint64_t
hwq_umq::
reserve_slot()
{
  uint64_t cur_slot = 0;
  bool queue_full = false;
  auto h = get_header_ptr();

  do {
    if (h->write_index < h->read_index) {
      shim_err(EINVAL, "Queue read before write! read_index=0x%lx, write_index=0x%lx",
        h->read_index, h->write_index);
      dump();
    } else if ((h->write_index - h->read_index) < h->capacity) {
      cur_slot = h->write_index;
      h->write_index++;
      break;
    } else {
      queue_full = true;
    }

    if (queue_full) {
      shim_debug("Queue is full, wait for next available slot");
      //should wait for h->read_index which should be the first available slot.
      wait_command(h->read_index, 0);
    }
  } while (queue_full);

  return cur_slot;
}

int
hwq_umq::
get_pkt_idx(uint64_t index)
{
  return index & (get_header_ptr()->capacity - 1);
}

volatile struct host_queue_packet *
hwq_umq::
get_pkt(uint64_t index)
{
  auto pkt = &m_umq_pkt[get_pkt_idx(index)];
  if (is_slot_valid(pkt)) {
    shim_err(EINVAL, "Slot is ready before use! index=0x%lx", index);
    dump();
  }
  return pkt;
}

uint64_t
hwq_umq::
issue_exec_buf(uint16_t cu_idx, ert_dpu_data *dpu, uint64_t comp)
{
  auto slot_idx = reserve_slot();
  auto pkt = get_pkt(slot_idx);
  size_t pkt_size;

  if (get_ert_dpu_data_next(dpu))
    pkt_size = fill_indirect_exec_buf(slot_idx, cu_idx, pkt, dpu);
  else
    pkt_size = fill_direct_exec_buf(cu_idx, pkt, dpu); 

  auto hdr = &pkt->xrt_header;
  hdr->common_header.opcode = HOST_QUEUE_PACKET_EXEC_BUF;
  hdr->completion_signal = comp;

  fill_slot_and_send(pkt, pkt_size);

  return slot_idx;
}

size_t
hwq_umq::
fill_indirect_exec_buf(uint64_t slot_idx, uint16_t cu_idx,
                        volatile struct host_queue_packet *pkt,
                        ert_dpu_data *dpu) {
  auto pkt_size = (dpu->chained + 1) * sizeof(struct host_indirect_packet_entry);

  if (dpu->chained + 1 >= HSA_MAX_LEVEL1_INDIRECT_ENTRIES)
    shim_err(EINVAL, "unsupported indirect number %d, valid number <= %d",
      dpu->chained + 1, HSA_MAX_LEVEL1_INDIRECT_ENTRIES);

  if (pkt_size > sizeof(pkt->data))
    shim_err(EINVAL, "dpu pkt_size=0x%lx > pkt_data max size=%x%lx",
      pkt_size, sizeof(pkt->data));

  // no need to memset to zero, all buffer will be set
  volatile struct host_indirect_packet_entry *hp =
    reinterpret_cast<volatile struct host_indirect_packet_entry *>(pkt->data);

  for (int i = 0; dpu; i++, hp++, dpu = get_ert_dpu_data_next(dpu)) {
    auto data_size = sizeof(struct host_indirect_data) * HSA_MAX_LEVEL1_INDIRECT_ENTRIES;
    auto prefix_off = get_pkt_idx(slot_idx) * data_size;
    auto prefix_idx = get_pkt_idx(slot_idx) * HSA_MAX_LEVEL1_INDIRECT_ENTRIES;
    auto buf_paddr = m_indirect_paddr + prefix_off +
       sizeof(struct host_indirect_data) * i;

    hp->host_addr_low = static_cast<uint32_t>(buf_paddr);
    hp->host_addr_high = static_cast<uint32_t>(buf_paddr >> 32);
    hp->uc_index = dpu->uc_index;

    auto cebp = &m_umq_indirect_buf[prefix_idx + i];
    // do not zero this buffer, the cebp->header is pre-set 
    // set every cebp->payload field in case of garbage data
    cebp->payload.cu_index = cu_idx;
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

  return pkt_size;
}

size_t
hwq_umq::
fill_direct_exec_buf(uint16_t cu_idx, volatile struct host_queue_packet *pkt,
                     ert_dpu_data *dpu) {
  auto pkt_size = sizeof(struct exec_buf);
  if (pkt_size > sizeof(pkt->data))
    shim_err(EINVAL, "dpu pkt_size=0x%lx > pkt_data max size=%x%lx",
      pkt_size, sizeof(pkt->data));
  
  // zero this buffer
  auto data = const_cast<uint32_t *>(pkt->data);
  std::memset(data, 0, pkt_size);
  // set correct dpu control code
  volatile struct exec_buf *ebp = reinterpret_cast<volatile struct exec_buf *>(pkt->data);
  ebp->cu_index = cu_idx;
  ebp->dpu_control_code_host_addr_low = static_cast<uint32_t>(dpu->instruction_buffer);
  ebp->dpu_control_code_host_addr_high = static_cast<uint32_t>(dpu->instruction_buffer >> 32);

  auto hdr = &pkt->xrt_header;
  hdr->common_header.distribute = 0;
  hdr->common_header.indirect = 0;

  return pkt_size;
}

void
hwq_umq::
fill_slot_and_send(volatile struct host_queue_packet *pkt, size_t size)
{
  if (size > sizeof(pkt->data))
    shim_err(EINVAL, "HSA packet payload too big, size=0x%lx", size);

  auto hdr = &pkt->xrt_header;
  hdr->common_header.count = size;

  //comment this out, debug only
  //dump();

  /* Always done as last step. */
  mark_slot_valid(pkt);

  /* Wake up CERT */
  *m_mapped_doorbell = 0;
}

uint64_t
hwq_umq::
issue_command(const cmd_buffer *cmd_bo)
{
  auto cmd = reinterpret_cast<ert_start_kernel_cmd *>(cmd_bo->vaddr());

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
    shim_debug("this is a multi-column dpu request.");

  // Completion signal area has to be a full WORD, we utilze the command_bo
  uint64_t comp = cmd_bo->paddr() + offsetof(ert_start_kernel_cmd, header);

  auto seq = issue_exec_buf(ffs(cmd->cu_mask) - 1, dpu_data, comp);
  shim_debug("Submitted command (%ld)", seq);
  return seq;
}

void
hwq_umq::
bind_hwctx(const hwctx& ctx)
{
  // link hwctx by parent class
  hwq::bind_hwctx(ctx);
  // setup doorbell mapping by child class
  map_doorbell(ctx.get_doorbell());
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

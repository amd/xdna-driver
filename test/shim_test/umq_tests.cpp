// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2024, Advanced Micro Devices, Inc. All rights reserved.

#include "bo.h"
#include "hwctx.h"
#include "dev_info.h"
#include "exec_buf.h"

#include "core/common/device.h"

namespace {

using namespace xrt_core;

void
prepare_ddr_cmd(bo& execbuf, const std::string& elf, bo& ctrl, bo& data)
{
  exec_buf ebuf(execbuf, ERT_START_DPU);

  ebuf.add_ctrl_bo(ctrl);
  ebuf.add_arg_bo(data, "input");
  ebuf.patch_ctrl_code(ctrl, elf);
  ebuf.dump();
 
  std::cout << "Init'ed exec_buf, patched control code from " << elf << std::endl;
}

void
prepare_basic_cmd(bo& execbuf, const std::string& elf, bo& ctrl)
{
  exec_buf ebuf(execbuf, ERT_START_DPU);

  ebuf.add_ctrl_bo(ctrl);
  ebuf.patch_ctrl_code(ctrl, elf);
  ebuf.dump();
 
  std::cout << "Init'ed exec_buf, patched control code from " << elf << std::endl;
}

void
prepare_vadd_cmd(bo& execbuf, const std::string& elf, bo& ctrl, bo& ifm, bo& wts, bo& ofm)
{
  exec_buf ebuf(execbuf, ERT_START_DPU);

  ebuf.add_ctrl_bo(ctrl);
  ebuf.add_arg_bo(ifm, "g.ifm_ddr");
  ebuf.add_arg_bo(wts, "g.wts_ddr");
  ebuf.add_arg_bo(ofm, "g.ofm_ddr");
  ebuf.patch_ctrl_code(ctrl, elf);
  ebuf.dump();
 
  std::cout << "Init'ed exec_buf, patched control code from " << elf << std::endl;
}

// Submit a cmd with control code buf directly
void
umq_cmd_submit(hwqueue_handle *hwq, bo& exec_buf_bo)
{
  // Send command through HSA queue and wait for it to complete
  hwq->submit_command(exec_buf_bo.get());
}

void
umq_cmd_wait(hwqueue_handle *hwq, bo& exec_buf_bo, uint32_t timeout_ms)
{
  auto cmd_packet = reinterpret_cast<ert_start_kernel_cmd *>(exec_buf_bo.map());

  while (cmd_packet->state < ERT_CMD_STATE_COMPLETED) {
    if (!hwq->wait_command(exec_buf_bo.get(), timeout_ms))
      throw std::runtime_error(std::string("exec buf timed out."));
    else
      break;
  }
  if (cmd_packet->state != ERT_CMD_STATE_COMPLETED)
    throw std::runtime_error(std::string("bad command state: ") + std::to_string(cmd_packet->header));
}

template <typename TEST_BO>
void init_umq_vadd_buffers(TEST_BO& ifm, TEST_BO& wts, TEST_BO& ofm)
{
  auto p = ifm.map();
  for (uint32_t i = 0; i < ifm.size() / sizeof (uint32_t); i++)
    p[i] = i;
  p = wts.map();
  for (uint32_t i = 0; i < wts.size() / sizeof (uint32_t); i++)
    p[i] = i * 10000;
  p = ofm.map();
  for (uint32_t i = 0; i < ofm.size() / sizeof (uint32_t); i++)
    p[i] = 0;
}

void check_umq_vadd_result(int *ifm, int *wts, int *ofm)
{
  int err = 0;
  for (uint32_t i = 0; i < 16 * 2; i++) {
    auto exp = ifm[i] + 2 * wts[i % 16];
    if (ofm[i] != exp) {
      std::cout << "error@" << i <<": " << ofm[i] << ", expecting: " << exp << std::endl;
      err++;
    }
  }

  if (err)
    throw std::runtime_error("result mis-match");
  else
    std::cout << "result matched" << std::endl;
}

} // namespace

void
TEST_shim_umq_remote_barrier(device::id_type id, std::shared_ptr<device> sdev, const std::vector<uint64_t>& arg)
{
  auto dev = sdev.get();

  auto wrk = get_xclbin_workspace(dev);
  auto elf = wrk + "/remote_barrier.elf";
  auto instr_size = exec_buf::get_ctrl_code_size(elf);
  bo bo_ctrl_code{dev, instr_size, XCL_BO_FLAGS_EXECBUF};
  bo bo_exec_buf{dev, 0x1000ul, XCL_BO_FLAGS_EXECBUF};

  {
    hw_ctx hwctx{dev, "remote_barrier.xclbin"};
    auto hwq = hwctx.get()->get_hw_queue();
    auto cu_idx = hwctx.get()->open_cu_context("dpu:remote_barrier");

    for (int i = 0; i < 3; i++) {
      std::cout << "=== " << __func__ << " round: " << i << std::endl;
      prepare_basic_cmd(bo_exec_buf, elf, bo_ctrl_code);
      exec_buf::set_cu_idx(bo_exec_buf, cu_idx);
      umq_cmd_submit(hwq, bo_exec_buf);
      umq_cmd_wait(hwq, bo_exec_buf, 600000 /* 600 sec, some simnow server are slow */);
      std::cout << "PASS\n" << std::endl;
    }
  }
}
void
TEST_shim_umq_ddr_memtile(device::id_type id, std::shared_ptr<device> sdev, const std::vector<uint64_t>& arg)
{
  auto dev = sdev.get();

  bo bo_data{dev, sizeof(uint32_t), XCL_BO_FLAGS_HOST_ONLY};
  auto p = bo_data.map();
  p[0] = 0xabcdabcd;

  auto wrk = get_xclbin_workspace(dev);
  auto elf = wrk + "/ddr_memtile.elf";
  auto instr_size = exec_buf::get_ctrl_code_size(elf);
  bo bo_ctrl_code{dev, instr_size, XCL_BO_FLAGS_CACHEABLE};
  bo bo_exec_buf{dev, 0x1000ul, XCL_BO_FLAGS_EXECBUF};

  {
    hw_ctx hwctx{dev, "ddr_memtile.xclbin"};
    auto hwq = hwctx.get()->get_hw_queue();
    auto cu_idx = hwctx.get()->open_cu_context("dpu:move_ddr_memtile");

    for (int i = 0; i < 3; i++) {
      std::cout << "=== " << __func__ << " round: " << i << std::endl;
      prepare_ddr_cmd(bo_exec_buf, elf, bo_ctrl_code, bo_data);
      exec_buf::set_cu_idx(bo_exec_buf, cu_idx);
      umq_cmd_submit(hwq, bo_exec_buf);
      umq_cmd_wait(hwq, bo_exec_buf, 600000 /* 600 sec, some simnow server are slow */);
      std::cout << "PASS\n" << std::endl;
    }
  }
}

void
TEST_shim_umq_memtiles(device::id_type id, std::shared_ptr<device> sdev, const std::vector<uint64_t>& arg)
{
  auto dev = sdev.get();

  auto wrk = get_xclbin_workspace(dev);
  auto elf = wrk + "/move_memtiles.elf";
  auto instr_size = exec_buf::get_ctrl_code_size(elf);
  bo bo_ctrl_code{dev, instr_size, XCL_BO_FLAGS_EXECBUF};
  bo bo_exec_buf{dev, 0x1000ul, XCL_BO_FLAGS_EXECBUF};

  {
    hw_ctx hwctx{dev, "move_memtiles.xclbin"};
    auto hwq = hwctx.get()->get_hw_queue();
    auto cu_idx = hwctx.get()->open_cu_context("dpu:move_memtiles");

    for (int i = 0; i < 3; i++) {
      std::cout << "=== " << __func__ << " round: " << i << std::endl;
      prepare_basic_cmd(bo_exec_buf, elf, bo_ctrl_code);
      exec_buf::set_cu_idx(bo_exec_buf, cu_idx);
      umq_cmd_submit(hwq, bo_exec_buf);
      umq_cmd_wait(hwq, bo_exec_buf, 600000 /* 600 sec, some simnow server are slow */);
      std::cout << "PASS\n" << std::endl;
    }
  }
}

void
TEST_shim_umq_vadd(device::id_type id, std::shared_ptr<device> sdev, const std::vector<uint64_t>& arg)
{
  auto dev = sdev.get();
  const size_t IFM_BYTE_SIZE = 16 * 16 * sizeof (uint32_t);
  const size_t WTS_BYTE_SIZE = 4 * 4 * sizeof (uint32_t);
  const size_t OFM_BYTE_SIZE = 16 * 16 * sizeof (uint32_t);
  bo bo_ifm{dev, IFM_BYTE_SIZE, XCL_BO_FLAGS_HOST_ONLY};
  bo bo_wts{dev, WTS_BYTE_SIZE, XCL_BO_FLAGS_HOST_ONLY};
  bo bo_ofm{dev, OFM_BYTE_SIZE, XCL_BO_FLAGS_HOST_ONLY};
  std::cout << "Allocated vadd ifm, wts and ofm BOs" << std::endl;

  auto wrk = get_xclbin_workspace(dev);
  auto elf = wrk + "/vadd.elf";
  auto instr_size = exec_buf::get_ctrl_code_size(elf);
  bo bo_ctrl_code{dev, instr_size, XCL_BO_FLAGS_CACHEABLE};
  bo bo_exec_buf{dev, 0x1000ul, XCL_BO_FLAGS_EXECBUF};
  prepare_vadd_cmd(bo_exec_buf, elf, bo_ctrl_code, bo_ifm, bo_wts, bo_ofm);

  // Obtain no-op control code
  // ASM code:
  // START_JOB 0
  // END_JOB
  // EOF
  uint32_t nop_ctrlcode[] =
    { 0x0000FFFF, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x0000000C, 0x00000007, 0x000000FF };
  bo bo_nop_ctrl_code{dev, 0x1000UL, XCL_BO_FLAGS_EXECBUF};
  std::memcpy(bo_nop_ctrl_code.map(), nop_ctrlcode, sizeof(nop_ctrlcode));
  std::cout << "Obtained nop ctrl-code BO" << std::endl;

  {
    hw_ctx hwctx{dev, "vadd.xclbin"};
    auto hwq = hwctx.get()->get_hw_queue();
    auto cu_idx = hwctx.get()->open_cu_context("dpu:vadd");
    exec_buf::set_cu_idx(bo_exec_buf, cu_idx);

    for (int i = 0; i < 1; i++) {
      sleep(5);
      std::cout << "Running vadd command" << std::endl;
      init_umq_vadd_buffers<bo>(bo_ifm, bo_wts, bo_ofm);
      umq_cmd_submit(hwq, bo_exec_buf);
      umq_cmd_wait(hwq, bo_exec_buf, 600000 /* 600 sec, some simnow server are slow */);
      check_umq_vadd_result(bo_ifm.map(), bo_wts.map(), bo_ofm.map());

      // noop ctrlcode is not updated yet.
      //sleep(5);
      //std::cout << "Running nop command" << std::endl;
      //umq_cmd_submit(hwq, cu_idx.domain_index, bo_exec_buf, bo_nop_ctrl_code);
      //umq_cmd_wait(hwq, exec_buf_bo, 600000 /* 600 sec, some simnow server are slow */);
    }
  }
}

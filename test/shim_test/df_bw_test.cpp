// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026, Advanced Micro Devices, Inc. All rights reserved.

#include "io.h"
#include "dev_info.h"
#include "exec_buf.h"

#include "core/common/device.h"
#include "core/include/ert.h"
#include "core/include/xrt/detail/xrt_mem.h"

#include <chrono>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>


constexpr const char* df_bw_tag = "df_bw";

namespace {

/*
 * df_bw loopback verify: output must equal input word-for-word.
 * Uses output BO size so both npu4 and npu3 classes share this implementation.
 */
void
df_bw_verify(std::array<io_test_bo, IO_TEST_BO_MAX_TYPES>& bos)
{
  auto* cpkt = reinterpret_cast<ert_start_kernel_cmd*>(bos[IO_TEST_BO_CMD].tbo->map());
  if (cpkt->state != ERT_CMD_STATE_COMPLETED)
    throw std::runtime_error("df_bw: command did not complete, state=" +
                             std::to_string(cpkt->state));

  auto* in_p  = reinterpret_cast<uint32_t*>(bos[IO_TEST_BO_INPUT].tbo->map());
  auto* out_p = reinterpret_cast<uint32_t*>(bos[IO_TEST_BO_OUTPUT].tbo->map());
  auto nwords = bos[IO_TEST_BO_OUTPUT].tbo->size() / sizeof(uint32_t);

  for (size_t i = 0; i < nwords; i++) {
    if (out_p[i] != in_p[i])
      throw std::runtime_error("df_bw: output mismatch at word " + std::to_string(i));
  }
}

/*
 * df_bw_io_test_bo_set - shim DMA loopback for npu4 (PARTIAL_ELF flow)
 *
 * Uses df_bw.xclbin + df_bw.elf (same binaries as xrt-smi validate).
 * ELF relocations: arg "3" = ifm, arg "5" = ofm (no reloc for arg "4").
 */
class df_bw_io_test_bo_set : public elf_io_test_bo_set
{
  static constexpr flow_type s_flow = PARTIAL_ELF;
public:
  df_bw_io_test_bo_set(device *dev)
    : elf_io_test_bo_set(dev, df_bw_tag, &s_flow)
  {
    constexpr size_t buf_size = 1UL * 1024 * 1024 * 1024;  // 1 GB
    m_bo_array[IO_TEST_BO_INPUT].tbo  = std::make_shared<bo>(dev, buf_size);
    m_bo_array[IO_TEST_BO_OUTPUT].tbo = std::make_shared<bo>(dev, buf_size);
  }

  void
  init_cmd(hw_ctx& hwctx, bool dump) override
  {
    exec_buf ebuf(*m_bo_array[IO_TEST_BO_CMD].tbo.get(), ERT_START_NPU);
    ebuf.set_cu_idx(get_cu_idx(hwctx));

    ebuf.add_arg_64(3);                                          // arg 0: host_app
    ebuf.add_arg_64(0);                                          // arg 1: unused
    ebuf.add_arg_32(0);                                          // arg 2: unused
    ebuf.add_arg_bo(*m_bo_array[IO_TEST_BO_INPUT].tbo.get());   // arg 3: ifm (patched)
    ebuf.add_arg_64(0);                                          // arg 4: wts (no reloc)
    ebuf.add_arg_bo(*m_bo_array[IO_TEST_BO_OUTPUT].tbo.get());  // arg 5: ofm (patched)
    ebuf.add_arg_64(0);                                          // arg 6: unused
    ebuf.add_arg_64(0);                                          // arg 7: unused

    if (dump)
      ebuf.dump();

    ebuf.add_ctrl_bo(*m_bo_array[IO_TEST_BO_INSTRUCTION].tbo.get());
    ebuf.patch_ctrl_code(*m_bo_array[IO_TEST_BO_INSTRUCTION].tbo.get(),
                         elf_patcher::buf_type::ctrltext, m_elf,
                         elf_int::no_ctrl_code_id);

    io_test_bo_set_base::init_cmd(hwctx, dump);
  }

  void
  verify_result() override
  {
    df_bw_verify(m_bo_array);
  }
};

/*
 * df_bw_elf_io_test_bo_set - shim DMA loopback for npu3/aie4 (FULL_ELF flow)
 *
 * ELF argument layout (ERT_START_DPU, patched via .rela.dyn):
 *   arg "0": ifm, arg "1": ofm
 */
class df_bw_elf_io_test_bo_set : public io_test_bo_set_base
{
  static constexpr flow_type s_flow = FULL_ELF;
public:
  df_bw_elf_io_test_bo_set(device *dev)
    : io_test_bo_set_base(dev, df_bw_tag, &s_flow)
  {
    constexpr size_t buf_size = 0x3ffc0000UL;  // ~1023.75 MB
    m_elf = xrt::elf(get_binary_path(dev, df_bw_tag, &s_flow));
    try {
      auto kname = get_kernel_name(dev, df_bw_tag, &s_flow);
      m_kernel_index = m_elf.get_handle()->get_ctrlcode_id(kname);
    } catch (...) {
      m_kernel_index = elf_int::no_ctrl_code_id;
    }

    m_bo_array[IO_TEST_BO_CMD].tbo = std::make_shared<bo>(dev, 0x1000ul, XCL_BO_FLAGS_EXECBUF);
    create_ctrl_bo_from_elf(m_bo_array[IO_TEST_BO_INSTRUCTION], elf_patcher::buf_type::ctrltext);
    m_bo_array[IO_TEST_BO_INPUT].tbo  = std::make_shared<bo>(dev, buf_size);
    m_bo_array[IO_TEST_BO_OUTPUT].tbo = std::make_shared<bo>(dev, buf_size);
  }

  void
  init_cmd(hw_ctx& hwctx, bool dump) override
  {
    exec_buf ebuf(*m_bo_array[IO_TEST_BO_CMD].tbo.get(), ERT_START_DPU);
    xrt_core::cuidx_type cu_idx{0};
    ebuf.set_cu_idx(cu_idx);

    ebuf.add_arg_64(2);
    ebuf.add_arg_bo(*m_bo_array[IO_TEST_BO_INPUT].tbo.get(),  "0");  // ifm
    ebuf.add_arg_bo(*m_bo_array[IO_TEST_BO_OUTPUT].tbo.get(), "1");  // ofm

    ebuf.add_ctrl_bo(*m_bo_array[IO_TEST_BO_INSTRUCTION].tbo.get());
    ebuf.patch_ctrl_code(*m_bo_array[IO_TEST_BO_INSTRUCTION].tbo.get(),
                         elf_patcher::buf_type::ctrltext, m_elf, m_kernel_index);

    if (dump)
      ebuf.dump();

    io_test_bo_set_base::init_cmd(hwctx, dump);
  }

  void
  verify_result() override
  {
    df_bw_verify(m_bo_array);
  }
};

} // namespace

void
TEST_df_bw(device::id_type id, std::shared_ptr<device>& sdev, arg_type& arg)
{
  auto dev = sdev.get();

  const auto& info = get_binary_info(dev, df_bw_tag, nullptr);

  std::unique_ptr<io_test_bo_set_base> bo_set;
  if (info.flow == PARTIAL_ELF)
    bo_set = std::make_unique<df_bw_io_test_bo_set>(dev);
  else
    bo_set = std::make_unique<df_bw_elf_io_test_bo_set>(dev);

  auto& bos   = bo_set->get_bos();
  auto* in_p  = reinterpret_cast<uint32_t*>(bos[IO_TEST_BO_INPUT].tbo->map());
  auto* out_p = reinterpret_cast<uint32_t*>(bos[IO_TEST_BO_OUTPUT].tbo->map());
  auto nwords = bos[IO_TEST_BO_INPUT].tbo->size() / sizeof(uint32_t);

  for (size_t i = 0; i < nwords; i++) in_p[i]  = static_cast<uint32_t>(i);
  for (size_t i = 0; i < nwords; i++) out_p[i]  = 0xdeadbeef;

  constexpr int iterations = 10;
  /* Run loop — create hwctx and iterate iterations times */
  hw_ctx hwctx{dev, df_bw_tag, &info.flow};
  auto hwq = hwctx.get()->get_hw_queue();
  auto cbo = bos[IO_TEST_BO_CMD].tbo.get();

  bo_set->init_cmd(hwctx, false);
  bo_set->sync_before_run();

  unsigned long long total_ns = 0;
  for (int i = 0; i < iterations; i++) {
    bo_set->reset_cmd_header();
    auto start = std::chrono::high_resolution_clock::now();
    hwq->submit_command(cbo->get());
    hwq->wait_command(cbo->get(), WAIT_CMD_NO_TIMEOUT);
    auto end = std::chrono::high_resolution_clock::now();
    total_ns += std::chrono::duration_cast<std::chrono::nanoseconds>(end - start).count();
  }

  bo_set->sync_after_run();
  bo_set->verify_result();

  auto buf_size = bos[IO_TEST_BO_INPUT].tbo->size();
  auto avg_us   = total_ns / iterations / 1000;
  double bw     = (buf_size * 2.0 * iterations * 1e9) /
                  (total_ns * 1024.0 * 1024 * 1024);
  std::cout << "df_bw: " << iterations << " iterations"
            << ", avg latency: " << avg_us << " us"
            << ", bandwidth: " << bw << " GB/s" << std::endl;
}

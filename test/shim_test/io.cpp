// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2024, Advanced Micro Devices, Inc. All rights reserved.

#include "io.h"
#include "hwctx.h"
#include "exec_buf.h"
#include "io_config.h"

#include <string>
#include <regex>

using namespace xrt_core;

namespace {

const char *io_test_bo_type_names[] = {
  "IO_TEST_BO_CMD",
  "IO_TEST_BO_INSTRUCTION",
  "IO_TEST_BO_INPUT",
  "IO_TEST_BO_PARAMETERS",
  "IO_TEST_BO_OUTPUT",
  "IO_TEST_BO_INTERMEDIATE",
  "IO_TEST_BO_MC_CODE",
  "IO_TEST_BO_BAD_INSTRUCTION",
};

std::string
find_first_match_ip_name(device* dev, const std::string& pattern)
{
  for (auto& ip : get_xclbin_ip_name2index(dev)) {
    const std::string& name = ip.first;
    if (std::regex_match(name, std::regex(pattern))) {
      return name;
    }
  }
  return ""; // Return an empty string if no match is found
}

}

void
io_test_bo_set::
init_sizes()
{
  // Should only need to load and init sizes once in case we reuse BO set.
  if (m_bo_array[IO_TEST_BO_CMD].size)
    return;

  m_bo_array[IO_TEST_BO_CMD].size = 0x1000;

  auto instr_word_size = get_instr_size(m_local_data_path + instr_file);
  m_bo_array[IO_TEST_BO_INSTRUCTION].size = instr_word_size * sizeof(int32_t);
  if (m_bo_array[IO_TEST_BO_INSTRUCTION].size == 0)
    throw std::runtime_error("instruction size cannot be 0");

  // Loading other sizes
  auto tp = parse_config_file(m_local_data_path + config_file);
  m_bo_array[IO_TEST_BO_INPUT].size = IFM_SIZE(tp);
  m_bo_array[IO_TEST_BO_INPUT].init_offset = IFM_DIRTY_BYTES(tp);
  m_bo_array[IO_TEST_BO_PARAMETERS].size = PARAM_SIZE(tp);
  m_bo_array[IO_TEST_BO_OUTPUT].size = OFM_SIZE(tp);
  m_bo_array[IO_TEST_BO_INTERMEDIATE].size = INTER_SIZE(tp);
  // Do not support patching MC_CODE. */
  if (MC_CODE_SIZE(tp))
    throw std::runtime_error("MC_CODE_SIZE is non zero!!!");
  m_bo_array[IO_TEST_BO_MC_CODE].size = DUMMY_MC_CODE_BUFFER_SIZE;
}

void
io_test_bo_set::
alloc_bos()
{
  for (int i = 0; i < IO_TEST_BO_MAX_TYPES; i++) {
    io_test_bo *ibo = &m_bo_array[i];
    switch(i) {
    case IO_TEST_BO_CMD:
      ibo->tbo = std::make_shared<bo>(m_dev, ibo->size, XCL_BO_FLAGS_EXECBUF);
      break;
    case IO_TEST_BO_INSTRUCTION:
      ibo->tbo = std::make_shared<bo>(m_dev, ibo->size, XCL_BO_FLAGS_CACHEABLE);
      break;
    default:
      ibo->tbo = std::make_shared<bo>(m_dev, ibo->size);
      break;
    }
  }
}

void
io_test_bo_set::
init_args()
{
  for (int i = 0; i < IO_TEST_BO_MAX_TYPES; i++) {
    io_test_bo *ibo = &m_bo_array[i];
    switch(i) {
    case IO_TEST_BO_INSTRUCTION:
      read_instructions_from_txt(m_local_data_path + instr_file, ibo->tbo->map());
      break;
    case IO_TEST_BO_INPUT:
      read_data_from_bin(m_local_data_path + ifm_file, ibo->init_offset,
        ibo->tbo->size() - ibo->init_offset, ibo->tbo->map());
      break;
    case IO_TEST_BO_PARAMETERS:
      read_data_from_bin(m_local_data_path + param_file, 0, ibo->tbo->size(), ibo->tbo->map());
      break;
    default:
      break;
    }
  }
}

io_test_bo_set::
io_test_bo_set(device* dev, const std::string& local_data_path) :
  m_bo_array{}
  , m_local_data_path(local_data_path)
  , m_dev(dev)
{
  init_sizes();
  alloc_bos();
  init_args();
}

void
io_test_bo_set::
sync_before_run()
{
  for (int i = 0; i < IO_TEST_BO_MAX_TYPES; i++) {
    io_test_bo *ibo = &m_bo_array[i];
    switch(i) {
    case IO_TEST_BO_INPUT:
    case IO_TEST_BO_INSTRUCTION:
    case IO_TEST_BO_PARAMETERS:
    case IO_TEST_BO_MC_CODE:
      ibo->tbo->get()->sync(buffer_handle::direction::host2device, ibo->tbo->size(), 0);
      break;
    default:
      break;
    }
  }
}

void
io_test_bo_set::
sync_after_run()
{
  for (int i = 0; i < IO_TEST_BO_MAX_TYPES; i++) {
    io_test_bo *ibo = &m_bo_array[i];
    switch(i) {
    case IO_TEST_BO_OUTPUT:
    case IO_TEST_BO_INTERMEDIATE:
      ibo->tbo->get()->sync(buffer_handle::direction::device2host, ibo->tbo->size(), 0);
      break;
    default:
      break;
    }
  }
}

void
io_test_bo_set::
init_cmd(xrt_core::cuidx_type idx, bool dump)
{
  exec_buf ebuf(*m_bo_array[IO_TEST_BO_CMD].tbo.get(), ERT_START_CU);

  ebuf.set_cu_idx(idx);
  ebuf.add_arg_64(1);
  ebuf.add_arg_bo(*m_bo_array[IO_TEST_BO_INPUT].tbo.get());
  ebuf.add_arg_bo(*m_bo_array[IO_TEST_BO_PARAMETERS].tbo.get());
  ebuf.add_arg_bo(*m_bo_array[IO_TEST_BO_OUTPUT].tbo.get());
  ebuf.add_arg_bo(*m_bo_array[IO_TEST_BO_INTERMEDIATE].tbo.get());
  ebuf.add_arg_bo(*m_bo_array[IO_TEST_BO_INSTRUCTION].tbo.get());
  ebuf.add_arg_32(m_bo_array[IO_TEST_BO_INSTRUCTION].tbo->size() / sizeof(int32_t));
  ebuf.add_arg_bo(*m_bo_array[IO_TEST_BO_MC_CODE].tbo.get());
  if (dump)
    ebuf.dump();
}

// For debug only
void
io_test_bo_set::
dump_content()
{
  for (int i = 0; i < IO_TEST_BO_MAX_TYPES; i++) {
    auto ibo = m_bo_array[i].tbo.get();
    auto ibo_p = reinterpret_cast<int8_t *>(ibo->map());
    std::string p("/tmp/");
    p += io_test_bo_type_names[i] + std::to_string(getpid());
    dump_buf_to_file(ibo_p, ibo->size(), p);
    std::cout << "Dumping BO to: " << p << std::endl;
  }
}

void
io_test_bo_set::
verify_result()
{
  auto ofm_bo = m_bo_array[IO_TEST_BO_OUTPUT].tbo.get();
  auto ofm_p = reinterpret_cast<int8_t *>(ofm_bo->map());

  if (verify_output(ofm_p, m_local_data_path))
    throw std::runtime_error("Test failed!!!");
}

const char *
io_test_bo_set::
bo_type2name(int type)
{
  return io_test_bo_type_names[type];
}

void
io_test_bo_set::
run(xrt_core::fence_handle* fence, bool no_check_result)
{
  hw_ctx hwctx{m_dev};
  auto hwq = hwctx.get()->get_hw_queue();
  auto ip_name = find_first_match_ip_name(m_dev, "DPU.*");
  if (ip_name.empty())
    throw std::runtime_error("Cannot find any kernel name matched DPU.*");
  auto cu_idx = hwctx.get()->open_cu_context(ip_name);
  std::cout << "Found kernel: " << ip_name << " with cu index " << cu_idx.index << std::endl;

  init_cmd(cu_idx, false);
  sync_before_run();

  auto cbo = m_bo_array[IO_TEST_BO_CMD].tbo.get();
  auto chdl = cbo->get();
  if (fence)
    hwq->submit_wait(fence);
  hwq->submit_command(chdl);
  hwq->wait_command(chdl, 5000);
  auto cpkt = reinterpret_cast<ert_start_kernel_cmd *>(cbo->map());
  if (cpkt->state != ERT_CMD_STATE_COMPLETED)
    throw std::runtime_error("Command error");

  sync_after_run();
  if (!no_check_result)
    verify_result();
}

void
io_test_bo_set::
run()
{
  run(nullptr, false);
}

void
io_test_bo_set::
run(bool no_check_result)
{
  run(nullptr, no_check_result);
}

std::array<io_test_bo, IO_TEST_BO_MAX_TYPES>&
io_test_bo_set::
get_bos()
{
  return m_bo_array;
}

// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2024, Advanced Micro Devices, Inc. All rights reserved.

#include "bo.h"
#include "2proc.h"
#include "dev_info.h"
#include "exec_buf.h"
#include "io_config.h"

#include "core/common/system.h"
#include <algorithm>

namespace {

using namespace xrt_core;
using arg_type = const std::vector<uint64_t>;
std::string local_data_path;

enum {
  IO_TEST_BO_CMD = 0,
  IO_TEST_BO_INSTRUCTION,
  IO_TEST_BO_INPUT,
  IO_TEST_BO_PARAMETERS,
  IO_TEST_BO_OUTPUT,
  IO_TEST_BO_INTERMEDIATE,
  IO_TEST_BO_MC_CODE,
  IO_TEST_BO_MAX_TYPES
};

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

struct io_test_bo {
  size_t size;
  size_t init_offset;
  std::shared_ptr<bo> tbo;
} io_test_bos[2]; // Two sets of commands in total

using io_test_bo_set = std::array<io_test_bo, IO_TEST_BO_MAX_TYPES>;

void
bo_set_init_size(io_test_bo_set& io_test_bos)
{
  // Should only need to load and init sizes once.
  if (io_test_bos[IO_TEST_BO_CMD].size)
    return;
  io_test_bos[IO_TEST_BO_CMD].size = 0x1000;

  // Loading instruction size
  auto instr_word_size = get_instr_size(local_data_path + instr_file);
  io_test_bos[IO_TEST_BO_INSTRUCTION].size = instr_word_size * sizeof(int32_t);

  // Loading other sizes
  auto tp = parse_config_file(local_data_path + config_file);

  // Test case design relies on input ad output buffer to be of same size
  io_test_bos[IO_TEST_BO_INPUT].size = std::max(IFM_SIZE(tp), OFM_SIZE(tp));
  io_test_bos[IO_TEST_BO_OUTPUT].size = io_test_bos[IO_TEST_BO_INPUT].size;

  io_test_bos[IO_TEST_BO_INPUT].init_offset = IFM_DIRTY_BYTES(tp);
  io_test_bos[IO_TEST_BO_PARAMETERS].size = PARAM_SIZE(tp);
  io_test_bos[IO_TEST_BO_INTERMEDIATE].size = INTER_SIZE(tp);
  io_test_bos[IO_TEST_BO_MC_CODE].size = DUMMY_MC_CODE_BUFFER_SIZE;
}

void
bo_set_alloc_bo(io_test_bo_set& io_test_bos, device* dev)
{
  for (int i = 0; i < IO_TEST_BO_MAX_TYPES; i++) {
    io_test_bo *ibo = &io_test_bos[i];
    switch(i) {
    case IO_TEST_BO_CMD:
      ibo->tbo = std::make_shared<bo>(dev, ibo->size, XCL_BO_FLAGS_EXECBUF);
      break;
    case IO_TEST_BO_INSTRUCTION:
      ibo->tbo = std::make_shared<bo>(dev, ibo->size, XCL_BO_FLAGS_CACHEABLE);
      break;
    default:
      ibo->tbo = std::make_shared<bo>(dev, ibo->size);
      break;
    }
  }
}

void
bo_set_init_arg(io_test_bo_set& io_test_bos)
{
  for (int i = 0; i < IO_TEST_BO_MAX_TYPES; i++) {
    io_test_bo *ibo = &io_test_bos[i];
    switch(i) {
    case IO_TEST_BO_INSTRUCTION: {
      auto instruction_p = ibo->tbo->map();
      read_instructions_from_txt(local_data_path + instr_file, instruction_p);
      break;
    }
    case IO_TEST_BO_INPUT:
      read_data_from_bin(local_data_path + ifm_file, ibo->init_offset,
        ibo->size - ibo->init_offset, ibo->tbo->map());
      break;
    case IO_TEST_BO_PARAMETERS:
      read_data_from_bin(local_data_path + param_file, 0, ibo->tbo->size(), ibo->tbo->map());
      break;
    default:
      break;
    }
  }
}

void
bo_set_sync_before_run(io_test_bo_set& io_test_bos)
{
  for (int i = 0; i < IO_TEST_BO_MAX_TYPES; i++) {
    io_test_bo *ibo = &io_test_bos[i];
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
bo_set_sync_after_run(io_test_bo_set& io_test_bos)
{
  for (int i = 0; i < IO_TEST_BO_MAX_TYPES; i++) {
    io_test_bo *ibo = &io_test_bos[i];
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
bo_set_init_cmd(io_test_bo_set& io_test_bos, xrt_core::cuidx_type idx)
{
  exec_buf ebuf(*io_test_bos[IO_TEST_BO_CMD].tbo.get(), ERT_START_CU);

  ebuf.set_cu_idx(idx);
  ebuf.add_arg_64(1);
  ebuf.add_arg_bo(*io_test_bos[IO_TEST_BO_INPUT].tbo.get());
  ebuf.add_arg_bo(*io_test_bos[IO_TEST_BO_PARAMETERS].tbo.get());
  ebuf.add_arg_bo(*io_test_bos[IO_TEST_BO_OUTPUT].tbo.get());
  ebuf.add_arg_bo(*io_test_bos[IO_TEST_BO_INTERMEDIATE].tbo.get());
  ebuf.add_arg_bo(*io_test_bos[IO_TEST_BO_INSTRUCTION].tbo.get());
  ebuf.add_arg_32(io_test_bos[IO_TEST_BO_INSTRUCTION].tbo->size() / sizeof(int32_t));
  ebuf.add_arg_bo(*io_test_bos[IO_TEST_BO_MC_CODE].tbo.get());
}

void
bo_set_verify_result(io_test_bo_set& io_test_bos)
{
  auto ofm_bo = io_test_bos[IO_TEST_BO_OUTPUT].tbo.get();
  auto ofm_p = reinterpret_cast<int8_t *>(ofm_bo->map());

  if (verify_output(ofm_p, local_data_path))
    throw std::runtime_error("Test failed!!!");
}

class test_2proc_cmd_fence : public test_2proc
{
public:
  test_2proc_cmd_fence(device::id_type id) : test_2proc(id)
  {}

private:
  struct ipc_data {
    pid_t pid;
    shared_handle::export_handle hdl;
  };

  void
  run_test_parent() override
  {
    std::cout << "Running parent test..." << std::endl;

    ipc_data idata = {};
    recv_ipc_data(&idata, sizeof(idata));
    std::cout << "Received BO " << idata.hdl << " from PID " << idata.pid;
    std::cout << std::endl;

    bool success = true;
    // TODO
    send_ipc_data(&success, sizeof(success));
  }

  void
  run_test_child() override
  {
    std::cout << "Running child test..." << std::endl;

    auto dev = get_userpf_device(get_dev_id());
    ipc_data idata = { getpid(), 0 };
    send_ipc_data(&idata, sizeof(idata));
    bool success;
    recv_ipc_data(&success, sizeof(success));
  }
};

}

void
TEST_cmd_fence(device::id_type id, std::shared_ptr<device> sdev, arg_type& arg)
{
  local_data_path = get_xclbin_workspace(sdev.get()) + "/data/";

  // Can't fork with opened device.
  sdev.reset();

  test_2proc_cmd_fence t2p(id);
  t2p.run_test();
}

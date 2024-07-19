// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2024, Advanced Micro Devices, Inc. All rights reserved.

#include "bo.h"
#include "hwctx.h"
#include "speed.h"
#include "dev_info.h"
#include "exec_buf.h"
#include "io_param.h"
#include "io_config.h"

#include "core/common/device.h"
#include <string>
#include <regex>

using namespace xrt_core;
using arg_type = const std::vector<uint64_t>;

namespace {

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
  std::unique_ptr<bo> tbo;
};
using io_test_bo_set = std::array<io_test_bo, IO_TEST_BO_MAX_TYPES>;

void
io_test_parameter_init(int perf, int type, bool debug = false)
{
  io_test_parameters.perf = perf;
  io_test_parameters.type = type;
  io_test_parameters.debug = debug;
}

void
bo_set_init_size(io_test_bo_set& io_test_bos, std::string& local_data_path)
{
  // Should only need to load and init sizes once.
  if (io_test_bos[IO_TEST_BO_CMD].size)
    return;
  io_test_bos[IO_TEST_BO_CMD].size = 0x1000;

  // Loading instruction size
  size_t instr_word_size;
  if (io_test_parameters.type == IO_TEST_NOOP_RUN) {
    instr_word_size = 32;
  } else {
    auto instruction_file = local_data_path + instr_file;
    if (io_test_parameters.debug)
      std::cout << "Getting instruction BO size from " << instruction_file << std::endl;
    instr_word_size = get_instr_size(instruction_file);
  }
  // Loading other sizes
  auto bo_size_config_file = local_data_path + config_file;
  if (io_test_parameters.debug)
    std::cout << "Getting non-instruction BO sizes from " << bo_size_config_file << std::endl;
  auto tp = parse_config_file(bo_size_config_file);

  io_test_bos[IO_TEST_BO_INSTRUCTION].size = instr_word_size * sizeof(int32_t);
  io_test_bos[IO_TEST_BO_INPUT].size = IFM_SIZE(tp);
  io_test_bos[IO_TEST_BO_INPUT].init_offset = IFM_DIRTY_BYTES(tp);
  io_test_bos[IO_TEST_BO_PARAMETERS].size = PARAM_SIZE(tp);
  io_test_bos[IO_TEST_BO_OUTPUT].size = OFM_SIZE(tp);
  io_test_bos[IO_TEST_BO_INTERMEDIATE].size = INTER_SIZE(tp);
  io_test_bos[IO_TEST_BO_MC_CODE].size = MC_CODE_SIZE(tp);

  // Sanity test and dump
  if (io_test_bos[IO_TEST_BO_INSTRUCTION].size == 0)
    throw std::runtime_error("instruction size cannot be 0");
  if (io_test_parameters.debug) {
    for (int i = 0; i < IO_TEST_BO_MAX_TYPES; i++) {
      std::cout << io_test_bo_type_names[i] << "'s size and init_offset: "
                << io_test_bos[i].size << ", "
                << io_test_bos[i].init_offset
                << std::endl;
    }
  }
}

void
bo_set_alloc_bo(io_test_bo_set& io_test_bos, device* dev)
{
  for (int i = 0; i < IO_TEST_BO_MAX_TYPES; i++) {
    io_test_bo *ibo = &io_test_bos[i];
    switch(i) {
    case IO_TEST_BO_CMD:
      ibo->tbo = std::make_unique<bo>(dev, ibo->size, XCL_BO_FLAGS_EXECBUF);
      break;
    case IO_TEST_BO_INSTRUCTION:
      ibo->tbo = std::make_unique<bo>(dev, ibo->size, XCL_BO_FLAGS_CACHEABLE);
      break;
    case IO_TEST_BO_MC_CODE:
      ibo->tbo = std::make_unique<bo>(dev, std::max(ibo->size, DUMMY_MC_CODE_BUFFER_SIZE));
      break;
    default:
      ibo->tbo = std::make_unique<bo>(dev, ibo->size);
      break;
    }
  }
}

void
bo_set_init_arg(io_test_bo_set& io_test_bos, std::string& local_data_path)
{
  for (int i = 0; i < IO_TEST_BO_MAX_TYPES; i++) {
    io_test_bo *ibo = &io_test_bos[i];
    switch(i) {
    case IO_TEST_BO_INSTRUCTION:
      if (io_test_parameters.type == IO_TEST_NOOP_RUN) {
        std::memset(ibo->tbo->map(), 0, ibo->tbo->size());
      } else {
        auto instruction_p = ibo->tbo->map();
        read_instructions_from_txt(local_data_path + instr_file, instruction_p);
        if (io_test_parameters.type == IO_TEST_BAD_RUN) {
          std::memset(instruction_p, 0, ibo->tbo->size());
          // Error Event ID: 64
          // Expect "Row: 0, Col: 1, module 2, event ID 64, category 4" in dmesg
          instruction_p[0] = 0x02000000;
          instruction_p[1] = 0x00034008;
          instruction_p[2] = 0x00000040;
        }
      }
      break;
    case IO_TEST_BO_MC_CODE: {
      if (ibo->size != 0) {
        // Do not support patching MC_CODE. */
        throw std::runtime_error("MC_CODE_SIZE is non zero!!!");
      }
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
bo_set_init_cmd(io_test_bo_set& io_test_bos)
{
  exec_buf ebuf(*io_test_bos[IO_TEST_BO_CMD].tbo.get(), ERT_START_CU);

  ebuf.add_arg_64(1);
  ebuf.add_arg_bo(*io_test_bos[IO_TEST_BO_INPUT].tbo.get());
  ebuf.add_arg_bo(*io_test_bos[IO_TEST_BO_PARAMETERS].tbo.get());
  ebuf.add_arg_bo(*io_test_bos[IO_TEST_BO_OUTPUT].tbo.get());
  ebuf.add_arg_bo(*io_test_bos[IO_TEST_BO_INTERMEDIATE].tbo.get());
  ebuf.add_arg_bo(*io_test_bos[IO_TEST_BO_INSTRUCTION].tbo.get());
  ebuf.add_arg_32(io_test_bos[IO_TEST_BO_INSTRUCTION].tbo->size() / sizeof(int32_t));
  ebuf.add_arg_bo(*io_test_bos[IO_TEST_BO_MC_CODE].tbo.get());
  if (io_test_parameters.debug)
    ebuf.dump();
}

void
bo_set_init_cmd_cu_index(io_test_bo_set& io_test_bos, xrt_core::cuidx_type idx)
{
  exec_buf::set_cu_idx(*io_test_bos[IO_TEST_BO_CMD].tbo.get(), idx);
}

// For debug only
void
bo_set_dump_content(io_test_bo *io_test_bos)
{
  for (int i = 0; i < IO_TEST_BO_MAX_TYPES; i++) {
    auto ibo = io_test_bos[i].tbo.get();
    auto ibo_p = reinterpret_cast<int8_t *>(ibo->map());
    std::string p("/tmp/");
    dump_buf_to_file(ibo_p, ibo->size(), p + io_test_bo_type_names[i]);
  }
}

void
io_test_init_runlist_cmd(bo* cmd_bo, std::vector<bo*>& cmd_bos)
{
  auto cmd_packet = reinterpret_cast<ert_packet *>(cmd_bo->map());

  cmd_packet->state = ERT_CMD_STATE_NEW;
  cmd_packet->count = (cmd_bos.size() * sizeof(uint64_t) + sizeof(struct ert_cmd_chain_data)) / sizeof(uint32_t);
  cmd_packet->opcode = ERT_CMD_CHAIN;
  cmd_packet->type = ERT_SCU; /* Don't care? */

  auto payload = get_ert_cmd_chain_data(cmd_packet);
  payload->command_count = cmd_bos.size();
  payload->submit_index = 0;
  payload->error_index = 0;

  for (size_t i = 0; i < cmd_bos.size(); i++) {
    auto run_bo = cmd_bos[i];
    payload->data[i] = run_bo->get()->get_properties().kmhdl;
    cmd_bo->get()->bind_at(i, run_bo->get(), 0, run_bo->size());
  }
}

void
bo_set_verify_result(io_test_bo_set& io_test_bos, std::string& local_data_path)
{
  if (io_test_parameters.type == IO_TEST_NOOP_RUN)
    return;

  auto intr_bo = io_test_bos[IO_TEST_BO_INTERMEDIATE].tbo.get();
  auto inter_p = reinterpret_cast<int8_t *>(intr_bo->map());
  auto ofm_bo = io_test_bos[IO_TEST_BO_OUTPUT].tbo.get();
  auto ofm_p = reinterpret_cast<int8_t *>(ofm_bo->map());

  dump_buf_to_file(inter_p, intr_bo->size(), local_data_path + dump_inter_file);
  if (verify_output(ofm_p, local_data_path))
    throw std::runtime_error("Test failed!!!");
}

#define IO_TEST_TIMEOUT 5000 /* millisecond */
void
io_test_cmd_submit_and_wait_latency(
  hwqueue_handle *hwq,
  int total_cmd_submission,
  std::vector< std::pair<std::unique_ptr<bo>, ert_start_kernel_cmd *> >& cmdlist_bos
  )
{
  int completed = 0;
  int wait_idx = 0;

  while (completed < total_cmd_submission) {
    for (auto& cmd : cmdlist_bos) {
        hwq->submit_command(std::get<0>(cmd).get()->get());
        hwq->wait_command(std::get<0>(cmd).get()->get(), IO_TEST_TIMEOUT);
        if (std::get<1>(cmd)->state != ERT_CMD_STATE_COMPLETED)
          throw std::runtime_error("Command error");
        completed++;
        if (completed >= total_cmd_submission)
          break;
    }
  }
}

void
io_test_cmd_submit_and_wait_thruput(
  hwqueue_handle *hwq,
  int total_cmd_submission,
  std::vector< std::pair<std::unique_ptr<bo>, ert_start_kernel_cmd *> >& cmdlist_bos
  )
{
  int issued = 0;
  int completed = 0;
  int wait_idx = 0;

  for (auto& cmd : cmdlist_bos) {
      hwq->submit_command(std::get<0>(cmd).get()->get());
      issued++;
      if (issued >= total_cmd_submission)
        break;
  }

  while (completed < issued) {
    hwq->wait_command(std::get<0>(cmdlist_bos[wait_idx]).get()->get(), IO_TEST_TIMEOUT);
    if (std::get<1>(cmdlist_bos[wait_idx])->state != ERT_CMD_STATE_COMPLETED)
      throw std::runtime_error("Command error");
    completed++;

    if (issued < total_cmd_submission) {
      hwq->submit_command(std::get<0>(cmdlist_bos[wait_idx]).get()->get());
      issued++;
    }

    if (++wait_idx == cmdlist_bos.size())
      wait_idx = 0;
  }
}

std::string find_first_match_ip_name(device* dev, const std::string& pattern)
{
  for (auto& ip : get_xclbin_ip_name2index(dev)) {
    const std::string& name = ip.first;
    if (std::regex_match(name, std::regex(pattern))) {
      return name;
    }
  }
  return ""; // Return an empty string if no match is found
}

void
io_test(device::id_type id, device* dev, int total_hwq_submit, int num_cmdlist, int cmds_per_list)
{
  // Allocate set of BOs for command submission based on num_cmdlist and cmds_per_list
  // Intentionally this is done before context creation to make sure BO and context
  // are totally decoupled.
  auto wrk = get_xclbin_workspace(dev);
  auto local_data_path = wrk + "/data/";
  std::vector<io_test_bo_set> bo_set(num_cmdlist * cmds_per_list);
  for (auto& bos : bo_set) {
    bo_set_init_size(bos, local_data_path);
    bo_set_alloc_bo(bos, dev);
    bo_set_init_arg(bos, local_data_path);
    bo_set_sync_before_run(bos);
    bo_set_init_cmd(bos);
  }

  // Creating HW context for cmd submission
  hw_ctx hwctx{dev};
  auto hwq = hwctx.get()->get_hw_queue();
  auto ip_name = find_first_match_ip_name(dev, "DPU.*");
  if (ip_name.empty())
    throw std::runtime_error("Cannot find any kernel name matched DPU.*");
  auto cu_idx = hwctx.get()->open_cu_context(ip_name);
  std::cout << "Found kernel: " << ip_name << " with cu index " << cu_idx.index << std::endl;

  // Initialize CU index in the cmd BO
  for (auto& bos : bo_set)
    bo_set_init_cmd_cu_index(bos, cu_idx);

  // Creating list of commands to be submitted
  std::vector< std::pair<std::unique_ptr<bo>, ert_start_kernel_cmd *> > cmdlist_bos;
  if (cmds_per_list == 1) {
    // Single command per list, just send the command BO itself
    for (auto& bos : bo_set) {
      auto& cbo = bos[IO_TEST_BO_CMD].tbo;
      auto cmdpkt = reinterpret_cast<ert_start_kernel_cmd *>(cbo->map());
      cmdlist_bos.push_back( {std::move(cbo), cmdpkt} );
    }
  } else {
    // Multiple commands per list, create and send the chained command
    std::vector<bo*> tmp_cmd_bos;
    for (auto& bos : bo_set) {
      tmp_cmd_bos.push_back(bos[IO_TEST_BO_CMD].tbo.get());
      if ((tmp_cmd_bos.size() % cmds_per_list) == 0) {
        auto cbo = std::make_unique<bo>(dev, 0x1000ul, XCL_BO_FLAGS_EXECBUF);
        auto cmdpkt = reinterpret_cast<ert_start_kernel_cmd *>(cbo->map());
        io_test_init_runlist_cmd(cbo.get(), tmp_cmd_bos);
        tmp_cmd_bos.clear();
        cmdlist_bos.push_back( {std::move(cbo), cmdpkt} );
      }
    }
  }

  // Submit commands and wait for results
  auto start = clk::now();
  if (io_test_parameters.perf == IO_TEST_THRUPUT_PERF)
    io_test_cmd_submit_and_wait_thruput(hwq, total_hwq_submit, cmdlist_bos);
  else
    io_test_cmd_submit_and_wait_latency(hwq, total_hwq_submit, cmdlist_bos);
  auto end = clk::now();

  // Verify result
  for (auto& bos : bo_set) {
    bo_set_sync_after_run(bos);
    bo_set_verify_result(bos, local_data_path);
  }

  // Report the performance numbers
  if (io_test_parameters.perf != IO_TEST_NO_PERF) {
    auto duration_us = std::chrono::duration_cast<us_t>(end - start).count();
    auto cps = (total_hwq_submit * cmds_per_list * 1000000.0) / duration_us;
    auto latency_us = 1000000.0 / cps;
    std::cout << total_hwq_submit * cmds_per_list << " commands finished in "
              << duration_us << " us, " << cmds_per_list << " commands per list, "
              << cps << " Command/sec,"
              << " Average latency " << latency_us << " us" << std::endl;
  }
}

}

void
TEST_io(device::id_type id, std::shared_ptr<device> sdev, arg_type& arg)
{
  io_test_parameter_init(IO_TEST_NO_PERF, static_cast<unsigned int>(arg[0]));
  io_test(id, sdev.get(), 1, 1, arg[1]);
}

void
TEST_io_latency(device::id_type id, std::shared_ptr<device> sdev, arg_type& arg)
{
  io_test_parameter_init(IO_TEST_LATENCY_PERF, static_cast<unsigned int>(arg[0]));
  io_test(id, sdev.get(), 1000, 1, 1);
}

void
TEST_io_throughput(device::id_type id, std::shared_ptr<device> sdev, arg_type& arg)
{
  int num_bo_set = 256;
  int total_commands = 32000;
  const size_t max_cmd_per_list = 24;

  io_test_parameter_init(IO_TEST_THRUPUT_PERF, static_cast<unsigned int>(arg[0]));

  int cmds_per_list;
  for (cmds_per_list = 1; cmds_per_list <= 32; cmds_per_list *= 2) {
    if (cmds_per_list > max_cmd_per_list)
      cmds_per_list = max_cmd_per_list;
    int num_cmdlist = num_bo_set / cmds_per_list;
    int total_hwq_submit = total_commands / cmds_per_list;
    io_test(id, sdev.get(), total_hwq_submit, num_cmdlist, cmds_per_list);
  }
}


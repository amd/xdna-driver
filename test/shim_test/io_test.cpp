// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2024, Advanced Micro Devices, Inc. All rights reserved.

#include "io.h"
#include "hwctx.h"
#include "speed.h"
#include "dev_info.h"
#include "io_param.h"

#include "core/common/device.h"
#include <string>
#include <regex>

using namespace xrt_core;
using arg_type = const std::vector<uint64_t>;

namespace {

io_test_parameter io_test_parameters;

void
io_test_parameter_init(int perf, int type, bool debug = false)
{
  io_test_parameters.perf = perf;
  io_test_parameters.type = type;
  io_test_parameters.debug = debug;
}

io_test_bo_set
alloc_and_init_bo_set(device* dev, const std::string& local_data_path)
{
  io_test_bo_set boset{dev, local_data_path};
  auto bos = boset.get_bos();

  if (io_test_parameters.type == IO_TEST_NOOP_RUN) {
    // Preparing no-op kernel's special control code
    size_t sz = 32 * sizeof(int32_t);
    auto tbo = std::make_shared<bo>(dev, sz, XCL_BO_FLAGS_CACHEABLE);
    bos[IO_TEST_BO_INSTRUCTION].tbo = tbo;
    std::memset(tbo->map(), 0, sz);
  } else if (io_test_parameters.type == IO_TEST_BAD_RUN) {
    auto instruction_p = bos[IO_TEST_BO_INSTRUCTION].tbo->map();
    auto sz = bos[IO_TEST_BO_INSTRUCTION].tbo->size();
    std::memset(instruction_p, 0, sz);
    // Error Event ID: 64
    // Expect "Row: 0, Col: 1, module 2, event ID 64, category 4" in dmesg
    instruction_p[0] = 0x02000000;
    instruction_p[1] = 0x00034008;
    instruction_p[2] = 0x00000040;
  }

  if (io_test_parameters.debug) {
    for (int i = 0; i < IO_TEST_BO_MAX_TYPES; i++) {
      std::cout << io_test_bo_set::bo_type2name(i) << "'s size and init_offset: "
                << bos[i].tbo->size() << ", " << bos[i].init_offset << std::endl;
    }
  }

  return boset;
}

void
io_test_init_runlist_cmd(bo* cmd_bo, std::vector<bo*>& cmd_bos)
{
  auto cmd_packet = reinterpret_cast<ert_packet *>(cmd_bo->map());

  cmd_packet->state = ERT_CMD_STATE_NEW;
  cmd_packet->count = (cmd_bos.size() * sizeof(uint64_t) +
    sizeof(struct ert_cmd_chain_data)) / sizeof(uint32_t);
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

#define IO_TEST_TIMEOUT 5000 /* millisecond */
void
io_test_cmd_submit_and_wait_latency(
  hwqueue_handle *hwq,
  int total_cmd_submission,
  std::vector< std::pair<std::shared_ptr<bo>, ert_start_kernel_cmd *> >& cmdlist_bos
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
  std::vector< std::pair<std::shared_ptr<bo>, ert_start_kernel_cmd *> >& cmdlist_bos
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
  std::vector<io_test_bo_set> bo_set;
  for (int i = 0; i < num_cmdlist * cmds_per_list; i++)
    bo_set.push_back(std::move(alloc_and_init_bo_set(dev, local_data_path)));

  // Creating HW context for cmd submission
  hw_ctx hwctx{dev};
  auto hwq = hwctx.get()->get_hw_queue();
  auto ip_name = find_first_match_ip_name(dev, "DPU.*");
  if (ip_name.empty())
    throw std::runtime_error("Cannot find any kernel name matched DPU.*");
  auto cu_idx = hwctx.get()->open_cu_context(ip_name);
  std::cout << "Found kernel: " << ip_name << " with cu index " << cu_idx.index << std::endl;

  // Finalize cmd before submission
  for (auto& boset : bo_set) {
    boset.init_cmd(cu_idx, io_test_parameters.debug);
    boset.sync_before_run();
  }

  // Creating list of commands to be submitted
  std::vector< std::pair<std::shared_ptr<bo>, ert_start_kernel_cmd *> > cmdlist_bos;
  if (cmds_per_list == 1) {
    // Single command per list, just send the command BO itself
    for (auto& boset : bo_set) {
      auto& cbo = boset.get_bos()[IO_TEST_BO_CMD].tbo;
      auto cmdpkt = reinterpret_cast<ert_start_kernel_cmd *>(cbo->map());
      cmdlist_bos.push_back( {std::move(cbo), cmdpkt} );
    }
  } else {
    // Multiple commands per list, create and send the chained command
    std::vector<bo*> tmp_cmd_bos;
    for (auto& boset : bo_set) {
      tmp_cmd_bos.push_back(boset.get_bos()[IO_TEST_BO_CMD].tbo.get());
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
  if (io_test_parameters.type != IO_TEST_NOOP_RUN) {
    for (auto& boset : bo_set) {
      boset.sync_after_run();
      boset.verify_result();
    }
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
TEST_io_runlist_latency(device::id_type id, std::shared_ptr<device> sdev, arg_type& arg)
{
  io_test_parameter_init(IO_TEST_LATENCY_PERF, static_cast<unsigned int>(arg[0]));
  io_test(id, sdev.get(), 32000, 1,  1);
  io_test(id, sdev.get(), 16000, 1,  2);
  io_test(id, sdev.get(),  8000, 1,  4);
  io_test(id, sdev.get(),  4000, 1,  8);
  io_test(id, sdev.get(),  2000, 1, 16);
  io_test(id, sdev.get(),  1333, 1, 24);
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

void
TEST_noop_io_with_dup_bo(device::id_type id, std::shared_ptr<device> sdev, arg_type& arg)
{
  auto wrk = get_xclbin_workspace(sdev.get());
  io_test_bo_set boset{sdev.get(), wrk + "/data/"};

  // Use same BO for both input and output
  boset.get_bos()[IO_TEST_BO_OUTPUT].tbo = boset.get_bos()[IO_TEST_BO_INPUT].tbo;
  auto ibo = boset.get_bos()[IO_TEST_BO_INSTRUCTION].tbo;
  std::memset(ibo->map(), 0, ibo->size());
  boset.run(true);
}


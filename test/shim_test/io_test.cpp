// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2024-2026, Advanced Micro Devices, Inc. All rights reserved.

#include "io.h"
#include "hwctx.h"
#include "multi_threads.h"
#include "speed.h"
#include "dev_info.h"
#include "io_param.h"

#include "core/common/device.h"
#include <fstream>
#include <string>
#include <regex>
#include <unistd.h>

using namespace xrt_core;
using arg_type = const std::vector<uint64_t>;

namespace {

io_test_parameter io_test_parameters;

void
io_test_parameter_init(int perf, int type, int wait, bool debug = false)
{
  io_test_parameters.perf = perf;
  io_test_parameters.type = type;
  io_test_parameters.wait = wait;
  io_test_parameters.debug = debug;
}

std::unique_ptr<io_test_bo_set_base>
alloc_and_init_bo_set(device* dev, const char *tag, const flow_type* flow = nullptr)
{
  const auto& info = get_binary_info(dev, tag, flow);
  const std::string tag_str(tag ? tag : "");

  std::unique_ptr<io_test_bo_set_base> base;
  switch (info.flow) {
  case LEGACY:
    base = std::make_unique<io_test_bo_set>(dev);
    break;
  case PARTIAL_ELF:
    base = std::make_unique<elf_io_test_bo_set>(dev, tag_str, flow);
    break;
  case FULL_ELF:
    base = std::make_unique<elf_full_io_test_bo_set>(dev, tag_str, flow);
    break;
  case PREEMPT_PARTIAL_ELF:
  case PREEMPT_FULL_ELF:
    base = std::make_unique<elf_preempt_io_test_bo_set>(dev, tag_str, flow);
    break;
  default:
    throw std::runtime_error("Unknown flow type");
  }

  auto& bos = base->get_bos();

  if (io_test_parameters.type == IO_TEST_BAD_RUN) {
    if (info.flow != LEGACY)
      throw std::runtime_error("ELF flow can't support bad run");

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

  return base;
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

  cmd_bo->get()->reset();
  for (size_t i = 0; i < cmd_bos.size(); i++) {
    auto run_bo = cmd_bos[i];
    payload->data[i] = run_bo->get()->get_properties().kmhdl;
    cmd_bo->get()->bind_at(i, run_bo->get(), 0, run_bo->size());
  }
}

void io_test_cmd_wait(hwqueue_handle *hwq, std::shared_ptr<bo> bo)
{
    if (io_test_parameters.wait == IO_TEST_POLL_WAIT) {
      while(!hwq->poll_command(bo->get()));
    } else {
      hwq->wait_command(bo->get(), 0);
    }
}

static void
reset_cmd_headers_before_submit(
  std::vector<std::unique_ptr<io_test_bo_set_base>>& bo_set,
  size_t list_idx, int cmds_per_list, ert_start_kernel_cmd* cmd_pkt)
{
  if (cmd_pkt->opcode == ERT_CMD_CHAIN) {
    size_t start_idx = list_idx * cmds_per_list;
    size_t end_idx = std::min(start_idx + static_cast<size_t>(cmds_per_list), bo_set.size());
    for (size_t i = start_idx; i < end_idx; i++)
      bo_set[i]->reset_cmd_header();
  } else {
    bo_set[list_idx]->reset_cmd_header();
  }
}

void
io_test_cmd_submit_and_wait_latency(
  hwqueue_handle *hwq,
  int total_cmd_submission,
  std::vector< std::pair<std::shared_ptr<bo>, ert_start_kernel_cmd *> >& cmdlist_bos,
  std::vector< std::unique_ptr<io_test_bo_set_base> >& bo_set,
  int cmds_per_list
  )
{
  int completed = 0;

  while (completed < total_cmd_submission) {
    size_t cmd_idx = 0;
    for (auto& cmd : cmdlist_bos) {
      auto cmd_hdl = std::get<0>(cmd).get()->get();
      auto cmd_pkt = std::get<1>(cmd);

      reset_cmd_headers_before_submit(bo_set, cmd_idx, cmds_per_list, cmd_pkt);

      hwq->submit_command(cmd_hdl);
      io_test_cmd_wait(hwq, std::get<0>(cmd));

      if (cmd_pkt->state != ERT_CMD_STATE_COMPLETED)
        throw std::runtime_error("Command " + std::to_string(completed) +
                                 " failed, state=" + std::to_string(cmd_pkt->state));

      completed++;
      cmd_idx++;
      if (completed >= total_cmd_submission)
        break;
      cmd_pkt->state = ERT_CMD_STATE_NEW;
    }
  }
}

void
io_test_cmd_submit_and_wait_thruput(
  hwqueue_handle *hwq,
  int total_cmd_submission,
  std::vector< std::pair<std::shared_ptr<bo>, ert_start_kernel_cmd *> >& cmdlist_bos,
  std::vector< std::unique_ptr<io_test_bo_set_base> >& bo_set,
  int cmds_per_list
  )
{
  int issued = 0;
  int completed = 0;
  size_t wait_idx = 0;

  for (size_t i = 0; i < cmdlist_bos.size(); i++) {
    auto cmd_hdl = std::get<0>(cmdlist_bos[i]).get()->get();
    auto cmd_pkt = std::get<1>(cmdlist_bos[i]);

    cmd_pkt->state = ERT_CMD_STATE_NEW;
    hwq->submit_command(cmd_hdl);
    if (++issued >= total_cmd_submission)
      break;
  }

  while (completed < issued) {
    io_test_cmd_wait(hwq, std::get<0>(cmdlist_bos[wait_idx]));
    auto cmd_pkt = std::get<1>(cmdlist_bos[wait_idx]);
    if (cmd_pkt->state != ERT_CMD_STATE_COMPLETED)
      throw std::runtime_error("Command failed, state=" + std::to_string(cmd_pkt->state));
    completed++;

    if (issued < total_cmd_submission) {
      auto cmd_hdl = std::get<0>(cmdlist_bos[wait_idx]).get()->get();

      reset_cmd_headers_before_submit(bo_set, wait_idx, cmds_per_list, cmd_pkt);

      cmd_pkt->state = ERT_CMD_STATE_NEW;
      hwq->submit_command(cmd_hdl);
      issued++;
    }

    if (++wait_idx == cmdlist_bos.size())
      wait_idx = 0;
  }
}

std::vector<std::pair<int, uint64_t>>
get_fine_preemption_counters(device *dev)
{
  std::vector<std::pair<int, uint64_t>> counters;

  const auto telemetry = device_query<query::rtos_telemetry>(dev);
  for (auto& task : telemetry) {
    auto user_tid = task.preemption_data.slot_index;
    auto value = task.preemption_data.preemption_checkpoint_event;

    counters.emplace_back(user_tid, value);
  }
  return counters;
}

int
force_fine_preemption(device *dev, bool control)
{
  try {
    device_update<query::preemption>(dev, static_cast<uint32_t>(control));
  }
  catch (const std::runtime_error& e) {
    if (errno == EACCES) {
      std::cerr << "User doesn't have admin privilege. Skipping force preemption.\n";
      return -1;
    }
  }
  catch (...) {
    throw std::runtime_error("Caught an unknown exception.");
  }

  return 0;
}

uint64_t
get_fine_preemption_counter_delta(device *dev, hw_ctx& ctx, std::vector<std::pair<int, uint64_t>>& pre)
{
  auto ctx_id = ctx.get()->get_slotidx();
  auto cur = get_fine_preemption_counters(dev);
  uint64_t fine_preemption_count;
  int index = -1;

  // Find the user task ID for the ctx id
  for (int i = 0; i < cur.size(); i++) {
    auto id = cur[i].first;
    if (id == ctx_id) {
      fine_preemption_count = cur[i].second;
      index = i;
      break;
    }
  }

  if (index == -1)
    throw std::runtime_error("Can't determine user task ID for ctx!");
  if (fine_preemption_count < pre.at(index).second)
    throw std::runtime_error("Find preemption counter is smaller after the run!");

  return fine_preemption_count - pre.at(index).second;
}

void
io_test(device::id_type id, device* dev, int total_hwq_submit, int num_cmdlist,
  int cmds_per_list, const char *tag, const flow_type* flow = nullptr)
{
  // Allocate set of BOs for command submission based on num_cmdlist and cmds_per_list
  // Intentionally this is done before context creation to make sure BO and context
  // are totally decoupled.
  std::vector< std::unique_ptr<io_test_bo_set_base> > bo_set;
  for (int i = 0; i < num_cmdlist * cmds_per_list; i++)
    bo_set.push_back(std::move(alloc_and_init_bo_set(dev, tag, flow)));

  bool preemption_enabled = false;
  std::vector<std::pair<int, uint64_t>> pre_cntrs;
  if (io_test_parameters.type == IO_TEST_FORCE_PREEMPTION) {
    // Enable force preemption and take snapshot of current fw counters before running any cmd.
    preemption_enabled = !force_fine_preemption(dev, true);
    pre_cntrs = get_fine_preemption_counters(dev);
  }

  // Creating HW context for cmd submission
  hw_ctx hwctx{dev, tag, flow};
  auto hwq = hwctx.get()->get_hw_queue();

  // Initialize cmd before submission
  for (auto& boset : bo_set) {
    boset->init_cmd(hwctx, io_test_parameters.debug);
    boset->sync_before_run();
  }

  // Creating list of commands to be submitted
  std::vector< std::pair<std::shared_ptr<bo>, ert_start_kernel_cmd *> > cmdlist_bos;
  if (cmds_per_list == 1) {
    // Single command per list, just send the command BO itself
    for (auto& boset : bo_set) {
      auto cbo = boset->get_bos()[IO_TEST_BO_CMD].tbo;
      auto cmdpkt = reinterpret_cast<ert_start_kernel_cmd *>(cbo->map());
      cmdlist_bos.push_back( {cbo, cmdpkt} );
    }
  } else {
    // Multiple commands per list, create and send the chained command
    std::vector<bo*> tmp_cmd_bos;
    for (auto& boset : bo_set) {
      auto subcmd_bo = boset->get_bos()[IO_TEST_BO_CMD].tbo.get();
      tmp_cmd_bos.push_back(subcmd_bo);
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
    io_test_cmd_submit_and_wait_thruput(hwq, total_hwq_submit, cmdlist_bos, bo_set, cmds_per_list);
  else
    io_test_cmd_submit_and_wait_latency(hwq, total_hwq_submit, cmdlist_bos, bo_set, cmds_per_list);
  auto end = clk::now();

  // Verify preemption counters
  if (preemption_enabled) {
    force_fine_preemption(dev, false);
    auto delta = get_fine_preemption_counter_delta(dev, hwctx, pre_cntrs);
    auto total_cmds = total_hwq_submit * num_cmdlist * cmds_per_list;
    auto expected_preemption_count = total_cmds * bo_set[0]->get_preemption_checkpoints();
    if (delta != expected_preemption_count)
      throw std::runtime_error("Preemption counter does not match expectation!");
  }

  // Verify result
  for (auto& boset : bo_set) {
    // In case of runlist submission, status of original cmd BO won't be updated.
    // Let's update them here to indicate success. If any cmd processing has failed,
    // we'll throw before we get here.
    auto cbo = boset->get_bos()[IO_TEST_BO_CMD].tbo;
    auto cmdpkt = reinterpret_cast<ert_start_kernel_cmd *>(cbo->map());
    cmdpkt->state = ERT_CMD_STATE_COMPLETED;
    boset->sync_after_run();
    //boset->dump_content();
    boset->verify_result();
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
TEST_io(device::id_type id, std::shared_ptr<device>& sdev, arg_type& arg)
{
  unsigned int run_type = static_cast<unsigned int>(arg[0]);

  io_test_parameter_init(IO_TEST_NO_PERF, run_type, IO_TEST_IOCTL_WAIT);
  io_test(id, sdev.get(), 1, 1, arg[1], nullptr);
}

void
TEST_io_latency(device::id_type id, std::shared_ptr<device>& sdev, arg_type& arg)
{
  unsigned int run_type = static_cast<unsigned int>(arg[0]);
  unsigned int wait_type = static_cast<unsigned int>(arg[1]);
  unsigned int total = static_cast<unsigned int>(arg[2]);

  io_test_parameter_init(IO_TEST_LATENCY_PERF, run_type, wait_type);
  io_test(id, sdev.get(), total, 1, 1, run_type == IO_TEST_NOOP_RUN ? "nop" : nullptr);
}

void
TEST_io_throughput(device::id_type id, std::shared_ptr<device>& sdev, arg_type& arg)
{
  unsigned int run_type = static_cast<unsigned int>(arg[0]);
  unsigned int wait_type = static_cast<unsigned int>(arg[1]);
  unsigned int total = static_cast<unsigned int>(arg[2]);

  io_test_parameter_init(IO_TEST_THRUPUT_PERF, run_type, wait_type);
  io_test(id, sdev.get(), total, 8, 1, run_type == IO_TEST_NOOP_RUN ? "nop" : nullptr);
}

void
TEST_io_runlist_latency(device::id_type id, std::shared_ptr<device>& sdev, arg_type& arg)
{
  unsigned int run_type = static_cast<unsigned int>(arg[0]);
  unsigned int wait_type = static_cast<unsigned int>(arg[1]);
  unsigned int total = static_cast<unsigned int>(arg[2]);
  const size_t max_cmd_per_list = 24;

  io_test_parameter_init(IO_TEST_LATENCY_PERF, run_type, wait_type);
  for (int cmds_per_list = 1; cmds_per_list <=32; cmds_per_list *=2) {
    if (cmds_per_list > max_cmd_per_list)
      cmds_per_list = max_cmd_per_list;
    int total_hwq_submit = total / cmds_per_list;
    io_test(id, sdev.get(), total_hwq_submit, 1, cmds_per_list,
      run_type == IO_TEST_NOOP_RUN ? "nop" : nullptr);
  }
}

void
TEST_io_runlist_throughput(device::id_type id, std::shared_ptr<device>& sdev, arg_type& arg)
{
  unsigned int run_type = static_cast<unsigned int>(arg[0]);
  unsigned int wait_type = static_cast<unsigned int>(arg[1]);
  unsigned int total_commands = static_cast<unsigned int>(arg[2]);
  int num_bo_set = 256;
  const size_t max_cmd_per_list = 24;

  io_test_parameter_init(IO_TEST_THRUPUT_PERF, run_type, wait_type);
  for (int cmds_per_list = 1; cmds_per_list <= 32; cmds_per_list *= 2) {
    if (cmds_per_list > max_cmd_per_list)
      cmds_per_list = max_cmd_per_list;
    int num_cmdlist = num_bo_set / cmds_per_list;
    int total_hwq_submit = total_commands / cmds_per_list;
    io_test(id, sdev.get(), total_hwq_submit, num_cmdlist, cmds_per_list,
      run_type == IO_TEST_NOOP_RUN ? "nop" : nullptr);
  }
}

void
TEST_noop_io_with_dup_bo(device::id_type id, std::shared_ptr<device>& sdev, arg_type& arg)
{
  io_test_bo_set boset{sdev.get()};

  // Use same BO for both input and output
  boset.get_bos()[IO_TEST_BO_OUTPUT].tbo = boset.get_bos()[IO_TEST_BO_INPUT].tbo;
  auto ibo = boset.get_bos()[IO_TEST_BO_INSTRUCTION].tbo;
  std::memset(ibo->map(), 0, ibo->size());
  boset.run_no_check_result();
}

void
elf_io(device::id_type id, std::shared_ptr<device>& sdev,
  const std::vector<uint64_t>& arg, const char *tag, const flow_type* flow = nullptr)
{
  unsigned int run_type = static_cast<unsigned int>(arg[0]);

  io_test_parameter_init(IO_TEST_NO_PERF, run_type, IO_TEST_IOCTL_WAIT);
  io_test(id, sdev.get(), 1, 1, arg[1], tag, flow);
}

void
TEST_elf_io(device::id_type id, std::shared_ptr<device>& sdev, const std::vector<uint64_t>& arg)
{
  static const flow_type flow = PARTIAL_ELF;
  elf_io(id, sdev, arg, "good", &flow);
}

void
TEST_preempt_elf_io(device::id_type id, std::shared_ptr<device>& sdev, const std::vector<uint64_t>& arg)
{
  static const flow_type flow = PREEMPT_PARTIAL_ELF;
  elf_io(id, sdev, arg, "good", &flow);
}

void
TEST_io_with_ubuf_bo(device::id_type id, std::shared_ptr<device>& sdev, arg_type& arg)
{
  io_test_bo_set boset{sdev.get(), true};
  boset.run();
}

void
TEST_io_suspend_resume(device::id_type id, std::shared_ptr<device>& sdev, arg_type& arg)
{
  /*
   * For this code path, we expecte 2 times of suspend and resume
   * in dmesg log if dyndbg=+pf is set.
   */

  const int seconds = 8;
  io_test_bo_set boset{sdev.get()};

  std::cout << "Wait " << seconds << " seconds for auto-suspend" << std::endl;
  sleep(seconds);

  std::cout << "Submit command to resume" << std::endl;
  boset.run();

  std::cout << "Wait " << seconds << " seconds for auto-suspend" << std::endl;
  sleep(seconds);

  std::cout << "Submit command to resume" << std::endl;
  boset.run();
}

void
TEST_preempt_full_elf_io(device::id_type id, std::shared_ptr<device>& sdev, const std::vector<uint64_t>& arg)
{
  static const flow_type flow = PREEMPT_FULL_ELF;
  elf_io(id, sdev, arg, "good", &flow);
}

void
TEST_io_timeout(device::id_type id, std::shared_ptr<device>& sdev, arg_type& arg)
{
  elf_io_negative_test_bo_set boset{sdev.get(),
    "bad", "ert_crash.elf", ERT_CMD_STATE_TIMEOUT, 0x11800};
  boset.run();
}

void
TEST_async_error_io(device::id_type id, std::shared_ptr<device>& sdev, arg_type& arg)
{
  async_error_io_test_bo_set async_error_io_test_bo_set{sdev.get()};
  // verification is inside run()
  async_error_io_test_bo_set.run();
  // Run again to check if we can catch newly generated async error
  async_error_io_test_bo_set.run();
}

void
TEST_async_error_aie4_io(device::id_type id, std::shared_ptr<device>& sdev, arg_type& arg)
{
  async_error_aie4_io_test_bo_set async_error_aie4_io_test_bo_set{sdev.get(), "bad"};
  // verification is inside run()
  async_error_aie4_io_test_bo_set.run();
}

/**
 * This test is to test if there is deadlock in reading async error ioctl
 */
static void TEST_async_error_continue_read(device::id_type id, std::shared_ptr<device>& sdev,
                                           arg_type& arg)
{
  auto devptr = sdev.get();
  auto must_error = arg[0];
  xrtErrorTime last_err_timestamp;

  constexpr uint32_t iters = 2;
  for (uint32_t i = 0; i < iters; i++) {
    auto buf = device_query<query::xocl_errors>(devptr);
    if (buf.empty())
      throw std::runtime_error("async error multithread failed, buffer is null.");

    auto ect = query::xocl_errors::to_value(buf, XRT_ERROR_CLASS_AIE);
    xrtErrorTime err_timestamp;
    xrtErrorCode err_code;
    std::tie(err_code, err_timestamp) = ect;
    if (must_error && !err_code)
      throw std::runtime_error("async error multithread failed, expect error, but no error.");

    if (i && (err_timestamp != last_err_timestamp)) {
      std::stringstream ss;
      ss << "async error continuous read failed, timestamp different: " << err_timestamp
         << ", " << last_err_timestamp << ".";
      throw std::runtime_error(ss.str());
    }
    last_err_timestamp = err_timestamp;
  }
}

void TEST_async_error_multi(device::id_type id, std::shared_ptr<device>& sdev, arg_type& arg)
{
  multi_thread threads(10, TEST_async_error_continue_read);
  threads.run_test(id, sdev, arg);
}

void
TEST_instr_invalid_addr_io(device::id_type id, std::shared_ptr<device>& sdev, arg_type& arg)
{
  elf_io_negative_test_bo_set bo_set{sdev.get(),
    "bad", "instr_invalid_addr.elf", ERT_CMD_STATE_TIMEOUT, 0xFFFFFFFF};
  bo_set.run();

  std::vector<uint64_t> params = {IO_TEST_NORMAL_RUN, 1};
  static const flow_type flow = PARTIAL_ELF;
  elf_io(id, sdev, params, "good", &flow);
}

void
TEST_io_gemm(device::id_type id, std::shared_ptr<device>& sdev, arg_type& arg)
{
  elf_io_gemm_test_bo_set boset{sdev.get(), "gemm", "gemm_int8.elf"};
  boset.run();
}

void
TEST_io_runlist_bad_cmd(device::id_type id, std::shared_ptr<device>& sdev, arg_type& arg)
{
  bool is_timeout = static_cast<bool>(arg[0]);
  const char *good_tag = "good";
  const char *bad_tag = "bad";
  static const flow_type good_flow = PARTIAL_ELF;

  // Creating commands and BOs

  // Two good ones
  elf_io_test_bo_set good_bo_set1{sdev.get(), good_tag, &good_flow};
  elf_io_test_bo_set good_bo_set2{sdev.get(), good_tag, &good_flow};
  // A timeout one
  elf_io_negative_test_bo_set timeout_bo_set{sdev.get(), bad_tag,
    "ert_crash.elf", ERT_CMD_STATE_TIMEOUT, 0x11800};
  // An error one
  elf_io_negative_test_bo_set error_bo_set{sdev.get(), bad_tag,
    "instr_invalid_op.elf", ERT_CMD_STATE_ERROR, 0};

  // Creating HW context for cmd submission. We use the good xclbin here to
  // make sure good cmd can complete successfully. The bad ones don't really
  // require any specific xclbin to fail.
  hw_ctx hwctx{sdev.get(), good_tag, &good_flow};

  // Initialize cmd before submission
  good_bo_set1.init_cmd(hwctx, false);
  good_bo_set1.sync_before_run();
  good_bo_set2.init_cmd(hwctx, false);
  good_bo_set2.sync_before_run();
  timeout_bo_set.init_cmd(hwctx, false);
  timeout_bo_set.sync_before_run();
  error_bo_set.init_cmd(hwctx, false);
  error_bo_set.sync_before_run();

  // Create and send the chained command, keep the bad one in the middle
  // Command chain: good, bad (error or timeout), good
  const uint32_t bad_index = 1;
  const uint32_t bad_state = is_timeout ? ERT_CMD_STATE_TIMEOUT : ERT_CMD_STATE_ERROR;
  io_test_bo_set_base *bad = is_timeout ? &timeout_bo_set : &error_bo_set;
  std::vector<bo*> tmp_cmd_bos;
  tmp_cmd_bos.push_back(good_bo_set1.get_bos()[IO_TEST_BO_CMD].tbo.get());
  tmp_cmd_bos.push_back((*bad).get_bos()[IO_TEST_BO_CMD].tbo.get());
  tmp_cmd_bos.push_back(good_bo_set2.get_bos()[IO_TEST_BO_CMD].tbo.get());

  auto cbo = std::make_unique<bo>(sdev.get(), 0x1000ul, XCL_BO_FLAGS_EXECBUF);
  io_test_init_runlist_cmd(cbo.get(), tmp_cmd_bos);

  // Submit the chained command and wait for completion/timeout
  auto hwq = hwctx.get()->get_hw_queue();
  auto cmd_hdl = cbo->get();
  auto cmd_pkt = reinterpret_cast<ert_start_kernel_cmd *>(cbo->map());

  hwq->submit_command(cmd_hdl);
  hwq->wait_command(cmd_hdl, 0);

  // Check the result
  auto cmd_packet = reinterpret_cast<ert_packet *>(cbo->map());
  auto payload = get_ert_cmd_chain_data(cmd_packet);
  if (bad_state != cmd_packet->state || bad_index != payload->error_index) {
    throw std::runtime_error(
      std::string("runlist state=") + std::to_string(cmd_packet->state) +
      std::string(", error index=") + std::to_string(payload->error_index) +
      std::string(", expected state=") + std::to_string(bad_state) +
      std::string(", expected error index=") + std::to_string(bad_index)
      );
  }
  auto err_cmd_packet_by_index = reinterpret_cast<ert_packet *>(tmp_cmd_bos[bad_index]->map());
  // Setting the error state of the bad one for verify_result call on the bad one later.
  err_cmd_packet_by_index->state = cmd_packet->state;
  // In case of timeout, the returned context health data is in index 0's cmd pkt,
  // copy it to the real bad command for verify_result call on the bad one later.
  if (is_timeout) {
    auto cmdpkt = (*bad).get_bos()[IO_TEST_BO_CMD].tbo.get()->map();
    auto size = (*bad).get_bos()[IO_TEST_BO_CMD].tbo.get()->size();
    std::memcpy(cmdpkt, err_cmd_packet_by_index, size);
  }

  (*bad).verify_result();
}

void
TEST_io_coredump(device::id_type id, std::shared_ptr<device>& sdev, arg_type& arg)
{
  constexpr uint32_t CORE_STATUS_REG_OFFSET = 0x32004;
  constexpr size_t TILE_ADDRESS_SPACE = 0x100000;
  constexpr uint32_t CORE_ENABLE = 0x1;
  constexpr uint32_t CORE_IS_STALL_MASK = 0x1E; // Reset | MemStall_S | MemStall_W | MemStall_N

  auto dev = sdev.get();
  static const char* tag = "aie_debug";
  elf_io_aie_debug_test_bo_set boset{dev, tag};
  hw_ctx hwctx{dev, tag};

  boset.init_cmd(hwctx, false);
  boset.sync_before_run();
  auto hwq = hwctx.get()->get_hw_queue();
  auto cbo = boset.get_bos()[IO_TEST_BO_CMD].tbo.get();
  hwq->submit_command(cbo->get());
  hwq->wait_command(cbo->get(), 0);
  boset.sync_after_run();
  boset.verify_result();

  xrt_core::query::aie_coredump::args coredump_args{};
  coredump_args.pid = static_cast<uint64_t>(getpid());
  coredump_args.context_id = static_cast<uint32_t>(hwctx.get()->get_slotidx());
  std::vector<char> payload = xrt_core::device_query<xrt_core::query::aie_coredump>(dev, coredump_args);
  if (payload.empty() || (payload.size() % TILE_ADDRESS_SPACE) != 0)
    throw std::runtime_error("Unexpected AIE coredump payload size");

  auto aie_stats = xrt_core::device_query<xrt_core::query::aie_tiles_stats>(dev);
  if (aie_stats.cols == 0)
    throw std::runtime_error("AIE tiles stats reports zero columns");

  size_t num_tiles = payload.size() / TILE_ADDRESS_SPACE;
  uint32_t num_rows = (num_tiles % aie_stats.cols == 0)
      ? static_cast<uint32_t>(num_tiles / aie_stats.cols)
      : (aie_stats.shim_rows + aie_stats.mem_rows + aie_stats.core_rows);

  const uint8_t* base = reinterpret_cast<const uint8_t*>(payload.data());
  auto load_u32 = [](const uint8_t* p) {
    return static_cast<uint32_t>(p[0]) | (static_cast<uint32_t>(p[1]) << 8) |
        (static_cast<uint32_t>(p[2]) << 16) | (static_cast<uint32_t>(p[3]) << 24);
  };

  uint32_t st = load_u32(base + (0 * num_rows + 2) * TILE_ADDRESS_SPACE + CORE_STATUS_REG_OFFSET);
  uint32_t id_status = load_u32(base + (2 * num_rows + 2) * TILE_ADDRESS_SPACE + CORE_STATUS_REG_OFFSET);

  const size_t memtile0_offset = (0 * num_rows + 1) * TILE_ADDRESS_SPACE;
  for (size_t i = 1; i < 256; ++i) {
    uint32_t val = load_u32(base + memtile0_offset + i * sizeof(uint32_t));
    if (val != 0xdeadface)
      throw std::runtime_error("Memtile data expected 0xdeadface");
  }

  if ((st & CORE_ENABLE) == 0 || (st & CORE_IS_STALL_MASK) == 0)
    throw std::runtime_error("Core (0,2) expected STALL");

  if ((id_status & CORE_ENABLE) != 0)
    throw std::runtime_error("Core (2,2) expected IDLE");
}

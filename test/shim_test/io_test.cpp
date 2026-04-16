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
#include <sstream>
#include <string>
#include <regex>
#include <chrono>
#include <cstdint>
#include <thread>
#include <dirent.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/types.h>

// FIXME
#include "../../src/include/uapi/drm_local/amdxdna_accel.h"
// end of FIXME

using namespace xrt_core;
using arg_type = const std::vector<uint64_t>;

extern int open_accel_fd(device* dev);

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

void
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

uint64_t
get_npu_busy_time_ns()
{
  std::ostringstream dir_path;
  dir_path << "/proc/" << getpid() << "/fdinfo";

  DIR *dir = ::opendir(dir_path.str().c_str());
  if (!dir)
    throw std::runtime_error("Failed to open fdinfo directory!");

  struct dirent *de;
  static const std::regex re(R"(drm-engine-[^:]+:\s*([0-9]+)\s+ns)");

  while ((de = ::readdir(dir)) != nullptr) {
    if (de->d_name[0] == '.')
      continue;

    std::ostringstream fdinfo_path;
    fdinfo_path << dir_path.str() << "/" << de->d_name;

    std::ifstream ifs(fdinfo_path.str());
    if (!ifs)
      continue;

    std::string line;
    std::smatch match;
    while (std::getline(ifs, line)) {
      if (std::regex_search(line, match, re)) {
        ::closedir(dir);
        return std::stoull(match[1].str());
      }
    }
  }

  ::closedir(dir);
  // TODO: Throw when aie4 also support the same io stat
  //throw std::runtime_error("Failed to find drm-engine entry!");
  return 0;
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
  auto start_busy = get_npu_busy_time_ns();
  auto start = clk::now();
  if (io_test_parameters.perf == IO_TEST_THRUPUT_PERF)
    io_test_cmd_submit_and_wait_thruput(hwq, total_hwq_submit, cmdlist_bos, bo_set, cmds_per_list);
  else
    io_test_cmd_submit_and_wait_latency(hwq, total_hwq_submit, cmdlist_bos, bo_set, cmds_per_list);
  auto end = clk::now();
  auto end_busy = get_npu_busy_time_ns();

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
    auto busy_us = (end_busy - start_busy) / 1000;
    auto cps = (total_hwq_submit * cmds_per_list * 1000000.0) / duration_us;
    auto latency_us = 1000000.0 / cps;
    std::cout << total_hwq_submit * cmds_per_list << " commands finished in "
              << duration_us << " us, " << cmds_per_list << " commands per list, "
              << cps << " Command/sec,"
              << " Average latency " << latency_us << " us,"
              << " Device was " << busy_us * 100.0 / duration_us << "% busy"
              << std::endl;
  }
}

struct dpm_clk_entry {
  uint32_t npuclk;
  uint32_t hclk;
};

const dpm_clk_entry npu4_dpm_table[] = {
  {396, 792},
  {600, 1056},
  {792, 1152},
  {975, 1267},
  {975, 1267},
  {1056, 1408},
  {1152, 1584},
  {1267, 1800},
};

constexpr int DPM_NUM_LEVELS = 8;
constexpr uint32_t HCLK_MARGIN_PCT = 2;
constexpr uint32_t DPM_COL_OPC = 4096;
constexpr uint32_t DPM_NOP_NUM_COL = 4;
constexpr uint32_t DPM_MAX_OPC = DPM_COL_OPC * DPM_NOP_NUM_COL;

constexpr uint32_t SYS_EFF_FACTOR = 2;

uint32_t
query_hclk(device* dev)
{
  int fd = open_accel_fd(dev);
  amdxdna_drm_query_clock_metadata clock = {};
  amdxdna_drm_get_info arg = {
    .param = DRM_AMDXDNA_QUERY_CLOCK_METADATA,
    .buffer_size = sizeof(clock),
    .buffer = reinterpret_cast<uintptr_t>(&clock),
  };

  int ret = ::ioctl(fd, DRM_IOCTL_AMDXDNA_GET_INFO, &arg);
  close(fd);
  if (ret == -1)
    throw std::runtime_error("ioctl(QUERY_CLOCK_METADATA) failed");

  return clock.h_clock.freq_mhz;
}

void
set_power_mode(device* dev, int mode)
{
  int fd = open_accel_fd(dev);
  amdxdna_drm_set_power_mode pm = {};
  pm.power_mode = static_cast<uint8_t>(mode);

  amdxdna_drm_set_state arg = {
    .param = DRM_AMDXDNA_SET_POWER_MODE,
    .buffer_size = sizeof(pm),
    .buffer = reinterpret_cast<uintptr_t>(&pm),
  };

  int ret = ::ioctl(fd, DRM_IOCTL_AMDXDNA_SET_STATE, &arg);
  close(fd);
  if (ret == -1)
    throw std::runtime_error("ioctl(SET_POWER_MODE) failed for mode " + std::to_string(mode));
}

bool
hclk_within_margin(uint32_t actual, uint32_t expected)
{
  uint32_t margin = expected * HCLK_MARGIN_PCT / 100;
  if (margin == 0)
    margin = 1;
  return actual >= expected - margin && actual <= expected + margin;
}

void
verify_hclk(device* dev, uint32_t expected, const std::string& ctx)
{
  constexpr int timeout_ms = 20000;
  constexpr int poll_interval_ms = 10;
  uint32_t actual = 0;

  auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
  do {
    actual = query_hclk(dev);
    if (hclk_within_margin(actual, expected))
      break;
    std::this_thread::sleep_for(std::chrono::milliseconds(poll_interval_ms));
  } while (std::chrono::steady_clock::now() < deadline);

  if (!hclk_within_margin(actual, expected)) {
    throw std::runtime_error(ctx + ": expected H-clock ~" + std::to_string(expected) +
                             " MHz (±" + std::to_string(HCLK_MARGIN_PCT) + "%), got " +
                             std::to_string(actual) + " MHz (after " +
                             std::to_string(timeout_ms) + "ms polling)");
  }
  std::cout << "  " << ctx << ": H-clock " << actual << " MHz (expected ~"
            << expected << ") [OK]" << std::endl;
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
  auto boset = create_bo_set_for_device(sdev.get(), false, "nop");

  // Use same BO for both input and output
  boset->get_bos()[IO_TEST_BO_OUTPUT].tbo = boset->get_bos()[IO_TEST_BO_INPUT].tbo;
  auto ibo = boset->get_bos()[IO_TEST_BO_INSTRUCTION].tbo;
  std::memset(ibo->map(), 0, ibo->size());
  boset->run_no_check_result();
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
  auto boset = create_bo_set_for_device(sdev.get(), true);
  boset->run();
}

void
TEST_io_suspend_resume(device::id_type id, std::shared_ptr<device>& sdev, arg_type& arg)
{
  /*
   * For this code path, we expecte 2 times of suspend and resume
   * in dmesg log if dyndbg=+pf is set.
   */

  const int seconds = 8;
  auto boset = create_bo_set_for_device(sdev.get());

  std::cout << "Wait " << seconds << " seconds for auto-suspend" << std::endl;
  sleep(seconds);

  std::cout << "Submit command to resume" << std::endl;
  boset->run();

  std::cout << "Wait " << seconds << " seconds for auto-suspend" << std::endl;
  sleep(seconds);

  std::cout << "Submit command to resume" << std::endl;
  boset->run();
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
  elf_io_negative_test_bo_set boset{sdev.get(), "bad_timeout"};
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
  {
    auto good_bo_set = create_bo_set_for_device(sdev.get(), false, "good");
    async_error_aie4_io_test_bo_set bad_bo_set{sdev.get(), "bad_timeout"};

    hw_ctx hwctx{sdev.get(), "good"};

    good_bo_set->init_cmd(hwctx, false);
    good_bo_set->sync_before_run();
    bad_bo_set.init_cmd(hwctx, false);
    bad_bo_set.sync_before_run();

    // Command chain: good (index 0), bad_timeout (index 1)
    const uint32_t bad_index = 1;
    std::vector<bo*> tmp_cmd_bos;
    tmp_cmd_bos.push_back(good_bo_set->get_bos()[IO_TEST_BO_CMD].tbo.get());
    tmp_cmd_bos.push_back(bad_bo_set.get_bos()[IO_TEST_BO_CMD].tbo.get());

    auto cbo = std::make_unique<bo>(sdev.get(), 0x1000ul, XCL_BO_FLAGS_EXECBUF);
    io_test_init_runlist_cmd(cbo.get(), tmp_cmd_bos);

    auto hwq = hwctx.get()->get_hw_queue();
    hwq->submit_command(cbo->get());
    hwq->wait_command(cbo->get(), 0);

    auto cmd_packet = reinterpret_cast<ert_packet *>(cbo->map());
    auto payload = get_ert_cmd_chain_data(cmd_packet);
    if (cmd_packet->state != ERT_CMD_STATE_TIMEOUT || payload->error_index != bad_index) {
      throw std::runtime_error(
        std::string("runlist state=") + std::to_string(cmd_packet->state) +
        std::string(", error_index=") + std::to_string(payload->error_index) +
        std::string(", expected state=") + std::to_string(ERT_CMD_STATE_TIMEOUT) +
        std::string(", expected error_index=") + std::to_string(bad_index)
      );
    }

    // Health data is in the subcmd at error_index, copy it to bad_bo_set's cmd BO for verification
    auto bad_cmd_pkt = reinterpret_cast<ert_packet *>(tmp_cmd_bos[bad_index]->map());
    bad_cmd_pkt->state = cmd_packet->state;

    bad_bo_set.verify_result();
  }
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
  elf_io_negative_test_bo_set bo_set{sdev.get(), "bad_addr"};
  bo_set.run();

  std::vector<uint64_t> params = {IO_TEST_NORMAL_RUN, 1};
  static const flow_type flow = PARTIAL_ELF;
  elf_io(id, sdev, params, "good", &flow);
}

void
TEST_io_gemm(device::id_type id, std::shared_ptr<device>& sdev, arg_type& arg)
{
  elf_io_gemm_test_bo_set boset{sdev.get(), "gemm"};
  boset.run();
}

void
TEST_io_runlist_bad_cmd(device::id_type id, std::shared_ptr<device>& sdev, arg_type& arg)
{
  bool is_timeout = static_cast<bool>(arg[0]);
  device* dev = sdev.get();
  const char *good_tag = "good";

  /* NPU4-class: prefer partial-ELF, NPU3: FULL_ELF */
  static const flow_type flow_partial = PARTIAL_ELF;
  static const flow_type flow_full = FULL_ELF;
  const binary_info& good_info = [&]() -> const binary_info& {
    try {
      return get_binary_info(dev, good_tag, &flow_partial);
    } catch (const std::runtime_error&) {
      return get_binary_info(dev, good_tag, &flow_full);
    }
  }();
  flow_type good_flow = good_info.flow;

  // Two good ones
  auto good_bo_set1 = create_bo_set_for_device(dev, false, good_tag, &good_flow);
  auto good_bo_set2 = create_bo_set_for_device(dev, false, good_tag, &good_flow);
  // A timeout one
  elf_io_negative_test_bo_set timeout_bo_set{dev, "bad_timeout"};
  std::unique_ptr<elf_io_negative_test_bo_set> error_bo_set;
  // An error one
  if (!is_timeout)
    error_bo_set = std::make_unique<elf_io_negative_test_bo_set>(dev, "bad_op");

  // Creating HW context for cmd submission. We use the good xclbin here to
  // make sure good cmd can complete successfully. The bad ones don't really
  // require any specific xclbin to fail.
  hw_ctx hwctx{dev, good_tag, &good_flow};

  // Initialize cmd before submission
  good_bo_set1->init_cmd(hwctx, false);
  good_bo_set1->sync_before_run();
  good_bo_set2->init_cmd(hwctx, false);
  good_bo_set2->sync_before_run();
  timeout_bo_set.init_cmd(hwctx, false);
  timeout_bo_set.sync_before_run();
  if (error_bo_set) {
    error_bo_set->init_cmd(hwctx, false);
    error_bo_set->sync_before_run();
  }

  // When runlist cmd times out, the index returned from FW depends on device type.
  // AIE4 runlist timeouts report error_index == 1, while NPU4 may still return 0
  // for legacy firmware and 1 for newer firmware with the fix applied.
  // When runlist cmd fails (non-timeout), the index returned from FW is accurate (1).
  const bool is_npu4 = (good_info.device == npu4_device_id);
  const uint32_t bad_index = is_timeout ? (is_npu4 ? 0 : 1) : 1;
  const uint32_t bad_state = is_timeout ? ERT_CMD_STATE_TIMEOUT : ERT_CMD_STATE_ERROR;
  io_test_bo_set_base *bad = is_timeout ? &timeout_bo_set : error_bo_set.get();
  std::vector<bo*> tmp_cmd_bos;
  tmp_cmd_bos.push_back(good_bo_set1->get_bos()[IO_TEST_BO_CMD].tbo.get());
  tmp_cmd_bos.push_back((*bad).get_bos()[IO_TEST_BO_CMD].tbo.get());
  tmp_cmd_bos.push_back(good_bo_set2->get_bos()[IO_TEST_BO_CMD].tbo.get());

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

void
TEST_io_aie_mem(device::id_type id, std::shared_ptr<device>& sdev, arg_type& arg)
{
  constexpr uint32_t MEM_OFFSET = 0x400;
  constexpr uint32_t MEM_SIZE = 1024;
  constexpr uint32_t WORDS_PER_READ = MEM_SIZE / sizeof(uint32_t);
  constexpr uint32_t EXPECTED_READ_VAL = 0xdeadface;
  constexpr uint32_t WRITE_VAL = 0xdeadbeef;

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

  auto aie_stats = xrt_core::device_query<xrt_core::query::aie_tiles_stats>(dev);
  if (aie_stats.cols == 0)
    throw std::runtime_error("AIE tiles stats reports zero columns");

  const uint16_t num_cols = 4; // 4 cols used for verify_4x4.xclbin

  pid_t pid = getpid();
  uint16_t context_id = static_cast<uint16_t>(hwctx.get()->get_slotidx());

  using aie_read_args = xrt_core::query::aie_read::args;
  using aie_write_args = xrt_core::query::aie_write::args;

  for (uint16_t col = 0; col < num_cols; ++col) {
    for (uint16_t r = 0; r < aie_stats.mem_rows; ++r) {
      uint16_t row = aie_stats.mem_row_start + r;
      aie_read_args read_args = {
        .type = xrt_core::query::aie_read::access_type::mem,
        .pid = static_cast<uint64_t>(pid),
        .context_id = context_id,
        .col = col,
        .row = row,
        .offset = MEM_OFFSET,
        .size = MEM_SIZE
      };
      std::vector<char> buf = xrt_core::device_query<xrt_core::query::aie_read>(dev, read_args);
      if (buf.size() != MEM_SIZE)
        throw std::runtime_error("AIE mem read size mismatch");
      const uint32_t* words = reinterpret_cast<const uint32_t*>(buf.data());
      for (uint32_t i = 0; i < WORDS_PER_READ; ++i) {
        if (words[i] != EXPECTED_READ_VAL)
          throw std::runtime_error("AIE mem read expected 0xdeadface at ("
            + std::to_string(col) + "," + std::to_string(row) + ") word " + std::to_string(i));
      }
    }
  }

  std::vector<char> write_buf(MEM_SIZE);
  uint32_t* write_words = reinterpret_cast<uint32_t*>(write_buf.data());
  for (uint32_t i = 0; i < WORDS_PER_READ; ++i)
    write_words[i] = WRITE_VAL;

  for (uint16_t col = 0; col < num_cols; ++col) {
    for (uint16_t r = 0; r < aie_stats.mem_rows; ++r) {
      uint16_t row = aie_stats.mem_row_start + r;
      aie_write_args write_args = {
        .type = xrt_core::query::aie_write::access_type::mem,
        .pid = static_cast<uint64_t>(pid),
        .context_id = context_id,
        .col = col,
        .row = row,
        .offset = MEM_OFFSET,
        .data = write_buf
      };
      xrt_core::device_query<xrt_core::query::aie_write>(dev, write_args);
    }
  }

  for (uint16_t col = 0; col < num_cols; ++col) {
    for (uint16_t r = 0; r < aie_stats.mem_rows; ++r) {
      uint16_t row = aie_stats.mem_row_start + r;
      aie_read_args read_args = {
        .type = xrt_core::query::aie_read::access_type::mem,
        .pid = static_cast<uint64_t>(pid),
        .context_id = context_id,
        .col = col,
        .row = row,
        .offset = MEM_OFFSET,
        .size = MEM_SIZE
      };
      std::vector<char> read_back = xrt_core::device_query<xrt_core::query::aie_read>(dev, read_args);
      if (read_back.size() != MEM_SIZE)
        throw std::runtime_error("AIE mem read-back size mismatch");
      const uint32_t* back_words = reinterpret_cast<const uint32_t*>(read_back.data());
      for (uint32_t i = 0; i < WORDS_PER_READ; ++i) {
        if (back_words[i] != WRITE_VAL)
          throw std::runtime_error("AIE mem read-back expected 0xdeadbeef");
      }
    }
  }
}

void
TEST_io_aie_reg(device::id_type id, std::shared_ptr<device>& sdev, arg_type& arg)
{
  constexpr uint32_t CORE_STATUS_REG = 0x32004;
  constexpr uint32_t CORE_CONTROL_REG = 0x32000;
  constexpr uint32_t EXPECTED_COL0_STATUS = 0x3;   // reset + enabled
  constexpr uint32_t EXPECTED_OTHER_STATUS = 0x2;  // reset
  constexpr uint32_t EXPECTED_AFTER_WRITE = 0x1;  // enabled

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

  auto aie_stats = xrt_core::device_query<xrt_core::query::aie_tiles_stats>(dev);
  if (aie_stats.cols == 0)
    throw std::runtime_error("AIE tiles stats reports zero columns");

  const uint16_t num_cols = 4; // 4 cols used for verify_4x4.xclbin

  pid_t pid = getpid();
  uint16_t context_id = static_cast<uint16_t>(hwctx.get()->get_slotidx());

  using aie_read_args = xrt_core::query::aie_read::args;
  using aie_write_args = xrt_core::query::aie_write::args;

  auto read_reg = [&](uint16_t col, uint16_t row, uint32_t addr) -> uint32_t {
    aie_read_args read_args = {
      .type = xrt_core::query::aie_read::access_type::reg,
      .pid = static_cast<uint64_t>(pid),
      .context_id = context_id,
      .col = col,
      .row = row,
      .offset = addr,
      .size = sizeof(uint32_t)
    };
    std::vector<char> buf = xrt_core::device_query<xrt_core::query::aie_read>(dev, read_args);
    if (buf.size() != sizeof(uint32_t))
      throw std::runtime_error("AIE reg read size mismatch");
    return *reinterpret_cast<const uint32_t*>(buf.data());
  };

  auto write_reg = [&](uint16_t col, uint16_t row, uint32_t addr, uint32_t val) {
    std::vector<char> data(sizeof(uint32_t));
    *reinterpret_cast<uint32_t*>(data.data()) = val;
    aie_write_args write_args = {
      .type = xrt_core::query::aie_write::access_type::reg,
      .pid = static_cast<uint64_t>(pid),
      .context_id = context_id,
      .col = col,
      .row = row,
      .offset = addr,
      .data = std::move(data)
    };
    xrt_core::device_query<xrt_core::query::aie_write>(dev, write_args);
  };

  for (uint16_t col = 0; col < num_cols; ++col) {
    for (uint16_t r = 0; r < aie_stats.core_rows; ++r) {
      uint16_t row = aie_stats.core_row_start + r;
      uint32_t status = read_reg(col, row, CORE_STATUS_REG);
      uint32_t expected = (col == 0) ? EXPECTED_COL0_STATUS : EXPECTED_OTHER_STATUS;
      if (status != expected)
        throw std::runtime_error("Core (" + std::to_string(col) + "," + std::to_string(row)
          + ") expected status 0x3 or 0x2");
    }
  }

  // WRITE 0x1 to core control for Col 1+ (skip col 0)
  for (uint16_t col = 1; col < num_cols; ++col) {
    for (uint16_t r = 0; r < aie_stats.core_rows; ++r) {
      uint16_t row = aie_stats.core_row_start + r;
      write_reg(col, row, CORE_CONTROL_REG, EXPECTED_AFTER_WRITE);
      uint32_t status = read_reg(col, row, CORE_STATUS_REG);
      if (status != EXPECTED_AFTER_WRITE)
        throw std::runtime_error("Core (" + std::to_string(col) + "," + std::to_string(row)
          + ") expected status 0x1 after write");
    }
  }
}

void
TEST_dpm_noop_no_qos(device::id_type id, std::shared_ptr<device>& sdev, arg_type& arg)
{
  auto dev = sdev.get();
  uint32_t max_hclk = npu4_dpm_table[DPM_NUM_LEVELS - 1].hclk;

  set_power_mode(dev, POWER_MODE_DEFAULT);

  {
    hw_ctx hwctx{dev, "nop"};
    dpm_test_bo_set nop{dev, "nop"};
    nop.run_with_ctx(hwctx);
    verify_hclk(dev, max_hclk, "noop context (no fps/latency QoS)");
  }
}

void
TEST_dpm_power_modes(device::id_type id, std::shared_ptr<device>& sdev, arg_type& arg)
{
  auto dev = sdev.get();
  uint32_t max_hclk = npu4_dpm_table[DPM_NUM_LEVELS - 1].hclk;
  uint32_t low_hclk = npu4_dpm_table[0].hclk;
  uint32_t med_hclk = npu4_dpm_table[DPM_NUM_LEVELS / 2].hclk;

  set_power_mode(dev, POWER_MODE_TURBO);
  verify_hclk(dev, max_hclk, "POWER_MODE_TURBO");

  set_power_mode(dev, POWER_MODE_LOW);
  verify_hclk(dev, low_hclk, "POWER_MODE_LOW");

  set_power_mode(dev, POWER_MODE_MEDIUM);
  verify_hclk(dev, med_hclk, "POWER_MODE_MEDIUM");

  set_power_mode(dev, POWER_MODE_HIGH);
  verify_hclk(dev, max_hclk, "POWER_MODE_HIGH");

  set_power_mode(dev, POWER_MODE_LOW);
  verify_hclk(dev, low_hclk, "POWER_MODE_LOW");

  set_power_mode(dev, POWER_MODE_DEFAULT);
}

void
TEST_dpm_refcount_scaling(device::id_type id, std::shared_ptr<device>& sdev, arg_type& arg)
{
  auto dev = sdev.get();
  const auto* tbl = npu4_dpm_table;
  uint32_t factor = SYS_EFF_FACTOR;

  std::cout << "  Platform info: col_opc=" << DPM_COL_OPC
            << " num_col=" << DPM_NOP_NUM_COL
            << " max_opc=" << DPM_MAX_OPC
            << " sys_eff_factor=" << factor << std::endl;

  /*
   * Compute per-level GOPs thresholds to target each DPM level.
   * The driver computes: req_gops = gops * fps * sys_eff_factor
   * and picks the lowest level where req_gops <= max_opc * hclk / 1000.
   * We divide capacities by the factor so the gops param we pass
   * results in the correct req_gops after the driver's multiplication.
   */
  struct level_qos {
    uint32_t gops;
    uint32_t fps;
    uint32_t expected_hclk;
  };

  std::vector<level_qos> levels;
  for (int i = 0; i < DPM_NUM_LEVELS; i++) {
    uint32_t raw_capacity = DPM_MAX_OPC * tbl[i].hclk / 1000;
    uint32_t capacity = raw_capacity / factor;
    uint32_t prev_raw = (i > 0) ? DPM_MAX_OPC * tbl[i - 1].hclk / 1000 : 0;
    uint32_t prev_capacity = prev_raw / factor;

    uint32_t target = (prev_capacity > 0) ? prev_capacity + 1 : 1;
    if (target > capacity)
      target = capacity;

    levels.push_back({target, 1, tbl[i].hclk});

    std::cout << "  Level " << i
              << ": hclk=" << tbl[i].hclk
              << " raw_cap=" << raw_capacity
              << " eff_cap=" << capacity
              << " target_gops=" << target << std::endl;
  }

  set_power_mode(dev, POWER_MODE_DEFAULT);

  std::vector<std::unique_ptr<hw_ctx>> ctxs;

  std::cout << "  Phase 1: Creating " << DPM_NUM_LEVELS << " contexts (DPM scaling up)" << std::endl;
  for (int i = 0; i < DPM_NUM_LEVELS; i++) {
    xrt::hw_context::qos_type qos{
      {"gops", levels[i].gops},
      {"fps",  levels[i].fps},
      {"priority", 0x180},
    };

    uint32_t drv_req_gops = levels[i].fps * levels[i].gops * factor;
    std::cout << "  Creating context " << i
              << ": qos{gops=" << levels[i].gops
              << ", fps=" << levels[i].fps
              << ", priority=0x180}"
              << " drv_req_gops=" << drv_req_gops << std::endl;

    ctxs.push_back(std::make_unique<hw_ctx>(dev, qos, "nop"));
    dpm_test_bo_set nop{dev, "nop"};
    nop.run_with_ctx(*ctxs.back());
    std::cout << "  Context " << i << " created successfully" << std::endl;

    uint32_t expected = levels[i].expected_hclk;
    for (int j = 0; j < i; j++) {
      if (levels[j].expected_hclk > expected)
        expected = levels[j].expected_hclk;
    }

    verify_hclk(dev, expected, "after context " + std::to_string(i) +
                " (target level " + std::to_string(i) + ")");
  }

  std::cout << "  Phase 2: Destroying " << DPM_NUM_LEVELS << " contexts (DPM scaling down)" << std::endl;
  for (int i = DPM_NUM_LEVELS - 1; i >= 0; i--) {
    ctxs.pop_back();
    std::cout << "  Destroyed context " << i << std::endl;

    if (i == 0) {
      verify_hclk(dev, tbl[0].hclk, "after destroying last context (all refs gone)");
      break;
    }

    uint32_t expected = 0;
    for (int j = 0; j < i; j++) {
      if (levels[j].expected_hclk > expected)
        expected = levels[j].expected_hclk;
    }

    verify_hclk(dev, expected, "after destroying context " + std::to_string(i));
  }
}

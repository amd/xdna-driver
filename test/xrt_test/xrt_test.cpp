// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2024-2026, Advanced Micro Devices, Inc. All rights reserved.

// XRT includes
#include "xrt/xrt_device.h"
#include "xrt/xrt_kernel.h"
#include "xrt/xrt_bo.h"
#include "xrt/experimental/xrt_elf.h"
#include "xrt/experimental/xrt_ext.h"
#include "xrt/experimental/xrt_module.h"
#include "xrt/experimental/xrt_kernel.h"
#include "resnet50.h"

#include <cstdint>
#include <fstream>
#include <algorithm>
#include <filesystem>
#include <iostream>
#include <libgen.h>
#include <set>
#include <stdlib.h>
#include <string>
#include <vector>
#include <chrono>
#include <regex>
#include <unistd.h>
#include <thread>

#define MAX_RUNLIST_CMDS 24

namespace {

using arg_type = const std::vector<uint64_t>;
uint64_t c_rounds = 1;
unsigned o_cmds = 1;
unsigned r_cmds = 1;
unsigned m_rounds = 32;
unsigned device_index = 0;
unsigned threads = 2;
unsigned vf_cnt;
bool vf_test = false;
// silicon default timeout 10s
unsigned timeout_ms = 10000;
std::vector<unsigned> exec_list;

std::string program;
// Test harness setup helpers
std::string curpath;
std::string elfpath;
#ifdef __aarch64__
std::string path = "local_shim_test_data/npu3a/";
#else
std::string path = "local_shim_test_data/npu3/";
#endif
bool printing_on;
bool elf_flow = true;

std::string dolphinPass = R"(
                                         .--.
                  _______             .-"  .'
          .---u"""       """"---._  ."    %
        .'                        "--.    %
   __.--'  o                          "".. "
  (____.                                  ":
   `----.__                                 ".
           `----------__                     ".
                 ".   . ""--.                 ".
                   ". ". pass ""-.              ".
                     "-.)        ""-.           ".
                                     "".         ".
                                        "".       ".
                                           "".      ".
                                              "".    ".
                        ^~^~^~^~^~^~^~^~^~^~^~^~^"".  "^~^~^~^~^
                                              ^~^~^~^  ~^~
                                                   ^~^~^~
    )";

void
usage(const std::string& prog)
{
  std::cout << "\nUsage: " << prog << " [options] [test case ID separated by space]\n";
  std::cout << "Options:\n";
  std::cout << "\t" << "xrt_test" << " - run all test cases\n";
  std::cout << "\t" << "xrt_test" << " [test case ID separated by space] - run specified test cases\n";
  std::cout << "\t" << "-c" << ": n rounds in sequence within 1 hwctx\n";
  std::cout << "\t" << "-o" << ": max n outstanding cmds within 1 hwctx\n";
  std::cout << "\t" << "-r" << ": n cmds per runlist\n";
  std::cout << "\t" << "-m" << ": n hwctx in parallel\n";
  std::cout << "\t" << "-x" << ": specify xclbin and elf to use (nop, stress hwctx, max runlist only)\n";
  std::cout << "\t" << "-i" << ": specify device index (0 for non-sriov or VF0, 1, 2, 3 for VFs)\n";
  std::cout << "\t" << "-t" << ": n thread to be created in thread test (default 2)\n";
  std::cout << "\t" << "-e" << ": specify tests to add to thread test (default vadd) [-e test# -e test# ...]\n";
  std::cout << "\t" << "-v" << ": apply each thread to corresponding vf, max 4\n";
  std::cout << "\t" << "-w" << ": timeout in seconds (default 600 sec, some simnow server are slow)\n";
  std::cout << "\t" << "-l" << ": use xclbin flow if available\n";
  std::cout << "\t" << "-h" << ": print this help message and available test cases\n\n";
  std::cout << "\t" << "Example Usage: ./xrt_test 0 -c 20 -o 2\n";
  std::cout << "\t" << "               Run vadd test for 20 rounds with 2 outstanding commands\n";
  std::cout << std::endl;
}

//local_path(const char *fname)
inline const std::string
local_path(std::string fname)
{
  return (curpath + "/../" + fname);
}

inline void
set_xrt_path()
{
  setenv("XILINX_XRT", local_path("").c_str(), true);
}

struct test_case { // Definition of one test case
  const char *description;
  void (*func)(int device_index, arg_type& arg);
  arg_type arg;
};

// For overall test result evaluation
int test_passed = 0;
int test_skipped = 0;
int test_failed = 0;

// All test case runners

class xrt_bo {
public:
  xrt_bo(const xrt::device& dev, size_t size, xrt::bo::flags bo_flags)
    : m_boh{xrt::bo{dev, size, bo_flags, 0}}
    , m_bop{reinterpret_cast<int *>(m_boh.map())}
  {
    if (!m_bop)
      throw std::runtime_error("map shim test bo of " + std::to_string(size) + "bytes failed");
  }

  ~xrt_bo()
  {
  }

  int *
  map()
  { return m_bop; }

  size_t
  size()
  { return m_boh.size(); }

  xrt::bo&
  get()
  { return m_boh; }

private:
  xrt::bo m_boh;
  int *m_bop;
};

std::pair<xrt::hw_context, xrt::kernel> get_xrt_hwctx_kernel(
  xrt::device& device,
  const std::string xclbin_path,
  const std::string xclbin_elf,
  const std::string xclbin_kernel,
  const std::string full_elf,
  const std::string full_elf_kernel)
{
  if (elf_flow) {
    xrt::elf elf{local_path(path + full_elf)};
    xrt::hw_context hwctx{device, elf};
    xrt::kernel kernel = xrt::ext::kernel{hwctx, full_elf_kernel};
    return {std::move(hwctx), std::move(kernel)};
  }
  xrt::xclbin xclbin = xrt::xclbin(local_path(path + xclbin_path));
  auto uuid = device.register_xclbin(xclbin);
  xrt::elf elf{local_path(path + xclbin_elf)};
  xrt::module mod{elf};
  xrt::hw_context hwctx{device, uuid};
  xrt::kernel kernel = xrt::ext::kernel{hwctx, mod, xclbin_kernel};
  return {std::move(hwctx), std::move(kernel)};
}

template <typename TEST_BO>
void init_umq_ifm_bo(TEST_BO& ifm)
{
  auto p = ifm.map();
  for (uint32_t i = 0; i < ifm.size() / sizeof (uint32_t); i++)
    p[i] = i;
}

template <typename TEST_BO>
void init_umq_wts_bo(TEST_BO& wts)
{
  auto p = wts.map();
  for (uint32_t i = 0; i < wts.size() / sizeof (uint32_t); i++)
    p[i] = i * 10000;
}

template <typename TEST_BO>
void init_umq_ofm_bo(TEST_BO& ofm)
{
  auto p = ofm.map();
  for (uint32_t i = 0; i < ofm.size() / sizeof (uint32_t); i++)
    p[i] = 0;
}

template <typename TEST_BO>
void init_umq_vadd_buffers(TEST_BO& ifm, TEST_BO& wts, TEST_BO& ofm)
{
  init_umq_ifm_bo(ifm);
  init_umq_wts_bo(wts);
  init_umq_ofm_bo(ofm);
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

void check_umq_resnet50_result(int *ofm, const std::string& filename)
{
  uint32_t value;
  int err = 0;
  int i = 0;

  std::ifstream infile(filename, std::ios::binary);
  if (!infile)
    throw std::runtime_error("Unable to open .bin file");

  while (infile.read(reinterpret_cast<char*>(&value), sizeof(value))) {
    if(ofm[i] != value) {
      std::cout << "error@" << i <<": " << ofm[i] << ", expecting: " << value << std::endl;
      err++;
    }
    i++;
  }
  infile.close();

  if (err)
    throw std::runtime_error("result mis-match");
  else
    std::cout << "result matched" << std::endl;
}

template <typename TEST_BO>
void
dump_ofm_to_file(TEST_BO& ofm_bo)
{
  auto timestamp = std::chrono::duration_cast<std::chrono::seconds>(
    std::chrono::system_clock::now().time_since_epoch()).count();
  
  std::string filename = "ofm_dump_" + std::to_string(timestamp) + ".txt";
  
  std::ofstream outfile(filename);
  if (!outfile) {
    std::cout << "Failed to create dump file: " << filename << std::endl;
    return;
  }
  
  auto ofm_mapped = ofm_bo.map();
  size_t ofm_size = ofm_bo.size() / sizeof(uint32_t);
  
  for (size_t i = 0; i < ofm_size; i++) {
    outfile << std::hex << "0x" << ofm_mapped[i] << std::endl;
  }
  
  outfile.close();
  std::cout << "OFM data dumped to: " << filename << " (" << ofm_size << " words)" << std::endl;
}

template <typename TEST_BO>
void
read_txt_file(std::string& filename, TEST_BO& test_bo)
{
  int i = 0;

  std::ifstream infile;
  infile.open(filename);
  if (!infile.is_open())
    throw std::runtime_error("Unable to open .txt file");

  auto p = test_bo.map();
  for (int i = 0; i < test_bo.size()/sizeof(uint32_t); i++) {
    uint32_t value;
    infile >> std::hex >> value;
    p[i] = value;
  }
    infile.close();
}

void
sync_bo_to_dev(xrt_bo& bo)
{
  bo.get().sync(XCL_BO_SYNC_BO_TO_DEVICE, bo.size(), 0);
}

void
sync_bo_from_dev(xrt_bo& bo)
{
  bo.get().sync(XCL_BO_SYNC_BO_FROM_DEVICE, bo.size(), 0);
}

/* Execute c_rounds batches with up to o_cmds outstanding. When r_cmds==1 each
   batch is one run; when r_cmds>1 each batch is a runlist of r_cmds runs.
   runs must have size o_cmds * max(r_cmds, 1). Uses global o_cmds, c_rounds,
   timeout_ms. */
static void
execute_batches(xrt::hw_context& hwctx, std::vector<xrt::run>& runs, unsigned r_cmds)
{
  if (r_cmds <= 1) {
    /* runs.size() == o_cmds; submit up to c_rounds total, at most o_cmds outstanding */
    uint64_t submitted = 0;
    uint64_t completed = 0;
    const auto runs_size = runs.size();
    while (submitted < runs_size && submitted < c_rounds) {
      runs[static_cast<size_t>(submitted)].start();
      submitted++;
    }
    while (completed < submitted) {
      const auto i = static_cast<size_t>(completed % runs_size);
      auto state = runs[i].wait(timeout_ms);
      completed++;
      if (state == ERT_CMD_STATE_TIMEOUT)
        throw std::runtime_error(std::string("exec buf timed out."));
      if (state != ERT_CMD_STATE_COMPLETED)
        throw std::runtime_error(std::string("bad command state: ") + std::to_string(state));
      if (submitted < c_rounds) {
        runs[i].start();
        submitted++;
      }
    }
    return;
  }
  std::vector<xrt::runlist> runlists;
  for (unsigned i = 0; i < o_cmds; i++) {
    runlists.emplace_back(hwctx);
    for (unsigned j = 0; j < r_cmds; j++)
      runlists[i].add(runs[i * r_cmds + j]);
  }
  uint64_t submitted = 0;
  uint64_t completed = 0;
  const auto runlists_size = runlists.size();
  auto start = std::chrono::high_resolution_clock::now();

  while (submitted < runlists_size && submitted < c_rounds) {
    runlists[static_cast<size_t>(submitted)].execute();
    submitted++;
  }
  while (completed < submitted) {
    const auto i = static_cast<size_t>(completed % runlists_size);
    auto state = runlists[i].wait(timeout_ms * r_cmds * std::chrono::milliseconds{1});
    completed++;
    if (state == std::cv_status::timeout)
      throw std::runtime_error(std::string("exec buf timed out."));
    auto ert_state = runlists[i].state();
    if (ert_state != ERT_CMD_STATE_COMPLETED)
      throw std::runtime_error(std::string("bad command state: ") + std::to_string(ert_state));
    if (submitted < c_rounds) {
      runlists[i].execute();
      submitted++;
    }
  }

  auto end = std::chrono::high_resolution_clock::now();
  auto duration_us = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
  std::cout << "Executed total " << c_rounds << " runlists in " << duration_us
	    << "us with max " << o_cmds << " outstanding runlist (" << r_cmds
	    << " commands per runlist), average latency: "
	    << duration_us * 1.0 / (static_cast<uint64_t>(r_cmds) * c_rounds) << "us\n";
}

void
TEST_xrt_umq_vadd(int device_index, arg_type& arg)
{
  auto device = xrt::device{device_index};

  const uint32_t IFM_BYTE_SIZE = 16 * 16 * sizeof (uint32_t);
  const uint32_t WTS_BYTE_SIZE = 4 * 4 * sizeof (uint32_t);
  const uint32_t OFM_BYTE_SIZE = 16 * 16 * sizeof (uint32_t);
  xrt_bo bo_ifm{device, IFM_BYTE_SIZE, xrt::bo::flags::host_only};
  xrt_bo bo_wts{device, WTS_BYTE_SIZE, xrt::bo::flags::host_only};
  xrt_bo bo_ofm{device, OFM_BYTE_SIZE, xrt::bo::flags::host_only};

  init_umq_vadd_buffers<xrt_bo>(bo_ifm, bo_wts, bo_ofm);

  auto [hwctx, kernel] = get_xrt_hwctx_kernel(device,
	  "vadd/xclbin_vadd.xclbin",
	  "vadd/xclbin_vadd.elf",
	  "dpu:{vadd}",
	  "vadd/vadd.elf",
	  "DPU:dpu");
  unsigned n = o_cmds * (r_cmds > 1 ? r_cmds : 1);
  std::vector<xrt::run> runs;
  for (unsigned i = 0; i < n; i++)
    runs.emplace_back(kernel);
  for (auto& r : runs) {
    r.set_arg(0, bo_ifm.get());
    r.set_arg(1, bo_wts.get());
    r.set_arg(2, bo_ofm.get());
  }
  sync_bo_to_dev(bo_ifm);
  sync_bo_to_dev(bo_wts);
  sync_bo_to_dev(bo_ofm);
  execute_batches(hwctx, runs, r_cmds);
  sync_bo_from_dev(bo_ofm);
  check_umq_vadd_result(bo_ifm.map(), bo_wts.map(), bo_ofm.map());
}

void
TEST_xrt_umq_memtiles(int device_index, arg_type& arg)
{
  auto device = xrt::device{device_index};
  xrt::elf elf{local_path(path + "move_memtiles/move_memtiles.elf")};
  xrt::hw_context hwctx{device, elf};
  xrt::kernel kernel = xrt::ext::kernel{hwctx, "DPU:dpu"};
  unsigned n = o_cmds * (r_cmds > 1 ? r_cmds : 1);
  std::vector<xrt::run> runs;
  for (unsigned i = 0; i < n; i++)
    runs.emplace_back(kernel);
  execute_batches(hwctx, runs, r_cmds);
}

void
TEST_xrt_umq_ddr_memtile(int device_index, arg_type& arg)
{
  auto device = xrt::device{device_index};
  xrt_bo bo_data{device, sizeof(uint32_t), xrt::bo::flags::cacheable};
  auto p = bo_data.map();
  p[0] = 0xabcdabcd;
  sync_bo_to_dev(bo_data);

  auto [hwctx, kernel] = get_xrt_hwctx_kernel(device,
	  "ddr_memtile/xclbin_ddr.xclbin",
	  "ddr_memtile/xclbin_ddr.elf",
	  "dpu:{vadd}",
	  "ddr_memtile/ddr_memtile.elf",
	  "DPU:dpu");
  unsigned n = o_cmds * (r_cmds > 1 ? r_cmds : 1);
  std::vector<xrt::run> runs;
  for (unsigned i = 0; i < n; i++)
    runs.emplace_back(kernel);
  for (auto& r : runs)
    r.set_arg(0, bo_data.get());
  execute_batches(hwctx, runs, r_cmds);
}

void
TEST_xrt_umq_remote_barrier(int device_index, arg_type& arg)
{
  auto device = xrt::device{device_index};
  auto [hwctx, kernel] = get_xrt_hwctx_kernel(device,
	  "remote_barrier/xclbin_rmb.xclbin",
	  "remote_barrier/xclbin_rmb.elf",
	  "dpu:{vadd}",
	  "remote_barrier/remote_barrier.elf",
	  "DPU:dpu");
  unsigned n = o_cmds * (r_cmds > 1 ? r_cmds : 1);
  std::vector<xrt::run> runs;
  for (unsigned i = 0; i < n; i++)
    runs.emplace_back(kernel);
  execute_batches(hwctx, runs, r_cmds);
}

void
TEST_xrt_umq_nop(int device_index, arg_type& arg)
{
  auto device = xrt::device{device_index};
  auto elf = xrt::elf(elfpath.empty() ? local_path(path + "nop/nop.elf") : elfpath);
  xrt::hw_context hwctx{device, elf};
  xrt::kernel kernel = xrt::ext::kernel{hwctx, "DPU:dpu"};
  unsigned n = o_cmds * (r_cmds > 1 ? r_cmds : 1);
  std::vector<xrt::run> runs;
  for (unsigned i = 0; i < n; i++)
    runs.emplace_back(kernel);
  execute_batches(hwctx, runs, r_cmds);
}

void
TEST_xrt_umq_single_col_resnet50_all_layer(int device_index, arg_type& arg)
{
  std::vector<xrt_bo> wts_v;
  auto device = xrt::device{device_index};

  std::string ifm_path = local_path(path + "resnet50/ifm32.txt");
  std::string wts_path = local_path(path + "resnet50/wts32.txt");
  std::string ofm_path = local_path(path + "resnet50/ofm32.txt");

  const uint32_t IFM_BYTE_SIZE = 233472;
  const uint32_t WTS_BYTE_SIZE = 25704832;
  const uint32_t OFM_BYTE_SIZE = 1024;
  xrt_bo bo_ifm{device, IFM_BYTE_SIZE, xrt::bo::flags::host_only};
  xrt_bo bo_wts{device, WTS_BYTE_SIZE, xrt::bo::flags::host_only};
  xrt_bo bo_ofm{device, OFM_BYTE_SIZE, xrt::bo::flags::host_only};

  read_txt_file<xrt_bo>(ifm_path, bo_ifm);

  auto [hwctx, kernel] = get_xrt_hwctx_kernel(device,
	  "resnet50/xclbin_resnet50.xclbin",
	  "resnet50/xclbin_resnet50.elf",
	  "dpu:{vadd}",
	  "resnet50/resnet50.elf",
	  "DPU:dpu");

  std::ifstream wts_ifs(wts_path);
  if (!wts_ifs.is_open())
    throw std::runtime_error("Unable to open weights file: " + wts_path);
  auto p = bo_wts.map();
  uint32_t tmp;
  int wi = 0;
  while (wts_ifs >> std::hex >> tmp) {
    p[wi] = tmp;
    wi++;
  }
  wts_ifs.close();

  unsigned n = o_cmds * (r_cmds > 1 ? r_cmds : 1);
  std::vector<xrt::run> runs;
  for (unsigned i = 0; i < n; i++)
    runs.emplace_back(kernel);
  for (auto& r : runs) {
    r.set_arg(54, bo_ifm.get());
    for (int i = 0; i < 54; i++)
      r.set_arg(i, bo_wts.get().address() + (wts_offset[i] * sizeof(uint32_t)));
    r.set_arg(55, bo_ofm.get());
  }
  sync_bo_to_dev(bo_ifm);
  sync_bo_to_dev(bo_wts);
  sync_bo_to_dev(bo_ofm);
  execute_batches(hwctx, runs, r_cmds);
  sync_bo_from_dev(bo_ofm);

  auto ofm = bo_ofm.map();
  std::ifstream ofm_ifs(ofm_path);
  if (!ofm_ifs.is_open())
    std::cout << "[ERROR]: failed to open " << ofm_path << std::endl;
  int err = 0;
  for (int i = 0; i < static_cast<int>(OFM_BYTE_SIZE / sizeof(uint32_t)); i++) {
    uint32_t gld;
    ofm_ifs >> std::hex >> gld;
    if (gld != ofm[i]) {
      std::cout << "[ERROR]: No." << i << std::hex << " golden = 0x" << gld << ", ofm = 0x" 
                << ofm[i] << std::endl; err++;
    }
  }
  if (err)
    throw std::runtime_error("result mis-match");
  std::cout << dolphinPass << std::endl << "result matched" << std::endl;
}

/* Create m_rounds hwctx and their runs first, then execute all in parallel.
   Stress-tests concurrent hwctx allocation and concurrent execution. */
void
TEST_xrt_stress_hwctx(int device_index, arg_type& arg)
{
  auto device = xrt::device{device_index};
  auto elf = xrt::elf(elfpath.empty() ? local_path(path + "nop/nop.elf") : elfpath);

  using hwctx_runs_t = std::pair<xrt::hw_context, std::vector<xrt::run>>;
  std::vector<hwctx_runs_t> contexts;
  contexts.reserve(m_rounds);
  for (unsigned i = 0; i < m_rounds; i++) {
    xrt::hw_context hwctx{device, elf};
    xrt::kernel kernel = xrt::ext::kernel{hwctx, "DPU:dpu"};
    unsigned n = o_cmds * (r_cmds > 1 ? r_cmds : 1);
    std::vector<xrt::run> runs;
    for (unsigned j = 0; j < n; j++)
      runs.emplace_back(kernel);
    contexts.emplace_back(std::move(hwctx), std::move(runs));
  }

  const unsigned r = r_cmds;
  std::vector<std::thread> workers;
  workers.reserve(m_rounds);
  for (unsigned i = 0; i < m_rounds; i++)
    workers.emplace_back([&contexts, i, r]() {
      execute_batches(contexts[i].first, contexts[i].second, r);
    });
  for (auto& t : workers)
    t.join();
}

void
TEST_xrt_umq_runlist(int device_index, arg_type& arg)
{
  auto device = xrt::device{device_index};
  auto elf = xrt::elf(elfpath.empty() ? local_path(path + "nop/nop.elf") : elfpath);
  xrt::hw_context hwctx{device, elf};
  xrt::kernel kernel = xrt::ext::kernel{hwctx, "DPU:dpu"};
  unsigned n = o_cmds * MAX_RUNLIST_CMDS;
  std::vector<xrt::run> runs;
  for (unsigned i = 0; i < n; i++)
    runs.emplace_back(kernel);
  execute_batches(hwctx, runs, MAX_RUNLIST_CMDS);
}

// List of all test cases
std::vector<test_case> test_list {
  test_case{ "npu3 xrt vadd", TEST_xrt_umq_vadd, {} },
  test_case{ "npu3 xrt move memtiles", TEST_xrt_umq_memtiles, {} },
  test_case{ "npu3 xrt ddr memtile", TEST_xrt_umq_ddr_memtile, {} },
  test_case{ "npu3 xrt remote barrier", TEST_xrt_umq_remote_barrier, {} },
  test_case{ "npu3 xrt nop/multi nop", TEST_xrt_umq_nop, {} },
  test_case{ "npu3 xrt stress - hwctx", TEST_xrt_stress_hwctx, {} },
  test_case{ "npu3 xrt single col resnet50 all layer", TEST_xrt_umq_single_col_resnet50_all_layer, {} },
  test_case{ "npu3 xrt max runlist", TEST_xrt_umq_runlist, {} },
};

void
print_available_tests()
{
  std::cout << "Available Test Cases:\n";
  for (size_t i = 0; i < test_list.size(); i++) {
    std::cout << "  #" << i << " - " << test_list[i].description << "\n";
  }
  std::cout << "  #99 - npu3 xrt thread test\n";
  std::cout << std::endl;
}

/* test n threads of 1 or more tests */
void
TEST_xrt_threads(int device_index, arg_type& arg)
{
  std::vector<std::thread> m_threads;
  std::vector<bool> m_failed(threads, false);

  if (exec_list.empty())
    exec_list.insert(exec_list.begin(), threads, 0);
  else if (exec_list.size() < threads)
    exec_list.insert(exec_list.end(), threads - exec_list.size(), exec_list.back()); // if more threads requested than tests given, run test at last element
  else
    threads = exec_list.size(); // if more tests than threads, increase threads to run all tests

  if (vf_test) {
    for (int i = 0; i < threads; i++) {
      m_threads.push_back(std::thread([&, i](){
        std::cout << "Thread " << i << " started" << std::endl;
	try {
	  test_list[exec_list[i]].func(i % vf_cnt, test_list[exec_list[i]].arg);
	} catch (const std::exception& ex) {
	  m_failed[i] = true;
	  std::cerr << "Thread " << i << " failed: " << ex.what() << std::endl;
	}
      })
      );
    }
  }
  else {
    for (int i = 0; i < threads; i++) {
      m_threads.push_back(std::thread([&, i](){
        std::cout << "Thread " << i << " started" << std::endl;
	try {
	  test_list[exec_list[i]].func(device_index, test_list[exec_list[i]].arg);
	} catch (const std::exception& ex) {
	  m_failed[i] = true;
	  std::cerr << "Thread " << i << " failed: " << ex.what() << std::endl;
	}
      })
      );
    }
  }

  for (int i = 0; i < threads; i++)
    m_threads[i].join();

  for (int i = 0; i < threads; i++) {
    if (m_failed[i])
      throw std::runtime_error("At least one thread has failed");
  }

}

}

// Test case executor implementation

void
run_test(int id, const test_case& test, int device_index)
{
  bool failed = false;

  std::cout << "====== " << id << ": " << test.description << " started =====" << std::endl;

  try {
    test.func(device_index, test.arg);
  }
  catch (const std::exception& ex) {
    std::cerr << test.description << " exception: " << ex.what() << std::endl;
    failed = true;
  }

  std::string result = failed ? "FAILED" : "PASSED";
  std::cout << "====== " << id << ": " << test.description  << " " << result << "  =====" << std::endl;

  if (failed)
    test_failed++;
  else
    test_passed++;
}

void
run_all_test(std::set<int>& tests)
{
  auto all = tests.empty();

  if (!test_list.size())
    std::cout << "test_list is empty!" << std::endl;

  for (int i = 0; i < test_list.size(); i++) {
    if (!all) {
      if (tests.find(i) == tests.end())
        continue;
      else
        tests.erase(i);
    }
    const auto& t = test_list[i];
    run_test(i, t, device_index);
    std::cout << std::endl;
  }
}

int
main(int argc, char **argv)
{
  program = std::filesystem::path(argv[0]).filename();
  std::set<int> tests;
  curpath = dirname(argv[0]);
  printing_on = true;

  try {
    int option, val;
    while ((option = getopt(argc, argv, ":c:o:r:m:x:i:t:e:v:w:lh")) != -1) {
      switch (option) {
        case 'c': {
          val = std::stoi(optarg);
	  std::cout << "Using c_rounds: " << val << std::endl;
	  c_rounds = val;
	  break;
        }
        case 'o': {
          val = std::stoi(optarg);
	  std::cout << "Maximum outstanding cmds " << val << std::endl;
	  o_cmds = val;
	  break;
        }
        case 'r': {
          val = std::stoi(optarg);
          if (val > MAX_RUNLIST_CMDS) {
            std::cout << "r_cmds max is " << MAX_RUNLIST_CMDS << std::endl;
            return 1;
          }
	  std::cout << "Per runlist cmds: " << val << std::endl;
	  r_cmds = val;
	  break;
        }
        case 'm': {
          val = std::stoi(optarg);
          std::cout << "Using m_rounds: " << val << std::endl;
          m_rounds = val;
          break;
        }
        case 'i': {
          val = std::stoi(optarg);
          std::cout << "Using device_index: " << val << std::endl;
          device_index = val;
          break;
        }
        case 't': {
          val = std::stoi(optarg);
          if (val <= 0) {
            std::cout << "Thread count should be greater than 0" << std::endl;
            return 1;
          }
          std::cout << "Creating " << val << " threads" << std::endl;
          threads = val;
          break;
        }
        case 'e': {
          val = std::stoi(optarg);
          if (val > test_list.size() - 1 || val < 0) {
            std::cout << "Invalid test number" << std::endl;
            return 1;
          }
          std::cout << "Add test #" << val << " to thread test" << std::endl;
          exec_list.push_back(val);
          break;
        }
        case 'w': {
          val = std::stoi(optarg);
          if (val <= 0) {
            std::cout << "Timeout should be greater than 0 seconds" << std::endl;
            return 1;
          }
          timeout_ms = val * 1000; // Convert seconds to milliseconds
          std::cout << "Using timeout: " << val << " seconds (" << timeout_ms << " ms)" << std::endl;
          break;
        }
        case 'x': {
          elfpath = local_path(path + optarg + "/" + optarg + ".elf");
          if (!elfpath.empty()) {
            std::cout << "Using elf file: " << elfpath << std::endl;
            break;
          } else {
            std::cout << "Failed to open elf file: " << elfpath << std::endl;
            return 1;
          }
        }
        case 'l': {
          std::cout << "swtiching to xclbin flow" << std::endl;
          elf_flow = false;
          break;
        }
        case 'v': {
          val = std::stoi(optarg);
          if (val > 4 || val < 1) {
            std::cout << "VF count is between 1-4" << std::endl;
            return 1;
          }
          vf_cnt = val;
          vf_test = true;
          break;
        }
        case 'h':
          usage(program);
          print_available_tests();
          return 0;
        case '?':
          std::cout << "Unknown option: " << static_cast<char>(optopt) << std::endl;
          usage(program);
          return 1;
        case ':':
          std::cout << "Missing value for option: " << argv[optind-1] << std::endl;
          return 1;
        default:
          usage(program);
          return 1;
      }
    }

    for (int i = optind; i < argc; i++) {
      int idx = std::stoi(argv[i]);
      if (idx >= 0)
        tests.insert(idx);
      else
        return 1;
    }
  }
  catch (...) {
    usage(program);
    return 2;
  }

  set_xrt_path();

  test_list.push_back(test_case{ "npu3 xrt thread test", TEST_xrt_threads, {threads} });

  // Resolve 99 to thread test
  if (tests.find(99) != tests.end()) {
    tests.erase(99);
    tests.insert(test_list.size() - 1);
  }

  run_all_test(tests);

  if (!tests.empty()) {
    std::cout << tests.size() << "\ttest(s) not found:";
    for (auto i : tests)
      std::cout << " " << i;
    std::cout << std::endl;
  }

  if (test_skipped)
    std::cout << test_skipped << "\ttest(s) skipped" << std::endl;

  if (test_passed + test_failed == 0)
    return 0;

  std::cout << test_passed + test_failed << "\ttest(s) executed" << std::endl;
  if (test_failed == 0) {
    std::cout << "ALL " << test_passed << " executed test(s) PASSED!" << std::endl;
    return 0;
  }
  std::cout << test_failed << "\ttest(s) \x1b[5m\x1b[31mFAILED\x1b[0m!" << std::endl;
  return 1;
}

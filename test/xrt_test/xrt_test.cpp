// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2024, Advanced Micro Devices, Inc. All rights reserved.

// XRT includes
#include "xrt/xrt_device.h"
#include "xrt/xrt_kernel.h"
#include "xrt/xrt_bo.h"
#include "experimental/xrt_elf.h"
#include "experimental/xrt_ext.h"
#include "experimental/xrt_module.h"

#include <fstream>
#include <algorithm>
#include <filesystem>
#include <libgen.h>
#include <set>
#include <stdlib.h>
#include <string>
#include <vector>
#include <chrono>
#include <regex>

namespace {

using arg_type = const std::vector<uint64_t>;

const uint16_t npu3_device_id = 0x1569;

std::string program;
// Test harness setup helpers
std::string curpath;
std::string xclbinpath;
bool printing_on; 

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

static void test_pause()
{
  std::cout << "press any key to continue..." << std::endl;
  std::cin.get();
}

enum test_mode {
  TEST_POSITIVE,
  TEST_NEGATIVE,
};

void
usage(const std::string& prog)
{
  std::cout << "\nUsage: " << prog << " [xclbin] [test case ID separated by space]\n";
  std::cout << "Examples:\n";
  std::cout << "\t" << prog << " - run all test cases\n";
  std::cout << "\t" << prog << " [test case ID separated by space] - run specified test cases\n";
  std::cout << "\t" << prog << " /path/to/a/test.xclbin - run all test cases with test.xclbin\n";
  std::cout << "\n";
  std::cout << std::endl;
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

void
TEST_xrt_umq_vadd(int device_index, arg_type& arg)
{
  auto device = xrt::device{device_index};

  // Prepare input/output/weights BOs
  const uint32_t IFM_BYTE_SIZE = 16 * 16 * sizeof (uint32_t);
  const uint32_t WTS_BYTE_SIZE = 4 * 4 * sizeof (uint32_t);
  const uint32_t OFM_BYTE_SIZE = 16 * 16 * sizeof (uint32_t);
  xrt_bo bo_ifm{device, IFM_BYTE_SIZE, xrt::bo::flags::host_only};
  xrt_bo bo_wts{device, WTS_BYTE_SIZE, xrt::bo::flags::host_only};
  xrt_bo bo_ofm{device, OFM_BYTE_SIZE, xrt::bo::flags::host_only};

  // Populate input & weight buffers
  init_umq_vadd_buffers<xrt_bo>(bo_ifm, bo_wts, bo_ofm);

  auto xclbin = xrt::xclbin(
      xclbinpath.empty() ? local_path("npu3_workspace/vadd.xclbin") : xclbinpath);
  auto uuid = device.register_xclbin(xclbin);

  xrt::elf elf{local_path("npu3_workspace/vadd.elf")};
  xrt::module mod{elf};

  xrt::hw_context hwctx{device, uuid};
  xrt::kernel kernel = xrt::ext::kernel{hwctx, mod, "dpu:{vadd}"};
  xrt::run run{kernel};

  // Setting args for patching control code buffer
  run.set_arg(0, bo_ifm.get());
  run.set_arg(1, bo_wts.get());
  run.set_arg(2, bo_ofm.get());

  // Send the command to device and wait for it to complete
  run.start();
  auto state = run.wait(600000 /* 600 sec, some simnow server are slow */);
  if (state == ERT_CMD_STATE_TIMEOUT)
    throw std::runtime_error(std::string("exec buf timed out."));
  if (state != ERT_CMD_STATE_COMPLETED)
    throw std::runtime_error(std::string("bad command state: ") + std::to_string(state));

  // Check result
  check_umq_vadd_result(bo_ifm.map(), bo_wts.map(), bo_ofm.map());
}

void
TEST_xrt_umq_memtiles(int device_index, arg_type& arg)
{
  auto device = xrt::device{device_index};

  auto xclbin = xrt::xclbin(
      xclbinpath.empty() ? local_path("npu3_workspace/move_memtiles.xclbin") : xclbinpath);
  auto uuid = device.register_xclbin(xclbin);

  xrt::elf elf{local_path("npu3_workspace/move_memtiles.elf")};
  xrt::module mod{elf};

  xrt::hw_context hwctx{device, uuid};
  xrt::kernel kernel = xrt::ext::kernel{hwctx, mod, "dpu:{move_memtiles}"};
  xrt::run run{kernel};

  // Send the command to device and wait for it to complete
  run.start();
  auto state = run.wait(600000 /* 600 sec, some simnow server are slow */);
  if (state == ERT_CMD_STATE_TIMEOUT)
    throw std::runtime_error(std::string("exec buf timed out."));
  if (state != ERT_CMD_STATE_COMPLETED)
    throw std::runtime_error(std::string("bad command state: ") + std::to_string(state));
}

void
TEST_xrt_umq_ddr_memtile(int device_index, arg_type& arg)
{
  auto device = xrt::device{device_index};

  /* init input buffer */
  xrt_bo bo_data{device, sizeof(uint32_t), xrt::bo::flags::cacheable};
  auto p = bo_data.map();
  p[0] = 0xabcdabcd;

  auto xclbin = xrt::xclbin(
      xclbinpath.empty() ? local_path("npu3_workspace/ddr_memtile.xclbin") : xclbinpath);
  auto uuid = device.register_xclbin(xclbin);

  xrt::elf elf{local_path("npu3_workspace/ddr_memtile.elf")};
  xrt::module mod{elf};

  xrt::hw_context hwctx{device, uuid};
  xrt::kernel kernel = xrt::ext::kernel{hwctx, mod, "dpu:{move_ddr_memtile}"};
  xrt::run run{kernel};

  // Setting args for patching control code buffer
  run.set_arg(0, bo_data.get());

  // Send the command to device and wait for it to complete
  run.start();
  auto state = run.wait(600000 /* 600 sec, some simnow server are slow */);
  if (state == ERT_CMD_STATE_TIMEOUT)
    throw std::runtime_error(std::string("exec buf timed out."));
  if (state != ERT_CMD_STATE_COMPLETED)
    throw std::runtime_error(std::string("bad command state: ") + std::to_string(state));
}

void
TEST_xrt_umq_remote_barrier(int device_index, arg_type& arg)
{
  auto device = xrt::device{device_index};

  auto xclbin = xrt::xclbin(
      xclbinpath.empty() ? local_path("npu3_workspace/remote_barrier.xclbin") : xclbinpath);
  auto uuid = device.register_xclbin(xclbin);

  xrt::elf elf{local_path("npu3_workspace/remote_barrier.elf")};
  xrt::module mod{elf};

  xrt::hw_context hwctx{device, uuid};
  xrt::kernel kernel = xrt::ext::kernel{hwctx, mod, "dpu:{remote_barrier}"};
  xrt::run run{kernel};

  // Send the command to device and wait for it to complete
  run.start();
  auto state = run.wait(600000 /* 600 sec, some simnow server are slow */);
  if (state == ERT_CMD_STATE_TIMEOUT)
    throw std::runtime_error(std::string("exec buf timed out."));
  if (state != ERT_CMD_STATE_COMPLETED)
    throw std::runtime_error(std::string("bad command state: ") + std::to_string(state));
}

// List of all test cases
std::vector<test_case> test_list {
  test_case{ "npu3 xrt vadd", TEST_xrt_umq_vadd, {} },
  test_case{ "npu3 xrt move memtiles", TEST_xrt_umq_memtiles, {} },
  test_case{ "npu3 xrt ddr_memtile", TEST_xrt_umq_ddr_memtile, {} },
  test_case{ "npu3 xrt remote_barrier", TEST_xrt_umq_remote_barrier, {} },
};

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
    std::cerr << ex.what() << std::endl;
    failed = true;
  }

  std::string result;
  result = failed ? "\x1b[5m\x1b[31mFAILED\x1b[0m" : "passed";
  std::cout << "====== " << id << ": " << test.description << " " << result << "  =====" << std::endl;

  if (failed)
    test_failed++;
  else
    test_passed++;
}

void
run_all_test(std::set<int>& tests)
{
  auto all = tests.empty();
  unsigned int device_index = 0;

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

  printing_on = true;
  try {
    int first_test_id = 1;

    if (argc >= 2) {
      std::ifstream xclbin(argv[1]);
      if (xclbin) {
        xclbinpath = argv[1];
        std::cout << "Xclbin file: " << xclbinpath << std::endl;
        first_test_id++;
      }
    }

    for (int i = first_test_id; i < argc; i++)
      tests.insert(std::stoi(argv[i]));
  }
  catch (...) {
    usage(program);
    return 2;
  }

  curpath = dirname(argv[0]);
  set_xrt_path();

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

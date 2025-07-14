// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2024-2025, Advanced Micro Devices, Inc. All rights reserved.

// XRT includes
#include "xrt/xrt_device.h"
#include "xrt/xrt_kernel.h"
#include "xrt/xrt_bo.h"
#include "xrt/experimental/xrt_elf.h"
#include "xrt/experimental/xrt_ext.h"
#include "xrt/experimental/xrt_module.h"
#include "multi-layer.h"
#include "resnet50.h"

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
#include <unistd.h>
#include <thread>

namespace {

using arg_type = const std::vector<uint64_t>;
unsigned c_rounds = 1;
unsigned s_rounds = 128;
unsigned m_rounds = 32;
unsigned device_index = 0;
unsigned threads = 2;
std::vector<unsigned> exec_list;
std::string dpu = "nop";

std::string program;
// Test harness setup helpers
std::string curpath;
std::string xclbinpath;
std::string elfpath;
bool printing_on;

void
usage(const std::string& prog)
{
  std::cout << "\nUsage: " << prog << " [options] [test case ID separated by space]\n";
  std::cout << "Options:\n";
  std::cout << "\t" << "xrt_test" << " - run all test cases\n";
  std::cout << "\t" << "xrt_test" << " [test case ID separated by space] - run specified test cases\n";
  std::cout << "\t" << "-c" << ": n rounds in sequence within 1 hwctx (for vadd only)\n";
  std::cout << "\t" << "-s" << ": n rounds in parallel within 1 hwctx\n";
  std::cout << "\t" << "-m" << ": n hwctx in parallel\n";
  std::cout << "\t" << "-x" << ": specify xclbin and elf to use (only effects stress test and multi-layer)\n";
  std::cout << "\t" << "-d" << ": specify dpu kernel (only effects stress test)\n";
  std::cout << "\t" << "-i" << ": specify device index (0 for non-sriov or VF0, 1, 2, 3 for VFs)\n";
  std::cout << "\t" << "-t" << ": n thread to be created in thread test (default 2)\n";
  std::cout << "\t" << "-e" << ": specify tests to add to thread test (default vadd) [-e test1 -e test2 ...]\n";
  std::cout << "\t" << "-h" << ": print this help message\n\n";
  std::cout << "\t" << "Example Usage: ./xrt_test <# for stress test> -s 20 -d vadd -x vadd\n";
  std::cout << "\t" << "               Run stress test with Vadd kernel and xclbin for 20 rounds\n";
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

static void test_pause()
{
  std::cout << "press any key to continue..." << std::endl;
  std::cin.get();
}

enum test_mode {
  TEST_POSITIVE,
  TEST_NEGATIVE,
};

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

void check_umq_multi_layer_result(int *ifm, int *wts, int *wts2, int *ofm)
{
  int err = 0;
  for (uint32_t i = 0; i < 16 * 16; i++) {
    if (ofm[i] != multi_layer[i]) {
      std::cout << "error@" << i <<": " << ofm[i] << ", expecting: " << multi_layer[i]<< std::endl;
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
read_bin_file(std::string& filename, TEST_BO& test_bo)
{
  uint32_t value;
  int i = 0;

  std::ifstream infile(filename, std::ios::binary);
  if (!infile)
    throw std::runtime_error("Unable to open .bin file");

  auto p = test_bo.map();
  while (infile.read(reinterpret_cast<char*>(&value), sizeof(value))) {
    p[i] = value;
    i++;
  }
  infile.close();
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

  xrt::elf elf{local_path("npu3_workspace/vadd.elf")};

  xrt::hw_context hwctx{device, elf};
  xrt::kernel kernel = xrt::ext::kernel{hwctx, "DPU:vadd"};
  xrt::run run{kernel};

  // Setting args for patching control code buffer
  run.set_arg(0, bo_ifm.get());
  run.set_arg(1, bo_wts.get());
  run.set_arg(2, bo_ofm.get());

  // Send the command to device and wait for it to complete
  for (int i = 0 ; i < c_rounds; i++) {
    std::cout << "c_rounds: " << i << std::endl;
    //cleanup ofm on each run
    init_umq_ofm_bo(bo_ofm);

    run.start();
    auto state = run.wait(600000 /* 600 sec, some simnow server are slow */);
    if (state == ERT_CMD_STATE_TIMEOUT)
      throw std::runtime_error(std::string("exec buf timed out."));
    if (state != ERT_CMD_STATE_COMPLETED)
      throw std::runtime_error(std::string("bad command state: ") + std::to_string(state));

    // Check result
    check_umq_vadd_result(bo_ifm.map(), bo_wts.map(), bo_ofm.map());
  }
}

void
TEST_xrt_umq_memtiles(int device_index, arg_type& arg)
{
  auto device = xrt::device{device_index};

  xrt::elf elf{local_path("npu3_workspace/move_memtiles.elf")};

  xrt::hw_context hwctx{device, elf};
  xrt::kernel kernel = xrt::ext::kernel{hwctx, "DPU:move_memtiles"};
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

  xrt::elf elf{local_path("npu3_workspace/ddr_memtile.elf")};

  xrt::hw_context hwctx{device, elf};
  xrt::kernel kernel = xrt::ext::kernel{hwctx, "DPU:move_ddr_memtile"};
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

  xrt::elf elf{local_path("npu3_workspace/remote_barrier.elf")};

  xrt::hw_context hwctx{device, elf};
  xrt::kernel kernel = xrt::ext::kernel{hwctx, "DPU:remote_barrier"};
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
TEST_xrt_umq_nop(int device_index, arg_type& arg)
{
  auto device = xrt::device{device_index};

  xrt::elf elf{local_path("npu3_workspace/nop.elf")};

  xrt::hw_context hwctx{device, elf};
  xrt::kernel kernel = xrt::ext::kernel{hwctx, "DPU:nop"};
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
TEST_xrt_umq_single_col_preemption(int device_index, arg_type& arg)
{
  auto device = xrt::device{device_index};

  xrt::elf elf{local_path("npu3_workspace/single_col_preemption.elf")};

  xrt::hw_context hwctx{device, elf};
  xrt::kernel kernel = xrt::ext::kernel{hwctx, "DPU:preemption"};
  xrt::run run{kernel};

  /* init input buffer */
  const uint32_t data = 0x12345678;
  const uint32_t rw_size = sizeof(uint32_t); // number of shim BD used

  xrt_bo bo_ifm{device, rw_size, xrt::bo::flags::cacheable};
  xrt_bo bo_ofm{device, rw_size, xrt::bo::flags::cacheable};
  auto ifm_mapped = bo_ifm.map();
  ifm_mapped[0] = data;

  // Setting args for patching control code buffer
  run.set_arg(0, bo_ifm.get());
  run.set_arg(1, bo_ofm.get());

  // Send the command to device and wait for it to complete
  run.start();
  auto state = run.wait(600000 /* 600 sec, some simnow server are slow */);
  if (state == ERT_CMD_STATE_TIMEOUT)
    throw std::runtime_error(std::string("exec buf timed out."));
  if (state != ERT_CMD_STATE_COMPLETED)
    throw std::runtime_error(std::string("bad command state: ") + std::to_string(state));

  // Check result
  auto ofm_mapped = bo_ofm.map();
  if (ofm_mapped[0] != ifm_mapped[0]) {
    std::cout << "error: " << ofm_mapped[0] << ", expecting: " << ifm_mapped[0] << std::endl;
    throw std::runtime_error("result mis-match");
  }
  else
    std::cout << "result matched" << std::endl;
}

void 
TEST_xrt_umq_multi_col_preemption(int device_index, arg_type& arg)
{
  auto device = xrt::device{device_index};

  xrt::elf elf{local_path("npu3_workspace/multi_col_preemption.elf")};

  xrt::hw_context hwctx{device, elf};
  xrt::kernel kernel = xrt::ext::kernel{hwctx, "DPU:preemption"};
  xrt::run run{kernel};

  /* init input buffer */
  const uint32_t data = 0x12345678;
  const uint32_t rw_size = sizeof(uint32_t); // number of shim BD used

  xrt_bo bo_ifm{device, rw_size, xrt::bo::flags::cacheable};
  xrt_bo bo_ofm{device, rw_size, xrt::bo::flags::cacheable};
  auto ifm_mapped = bo_ifm.map();
  ifm_mapped[0] = data;

  // Setting args for patching control code buffer
  run.set_arg(0, bo_ifm.get());
  run.set_arg(1, bo_ofm.get());

  // Send the command to device and wait for it to complete
  run.start();
  auto state = run.wait(600000 /* 600 sec, some simnow server are slow */);
  if (state == ERT_CMD_STATE_TIMEOUT)
    throw std::runtime_error(std::string("exec buf timed out."));
  if (state != ERT_CMD_STATE_COMPLETED)
    throw std::runtime_error(std::string("bad command state: ") + std::to_string(state));

  // Check result
  auto ofm_mapped = bo_ofm.map();
  if (ofm_mapped[0] != ifm_mapped[0]) {
    std::cout << "error: " << ofm_mapped[0] << ", expecting: " << ifm_mapped[0] << std::endl;
    throw std::runtime_error("result mis-match");
  }
  else
    std::cout << "result matched" << std::endl;
}

void
TEST_xrt_umq_single_col_resnet50_1_layer(int device_index, arg_type& arg)
{
  auto device = xrt::device{device_index};

  std::string ifm_path = local_path("npu3_workspace/ifm.bin");
  std::string param_path = local_path("npu3_workspace/param.bin");
  std::string wgt_path = local_path("npu3_workspace/wgt.bin");
  std::string ofm_path = local_path("npu3_workspace/ofm.bin");

  const uint32_t IFM_BYTE_SIZE = std::filesystem::file_size(ifm_path);
  const uint32_t WTS_BYTE_SIZE = std::filesystem::file_size(wgt_path);
  const uint32_t OFM_BYTE_SIZE = std::filesystem::file_size(ofm_path);
  const uint32_t PARAM_BYTE_SIZE = std::filesystem::file_size(param_path);
  xrt_bo bo_ifm{device, IFM_BYTE_SIZE, xrt::bo::flags::host_only};
  xrt_bo bo_wts{device, WTS_BYTE_SIZE, xrt::bo::flags::host_only};
  xrt_bo bo_ofm{device, OFM_BYTE_SIZE, xrt::bo::flags::host_only};
  xrt_bo bo_param{device, PARAM_BYTE_SIZE, xrt::bo::flags::host_only};

  read_bin_file<xrt_bo>(ifm_path, bo_ifm);
  read_bin_file<xrt_bo>(wgt_path, bo_wts);
  read_bin_file<xrt_bo>(ofm_path, bo_ofm);
  read_bin_file<xrt_bo>(param_path, bo_param);

  xrt::elf elf{local_path("npu3_workspace/single_col_resnet50_1_layer.elf")};

  xrt::hw_context hwctx{device, elf};
  xrt::kernel kernel = xrt::ext::kernel{hwctx, "DPU:resnet50"};
  xrt::run run{kernel};

  run.set_arg(0, bo_ofm.get());
  run.set_arg(1, bo_ifm.get());
  run.set_arg(2, bo_wts.get());
  run.set_arg(3, bo_param.get());

  // Send the command to device and wait for it to complete
  run.start();
  auto state = run.wait(600000 /* 600 sec, some simnow server are slow */);
  if (state == ERT_CMD_STATE_TIMEOUT)
    throw std::runtime_error(std::string("exec buf timed out."));
  if (state != ERT_CMD_STATE_COMPLETED)
    throw std::runtime_error(std::string("bad command state: ") + std::to_string(state));

  check_umq_resnet50_result(bo_ofm.map(), ofm_path);
}

void
TEST_xrt_umq_single_col_resnet50_all_layer(int device_index, arg_type& arg)
{
  std::vector<xrt_bo> wts_v;
  auto device = xrt::device{device_index};

  std::string ifm_path = local_path("npu3_workspace/ifm32.txt");
  std::string wts_path = local_path("npu3_workspace/wts32.txt");
  std::string ofm_path = local_path("npu3_workspace/ofm32.txt");

  const uint32_t IFM_BYTE_SIZE = 233472;
  const uint32_t WTS_BYTE_SIZE = 25704832;
  const uint32_t OFM_BYTE_SIZE = 1024;
  xrt_bo bo_ifm{device, IFM_BYTE_SIZE, xrt::bo::flags::host_only};
  xrt_bo bo_wts{device, WTS_BYTE_SIZE, xrt::bo::flags::host_only};
  xrt_bo bo_ofm{device, OFM_BYTE_SIZE, xrt::bo::flags::host_only};

  read_txt_file<xrt_bo>(ifm_path, bo_ifm);

  xrt::elf elf{local_path("npu3_workspace/single_col_resnet50_all_layer.elf")};

  xrt::hw_context hwctx{device, elf};
  xrt::kernel kernel = xrt::ext::kernel{hwctx, "DPU:resnet50"};
  xrt::run run{kernel};

  run.set_arg(54, bo_ifm.get());

  std::ifstream wts_ifs(wts_path);
  if (!wts_ifs.is_open())
    throw std::runtime_error("Unable to open weights file: " + wts_path);

  auto p = bo_wts.map();
  uint32_t tmp;
  int i = 0;
  while (wts_ifs >> std::hex >> tmp) {
    p[i] = tmp;
    i++;
  }
  wts_ifs.close();

  for (int i = 0; i < 54; i++) {
    run.set_arg(i, bo_wts.get().address() + (wts_offset[i] * sizeof(uint32_t)));
  }

  run.set_arg(55, bo_ofm.get());

  // Send the command to device and wait for it to complete
  run.start();
  auto state = run.wait(3600000 /* 1 hour, some simnow server are slow */);
  if (state == ERT_CMD_STATE_TIMEOUT)
    throw std::runtime_error(std::string("exec buf timed out."));
  if (state != ERT_CMD_STATE_COMPLETED)
    throw std::runtime_error(std::string("bad command state: ") + std::to_string(state));

  auto ofm = bo_ofm.map();
  std::ifstream ofm_ifs;
  ofm_ifs.open(ofm_path);
  if (!ofm_ifs.is_open()) {
    std::cout << "[ERROR]: failed to open " << ofm_path << std::endl;
  }
  int err = 0;
  for (int i = 0; i < OFM_BYTE_SIZE / sizeof(uint32_t); i++) {
    uint32_t gld;
    ofm_ifs >> std::hex >> gld;
    if (gld != ofm[i]) {
      std::cout << "[ERROR]: No." << i << std::hex << "   golden = 0x" << gld << ", ofm = 0x" << ofm[i] << std::endl;
      err++;
    }
  }
  ofm_ifs.close();

  if (err)
    throw std::runtime_error("result mis-match");
  else
    std::cout << "result matched" << std::endl;
}

void
TEST_xrt_umq_multi_layer(int device_index, arg_type& arg)
{
  auto device = xrt::device{device_index};

  // Prepare input/output/weights BOs
  const uint32_t IFM_BYTE_SIZE = 16 * 16 * sizeof (uint32_t);
  const uint32_t WTS_BYTE_SIZE = 4 * 4 * sizeof (uint32_t);
  const uint32_t WTS2_BYTE_SIZE = 8 * 8 * sizeof (uint32_t);
  const uint32_t OFM_BYTE_SIZE = 16 * 16 * sizeof (uint32_t);
  xrt_bo bo_ifm{device, IFM_BYTE_SIZE, xrt::bo::flags::host_only};
  xrt_bo bo_wts{device, WTS_BYTE_SIZE, xrt::bo::flags::host_only};
  xrt_bo bo_wts2{device, WTS2_BYTE_SIZE, xrt::bo::flags::host_only};
  xrt_bo bo_ofm{device, OFM_BYTE_SIZE, xrt::bo::flags::host_only};

  // Populate input & weight buffers
  init_umq_vadd_buffers<xrt_bo>(bo_ifm, bo_wts, bo_ofm);
  auto p = bo_wts2.map();
  for (uint32_t i = 0; i < bo_wts2.size() / sizeof (uint32_t); i++)
    p[i] = i * 10000000;

  auto elf = xrt::elf(
      elfpath.empty() ? local_path("npu3_workspace/multi_layer.elf") : elfpath);

  xrt::hw_context hwctx{device, elf};
  xrt::kernel kernel = xrt::ext::kernel{hwctx, "DPU:vadd"};
  xrt::run run{kernel};

  // Setting args for patching control code buffer
  run.set_arg(0, bo_ifm.get());
  run.set_arg(1, bo_ofm.get());
  run.set_arg(2, bo_wts.get());
  run.set_arg(3, bo_wts2.get());

  // Send the command to device and wait for it to complete
  run.start();
  auto state = run.wait(600000 /* 600 sec, some simnow server are slow */);
  if (state == ERT_CMD_STATE_TIMEOUT)
    throw std::runtime_error(std::string("exec buf timed out."));
  if (state != ERT_CMD_STATE_COMPLETED)
    throw std::runtime_error(std::string("bad command state: ") + std::to_string(state));

  // Check result
  check_umq_multi_layer_result(bo_ifm.map(), bo_wts.map(), bo_wts2.map(), bo_ofm.map());
}

void
TEST_xrt_umq_core_equivalence(int device_index, arg_type& arg)
{
  auto device = xrt::device{device_index};

  // Prepare input/output/weights BOs
  const uint32_t IFM_BYTE_SIZE = 8 * 4 * 6 * sizeof (uint32_t);
  const uint32_t WTS_BYTE_SIZE = 6 * 6 * sizeof (uint32_t);
  const uint32_t WTS2_BYTE_SIZE = 6 * 6 * sizeof (uint32_t);
  const uint32_t OFM_BYTE_SIZE = 8 * 4 * 6 * sizeof (uint32_t);
  xrt_bo bo_ifm{device, IFM_BYTE_SIZE, xrt::bo::flags::host_only};
  xrt_bo bo_wts{device, WTS_BYTE_SIZE, xrt::bo::flags::host_only};
  xrt_bo bo_wts2{device, WTS2_BYTE_SIZE, xrt::bo::flags::host_only};
  xrt_bo bo_ofm{device, OFM_BYTE_SIZE, xrt::bo::flags::host_only};

  // Populate input & weight buffers
  auto p = bo_ifm.map();
  for (uint32_t i = 0; i < bo_ifm.size() / sizeof (uint32_t); i++)
    p[i] = i;
  p = bo_wts.map();
  for (uint32_t i = 0; i < bo_wts.size() / sizeof (uint32_t); i++)
    p[i] = i;
  p = bo_wts2.map();
  for (uint32_t i = 0; i < bo_wts2.size() / sizeof (uint32_t); i++)
    p[i] = i;

  xrt::elf elf{local_path("npu3_workspace/core_equivalence.elf")};

  xrt::hw_context hwctx{device, elf};
  xrt::kernel kernel = xrt::ext::kernel{hwctx, "DPU:vadd"};
  xrt::run run{kernel};

  // Setting args for patching control code buffer
  run.set_arg(0, bo_ifm.get());
  run.set_arg(1, bo_ofm.get());
  run.set_arg(2, bo_wts.get());
  run.set_arg(3, bo_wts2.get());

  // Send the command to device and wait for it to complete
  run.start();
  auto state = run.wait(600000 /* 600 sec, some simnow server are slow */);
  if (state == ERT_CMD_STATE_TIMEOUT)
    throw std::runtime_error(std::string("exec buf timed out."));
  if (state != ERT_CMD_STATE_COMPLETED)
    throw std::runtime_error(std::string("bad command state: ") + std::to_string(state));

  // Check result
  auto ofm_mapped = bo_ofm.map();
  int err = 0;
  for (uint32_t i = 0; i < bo_ofm.size() / sizeof (uint32_t); i++) {
    if (ofm_mapped[i] != core_equivalence[i]) {
      std::cout << "error@" << i <<": " << ofm_mapped[i] << ", expecting: " << core_equivalence[i] << std::endl;
      err++;
    }
  }

  if (err)
    throw std::runtime_error("result mis-match");
  else
    std::cout << "result matched" << std::endl;
}

void
TEST_xrt_umq_cascade_4ker_2lay(int device_index, arg_type& arg)
{
  auto device = xrt::device{device_index};

  // Prepare input/output/weights BOs
  const uint32_t IFM_BYTE_SIZE = 8 * 4 * 6 * sizeof (uint32_t);
  const uint32_t WTS_BYTE_SIZE = 6 * 6 * sizeof (uint32_t);
  const uint32_t WTS2_BYTE_SIZE = 6 * 6 * sizeof (uint32_t);
  const uint32_t OFM_BYTE_SIZE = 8 * 4 * 6 * sizeof (uint32_t);
  xrt_bo bo_ifm{device, IFM_BYTE_SIZE, xrt::bo::flags::host_only};
  xrt_bo bo_wts{device, WTS_BYTE_SIZE, xrt::bo::flags::host_only};
  xrt_bo bo_wts2{device, WTS2_BYTE_SIZE, xrt::bo::flags::host_only};
  xrt_bo bo_ofm{device, OFM_BYTE_SIZE, xrt::bo::flags::host_only};

  // Populate input & weight buffers
  auto p = bo_ifm.map();
  for (uint32_t i = 0; i < bo_ifm.size() / sizeof (uint32_t); i++)
    p[i] = i;
  p = bo_wts.map();
  for (uint32_t i = 0; i < bo_wts.size() / sizeof (uint32_t); i++)
    p[i] = i;
  p = bo_wts2.map();
  for (uint32_t i = 0; i < bo_wts2.size() / sizeof (uint32_t); i++)
    p[i] = i;

  xrt::elf elf{local_path("npu3_workspace/ml4v2.elf")};

  xrt::hw_context hwctx{device, elf};
  xrt::kernel kernel = xrt::ext::kernel{hwctx, "DPU:vadd"};
  xrt::run run{kernel};

  // Setting args for patching control code buffer
  run.set_arg(0, bo_ifm.get());
  run.set_arg(1, bo_ofm.get());
  run.set_arg(2, bo_wts.get());
  run.set_arg(3, bo_wts2.get());

  // Send the command to device and wait for it to complete
  run.start();
  auto state = run.wait(600000 /* 600 sec, some simnow server are slow */);
  if (state == ERT_CMD_STATE_TIMEOUT)
    throw std::runtime_error(std::string("exec buf timed out."));
  if (state != ERT_CMD_STATE_COMPLETED)
    throw std::runtime_error(std::string("bad command state: ") + std::to_string(state));

  // Check result
  auto ofm_mapped = bo_ofm.map();
  int err = 0;
  for (uint32_t i = 0; i < bo_ofm.size() / sizeof (uint32_t); i++) {
    if (ofm_mapped[i] != core_equivalence[i]) {
      std::cout << "error@" << i <<": " << ofm_mapped[i] << ", expecting: " << core_equivalence[i] << std::endl;
      err++;
    }
  }

  if (err)
    throw std::runtime_error("result mis-match");
  else
    std::cout << "result matched" << std::endl;
}

void
TEST_xrt_umq_parallel_branches(int device_index, arg_type& arg)
{
  auto device = xrt::device{device_index};

  // Prepare input/output/weights BOs
  const uint32_t IFM_BYTE_SIZE = 8 * 4 * sizeof (uint32_t);
  const uint32_t WTS_BYTE_SIZE = 8 * sizeof (uint32_t);
  const uint32_t OFM_BYTE_SIZE = 8 * 4 * sizeof (uint32_t);
  xrt_bo bo_ifm{device, IFM_BYTE_SIZE, xrt::bo::flags::host_only};
  xrt_bo bo_wts{device, WTS_BYTE_SIZE, xrt::bo::flags::host_only};
  xrt_bo bo_wts2l{device, WTS_BYTE_SIZE, xrt::bo::flags::host_only};
  xrt_bo bo_wts2r{device, WTS_BYTE_SIZE, xrt::bo::flags::host_only};
  xrt_bo bo_wts3{device, WTS_BYTE_SIZE, xrt::bo::flags::host_only};
  xrt_bo bo_ofm{device, OFM_BYTE_SIZE, xrt::bo::flags::host_only};

  // Populate input & weight buffers
  auto p = bo_ifm.map();
  for (uint32_t i = 0; i < bo_ifm.size() / sizeof (uint32_t); i++)
    p[i] = i;
  p = bo_wts.map();
  for (uint32_t i = 0; i < bo_wts.size() / sizeof (uint32_t); i++)
    p[i] = i;
  p = bo_wts2l.map();
  for (uint32_t i = 0; i < bo_wts2l.size() / sizeof (uint32_t); i++)
    p[i] = i;
  p = bo_wts2r.map();
  for (uint32_t i = 0; i < bo_wts2r.size() / sizeof (uint32_t); i++)
    p[i] = i;
  p = bo_wts3.map();
  for (uint32_t i = 0; i < bo_wts3.size() / sizeof (uint32_t); i++)
    p[i] = i;

  xrt::elf elf{local_path("npu3_workspace/parallel_branches.elf")};

  xrt::hw_context hwctx{device, elf};
  xrt::kernel kernel = xrt::ext::kernel{hwctx, "DPU:vadd"};
  xrt::run run{kernel};

  // Setting args for patching control code buffer
  run.set_arg(0, bo_ifm.get());
  run.set_arg(1, bo_ofm.get());
  run.set_arg(2, bo_wts.get());
  run.set_arg(3, bo_wts2l.get());
  run.set_arg(4, bo_wts2r.get());
  run.set_arg(5, bo_wts3.get());

  // Send the command to device and wait for it to complete
  run.start();
  auto state = run.wait(600000 /* 600 sec, some simnow server are slow */);
  if (state == ERT_CMD_STATE_TIMEOUT)
    throw std::runtime_error(std::string("exec buf timed out."));
  if (state != ERT_CMD_STATE_COMPLETED)
    throw std::runtime_error(std::string("bad command state: ") + std::to_string(state));

  // Check result
  auto ofm_mapped = bo_ofm.map();
  int err = 0;
  for (uint32_t i = 0; i < bo_ofm.size() / sizeof (uint32_t); i++) {
    if (ofm_mapped[i] != parallel_branches[i]) {
      std::cout << "error@" << i <<": " << ofm_mapped[i] << ", expecting: " << parallel_branches[i] << std::endl;
      err++;
    }
  }

  if (err)
    throw std::runtime_error("result mis-match");
  else
    std::cout << "result matched" << std::endl;
}

/* run.start n requests, then run.wait all of them */
void
TEST_xrt_stress_run(int device_index, arg_type& arg)
{
  auto device = xrt::device{device_index};
  unsigned round = s_rounds;

  auto elf = xrt::elf(
    elfpath.empty() ? local_path("npu3_workspace/nop.elf") : elfpath);

  xrt::hw_context hwctx{device, elf};
  xrt::kernel kernel = xrt::ext::kernel{hwctx, "DPU:" + dpu};

  std::vector<xrt::run> run_handles;

  for (int i = 0; i < round; i++) {
    auto run = xrt::run(kernel);
    run_handles.push_back(std::move(run));
  }

  for (int i = 0; i < round; i++) {
    run_handles[i].start();
  }

  for (int i = 0; i < round; i++) {
    auto state = run_handles[i].wait(60000 * round /* give 1 minute per round */);
    if (state == ERT_CMD_STATE_TIMEOUT)
      throw std::runtime_error(std::string("exec buf timed out."));
    if (state != ERT_CMD_STATE_COMPLETED)
      throw std::runtime_error(std::string("bad command state: ") + std::to_string(state));
  }
}

/* create n hwctx  */
void
TEST_xrt_stress_hwctx(int device_index, arg_type& arg)
{
  auto device = xrt::device{device_index};
  unsigned round = m_rounds;

  auto elf = xrt::elf(
    elfpath.empty() ? local_path("npu3_workspace/nop.elf") : elfpath);

  std::vector<xrt::hw_context> run_hwctxs;

  for (int i = 0; i < round; i++) {
    xrt::hw_context hwctx{device, elf};
    run_hwctxs.push_back(std::move(hwctx));
  }

  for (int i = 0; i < round; i++) {
    auto hwctx = run_hwctxs[i];
    auto kernel = xrt::ext::kernel{hwctx, "DPU:" + dpu};

    auto run = xrt::run(kernel);

    run.start();
    auto state = run.wait(60000 * round /* give 1 minute per round */);

    if (state == ERT_CMD_STATE_TIMEOUT)
      throw std::runtime_error(std::string("exec buf timed out."));
    if (state != ERT_CMD_STATE_COMPLETED)
      throw std::runtime_error(std::string("bad command state: ") + std::to_string(state));
  }
}

// List of all test cases
std::vector<test_case> test_list {
  test_case{ "npu3 xrt vadd", TEST_xrt_umq_vadd, {} },
  test_case{ "npu3 xrt move memtiles", TEST_xrt_umq_memtiles, {} },
  test_case{ "npu3 xrt ddr memtile", TEST_xrt_umq_ddr_memtile, {} },
  test_case{ "npu3 xrt remote barrier", TEST_xrt_umq_remote_barrier, {} },
  test_case{ "npu3 xrt nop", TEST_xrt_umq_nop, {} },
  test_case{ "npu3 xrt single col preemption", TEST_xrt_umq_single_col_preemption, {} },
  test_case{ "npu3 xrt multi col preemption", TEST_xrt_umq_multi_col_preemption, {} },
  test_case{ "npu3 xrt single col resnet50 1 layer", TEST_xrt_umq_single_col_resnet50_1_layer, {} },
  test_case{ "npu3 xrt multi layer", TEST_xrt_umq_multi_layer, {} },
  test_case{ "npu3 xrt core equivalence", TEST_xrt_umq_core_equivalence, {} },
  test_case{ "npu3 xrt cascade 4 kernel 2 layer", TEST_xrt_umq_cascade_4ker_2lay, {} },
  test_case{ "npu3 xrt parallel branches", TEST_xrt_umq_parallel_branches, {} },
  test_case{ "npu3 xrt stress - run", TEST_xrt_stress_run, {s_rounds} },
  test_case{ "npu3 xrt stress - hwctx", TEST_xrt_stress_hwctx, {m_rounds} },
  test_case{ "npu3 xrt single col resnet50 all layer", TEST_xrt_umq_single_col_resnet50_all_layer, {} }
};

/* test n threads of 1 or more tests */
void
TEST_xrt_threads(int device_index, arg_type& arg)
{
  std::vector<std::thread> m_threads;

  if (exec_list.empty())
    exec_list.insert(exec_list.begin(), threads, 0);
  else if (exec_list.size() < threads)
    exec_list.insert(exec_list.end(), threads - exec_list.size(), exec_list.back()); // if more threads requested than tests given, run test at last element
  else
    threads = exec_list.size(); // if more tests than threads, increase threads to run all tests

  for (int i = 0; i < threads; i++) {
    m_threads.push_back(std::thread([&, i](){
      std::cout << "Thread " << i << " started" << std::endl;
      test_list[exec_list[i]].func(device_index, test_list[exec_list[i]].arg);
    })
    );
  }

  for (int i = 0; i < threads; i++)
      m_threads[i].join();

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
    while ((option = getopt(argc, argv, ":c:s:m:x:d:i:t:e:h")) != -1) {
      switch (option) {
        case 'c': {
          val = std::stoi(optarg);
	  std::cout << "Using c_rounds: " << val << std::endl;
	  c_rounds = val;
	  break;
        }
	case 's': {
	  val = std::stoi(optarg);
	  std::cout << "Using s_rounds: " << val << std::endl;
	  s_rounds = val;
	  break;
	}
	case 'm': {
	  val = std::stoi(optarg);
	  std::cout << "Using m_rounds: " << val << std::endl;
	  m_rounds = val;
	  break;
	}
	case 'd': {
	  dpu = optarg;
	  std::cout << "Using dpu: " << dpu << std::endl;
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
	  if (val < 0) {
		  std::cout << "Invalid thread count" << std::endl;
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
	case 'x': {
    elfpath = local_path("npu3_workspace/") + optarg + ".elf";
    if (!elfpath.empty()) {
	    std::cout << "Using elf file: " << elfpath << std::endl;
	    break;
    } else {
      std::cout << "Failed to open elf file: " << optarg << std::endl;
	    return 1;
	  }
	}
	case 'h':
	  usage(program);
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

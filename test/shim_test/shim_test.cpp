// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2022-2023, Advanced Micro Devices, Inc. All rights reserved.
//
// WARNING: This file contains test cases calling XRT's SHIM layer APIs directly.
// These APIs are XRT's internal APIs and are not meant for any external XRT
// user to call. We can't provide any support if you use APIs here and run into issues.

#include "config.h"

#include "experimental/xrt_elf.h"
#include "experimental/xrt_ext.h"
#include "experimental/xrt_module.h"

#include "core/common/api/module_int.h"
#include "core/common/device.h"
#include "core/common/dlfcn.h"
#include "core/common/memalign.h"
#include "core/common/query_requests.h"
#include "core/common/sysinfo.h"
#include "core/common/system.h"
#include "core/include/ert.h"

#include <algorithm>
#include <filesystem>
#include <libgen.h>
#include <set>
#include <stdlib.h>
#include <string>
#include <vector>
#include <chrono>
#include <regex>
#include <sys/wait.h>

namespace {

using namespace xrt_core;
using arg_type = const std::vector<uint64_t>;
using Clock = std::chrono::high_resolution_clock;
using us_t = std::chrono::microseconds;
using ns_t = std::chrono::nanoseconds;

const uint16_t npu1_device_id = 0x1502;
const uint16_t npu2_device_id = 0x17f0;
const uint16_t npu3_device_id = 0x1569;
const uint16_t npu2_revision_id = 0x0;
const uint16_t npu4_revision_id = 0x10;
const uint16_t npu5_revision_id = 0x11;

std::string program;
// Test harness setup helpers
std::string curpath;
std::string xclbinpath;
int base_write_speed;
int base_read_speed;

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
  enum test_mode mode;
  bool (*dev_filter)(device::id_type id, device *dev);
  void (*func)(device::id_type id, std::shared_ptr<device> dev, arg_type& arg);
  arg_type arg;
};

// For overall test result evaluation
int test_passed = 0;
int test_skipped = 0;
int test_failed = 0;

// Device type filters
bool
is_xdna_dev(device* dev)
{
  bool is_xdna = false;

  try {
    auto query_result = device_query<query::rom_fpga_name>(dev);
  }
  catch (const query::no_such_key& nk) {
    is_xdna = true;
  }
  return is_xdna;
}

bool
no_dev_filter(device::id_type id, device* dev)
{
  return true;
}

bool
skip_dev_filter(device::id_type id, device* dev)
{
  return false;
}

bool
dev_filter_xdna(device::id_type id, device* dev)
{
  return is_xdna_dev(dev);
}

bool
dev_filter_not_xdna(device::id_type id, device* dev)
{
  return !is_xdna_dev(dev);
}

bool
dev_filter_is_aie2(device::id_type id, device* dev)
{
  if (!is_xdna_dev(dev))
    return false;
  auto device_id = device_query<query::pcie_device>(dev);
  return device_id == npu1_device_id || device_id == npu2_device_id;
}

bool
dev_filter_is_aie4(device::id_type id, device* dev)
{
  if (!is_xdna_dev(dev))
    return false;
  auto device_id = device_query<query::pcie_device>(dev);
  return device_id == npu3_device_id;
}

bool
dev_filter_is_aie(device::id_type id, device* dev)
{
  return dev_filter_is_aie2(id, dev) || dev_filter_is_aie4(id, dev);
}

int
get_speed_and_print(std::string prefix, size_t size, Clock::time_point &start, Clock::time_point &end)
{
  std::ios_base::fmtflags f(std::cout.flags());

  auto dur = std::chrono::duration_cast<ns_t>(end - start).count();
  int speed = (size * 1000000000.0) / dur / 1024 / 1024.0;
  auto prec = std::cout.precision();

  std::cout << "\t" + prefix + " 0x" << std::hex << size << std::dec << " bytes in "
            << dur << " ns, " << std::setprecision(0) << std::fixed
            << "speed " << speed << " MB/sec"
            << std::setprecision(prec) << std::endl;

  std::cout.flags(f);
  return speed;
}

void speed_test_fill_buf(std::vector<int> &vec)
{
    auto buf = vec.data();

    for (int i = 0; i < vec.size(); i++)
       buf[i] = i;
}

int speed_test_copy_data(int *dst, int *src, size_t size)
{
  int num_element = size/sizeof(int);

  std::cout << "\tBuffer size 0x" << std::hex << size << std::dec << " bytes"
            << std::endl;
  auto start = Clock::now();
  memcpy(dst, src, size);
  auto end = Clock::now();
  return get_speed_and_print("move data (int type)", size, start, end);
}

void speed_test_base_line(size_t size)
{
  std::vector<int> ref_vec(size/sizeof(int));
  std::vector<int> trg_vec(size/sizeof(int));
  auto ref_buf = ref_vec.data();
  auto trg_buf = trg_vec.data();

  speed_test_fill_buf(ref_vec);

  std::cout << "\tBaseline *write* speed test start. vector -> vector " << std::endl;
  base_write_speed = speed_test_copy_data(trg_buf, ref_buf, size);

  std::cout << "\tBaseline *read* speed test start. vector -> vector" << std::endl;
  base_read_speed = speed_test_copy_data(ref_buf, trg_buf, size);
}

// All test case runners

void
TEST_get_xrt_info(device::id_type id, std::shared_ptr<device> sdev, arg_type& arg)
{
  boost::property_tree::ptree pt;
  const boost::property_tree::ptree empty_pt;
  sysinfo::get_xrt_info(pt);
  const boost::property_tree::ptree& drivers = pt.get_child("drivers", empty_pt);

  for(const auto& drv : drivers) {
    const boost::property_tree::ptree& driver = drv.second;
    const std::string drv_name = driver.get<std::string>("name", "");
    const std::string drv_version = driver.get<std::string>("version", "");
    const std::string drv_hash = driver.get<std::string>("hash", "");
    std::cout << "Driver: " << drv_name << std::endl;
    std::cout << "Version: " << drv_version << std::endl;
    std::cout << "HASH: " << drv_hash << std::endl;
  }
}

void
TEST_get_os_info(device::id_type id, std::shared_ptr<device> sdev, arg_type& arg)
{
  boost::property_tree::ptree pt;
  sysinfo::get_os_info(pt);
  std::cout << "Hostname: " << pt.get<std::string>("hostname", "N/A") << std::endl;
  std::cout << "OS: " << pt.get<std::string>("distribution", "N/A") << std::endl;
}

void
TEST_get_total_devices(device::id_type id, std::shared_ptr<device> sdev, arg_type& arg)
{
  auto is_user = arg[0];
  std::string pf { is_user ? "userpf" : "mgmtpf" };
  auto info = get_total_devices(is_user);
  std::cout << pf << " total: " << info.first << std::endl;
  std::cout << pf << " ready: " << info.second << std::endl;
}

const std::string
bdf_info2str(std::tuple<uint16_t, uint16_t, uint16_t, uint16_t>& info)
{
  char buf[100] = {};

  snprintf(buf, sizeof(buf), "%04x:%02x:%02x.%x",
    std::get<0>(info), std::get<1>(info), std::get<2>(info), std::get<3>(info));
  return buf;
}

void
TEST_get_bdf_info_and_get_device_id(device::id_type id, std::shared_ptr<device> sdev, arg_type& arg)
{
  auto is_user = arg[0];
  auto devinfo = get_total_devices(is_user);
  for (device::id_type i = 0; i < devinfo.first; i++) {
    auto info = get_bdf_info(i);
    auto bdf = bdf_info2str(info);
    std::cout << "device[" << i << "]: " << bdf << std::endl;
    auto devid = get_device_id(bdf);
    std::cout << "device[" << bdf << "]: " << devid << std::endl;
  }
}

void
TEST_get_mgmtpf_device(device::id_type id, std::shared_ptr<device> sdev, arg_type& arg)
{
  auto devinfo = get_total_devices(false);
  for (device::id_type i = 0; i < devinfo.first; i++)
    auto dev = get_mgmtpf_device(i);
}

template <typename QueryRequestType>
void
TEST_query_userpf(device::id_type id, std::shared_ptr<device> sdev, arg_type& arg)
{
  auto query_result = device_query<QueryRequestType>(sdev);
  std::cout << "dev[" << id << "]." << QueryRequestType::name() << ": "
    << QueryRequestType::to_string(query_result) << std::endl;
}

struct xclbin_info {
  const char* name;
  const uint16_t device;
  const uint16_t revision_id;
  const std::map<const char*, cuidx_type> ip_name2idx;
  const std::string workspace;
};

xclbin_info xclbin_infos[] = {
  {
    .name = "1x4.xclbin",
    .device = npu1_device_id,
    .revision_id = 0,
    .ip_name2idx = {
      { "DPU_PDI_0:IPUV1CNN",         {0} },
      { "DPU_PDI_1:IPUV1CNN",         {1} },
      { "DPU_PDI_2:IPUV1CNN",         {2} },
      { "DPU_PDI_3:IPUV1CNN",         {3} },
      { "DPU_PDI_4:IPUV1CNN",         {4} },
      { "DPU_PDI_5:IPUV1CNN",         {5} },
      { "DPU_PDI_6:IPUV1CNN",         {6} },
      { "DPU_PDI_7:IPUV1CNN",         {7} },
    },
    .workspace = "npu1_workspace",
  },
  {
    .name = "1x4.xclbin",
    .device = npu2_device_id,
    .revision_id = npu2_revision_id,
    .ip_name2idx = {
      { "DPU_PDI_0:IPUV1CNN",         {0} },
      { "DPU_PDI_1:IPUV1CNN",         {1} },
      { "DPU_PDI_2:IPUV1CNN",         {2} },
      { "DPU_PDI_3:IPUV1CNN",         {3} },
      { "DPU_PDI_4:IPUV1CNN",         {4} },
      { "DPU_PDI_5:IPUV1CNN",         {5} },
      { "DPU_PDI_6:IPUV1CNN",         {6} },
      { "DPU_PDI_7:IPUV1CNN",         {7} },
    },
    .workspace = "npu2_workspace",
  },
  {
    .name = "vadd.xclbin",
    .device = npu3_device_id,
    .revision_id = 0,
    .ip_name2idx = {
      { "dpu:vadd", {0} },
    },
    .workspace = "npu3_workspace",
  },
  {
    .name = "1x4.xclbin",
    .device = npu2_device_id,
    .revision_id = npu4_revision_id,
    .ip_name2idx = {
      { "DPU_PDI_0:IPUV1CNN",         {0} },
      { "DPU_PDI_1:IPUV1CNN",         {1} },
      { "DPU_PDI_2:IPUV1CNN",         {2} },
      { "DPU_PDI_3:IPUV1CNN",         {3} },
      { "DPU_PDI_4:IPUV1CNN",         {4} },
      { "DPU_PDI_5:IPUV1CNN",         {5} },
      { "DPU_PDI_6:IPUV1CNN",         {6} },
      { "DPU_PDI_7:IPUV1CNN",         {7} },
      { "DPU_PDI_8:IPUV1CNN",         {8} },
      { "DPU_PDI_9:IPUV1CNN",         {9} },
      { "DPU_PDI_10:IPUV1CNN",         {10} },
      { "DPU_PDI_11:IPUV1CNN",         {11} },
      { "DPU_PDI_12:IPUV1CNN",         {12} },
      { "DPU_PDI_13:IPUV1CNN",         {13} },
      { "DPU_PDI_14:IPUV1CNN",         {14} },
    },
    .workspace = "npu4_workspace",
  },
  {
    .name = "1x4.xclbin",
    .device = npu2_device_id,
    .revision_id = npu5_revision_id,
    .ip_name2idx = {
      { "DPU_PDI_0:IPUV1CNN",         {0} },
      { "DPU_PDI_1:IPUV1CNN",         {1} },
      { "DPU_PDI_2:IPUV1CNN",         {2} },
      { "DPU_PDI_3:IPUV1CNN",         {3} },
      { "DPU_PDI_4:IPUV1CNN",         {4} },
      { "DPU_PDI_5:IPUV1CNN",         {5} },
      { "DPU_PDI_6:IPUV1CNN",         {6} },
      { "DPU_PDI_7:IPUV1CNN",         {7} },
      { "DPU_PDI_8:IPUV1CNN",         {8} },
      { "DPU_PDI_9:IPUV1CNN",         {9} },
      { "DPU_PDI_10:IPUV1CNN",        {10} },
      { "DPU_PDI_11:IPUV1CNN",        {11} },
      { "DPU_PDI_12:IPUV1CNN",        {12} },
      { "DPU_PDI_13:IPUV1CNN",        {13} },
      { "DPU_PDI_14:IPUV1CNN",        {14} },
    },
    .workspace = "npu5_workspace",
  }
};

const xclbin_info&
get_xclbin_info(const uint16_t pci_dev_id, const uint16_t revision_id)
{
  for (auto& xclbin : xclbin_infos) {
    if ((xclbin.device == pci_dev_id) && (xclbin.revision_id == revision_id))
      return xclbin;
  }
  throw std::runtime_error("xclbin info not found");
}

std::string
get_xclbin_name(device* dev)
{
  return get_xclbin_info(device_query<query::pcie_device>(dev), device_query<query::pcie_id>(dev).revision_id).name;
}

std::string
get_xclbin_name(const xrt::device& dev)
{
  std::string target{"\"device\": \""};
  std::string pcieinfo = dev.get_info<xrt::info::device::pcie_info>();
  size_t pos = pcieinfo.find(target);
  if (pos == std::string::npos)
    throw std::runtime_error("bad pcie info string: " + pcieinfo);
  pos += target.size();
  return get_xclbin_info(std::stoi(pcieinfo.substr(pos), nullptr, 16), 0).name;
}

std::string
get_xclbin_workspace(device* dev)
{
  return get_xclbin_info(device_query<query::pcie_device>(dev), device_query<query::pcie_id>(dev).revision_id).workspace;
}

const std::map<const char*, cuidx_type>&
get_xclbin_ip_name2index(device* dev)
{
  return get_xclbin_info(device_query<query::pcie_device>(dev), device_query<query::pcie_id>(dev).revision_id).ip_name2idx;
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

class hw_ctx {
public:
  hw_ctx(device* dev)
  {
    auto wrk = get_xclbin_workspace(dev);

    if (!xclbinpath.empty())
      hw_ctx_init(dev, xclbinpath);
    else
      hw_ctx_init(dev, local_path(wrk + "/" + get_xclbin_name(dev)));
  }

  hw_ctx(device* dev, const char *xclbin_name)
  {
    auto wrk = get_xclbin_workspace(dev);

    if (!xclbinpath.empty())
      hw_ctx_init(dev, xclbinpath);
    else
      hw_ctx_init(dev, local_path(wrk + "/" + std::string(xclbin_name)));
  }

  ~hw_ctx()
  {
  }

  hwctx_handle *
  get()
  {
    return m_handle.get();
  }

private:
  std::unique_ptr<hwctx_handle> m_handle;

  void
  hw_ctx_init(device* dev, const std::string& xclbin_path)
  {
    xrt::xclbin xclbin;

    try {
      xclbin = xrt::xclbin(xclbin_path);
    } catch (...) {
      throw std::runtime_error(
        xclbin_path + " not found?\n"
        "specify xclbin path or run \"build.sh -xclbin_only\" to download them");
    }
    dev->record_xclbin(xclbin);
    auto xclbin_uuid = xclbin.get_uuid();
    xrt::hw_context::qos_type qos{ {"gops", 100} };
    xrt::hw_context::access_mode mode = xrt::hw_context::access_mode::shared;

    m_handle = dev->create_hw_context(xclbin_uuid, qos, mode);
    std::cout << "loaded " << xclbin_path << std::endl;
  }

};

uint64_t
get_bo_flags(uint32_t flags, uint32_t ext_flags)
{
  xcl_bo_flags f = {};

  f.flags = flags;
  f.extension = ext_flags;
  return f.all;
}

class bo {
public:
  bo(device* dev, size_t size, uint32_t boflags, uint32_t ext_boflags)
    : m_dev(dev)
  {
    m_handle = m_dev->alloc_bo(nullptr, size, get_bo_flags(boflags, ext_boflags));
    map_and_chk();
  }

  bo(device* dev, size_t size, uint32_t xcl_boflags)
    : bo(dev, size, xcl_boflags, 0)
  {
  }

  bo(device* dev, size_t size)
    : bo(dev, size, XCL_BO_FLAGS_HOST_ONLY, 0)
  {
  }

  bo(device* dev, pid_t pid, shared_handle::export_handle ehdl)
    : m_dev(dev)
  {
    m_handle = m_dev->import_bo(pid, ehdl);
    map_and_chk();
  }

  ~bo()
  {
    if (!m_no_unmap)
      m_handle->unmap(m_bop);
  }

  buffer_handle *
  get()
  { return m_handle.get(); }

  int *
  map()
  { return m_bop; }

  void
  set_no_unmap()
  { m_no_unmap = true; }

  size_t
  size()
  { return m_handle->get_properties().size; }

private:
  device* m_dev;
  std::unique_ptr<buffer_handle> m_handle;
  int *m_bop = nullptr;
  bool m_no_unmap = false;

  int *
  map_and_chk()
  {
    m_bop = reinterpret_cast<int *>(m_handle->map(buffer_handle::map_type::write));
    if (!m_bop)
      throw std::runtime_error("map bo of " + std::to_string(size()) + "bytes failed");
    return m_bop;
  }
};

void
TEST_create_destroy_hw_context(device::id_type id, std::shared_ptr<device> sdev, arg_type& arg)
{
  hw_ctx hwctx{sdev.get()};
}

void
get_and_show_bo_properties(device* dev, buffer_handle *boh)
{
  buffer_handle::properties properties = boh->get_properties();
  std::cout << std::hex
    << "\tbo flags: 0x" << properties.flags << "\n"
    << "\tbo paddr: 0x" << properties.paddr << "\n"
    << "\tbo size: 0x" << properties.size << std::dec << std::endl;
}

void
TEST_create_free_debug_bo(device::id_type id, std::shared_ptr<device> sdev, arg_type& arg)
{
  auto dev = sdev.get();
  auto boflags = XRT_BO_FLAGS_CACHEABLE;
  auto ext_boflags = XRT_BO_USE_DEBUG << 4;
  auto size = static_cast<size_t>(arg[0]);

  // Create ctx -> create bo -> destroy bo -> destroy ctx
  {
    hw_ctx hwctx{dev};
    auto bo = hwctx.get()->alloc_bo(size, get_bo_flags(boflags, ext_boflags));

    auto dbg_p = static_cast<uint32_t *>(bo->map(buffer_handle::map_type::write));
    std::memset(dbg_p, 0xff, size);
    bo.get()->sync(buffer_handle::direction::device2host, size, 0);
    if (std::memcmp(dbg_p, std::string(size, 0xff).c_str(), size) != 0)
      throw std::runtime_error("Debug buffer is not zero");
  }

  // Create ctx -> create bo -> destroy ctx -> destroy bo
  std::unique_ptr<buffer_handle> bo;
  {
    hw_ctx hwctx{dev};
    bo = hwctx.get()->alloc_bo(size, get_bo_flags(boflags, ext_boflags));
  }
  try {
    bo.get()->sync(buffer_handle::direction::device2host, size, 0);
  } catch (const std::system_error& e) {
    std::cout << e.what() << std::endl;
  }
}

void
TEST_create_free_bo(device::id_type id, std::shared_ptr<device> sdev, arg_type& arg)
{
  auto dev = sdev.get();
  uint32_t boflags = static_cast<unsigned int>(arg[0]);
  uint32_t ext_boflags = static_cast<unsigned int>(arg[1]);
  arg_type bos_size(arg.begin() + 2, arg.end());
  std::vector<std::unique_ptr<bo>> bos;

  for (auto& size : bos_size)
    bos.push_back(std::make_unique<bo>(dev, static_cast<size_t>(size), boflags, ext_boflags));

  for (auto& bo : bos)
    get_and_show_bo_properties(dev, bo->get());
}

class test_2proc {
public:
  test_2proc(device::id_type id) : m_id(id)
  {
    int p_pipefd[2] = {-1, -1};
    int c_pipefd[2] = {-1, -1};

    if (pipe(p_pipefd) < 0 || pipe(c_pipefd) < 0) {
      std::cout << "Can't create pipes" << std::endl;
      // Just quit on these fundamental issues and let OS clean it up.
      _exit(EXIT_FAILURE);
    }
    auto pid = fork();
    if (pid == -1) {
      std::cout << "Can't fork" << std::endl;
      // Just quit on these fundamental issues and let OS clean it up.
      _exit(EXIT_FAILURE);
    }
    // We want to handle pipe comm issue ourselves.
    signal(SIGPIPE, SIG_IGN);

    m_is_parent = !!pid;

    if (m_is_parent) {
      m_read_fd = p_pipefd[0];
      close(p_pipefd[1]);
      m_write_fd = c_pipefd[1];
      close(c_pipefd[0]);
    } else {
      m_read_fd = c_pipefd[0];
      close(c_pipefd[1]);
      m_write_fd = p_pipefd[1];
      close(p_pipefd[0]);
    }

    std::cout << (m_is_parent ? "Parent" : "Child") << " started: " << getpid() << std::endl;
  }

  ~test_2proc()
  {
    close(m_read_fd);
    close(m_write_fd);
    if (m_is_parent)
      wait(nullptr);
    else
      _exit(m_child_failed ? EXIT_FAILURE : EXIT_SUCCESS);
  }

  void
  run_test()
  {
    if (m_is_parent) {
      run_test_parent();
      wait_for_child();
    } else {
      try {
        run_test_child();
      } catch (const std::exception& ex) {
        std::cout << "Child failed: " << ex.what() << std::endl;
        m_child_failed = true;
        return;
      }
      m_child_failed = false;
    }
  }

protected:
  void
  send_ipc_data(const void *buf, size_t size)
  {
    if (write(m_write_fd, buf, size) != size) {
      if (!m_is_parent)
        throw std::runtime_error("Failed to send IPC data to parent");
      else
        std::cout << "Failed to send IPC data to child" << std::endl;
    }
  }

  void
  recv_ipc_data(void *buf, size_t size)
  {
    if (read(m_read_fd, buf, size) != size) {
      if (!m_is_parent)
        throw std::runtime_error("Failed to read IPC data from parent");
      else
        std::cout << "Failed to read IPC data from child" << std::endl;
    }
  }

  device::id_type
  get_dev_id()
  {
    return m_id;
  }

private:
  virtual void
  run_test_parent() = 0;

  virtual void
  run_test_child() = 0;

  void
  wait_for_child()
  {
    int status = 0;

    wait(&status);
    if (!WIFEXITED(status) || WEXITSTATUS(status) != EXIT_SUCCESS)
      throw std::runtime_error("Child did not complete successfully");
  }

  bool m_is_parent = false;
  bool m_child_failed = true;
  int m_read_fd = -1;
  int m_write_fd = -1;
  device::id_type m_id;
};

class test_2proc_export_import_bo : public test_2proc
{
public:
  test_2proc_export_import_bo(device::id_type id) : test_2proc(id)
  {}

private:
  struct ipc_data {
    pid_t pid;
    shared_handle::export_handle hdl;
  };

  const uint8_t m_buf_char = 0x55;

  void
  run_test_parent() override
  {
    std::cout << "Running parent test..." << std::endl;

    ipc_data idata = {};
    recv_ipc_data(&idata, sizeof(idata));
    std::cout << "Received BO " << idata.hdl << " from PID " << idata.pid << std::endl;

    bool success = true;
    auto dev = get_userpf_device(get_dev_id());
    bo imp_bo{dev.get(), idata.pid, idata.hdl};
    char *imp_p = reinterpret_cast<char *>(imp_bo.map());
    for (int i = 0; i < imp_bo.size(); i++) {
      if (imp_p[i] != m_buf_char) {
        std::cout << "Imported BO content mis-match" << std::endl;
        success = false;
        break;
      }
    }
    send_ipc_data(&success, sizeof(success));
  }

  void
  run_test_child() override
  {
    std::cout << "Running child test..." << std::endl;

    auto dev = get_userpf_device(get_dev_id());
    bo exp_bo{dev.get(), 4096ul};
    auto exp_p = exp_bo.map();
    std::memset(exp_p, m_buf_char, exp_bo.size());
    auto share = exp_bo.get()->share();
    ipc_data idata = { getpid(), share->get_export_handle() };
    send_ipc_data(&idata, sizeof(idata));
    bool success;
    recv_ipc_data(&success, sizeof(success));
  }
};

void
TEST_export_import_bo(device::id_type id, std::shared_ptr<device> sdev, arg_type& arg)
{
  // Can't fork with opened device.
  sdev.reset();

  test_2proc_export_import_bo t2p(id);
  t2p.run_test();
}

void
TEST_sync_bo(device::id_type id, std::shared_ptr<device> sdev, arg_type& arg)
{
  auto boflags = static_cast<unsigned int>(arg[0]);
  auto ext_boflags = static_cast<unsigned int>(arg[1]);
  auto size = static_cast<size_t>(arg[2]);
  bo bo{sdev.get(), size, boflags, ext_boflags};

  auto start = Clock::now();
  bo.get()->sync(buffer_handle::direction::host2device, size / 2, 0);
  bo.get()->sync(buffer_handle::direction::device2host, size / 2, size / 2);
  auto end = Clock::now();

  get_speed_and_print("sync", size, start, end);
}

void
TEST_map_read_bo(device::id_type id, std::shared_ptr<device> sdev, arg_type& arg)
{
  auto dev = sdev.get();
  auto size = static_cast<size_t>(arg[0]);
  auto bo_hdl = dev->alloc_bo(size, get_bo_flags(XRT_BO_FLAGS_NONE, 0));

  auto buf = bo_hdl->map(buffer_handle::map_type::read);
}

void
TEST_map_bo(device::id_type id, std::shared_ptr<device> sdev, arg_type& arg)
{
  auto boflags = static_cast<unsigned int>(arg[0]);
  auto ext_boflags = static_cast<unsigned int>(arg[1]);
  auto size = static_cast<size_t>(arg[2]);
  bo bo{sdev.get(), size, boflags, ext_boflags};

  // Intentionally not unmap to test error handling in driver
  bo.set_no_unmap();

  if (!base_write_speed || !base_read_speed)
    speed_test_base_line(size);
  if (!base_write_speed || !base_read_speed)
    throw std::runtime_error("Failed to obtain speed test baseline.");

  std::vector<int> ref_vec(size/sizeof(int));
  speed_test_fill_buf(ref_vec);
  auto ref_buf = ref_vec.data();

  auto buf = bo.map();
  memset(buf, 0, size); /* warm up */
  std::cout << "\tBO *write* speed test start. vector -> bo " << std::endl;
  auto write_speed = speed_test_copy_data(buf, ref_buf, size);

  std::cout << "\tBo *read* speed test start. bo -> vector" << std::endl;
  auto read_speed = speed_test_copy_data(ref_buf, buf, size);

  auto wpercent = (write_speed * 1.0) / base_write_speed;
  auto rpercent = (read_speed * 1.0) / base_read_speed;

  //if (wpercent < 0.85 || rpercent < 0.85) {
  //  std::cout << "write percent " << std::fixed << wpercent << std::endl;
  //  std::cout << "read percent " << std::fixed << rpercent << std::endl;
  //  throw std::runtime_error("BO access speed is obviously degrading");
  //}
}

void
TEST_open_close_cu_context(device::id_type id, std::shared_ptr<device> sdev, arg_type& arg)
{
  auto dev = sdev.get();
  hw_ctx hwctx{dev};

  for (auto& ip : get_xclbin_ip_name2index(dev)) {
    auto idx = hwctx.get()->open_cu_context(ip.first);
    hwctx.get()->close_cu_context(idx);
    auto r = idx.index;
    auto e = ip.second.index;
    if (r != e) {
      std::string s = std::string("Wrong CU(") +
                      std::string(ip.first) +
                      std::string(") index: ") +
                      std::to_string(r) +
                      std::string(", should be: ") +
                      std::to_string(e);
      throw std::runtime_error(s);
    }
  }
}

void
TEST_create_destroy_hw_queue(device::id_type id, std::shared_ptr<device> sdev, arg_type& arg)
{
  hw_ctx hwctx{sdev.get()};
  // Test to create > 1 queues
  auto hwq = hwctx.get()->get_hw_queue();
  auto hwq2 = hwctx.get()->get_hw_queue();
}

// Global test parameters/configurations for all I/O test cases
struct {
#define IO_TEST_NO_PERF       0
#define IO_TEST_LATENCY_PERF  1
#define IO_TEST_THRUPUT_PERF  2
  int perf;
#define IO_TEST_NORMAL_RUN    0
#define IO_TEST_NOOP_RUN      1
#define IO_TEST_BAD_RUN       2
  int type;
  bool debug;
} io_test_parameters;

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
io_test_cmd_add_arg_bo(bo *cmd_bo, int *payload_idx, int *arg_idx, bo *arg_bo)
{
  auto cmd_packet = reinterpret_cast<ert_start_kernel_cmd *>(cmd_bo->map());
  auto prop = arg_bo->get()->get_properties();
  cmd_packet->data[(*payload_idx)++] = prop.paddr;
  cmd_packet->data[(*payload_idx)++] = prop.paddr >> 32;
  cmd_bo->get()->bind_at(*arg_idx, arg_bo->get(), 0, arg_bo->size());
  (*arg_idx)++;
}

void
bo_set_init_cmd(io_test_bo_set& io_test_bos)
{
  auto cmd_bo = io_test_bos[IO_TEST_BO_CMD].tbo.get();
  auto cmd_packet = reinterpret_cast<ert_start_kernel_cmd *>(cmd_bo->map());

  cmd_packet->state = ERT_CMD_STATE_NEW;
  cmd_packet->count = 16;
  cmd_packet->opcode = ERT_START_CU;
  cmd_packet->type = ERT_SCU;
  cmd_packet->extra_cu_masks = 0;
  // CU index will be set later after we know which hw ctx the command is for

  int cur_payload = 0;
  int cur_arg = 0;
  // 0x00 - opcode. 1 is the DPU self test opcode
  cmd_packet->data[cur_payload++] = 0x1;
  cmd_packet->data[cur_payload++] = 0x0;
  cur_arg++;
  // 0x08 - ifm dev addr
  io_test_cmd_add_arg_bo(cmd_bo, &cur_payload, &cur_arg,
    io_test_bos[IO_TEST_BO_INPUT].tbo.get());
  // 0x10 - param dev addr
  io_test_cmd_add_arg_bo(cmd_bo, &cur_payload, &cur_arg,
    io_test_bos[IO_TEST_BO_PARAMETERS].tbo.get());
  // 0x18 - ofm dev addr
  io_test_cmd_add_arg_bo(cmd_bo, &cur_payload, &cur_arg,
    io_test_bos[IO_TEST_BO_OUTPUT].tbo.get());
  // 0x20 - inter dev addr
  io_test_cmd_add_arg_bo(cmd_bo, &cur_payload, &cur_arg,
    io_test_bos[IO_TEST_BO_INTERMEDIATE].tbo.get());
  // 0x28 - instruct dev addr
  io_test_cmd_add_arg_bo(cmd_bo, &cur_payload, &cur_arg,
    io_test_bos[IO_TEST_BO_INSTRUCTION].tbo.get());
  // 0x30 - ninstruct
  cmd_packet->data[cur_payload++] = io_test_bos[IO_TEST_BO_INSTRUCTION].tbo->size() / sizeof(int32_t);
  cur_arg++;
  // 0x34 - mc_blob dev addr
  io_test_cmd_add_arg_bo(cmd_bo, &cur_payload, &cur_arg,
    io_test_bos[IO_TEST_BO_MC_CODE].tbo.get());

  if (io_test_parameters.debug) {
    for (int i = 0; i < 15; i++) {
      std::cout << "data[" << i << "]: 0x" << std::hex << cmd_packet->data[i]
                << std::dec << std::endl;
    }
  }
}

void
bo_set_init_cmd_cu_index(io_test_bo_set& io_test_bos, xrt_core::cuidx_type idx)
{
  auto cmd_bo = io_test_bos[IO_TEST_BO_CMD].tbo.get();
  auto cmd_packet = reinterpret_cast<ert_start_kernel_cmd *>(cmd_bo->map());

  cmd_packet->cu_mask = 0x1 << idx.index;
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

void
io_test(device::id_type id, device* dev, int total_hwq_submit, int num_cmdlist, int cmds_per_list)
{
  // Allocate set of BOs for command submission based on num_cmdlist and cmds_per_list
  // Intentionally this is done before context creation to make sure BO and context
  // are totally decoupled.
  auto wrk = get_xclbin_workspace(dev);
  auto local_data_path = local_path(wrk + "/data/");
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
  auto start = Clock::now();
  if (io_test_parameters.perf == IO_TEST_THRUPUT_PERF)
    io_test_cmd_submit_and_wait_thruput(hwq, total_hwq_submit, cmdlist_bos);
  else
    io_test_cmd_submit_and_wait_latency(hwq, total_hwq_submit, cmdlist_bos);
  auto end = Clock::now();

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
umq_prepare_execbuf_header(bo& exec_buf_bo, cuidx_type::domain_index_type cu_idx)
{
  auto cmd_packet = reinterpret_cast<ert_start_kernel_cmd *>(exec_buf_bo.map());
  cmd_packet->state = ERT_CMD_STATE_NEW;
  cmd_packet->count = sizeof (ert_dpu_data) / sizeof (uint32_t) + 1;
  cmd_packet->opcode = ERT_START_DPU;
  cmd_packet->type = ERT_CU;
  cmd_packet->extra_cu_masks = 0;
  cmd_packet->cu_mask = 0x1 << cu_idx;
}

void
umq_prepare_execbuf_payload(bo& exec_buf_bo, bo& ctrl_bo)
{
  auto cmd_packet = reinterpret_cast<ert_start_kernel_cmd *>(exec_buf_bo.map());
  auto dpu_data = get_ert_dpu_data(cmd_packet);
  dpu_data->instruction_buffer = ctrl_bo.get()->get_properties().paddr;
  dpu_data->instruction_buffer_size = ctrl_bo.size();
  dpu_data->chained = 0;
}

// Submit a cmd with control code buf directly
void
umq_cmd_submit(hwqueue_handle *hwq,
  cuidx_type::domain_index_type cu_idx, bo& exec_buf_bo, bo& ctrl_bo)
{
  if (cu_idx != 0)
    throw std::runtime_error("Non-zero CU index is not supported!!!");

  umq_prepare_execbuf_header(exec_buf_bo, cu_idx);
  umq_prepare_execbuf_payload(exec_buf_bo, ctrl_bo);

  // Send command through HSA queue and wait for it to complete
  hwq->submit_command(exec_buf_bo.get());
}

void
umq_cmd_wait(hwqueue_handle *hwq, bo& exec_buf_bo, uint32_t timeout_ms)
{
  auto cmd_packet = reinterpret_cast<ert_start_kernel_cmd *>(exec_buf_bo.map());

  while (cmd_packet->state < ERT_CMD_STATE_COMPLETED) {
    if (!hwq->wait_command(exec_buf_bo.get(), timeout_ms))
      throw std::runtime_error(std::string("exec buf timed out."));
    else
      break;
  }
  if (cmd_packet->state != ERT_CMD_STATE_COMPLETED)
    throw std::runtime_error(std::string("bad command state: ") + std::to_string(cmd_packet->header));
}

void
TEST_shim_umq_vadd(device::id_type id, std::shared_ptr<device> sdev, arg_type& arg)
{
  auto dev = sdev.get();
  const size_t IFM_BYTE_SIZE = 16 * 16 * sizeof (uint32_t);
  const size_t WTS_BYTE_SIZE = 4 * 4 * sizeof (uint32_t);
  const size_t OFM_BYTE_SIZE = 16 * 16 * sizeof (uint32_t);
  bo bo_ifm{dev, IFM_BYTE_SIZE, XCL_BO_FLAGS_EXECBUF};
  bo bo_wts{dev, WTS_BYTE_SIZE, XCL_BO_FLAGS_EXECBUF};
  bo bo_ofm{dev, OFM_BYTE_SIZE, XCL_BO_FLAGS_EXECBUF};

  std::cout << "Allocated vadd ifm, wts and ofm BOs" << std::endl;

  auto wrk = get_xclbin_workspace(dev);
  auto elf = xrt::elf{local_path(wrk + "/vadd.elf")};
  auto mod = xrt::module{elf};

  size_t instr_size = 0;
  xrt_core::module_int::patch(mod, nullptr, &instr_size, nullptr);
  bo bo_ctrl_code{dev, instr_size, XCL_BO_FLAGS_EXECBUF};
  std::vector< std::pair<std::string, uint64_t> > args = {
    {"g.ifm_ddr", bo_ifm.get()->get_properties().paddr},
    {"g.wts_ddr", bo_wts.get()->get_properties().paddr},
    {"g.ofm_ddr", bo_ofm.get()->get_properties().paddr}
  };
  xrt_core::module_int::patch(mod, reinterpret_cast<uint8_t*>(bo_ctrl_code.map()), &instr_size, &args);
  std::cout << "Obtained vadd ctrl-code BO as a xrt::module" << std::endl;

  // Obtain no-op control code
  // ASM code:
  // START_JOB 0
  // END_JOB
  // EOF
  uint32_t nop_ctrlcode[] =
    { 0x0000FFFF, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x0000000C, 0x00000007, 0x000000FF };
  bo bo_nop_ctrl_code{dev, 0x1000UL, XCL_BO_FLAGS_EXECBUF};
  std::memcpy(bo_nop_ctrl_code.map(), nop_ctrlcode, sizeof(nop_ctrlcode));
  std::cout << "Obtained nop ctrl-code BO" << std::endl;

  {
    hw_ctx hwctx{dev, "vadd.xclbin"};
    auto hwq = hwctx.get()->get_hw_queue();
    auto cu_idx = hwctx.get()->open_cu_context("dpu:vadd");
    bo bo_exec_buf{dev, 0x1000ul, XCL_BO_FLAGS_EXECBUF};

    for (int i = 0; i < 1; i++) {
      sleep(5);
      std::cout << "Running vadd command" << std::endl;
      init_umq_vadd_buffers<bo>(bo_ifm, bo_wts, bo_ofm);
      umq_cmd_submit(hwq, cu_idx.index, bo_exec_buf, bo_ctrl_code);
      umq_cmd_wait(hwq, bo_exec_buf, 600000 /* 600 sec, some simnow server are slow */);
      check_umq_vadd_result(bo_ifm.map(), bo_wts.map(), bo_ofm.map());

      // noop ctrlcode is not updated yet.
      //sleep(5);
      //std::cout << "Running nop command" << std::endl;
      //umq_cmd_submit(hwq, cu_idx.domain_index, bo_exec_buf, bo_nop_ctrl_code);
      //umq_cmd_wait(hwq, exec_buf_bo, 600000 /* 600 sec, some simnow server are slow */);
    }
  }
}

// List of all test cases
std::vector<test_case> test_list {
  test_case{ "get_xrt_info",
    TEST_POSITIVE, no_dev_filter, TEST_get_xrt_info, {}
  },
  test_case{ "get_os_info",
    TEST_POSITIVE, no_dev_filter, TEST_get_os_info, {}
  },
  test_case{ "get_total_devices",
    TEST_POSITIVE, no_dev_filter, TEST_get_total_devices, {true}
  },
  //test_case{ "get_total_devices(mgmtpf)",
  //  TEST_POSITIVE, no_dev_filter, TEST_get_total_devices, {false}
  //},
  test_case{ "get_bdf_info_and_get_device_id",
    TEST_POSITIVE, no_dev_filter, TEST_get_bdf_info_and_get_device_id, {true}
  },
  //test_case{ "get_bdf_info_and_get_device_id(mgmtpf)",
  //  TEST_POSITIVE, no_dev_filter, TEST_get_bdf_info_and_get_device_id, {false}
  //},
  //test_case{ "get_mgmtpf_device",
  //  TEST_POSITIVE, no_dev_filter, TEST_get_mgmtpf_device, {}
  //},
  test_case{ "query(pcie_vendor)",
    TEST_POSITIVE, dev_filter_xdna, TEST_query_userpf<query::pcie_vendor>, {}
  },
  //test_case{ "non_xdna_userpf: query(pcie_vendor)",
  //  TEST_POSITIVE, dev_filter_not_xdna, TEST_query_userpf<query::pcie_vendor>, {}
  //},
  test_case{ "query(rom_vbnv)",
    TEST_POSITIVE, dev_filter_xdna, TEST_query_userpf<query::rom_vbnv>, {}
  },
  test_case{ "query(rom_fpga_name)",
    TEST_NEGATIVE, dev_filter_xdna, TEST_query_userpf<query::rom_fpga_name>, {}
  },
  //test_case{ "non_xdna_userpf: query(rom_vbnv)",
  //  TEST_POSITIVE, dev_filter_not_xdna, TEST_query_userpf<query::rom_vbnv>, {}
  //},
  test_case{ "create_destroy_hw_context",
    TEST_POSITIVE, dev_filter_is_aie, TEST_create_destroy_hw_context, {}
  },
  test_case{ "create_invalid_bo",
    TEST_NEGATIVE, dev_filter_xdna, TEST_create_free_bo, {XCL_BO_FLAGS_P2P, 0, 128}
  },
  test_case{ "create_and_free_exec_buf_bo",
    TEST_POSITIVE, dev_filter_xdna, TEST_create_free_bo, {XCL_BO_FLAGS_EXECBUF, 0, 128}
  },
  test_case{ "create_and_free_dpu_sequence_bo 1 bo",
    TEST_POSITIVE, dev_filter_xdna, TEST_create_free_bo, {XCL_BO_FLAGS_CACHEABLE, 0, 128}
  },
  test_case{ "create_and_free_dpu_sequence_bo multiple bos",
    TEST_POSITIVE, dev_filter_xdna, TEST_create_free_bo,
    {XCL_BO_FLAGS_CACHEABLE, 0, 0x2000, 0x400, 0x3000, 0x100}
  },
  test_case{ "create_and_free_input_output_bo 1 pages",
    TEST_POSITIVE, dev_filter_xdna, TEST_create_free_bo, {XCL_BO_FLAGS_NONE, 0, 128}
  },
  test_case{ "create_and_free_input_output_bo multiple pages",
    TEST_POSITIVE, dev_filter_xdna, TEST_create_free_bo,
    {XCL_BO_FLAGS_NONE, 0, 0x10000, 0x23000, 0x2000}
  },
  test_case{ "create_and_free_input_output_bo huge pages",
    TEST_POSITIVE, dev_filter_is_aie, TEST_create_free_bo,
    {XCL_BO_FLAGS_NONE, 0, 0x20000000}
  },
  test_case{ "sync_bo for dpu sequence bo",
    TEST_POSITIVE, dev_filter_xdna, TEST_sync_bo, {XCL_BO_FLAGS_CACHEABLE, 0, 128}
  },
  test_case{ "sync_bo for input_output",
    TEST_POSITIVE, dev_filter_xdna, TEST_sync_bo, {XCL_BO_FLAGS_NONE, 0, 128}
  },
  test_case{ "map dpu sequence bo and test perf",
    TEST_POSITIVE, dev_filter_xdna, TEST_map_bo, {XCL_BO_FLAGS_CACHEABLE, 0, 361264 /*0x10000*/}
  },
  test_case{ "map input_output bo and test perf",
    TEST_POSITIVE, dev_filter_xdna, TEST_map_bo, {XCL_BO_FLAGS_NONE, 0, 361264}
  },
  test_case{ "map bo for read only",
    TEST_NEGATIVE, dev_filter_xdna, TEST_map_read_bo, {0x1000}
  },
  test_case{ "map exec_buf_bo and test perf",
    TEST_POSITIVE, dev_filter_xdna, TEST_create_free_bo, {XCL_BO_FLAGS_EXECBUF, 0, 0x1000}
  },
  test_case{ "open_close_cu_context",
    TEST_POSITIVE, dev_filter_is_aie2, TEST_open_close_cu_context, {}
  },
  test_case{ "create_destroy_hw_queue",
    TEST_POSITIVE, dev_filter_is_aie2, TEST_create_destroy_hw_queue, {}
  },
  // Keep bad run before normal run to test recovery of hw ctx
  test_case{ "io test real kernel bad run",
    TEST_NEGATIVE, dev_filter_is_aie2, TEST_io, { IO_TEST_BAD_RUN, 1 }
  },
  test_case{ "io test real kernel good run",
    TEST_POSITIVE, dev_filter_is_aie2, TEST_io, { IO_TEST_NORMAL_RUN, 1 }
  },
  test_case{ "measure no-op kernel latency",
    TEST_POSITIVE, dev_filter_is_aie2, TEST_io_latency, { IO_TEST_NOOP_RUN }
  },
  test_case{ "measure real kernel latency",
    TEST_POSITIVE, dev_filter_is_aie2, TEST_io_latency, { IO_TEST_NORMAL_RUN }
  },
  test_case{ "create and free debug bo",
    TEST_POSITIVE, dev_filter_is_aie2, TEST_create_free_debug_bo, { 0x1000 }
  },
  test_case{ "create and free large debug bo",
    TEST_POSITIVE, dev_filter_is_aie2, TEST_create_free_debug_bo, { 0x100000 }
  },
  test_case{ "multi-command io test real kernel good run",
    TEST_POSITIVE, dev_filter_is_aie2, TEST_io, { IO_TEST_NORMAL_RUN, 3 }
  },
  test_case{ "measure no-op kernel throughput listed command",
    TEST_POSITIVE, dev_filter_is_aie2, TEST_io_throughput, { IO_TEST_NOOP_RUN }
  },
  test_case{ "npu3 shim vadd",
    TEST_POSITIVE, dev_filter_is_aie4, TEST_shim_umq_vadd, {}
  },
  test_case{ "export import BO",
    TEST_POSITIVE, dev_filter_is_aie2, TEST_export_import_bo, {}
  },
};

}

// Test case executor implementation

void
run_test(int id, const test_case& test, bool force, const device::id_type& num_of_devices)
{
  bool failed = (test.mode == TEST_NEGATIVE);
  bool skipped = true;

  std::cout << "====== " << id << ": " << test.description << " started =====" << std::endl;
  try {
    if (test.dev_filter == no_dev_filter) { // system test
      skipped = false;
      test.func(0, nullptr, test.arg);
    } else { // per user device test
      for (device::id_type i = 0; i < num_of_devices; i++) {
        auto dev = get_userpf_device(i);
        if (!force && !test.dev_filter(i, dev.get()))
          continue;
        skipped = false;
        test.func(i, std::move(dev), test.arg);
      }
    }
  }
  catch (const std::exception& ex) {
    skipped = false;
    std::cerr << ex.what() << std::endl;
    failed = !failed;
  }

  std::string result;
  if (skipped)
    result = "skipped";
  else
    result = failed ? "\x1b[5m\x1b[31mFAILED\x1b[0m" : "passed";
  std::cout << "====== " << id << ": " << test.description << " " << result << "  =====" << std::endl;

  if (skipped)
    test_skipped++;
  else if (failed)
    test_failed++;
  else
    test_passed++;
}

void
run_all_test(std::set<int>& tests)
{
  auto all = tests.empty();
  device::id_type total_dev = 0;

  try {
    auto devinfo = get_total_devices(true);
    total_dev = devinfo.second;
  } catch (const std::runtime_error& e) {
    std::cout << e.what();
  }

  if (total_dev == 0) {
    std::cout << "No testable devices on this machine. Failing all tests.\n";
    test_failed = test_list.size();
    return;
  }

  for (int i = 0; i < test_list.size(); i++) {
    if (!all) {
      if (tests.find(i) == tests.end())
        continue;
      else
        tests.erase(i);
    }
    const auto& t = test_list[i];
    run_test(i, t, !all, total_dev);
    std::cout << std::endl;
  }
}

int
main(int argc, char **argv)
{
  program = std::filesystem::path(argv[0]).filename();
  std::set<int> tests;

  try {
    int first_test_id = 1;

    if (argc >= 2) {
      std::ifstream xclbin(argv[first_test_id]);
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

// vim: ts=2 sw=2 expandtab

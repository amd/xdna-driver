// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2022-2023, Advanced Micro Devices, Inc. All rights reserved.

#include "config.h"
#include "patch_DDR_address.h"

#include "core/common/device.h"
#include "core/common/dlfcn.h"
#include "core/common/memalign.h"
#include "core/common/query_requests.h"
#include "core/common/sysinfo.h"
#include "core/common/system.h"
#include "core/include/ert.h"
#include "experimental/xrt_elf.h"
#include "experimental/xrt_ext.h"
#include "experimental/xrt_module.h"
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

using namespace xrt_core;
using arg_type = const std::vector<uint64_t>;
using Clock = std::chrono::high_resolution_clock;
using us_t = std::chrono::microseconds;
using ns_t = std::chrono::nanoseconds;

const uint16_t npu1_device_id = 0x1502;
const uint16_t npu2_device_id = 0x17f0;
const uint16_t npu2_revision_id = 0x0;
const uint16_t npu4_revision_id = 0x10;

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
  enum test_mode mode;
  bool (*dev_filter)(device::id_type id, std::shared_ptr<device> dev);
  void (*func)(device::id_type id, std::shared_ptr<device> dev, arg_type& arg);
  arg_type arg;
};

// For overall test result evaluation
int test_passed = 0;
int test_skipped = 0;
int test_failed = 0;

// Device type filters
bool
is_xdna_dev(std::shared_ptr<device> dev)
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
no_dev_filter(device::id_type id, std::shared_ptr<device> dev)
{
  return true;
}

bool
skip_dev_filter(device::id_type id, std::shared_ptr<device> dev)
{
  return false;
}

bool
dev_filter_xdna(device::id_type id, std::shared_ptr<device> dev)
{
  return is_xdna_dev(dev);
}

bool
dev_filter_not_xdna(device::id_type id, std::shared_ptr<device> dev)
{
  return !is_xdna_dev(dev);
}

bool
dev_filter_is_npu(device::id_type id, std::shared_ptr<device> dev)
{
  if (!is_xdna_dev(dev))
    return false;
  auto device_id = device_query<query::pcie_device>(dev);
  return device_id == npu1_device_id || device_id == npu2_device_id;
}

int
get_speed_and_print(std::string prefix, size_t size, Clock::time_point &start, Clock::time_point &end)
{
  auto dur = std::chrono::duration_cast<ns_t>(end - start).count();
  int speed = (size * 1000000000.0) / dur / 1024 / 1024.0;
  auto prec = std::cout.precision();

  std::cout << "\t" + prefix + " 0x" << std::hex << size << std::dec << " bytes in "
            << dur << " ns, " << std::setprecision(0) << std::fixed
            << "speed " << speed << " MB/sec"
            << std::setprecision(prec) << std::endl;

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
TEST_get_xrt_info(device::id_type id, std::shared_ptr<device> dev, arg_type& arg)
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
TEST_get_os_info(device::id_type id, std::shared_ptr<device> dev, arg_type& arg)
{
  boost::property_tree::ptree pt;
  sysinfo::get_os_info(pt);
  std::cout << "Hostname: " << pt.get<std::string>("hostname", "N/A") << std::endl;
  std::cout << "OS: " << pt.get<std::string>("distribution", "N/A") << std::endl;
}

void
TEST_get_total_devices(device::id_type id, std::shared_ptr<device> dev, arg_type& arg)
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
TEST_get_bdf_info_and_get_device_id(device::id_type id, std::shared_ptr<device> dev, arg_type& arg)
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
TEST_get_mgmtpf_device(device::id_type id, std::shared_ptr<device> dev, arg_type& arg)
{
  auto devinfo = get_total_devices(false);
  for (device::id_type i = 0; i < devinfo.first; i++)
    auto dev = get_mgmtpf_device(i);
}

template <typename QueryRequestType>
void
TEST_query_userpf(device::id_type id, std::shared_ptr<device> dev, arg_type& arg)
{
  auto query_result = device_query<QueryRequestType>(dev);
  std::cout << "dev[" << id << "]." << QueryRequestType::name() << ": "
    << QueryRequestType::to_string(query_result) << std::endl;
}

struct xclbin_info {
  const char* name;
  const uint16_t device;
  const uint16_t revision_id;
  const std::map<const char*, xrt_core::cuidx_type> ip_name2idx;
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
get_xclbin_name(std::shared_ptr<device> dev)
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
get_xclbin_workspace(std::shared_ptr<device> dev)
{
  return get_xclbin_info(device_query<query::pcie_device>(dev), device_query<query::pcie_id>(dev).revision_id).workspace;
}

const std::map<const char*, xrt_core::cuidx_type>&
get_xclbin_ip_name2index(std::shared_ptr<device> dev)
{
  return get_xclbin_info(device_query<query::pcie_device>(dev), device_query<query::pcie_id>(dev).revision_id).ip_name2idx;
}

std::string find_first_match_ip_name(std::shared_ptr<device> dev, const std::string& pattern)
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
  hw_ctx(std::shared_ptr<device> dev)
  {
    auto wrk = get_xclbin_workspace(dev);

    if (!xclbinpath.empty())
      hw_ctx_init(dev, xclbinpath);
    else
      hw_ctx_init(dev, local_path(wrk + "/" + get_xclbin_name(dev)));
  }

  hw_ctx(std::shared_ptr<device> dev, const char *xclbin_name)
  {
    if (!xclbinpath.empty())
      hw_ctx_init(dev, xclbinpath);
    else
      hw_ctx_init(dev, local_path(std::string(xclbin_name)));
  }

  ~hw_ctx()
  {
  }

  xrt_core::hwctx_handle *
  get()
  {
    return m_handle.get();
  }

private:
  std::shared_ptr<device> m_dev;
  std::unique_ptr<xrt_core::hwctx_handle> m_handle;

  void
  hw_ctx_init(std::shared_ptr<device> dev, const std::string& xclbin_path)
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
    m_dev = dev;
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
  bo(std::shared_ptr<device> dev, size_t size, uint32_t boflags, uint32_t ext_boflags)
    : m_dev(dev)
  {
    m_handle = m_dev->alloc_bo(nullptr, size, get_bo_flags(boflags, ext_boflags));
    map_and_chk();
  }

  bo(std::shared_ptr<device> dev, size_t size, uint32_t xcl_boflags)
    : bo(dev, size, xcl_boflags, 0)
  {
  }

  bo(std::shared_ptr<device> dev, size_t size)
    : bo(dev, size, XCL_BO_FLAGS_HOST_ONLY, 0)
  {
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
  std::shared_ptr<device> m_dev;
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

class xrt_bo {
public:
  xrt_bo(const xrt::device& dev, size_t size)
    : m_boh{xrt::ext::bo{dev, size}}
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

void
TEST_create_destroy_hw_context(device::id_type id, std::shared_ptr<device> dev, arg_type& arg)
{
  hw_ctx hwctx{dev};
}

void
get_and_show_bo_properties(std::shared_ptr<device> dev, buffer_handle *boh)
{
  buffer_handle::properties properties = boh->get_properties();
  std::cout << std::hex
    << "\tbo flags: 0x" << properties.flags << "\n"
    << "\tbo paddr: 0x" << properties.paddr << "\n"
    << "\tbo size: 0x" << properties.size << std::dec << std::endl;
}

void
TEST_create_free_debug_bo(device::id_type id, std::shared_ptr<device> dev, arg_type& arg)
{
  auto boflags = XRT_BO_FLAGS_CACHEABLE;
  auto ext_boflags = XRT_BO_USE_DEBUG << 4;
  auto size = static_cast<size_t>(arg[0]);
  hw_ctx hwctx{dev};

  auto bo = hwctx.get()->alloc_bo(size, get_bo_flags(boflags, ext_boflags));
}

void
TEST_create_free_bo(device::id_type id, std::shared_ptr<device> dev, arg_type& arg)
{
  uint32_t boflags = static_cast<unsigned int>(arg[0]);
  uint32_t ext_boflags = static_cast<unsigned int>(arg[1]);
  arg_type bos_size(arg.begin() + 2, arg.end());
  std::vector<std::unique_ptr<bo>> bos;

  for (auto& size : bos_size)
    bos.push_back(std::make_unique<bo>(dev, static_cast<size_t>(size), boflags, ext_boflags));

  for (auto& bo : bos)
    get_and_show_bo_properties(dev, bo->get());
}

#if 0
void
TEST_create_free_userptr_bo(device::id_type id, std::shared_ptr<device> dev, arg_type& arg)
{
  auto boflags = static_cast<unsigned int>(arg[0]);
  arg_type bos_size(arg.begin() + 1, arg.end());
  std::vector<std::unique_ptr<bo>> bos;

  for (auto& size : bos_size) {
    auto buf = xrt_core::aligned_alloc(8, size);

    std::cout << "malloc " << buf.get() << std::endl;
    bos.push_back(std::make_unique<bo>(dev, buf.get(), static_cast<size_t>(size), boflags));
  }

  for (auto& bo : bos)
    get_and_show_bo_properties(dev, bo->get());
}
#endif

void
TEST_sync_bo(device::id_type id, std::shared_ptr<device> dev, arg_type& arg)
{
  auto boflags = static_cast<unsigned int>(arg[0]);
  auto ext_boflags = static_cast<unsigned int>(arg[1]);
  auto size = static_cast<size_t>(arg[2]);
  bo bo{dev, size, boflags, ext_boflags};

  auto start = Clock::now();
  bo.get()->sync(buffer_handle::direction::host2device, size / 2, 0);
  bo.get()->sync(buffer_handle::direction::device2host, size / 2, size / 2);
  auto end = Clock::now();

  get_speed_and_print("sync", size, start, end);
}

void
TEST_map_bo(device::id_type id, std::shared_ptr<device> dev, arg_type& arg)
{
  auto boflags = static_cast<unsigned int>(arg[0]);
  auto ext_boflags = static_cast<unsigned int>(arg[1]);
  auto size = static_cast<size_t>(arg[2]);
  bo bo{dev, size, boflags, ext_boflags};

  // Intentionally not unmap to test error handling in driver
  bo.set_no_unmap();

  if (!base_write_speed || !base_read_speed)
    speed_test_base_line(size);

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
TEST_open_close_cu_context(device::id_type id, std::shared_ptr<device> dev, arg_type& arg)
{
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
TEST_create_destroy_hw_queue(device::id_type id, std::shared_ptr<device> dev, arg_type& arg)
{
  hw_ctx hwctx{dev};
  // Test to create > 1 queues
  auto hwq = hwctx.get()->get_hw_queue();
  auto hwq2 = hwctx.get()->get_hw_queue();
}

struct submit_wait_config {
    bool perf;
    bool noop;
    int iters;
};

#define DEBUG_TEST 0
#define NORMAL_RUN 0
#define BAD_AND_GOOD_RUN 1
void
__npu_submit_wait_cmd(device::id_type id, std::shared_ptr<device> dev, arg_type& arg, struct submit_wait_config *config)
{
  hw_ctx hwctx{dev};
  auto hwq = hwctx.get()->get_hw_queue();
  auto test_type = static_cast<unsigned int>(arg[0]);
  auto wrk = get_xclbin_workspace(dev);
  auto data_path = wrk + "/data/";
  void *instr_bk = nullptr;

  auto ip_name = find_first_match_ip_name(dev, "DPU.*");
  if (ip_name.empty())
    throw std::runtime_error("Cannot found any kernel name matched DPU.*");
  auto cu_idx = hwctx.get()->open_cu_context(ip_name);

  std::cout << "data path: " << data_path << std::endl;
  if (!std::filesystem::exists(local_path(data_path)))
    throw std::runtime_error("workspace doesn't exist");

  auto instr_word_size = get_instr_size(local_path(data_path + instr_file));
  if (!instr_word_size)
    throw std::runtime_error("instr word size cannot be 0");

  auto tp = parse_config_file(local_path(data_path + config_file));

  if (config->noop)
    instr_word_size = 32;
  auto instr_size = instr_word_size * sizeof(int);
  std::cout << "------- Test information -------" << std::endl;
  std::cout << "Found kernel: " << ip_name << " with cu index " << cu_idx.index << std::endl;
  std::cout << "instr_size: " << instr_size << std::endl;
  std::cout << "IFM_SIZE: " << IFM_SIZE(tp) << std::endl;
  std::cout << "IFM_DIRTY_BYTES: " << IFM_DIRTY_BYTES(tp) << std::endl;
  std::cout << "PARAM_SIZE: " << PARAM_SIZE(tp) << std::endl;
  std::cout << "OFM_SIZE: " << OFM_SIZE(tp) << std::endl;
  std::cout << "INTER_SIZE: " << INTER_SIZE(tp) << std::endl;
  std::cout << "MC_CODE_SIZE: " << MC_CODE_SIZE(tp) << std::endl;

  auto bo_instr = bo(dev, instr_size, XCL_BO_FLAGS_CACHEABLE);
  auto bo_ifm   = bo(dev, IFM_SIZE(tp));
  auto bo_param = bo(dev, PARAM_SIZE(tp));
  auto bo_ofm   = bo(dev, OFM_SIZE(tp));
  auto bo_inter = bo(dev, INTER_SIZE(tp));
  auto bo_mc    = bo(dev, std::max(MC_CODE_SIZE(tp), DUMMY_MC_CODE_BUFFER_SIZE));
  buffer_handle::properties prop;

  std::cout << "Allocate buffer done" << std::endl;
  if (DEBUG_TEST)
    test_pause();

  // map and fill input buffers
  auto instr_p = bo_instr.map();
  auto ifm_p = bo_ifm.map();
  auto param_p = bo_param.map();
  auto mc_blob_p = bo_mc.map();

  if (config->noop)
      std::memset(instr_p, 0, instr_size);
  else
      read_from_instr(local_path(data_path + instr_file), instr_p);
  fill_buffer(ifm_p, IFM_SIZE(tp) - IFM_DIRTY_BYTES(tp), IFM_DIRTY_BYTES(tp),
    local_path(data_path + ifm_file));
  fill_buffer(param_p, PARAM_SIZE(tp), 0, local_path(data_path + param_file));

  /* In the orignal test case, this MC_CODE_SIZE can be 0.
   * If it is 0, use a constant value 16 to allocate bo_mc.
   * In the current, conv_case_0, MC_CODE_SIZE is 0. Keep this code here.
   */
  if (MC_CODE_SIZE(tp)) {
    std::cout << "!!! MC_CODE_SIZE is non zero !!!" << std::endl;
    fill_buffer(mc_blob_p, MC_CODE_SIZE(tp), 0, local_path(data_path + mc_blob_file));
    for (int i = 0; i < 16; i++) {
      std::cout << "mc_blob data: " << std::hex << mc_blob_p[i] << std::dec << std::endl;
    }

    prop = bo_ifm.get()->get_properties();
    uint64_t ifm_paddr = prop.paddr;
    prop = bo_param.get()->get_properties();
    uint64_t param_paddr = prop.paddr;
    prop = bo_ofm.get()->get_properties();
    uint64_t ofm_paddr = prop.paddr;
    prop = bo_inter.get()->get_properties();
    uint64_t inter_paddr = prop.paddr;

    patchMcCodeDDR(ifm_paddr, param_paddr, ofm_paddr, inter_paddr, (uint32_t *)(mc_blob_p), MC_CODE_SIZE(tp));
  }

  if (test_type == BAD_AND_GOOD_RUN) {
    instr_bk = malloc(instr_size);
    memcpy(instr_bk, instr_p, instr_size);
    /* this is like hack line 180 and 181 in mc_code.txt */
    instr_p[91] = 0xFFFFFFFF;
    instr_p[92] = 0xFFFFFFFF;
  }

  std::cout << "fill buffer done" << std::endl;
  if (DEBUG_TEST)
    test_pause();

  bo_instr.get()->sync(buffer_handle::direction::host2device, instr_size, 0);
  bo_ifm.get()->sync(buffer_handle::direction::host2device, IFM_SIZE(tp), 0);
  bo_param.get()->sync(buffer_handle::direction::host2device, PARAM_SIZE(tp), 0);
  bo_mc.get()->sync(buffer_handle::direction::host2device, std::max(MC_CODE_SIZE(tp), DUMMY_MC_CODE_BUFFER_SIZE), 0);

  std::cout << "sycn input buffer done" << std::endl;
  if (DEBUG_TEST)
    test_pause();

  auto exec_buf = bo(dev, 0x1000, XCL_BO_FLAGS_EXECBUF);
  auto cmd_packet = reinterpret_cast<ert_start_kernel_cmd *>(exec_buf.map());

  cmd_packet->state = ERT_CMD_STATE_NEW;
  cmd_packet->count = 16;
  cmd_packet->opcode = ERT_SK_START;
  cmd_packet->type = ERT_SCU;
  cmd_packet->extra_cu_masks = 0;
  cmd_packet->cu_mask = 0x1 << cu_idx.index;

  // 0x00 - opcode. 1 is the DPU self test opcode
  cmd_packet->data[0] = 0x1;
  cmd_packet->data[1] = 0x0;
  // 0x08 - ifm dev addr
  prop = bo_ifm.get()->get_properties();
  cmd_packet->data[2] = prop.paddr;
  cmd_packet->data[3] = prop.paddr >> 32;
  exec_buf.get()->bind_at(1, bo_ifm.get(), 0, bo_ifm.size());
  // 0x10 - param dev addr
  prop = bo_param.get()->get_properties();
  cmd_packet->data[4] = prop.paddr;
  cmd_packet->data[5] = prop.paddr >> 32;
  exec_buf.get()->bind_at(2, bo_param.get(), 0, bo_param.size());
  // 0x18 - ofm dev addr
  prop = bo_ofm.get()->get_properties();
  cmd_packet->data[6] = prop.paddr;
  cmd_packet->data[7] = prop.paddr >> 32;
  exec_buf.get()->bind_at(3, bo_ofm.get(), 0, bo_ofm.size());
  // 0x20 - inter dev addr
  prop = bo_inter.get()->get_properties();
  cmd_packet->data[8] = prop.paddr;
  cmd_packet->data[9] = prop.paddr >> 32;
  exec_buf.get()->bind_at(4, bo_inter.get(), 0, bo_inter.size());
  // 0x28 - instruct dev addr
  prop = bo_instr.get()->get_properties();
  cmd_packet->data[10] = prop.paddr;
  cmd_packet->data[11] = prop.paddr >> 32;
  exec_buf.get()->bind_at(5, bo_instr.get(), 0, bo_instr.size());
  // 0x30 - ninstruct
  cmd_packet->data[12] = instr_word_size;
  // 0x34 - mc_blob dev addr
  prop = bo_mc.get()->get_properties();
  cmd_packet->data[13] = prop.paddr;
  cmd_packet->data[14] = prop.paddr >> 32;
  exec_buf.get()->bind_at(7, bo_mc.get(), 0, bo_mc.size());

  if (DEBUG_TEST) {
    for (int i = 0; i < 15; i++)
      std::cout << "data[" << i << "]: 0x"
                << std::hex << cmd_packet->data[i]
                << std::dec << std::endl;
  }

  if (config->iters < 1)
    config->iters = 1;

  std::cout << "Submit command and wait..." << std::endl;
  if (test_type != BAD_AND_GOOD_RUN) {
    auto start = Clock::now();
    for (int i = 0; i < config->iters; i++) {
      hwq->submit_command(exec_buf.get());

      hwq->wait_command(exec_buf.get(), 15000);

      if (cmd_packet->state != ERT_CMD_STATE_COMPLETED)
          throw std::runtime_error("Command error");
    }
    auto end = Clock::now();
    if (config->perf) {
      auto duration_us = std::chrono::duration_cast<us_t>(end - start).count();
      auto fps = (config->iters * 1000000.0) / duration_us;
      auto latency_us = 1000000.0 / fps;
      std::cout << config->iters << " iterations finished in "
                << duration_us << " us, FPS: " << fps
                << " , latency " << latency_us << " us" << std::endl;
    }
  } else {
    hwq->submit_command(exec_buf.get());
    std::cout << "Command submitted, waiting..." << std::endl;

    hwq->wait_command(exec_buf.get(), 15000);
    std::cout << "Command state " << cmd_packet->state << std::endl;

    if (cmd_packet->state != ERT_CMD_STATE_ABORT)
      throw std::runtime_error("expected bad command, but pass??");

    memcpy(instr_p, instr_bk, instr_size);
    bo_instr.get()->sync(buffer_handle::direction::host2device, instr_size, 0);

    std::cout << "fix mc code, ready to run good case" << std::endl;
    if (DEBUG_TEST)
      test_pause();

    hwq->submit_command(exec_buf.get());
    hwq->wait_command(exec_buf.get(), 15000);

    if (cmd_packet->state != ERT_CMD_STATE_COMPLETED)
      throw std::runtime_error("Command error");
  }

  bo_ofm.get()->sync(buffer_handle::direction::device2host, OFM_SIZE(tp), 0);
  bo_inter.get()->sync(buffer_handle::direction::device2host, INTER_SIZE(tp), 0);

  auto inter_p = reinterpret_cast<int8_t *>(bo_inter.map());
  if (!inter_p)
      throw std::runtime_error("map inter bo failed");

  dump_buf_to_file(inter_p, INTER_SIZE(tp), local_path(data_path + dump_inter_file));

  if (!config->noop) {
      auto ofm_p = reinterpret_cast<int8_t *>(bo_ofm.map());
      if (!ofm_p)
          throw std::runtime_error("map ofm bo failed");

      if (verify_output(ofm_p, local_path(data_path)))
          throw std::runtime_error("Test failed!!!");
  }

}

void
TEST_npu_submit_wait_cmd(device::id_type id, std::shared_ptr<device> dev, arg_type& arg)
{
    struct submit_wait_config config = {
        .perf = false,
        .noop = false,
        .iters = 1,
    };

    __npu_submit_wait_cmd(id, dev, arg, &config);
}

void
TEST_npu_real_kernel_latency(device::id_type id, std::shared_ptr<device> dev, arg_type& arg)
{
    struct submit_wait_config config = {
        .perf = true,
        .noop = false,
        .iters = 1000,
    };

    __npu_submit_wait_cmd(id, dev, arg, &config);
}

void
TEST_npu_noop_kernel_latency(device::id_type id, std::shared_ptr<device> dev, arg_type& arg)
{
    struct submit_wait_config config = {
        .perf = true,
        .noop = true,
        .iters = 1000,
    };

    __npu_submit_wait_cmd(id, dev, arg, &config);
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
    TEST_POSITIVE, dev_filter_is_npu, TEST_create_destroy_hw_context, {}
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
    TEST_POSITIVE, dev_filter_is_npu, TEST_create_free_bo,
    {XCL_BO_FLAGS_NONE, 0, 0x20000000}
  },
  //test_case{ "create_and_free_input_output_bo multiple pages from userptr",
  //  TEST_POSITIVE, dev_filter_xdna, TEST_create_free_userptr_bo, {XCL_BO_FLAGS_NONE, 0x14, 0x10000, 0x23000, 0x2000, 0x20000000}
  //},
  //test_case{ "sync_bo for dpu sequence bo",
  //  TEST_POSITIVE, dev_filter_xdna, TEST_sync_bo, {XCL_BO_FLAGS_CACHEABLE, 128}
  //},
  test_case{ "sync_bo for input_output",
    TEST_POSITIVE, dev_filter_xdna, TEST_sync_bo, {XCL_BO_FLAGS_NONE, 0, 128}
  },
  test_case{ "map dpu sequence bo and test perf",
    TEST_POSITIVE, dev_filter_xdna, TEST_map_bo, {XCL_BO_FLAGS_CACHEABLE, 0, 361264 /*0x10000*/}
  },
  test_case{ "map input_output bo and test perf",
    TEST_POSITIVE, dev_filter_xdna, TEST_map_bo, {XCL_BO_FLAGS_NONE, 0, 361264}
  },
  test_case{ "map exec_buf_bo and test perf",
    TEST_POSITIVE, dev_filter_xdna, TEST_create_free_bo, {XCL_BO_FLAGS_EXECBUF, 0, 0x1000}
  },
  test_case{ "open_close_cu_context",
    TEST_POSITIVE, dev_filter_is_npu, TEST_open_close_cu_context, {}
  },
  test_case{ "create_destroy_hw_queue",
    TEST_POSITIVE, dev_filter_is_npu, TEST_create_destroy_hw_queue, {}
  },
  test_case{ "npu: submit_wait_cmd",
    TEST_POSITIVE, dev_filter_is_npu, TEST_npu_submit_wait_cmd, { NORMAL_RUN }
  },
  test_case{ "npu: measure no-op kernel latency",
    TEST_POSITIVE, dev_filter_is_npu, TEST_npu_noop_kernel_latency, { NORMAL_RUN }
  },
  test_case{ "npu: measure real kernel latency",
    TEST_POSITIVE, dev_filter_is_npu, TEST_npu_real_kernel_latency, { NORMAL_RUN }
  },
  //test_case{ "npu: submit bad mc code, after recover, submit good mc code",
  //  TEST_POSITIVE, dev_filter_is_npu, TEST_submit_wait_cmd, { BAD_AND_GOOD_RUN }
  //},
  test_case{ "create and free debug bo",
    TEST_POSITIVE, dev_filter_xdna, TEST_create_free_debug_bo, { 0x4000 }
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
        if (!force && !test.dev_filter(i, dev))
          continue;
        skipped = false;
        test.func(i, dev, test.arg);
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

  auto devinfo = get_total_devices(true);
  if (devinfo.second == 0) {
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
    run_test(i, t, !all, devinfo.second);
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

// vim: ts=2 sw=2 expandtab

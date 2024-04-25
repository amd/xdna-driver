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
  bool (*dev_filter)(device::id_type id, device *dev);
  void (*func)(device::id_type id, device *dev, arg_type& arg);
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
dev_filter_is_npu(device::id_type id, device* dev)
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
TEST_get_xrt_info(device::id_type id, device* dev, arg_type& arg)
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
TEST_get_os_info(device::id_type id, device* dev, arg_type& arg)
{
  boost::property_tree::ptree pt;
  sysinfo::get_os_info(pt);
  std::cout << "Hostname: " << pt.get<std::string>("hostname", "N/A") << std::endl;
  std::cout << "OS: " << pt.get<std::string>("distribution", "N/A") << std::endl;
}

void
TEST_get_total_devices(device::id_type id, device* dev, arg_type& arg)
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
TEST_get_bdf_info_and_get_device_id(device::id_type id, device* dev, arg_type& arg)
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
TEST_get_mgmtpf_device(device::id_type id, device* dev, arg_type& arg)
{
  auto devinfo = get_total_devices(false);
  for (device::id_type i = 0; i < devinfo.first; i++)
    auto dev = get_mgmtpf_device(i);
}

template <typename QueryRequestType>
void
TEST_query_userpf(device::id_type id, device* dev, arg_type& arg)
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

const std::map<const char*, xrt_core::cuidx_type>&
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
  device* m_dev;
  std::unique_ptr<xrt_core::hwctx_handle> m_handle;

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
TEST_create_destroy_hw_context(device::id_type id, device* dev, arg_type& arg)
{
  hw_ctx hwctx{dev};
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
TEST_create_free_debug_bo(device::id_type id, device* dev, arg_type& arg)
{
  auto boflags = XRT_BO_FLAGS_CACHEABLE;
  auto ext_boflags = XRT_BO_USE_DEBUG << 4;
  auto size = static_cast<size_t>(arg[0]);
  hw_ctx hwctx{dev};

  auto bo = hwctx.get()->alloc_bo(size, get_bo_flags(boflags, ext_boflags));
}

void
TEST_create_free_bo(device::id_type id, device* dev, arg_type& arg)
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
TEST_create_free_userptr_bo(device::id_type id, device* dev, arg_type& arg)
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
TEST_sync_bo(device::id_type id, device* dev, arg_type& arg)
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
TEST_map_bo(device::id_type id, device* dev, arg_type& arg)
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
TEST_open_close_cu_context(device::id_type id, device* dev, arg_type& arg)
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
TEST_create_destroy_hw_queue(device::id_type id, device* dev, arg_type& arg)
{
  hw_ctx hwctx{dev};
  // Test to create > 1 queues
  auto hwq = hwctx.get()->get_hw_queue();
  auto hwq2 = hwctx.get()->get_hw_queue();
}

// Global test parameters/configurations for all I/O test cases
struct {
  bool perf;
  int iters;
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
checkpoint(const char *msg)
{
  std::cout << msg << std::endl;
  if (io_test_parameters.debug)
    test_pause();
}

void
io_test_parameter_init(bool perf, int iters, int type, bool debug = false)
{
  io_test_parameters.perf = perf;
  io_test_parameters.iters = iters;
  io_test_parameters.type = type;
  io_test_parameters.debug = debug;
}

void
io_test_bo_size_init(io_test_bo_set& io_test_bos, std::string& local_data_path)
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
    std::cout << "Getting instruction BO size from " << instruction_file << std::endl;
    instr_word_size = get_instr_size(instruction_file);
  }
  // Loading other sizes
  auto bo_size_config_file = local_data_path + config_file;
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
io_test_bo_alloc(io_test_bo_set& io_test_bos, device* dev)
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
io_test_bo_content_init(io_test_bo_set& io_test_bos, std::string& local_data_path)
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
          instruction_p[0] = 0x02000000;
          instruction_p[1] = 0x00034008;
          instruction_p[2] = 0x00000040;
          std::cout << "Expected \"Row: 0, Col: 1, module 2, event ID 64, category 4\" on dmesg" << std::endl;
        }
      }
      break;
    case IO_TEST_BO_MC_CODE: {
      if (ibo->size == 0)
        break;
      /* In the orignal test case, this MC_CODE_SIZE can be 0.
       * If it is 0, use a constant value (16) to allocate bo_mc.
       * In the current conv_case_0, MC_CODE_SIZE is 0. But, keep this code here.
       */
      std::cout << "!!! MC_CODE_SIZE is non zero !!!" << std::endl;
      auto mc_blob_p = ibo->tbo->map();
      read_data_from_bin(local_data_path + mc_blob_file, 0, ibo->size, mc_blob_p);
      for (int i = 0; i < 16; i++)
        std::cout << "mc_blob data: " << std::hex << mc_blob_p[i] << std::dec << std::endl;

      uint64_t ifm_paddr = io_test_bos[IO_TEST_BO_INPUT].tbo->get()->get_properties().paddr;
      uint64_t param_paddr = io_test_bos[IO_TEST_BO_PARAMETERS].tbo->get()->get_properties().paddr;
      uint64_t ofm_paddr = io_test_bos[IO_TEST_BO_OUTPUT].tbo->get()->get_properties().paddr;
      uint64_t inter_paddr = io_test_bos[IO_TEST_BO_INTERMEDIATE].tbo->get()->get_properties().paddr;
      patchMcCodeDDR(ifm_paddr, param_paddr, ofm_paddr, inter_paddr,
        reinterpret_cast<uint32_t *>(mc_blob_p), ibo->size);
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
io_test_sync_bos_before_run(io_test_bo_set& io_test_bos)
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
io_test_sync_bos_after_run(io_test_bo_set& io_test_bos)
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
io_test_cmd_init(io_test_bo_set& io_test_bos)
{
  auto cmd_bo = io_test_bos[IO_TEST_BO_CMD].tbo.get();
  auto cmd_packet = reinterpret_cast<ert_start_kernel_cmd *>(cmd_bo->map());

  cmd_packet->state = ERT_CMD_STATE_NEW;
  cmd_packet->count = 16;
  cmd_packet->opcode = ERT_SK_START;
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

// For debug only
void
io_test_dump_bo_content(io_test_bo *io_test_bos)
{
  for (int i = 0; i < IO_TEST_BO_MAX_TYPES; i++) {
    auto ibo = io_test_bos[i].tbo.get();
    auto ibo_p = reinterpret_cast<int8_t *>(ibo->map());
    std::string p("/tmp/");
    dump_buf_to_file(ibo_p, ibo->size(), p + io_test_bo_type_names[i]);
  }
}

void
io_test_cmd_submit_wait(device* dev, std::vector<bo*> cmd_bos)
{
  auto ip_name = find_first_match_ip_name(dev, "DPU.*");
  if (ip_name.empty())
    throw std::runtime_error("Cannot find any kernel name matched DPU.*");

  hw_ctx hwctx{dev};
  auto hwq = hwctx.get()->get_hw_queue();
  auto cu_idx = hwctx.get()->open_cu_context(ip_name);
  std::cout << "Found kernel: " << ip_name << " with cu index " << cu_idx.index << std::endl;

  std::vector<xrt_core::buffer_handle*> cmdlist;
  ert_start_kernel_cmd *cmd_packet = nullptr;
  for (auto cmd_bo : cmd_bos) {
    cmd_packet = reinterpret_cast<ert_start_kernel_cmd *>(cmd_bo->map());
    // Set CU index before submit the command
    cmd_packet->cu_mask = 0x1 << cu_idx.index;
    cmdlist.push_back(cmd_bo->get());
  }

  auto start = Clock::now();

  for (int i = 0; i < io_test_parameters.iters; i++) {
    hwq->submit_command(cmdlist);
    hwq->wait_command(cmdlist.back(), 15000);
    if (cmd_packet->state != ERT_CMD_STATE_COMPLETED)
      throw std::runtime_error("Command error");
  }

  auto end = Clock::now();

  if (io_test_parameters.perf) {
    auto duration_us = std::chrono::duration_cast<us_t>(end - start).count();
    auto fps = (io_test_parameters.iters * 1000000.0) / duration_us;
    auto latency_us = 1000000.0 / fps;
    std::cout << io_test_parameters.iters << " iterations finished in "
              << duration_us << " us, FPS: " << fps
              << " , latency " << latency_us << " us" << std::endl;
  }
}

void
io_test_verify_result(io_test_bo_set& io_test_bos, std::string& local_data_path)
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

void
io_test(device::id_type id, device* dev, size_t cmds_chained)
{
  std::vector<io_test_bo_set> chained_bos(cmds_chained);

  auto wrk = get_xclbin_workspace(dev);
  auto local_data_path = local_path(wrk + "/data/");
  std::vector<bo*> cmd_bos;

  for (auto& bos : chained_bos) {
    io_test_bo_size_init(bos, local_data_path);
    io_test_bo_alloc(bos, dev);
    checkpoint("Buffer allocation done");
    io_test_bo_content_init(bos, local_data_path);
    checkpoint("Input buffers' content initialization done");
    io_test_sync_bos_before_run(bos);
    checkpoint("Input buffers' content synchronization to device done");
    io_test_cmd_init(bos);
    checkpoint("Composing exec buf done");
    cmd_bos.push_back(bos[IO_TEST_BO_CMD].tbo.get());
  }

  io_test_cmd_submit_wait(dev, std::move(cmd_bos));
  checkpoint("Cmd execution done");

  for (auto& bos : chained_bos) {
    io_test_sync_bos_after_run(bos);
    checkpoint("Output buffers' content synchronization to host done");
    io_test_verify_result(bos, local_data_path);
  }

}

void
TEST_io(device::id_type id, device* dev, arg_type& arg)
{
  io_test_parameter_init(false, 1, static_cast<unsigned int>(arg[0]));
  io_test(id, dev, arg[1]);
}

void
TEST_io_latency(device::id_type id, device* dev, arg_type& arg)
{
  io_test_parameter_init(true, 1000, static_cast<unsigned int>(arg[0]));
  io_test(id, dev, arg[1]);
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
  // Keep bad run before normal run to test recovery of hw ctx
  test_case{ "io test real kernel bad run",
    TEST_NEGATIVE, dev_filter_is_npu, TEST_io, { IO_TEST_BAD_RUN, 1 }
  },
  test_case{ "io test real kernel good run",
    TEST_POSITIVE, dev_filter_is_npu, TEST_io, { IO_TEST_NORMAL_RUN, 1 }
  },
  test_case{ "measure no-op kernel latency",
    TEST_POSITIVE, dev_filter_is_npu, TEST_io_latency, { IO_TEST_NOOP_RUN, 1 }
  },
  test_case{ "measure real kernel latency",
    TEST_POSITIVE, dev_filter_is_npu, TEST_io_latency, { IO_TEST_NORMAL_RUN, 1}
  },
  test_case{ "create and free debug bo",
    TEST_NEGATIVE, dev_filter_xdna, TEST_create_free_debug_bo, { 0x4000 }
  },
  test_case{ "multi-command io test real kernel good run",
    TEST_POSITIVE, dev_filter_is_npu, TEST_io, { IO_TEST_NORMAL_RUN, 3 }
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
        test.func(i, dev.get(), test.arg);
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

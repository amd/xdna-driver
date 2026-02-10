// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2022-2026, Advanced Micro Devices, Inc. All rights reserved.
//
// WARNING: This file contains test cases calling XRT's SHIM layer APIs directly.
// These APIs are XRT's internal APIs and are not meant for any external XRT
// user to call. We can't provide any support if you use APIs here and run into issues.


#include "multi_threads.h"
#include "dev_info.h"
#include "io_param.h"
#include "hwctx.h"
#include "speed.h"
#include "bo.h"

#include "core/common/query_requests.h"
#include "core/common/sysinfo.h"
#include "core/common/system.h"
#include "core/common/device.h"

#include <filesystem>
#include <fstream>
#include <vector>
#include <iostream>
#include <sstream>
#include <string>

#include <libgen.h>
#include <sys/utsname.h>
#include <unistd.h>
// FIXME
#include <fcntl.h>
#include <sys/ioctl.h>
#include "../../src/include/uapi/drm_local/amdxdna_accel.h"
// enf of FIXME

struct kern_version {
  int major;
  int minor;
};

kern_version current_kern;
std::string cur_path;
std::string xclbin_path;
int base_write_speed;
int base_read_speed;

using arg_type = const std::vector<uint64_t>;
void TEST_export_import_bo(device::id_type, std::shared_ptr<device>&, arg_type&);
void TEST_export_import_bo_single_proc(device::id_type, std::shared_ptr<device>&, arg_type&);
void TEST_export_bo_then_close_device(device::id_type, std::shared_ptr<device>&, arg_type&);
void TEST_io(device::id_type, std::shared_ptr<device>&, arg_type&);
void TEST_io_timeout(device::id_type, std::shared_ptr<device>&, arg_type&);
void TEST_io_gemm(device::id_type, std::shared_ptr<device>&, arg_type&);
void TEST_async_error_io(device::id_type id, std::shared_ptr<device>& sdev, arg_type& arg);
void TEST_async_error_aie4_io(device::id_type id, std::shared_ptr<device>& sdev, arg_type& arg);
void TEST_async_error_multi(device::id_type id, std::shared_ptr<device>& sdev, arg_type& arg);
void TEST_instr_invalid_addr_io(device::id_type id, std::shared_ptr<device>& sdev, arg_type& arg);
void TEST_io_latency(device::id_type, std::shared_ptr<device>&, arg_type&);
void TEST_io_throughput(device::id_type, std::shared_ptr<device>&, arg_type&);
void TEST_io_runlist_latency(device::id_type, std::shared_ptr<device>&, arg_type&);
void TEST_io_runlist_throughput(device::id_type, std::shared_ptr<device>&, arg_type&);
void TEST_io_runlist_bad_cmd(device::id_type, std::shared_ptr<device>&, arg_type&);
void TEST_noop_io_with_dup_bo(device::id_type, std::shared_ptr<device>&, arg_type&);
void TEST_io_with_ubuf_bo(device::id_type, std::shared_ptr<device>&, arg_type&);
void TEST_io_suspend_resume(device::id_type, std::shared_ptr<device>&, arg_type&);
void TEST_shim_umq_vadd(device::id_type, std::shared_ptr<device>&, arg_type&);
void TEST_shim_umq_memtiles(device::id_type, std::shared_ptr<device>&, arg_type&);
void TEST_shim_umq_ddr_memtile(device::id_type, std::shared_ptr<device>&, arg_type&);
void TEST_shim_umq_remote_barrier(device::id_type, std::shared_ptr<device>&, arg_type&);
void TEST_elf_io(device::id_type, std::shared_ptr<device>&, arg_type&);
void TEST_preempt_elf_io(device::id_type, std::shared_ptr<device>&, arg_type&);
void TEST_cmd_fence_host(device::id_type, std::shared_ptr<device>&, arg_type&);
void TEST_cmd_fence_device(device::id_type, std::shared_ptr<device>&, arg_type&);
void TEST_preempt_full_elf_io(device::id_type, std::shared_ptr<device>&, arg_type&);
void TEST_io_coredump(device::id_type, std::shared_ptr<device>&, arg_type&);

inline void
set_xrt_path()
{
  setenv("XILINX_XRT", (cur_path + "/../").c_str(), true);
}

#define TEST_POSITIVE false
#define TEST_NEGATIVE true

void
usage(const std::string& prog)
{
  std::cout << "\nUsage: " << prog << " [options] [test case ID/name separated by spaces]\n";
  std::cout << "Options:\n";
  std::cout << "\t" << "-h" << ": print this help message and available test cases\n";
  std::cout << "\t" << "-k" << ": evaluate test result based on kernel version\n";
  std::cout << "\t" << "-x <xclbin_path>" << ": run test cases with specified xclbin file\n";
  std::cout << std::endl;
}

// Definition of one test case
struct test_case {
  const std::string name;
  /*
   * k_ver = { 0, 0 }: test should behave as expected
   * k_ver = { -1, -1 }: test does not behave as expected for now
   * k_ver = { m, n }: test does not behave as expected until m.n kenrel
   */
  const kern_version k_ver;
  bool is_negative;
  bool (*dev_filter)(device::id_type id, device *dev);
  void (*func)(device::id_type id, std::shared_ptr<device>& dev, arg_type& arg);
  arg_type arg;
};

// For overall test result evaluation
std::vector<int> test_passed;
std::vector<int> test_skipped;
std::vector<int> test_failed;

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
is_amdxdna_drv(device* dev)
{
  const std::string amdxdna = "amdxdna";

  query::sub_device_path::args query_arg = {std::string(""), 0};
  auto sysfs = device_query<query::sub_device_path>(dev, query_arg);
  auto drv_path = std::filesystem::read_symlink(sysfs + "/driver");
  auto drv_name = drv_path.filename();
  return drv_name == amdxdna;
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
  return device_id == npu1_device_id || device_id == npu4_device_id;
}

bool
dev_filter_is_aie4(device::id_type id, device* dev)
{
  if (!is_xdna_dev(dev))
    return false;
  auto device_id = device_query<query::pcie_device>(dev);
  return device_id == npu3_device_id || device_id == npu3_device_id1;
}

bool
dev_filter_is_aie(device::id_type id, device* dev)
{
  return dev_filter_is_aie2(id, dev) || dev_filter_is_aie4(id, dev);
}

bool
dev_filter_is_npu1(device::id_type id, device* dev)
{
  if (!is_xdna_dev(dev))
    return false;
  auto device_id = device_query<query::pcie_device>(dev);
  return device_id == npu1_device_id;
}

bool
dev_filter_is_npu4(device::id_type id, device* dev)
{
  if (!is_xdna_dev(dev))
    return false;
  auto device_id = device_query<query::pcie_device>(dev);
  return device_id == npu4_device_id;
}

bool
dev_filter_is_aie4_or_npu4(device::id_type id, device* dev)
{
  return dev_filter_is_npu4(id, dev) || dev_filter_is_aie4(id, dev);
}

bool
dev_filter_is_xdna_and_amdxdna_drv(device::id_type id, device* dev)
{
  if (!is_xdna_dev(dev))
    return false;
  if (!is_amdxdna_drv(dev))
    return false;
  return true;
}

bool
dev_filter_is_aie2_and_amdxdna_drv(device::id_type id, device* dev)
{
  if (!dev_filter_is_aie2(id, dev))
    return false;
  if (!is_amdxdna_drv(dev))
    return false;
  return true;
}

bool
dev_filter_is_npu4_and_amdxdna_drv(device::id_type id, device* dev)
{
  if (!dev_filter_is_npu4(id, dev))
    return false;
  if (!is_amdxdna_drv(dev))
    return false;
  return true;
}

std::tuple<uint64_t, uint64_t, uint64_t>
get_bo_usage(device* dev, int pid)
{
  // FIXME: reimplement this when query key is defined in xrt
  const char *xdna = "/dev/accel/accel0";
  int fd = open(xdna, O_RDONLY);
  if (fd < 0) {
    std::perror("open");
    return {0, 0, 0};
  }

  amdxdna_drm_bo_usage usage = { .pid = pid };
  amdxdna_drm_get_array arg = {
    .param = DRM_AMDXDNA_BO_USAGE,
    .element_size = sizeof(usage),
    .num_element = 1,
    .buffer = reinterpret_cast<uintptr_t>(&usage)
  };
  int ret = ioctl(fd, DRM_IOCTL_AMDXDNA_GET_ARRAY, &arg);
  close(fd);
  if (ret == -1) {
    std::perror("ioctl(DRM_IOCTL_AMDXDNA_GET_ARRAY)");
    return {0, 0, 0};
  }

  return {usage.total_usage, usage.internal_usage, usage.heap_usage};
}

// All test case runners

void
TEST_get_xrt_info(device::id_type id, std::shared_ptr<device>& sdev, arg_type& arg)
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
TEST_get_os_info(device::id_type id, std::shared_ptr<device>& sdev, arg_type& arg)
{
  boost::property_tree::ptree pt;
  sysinfo::get_os_info(pt);
  std::cout << "Hostname: " << pt.get<std::string>("hostname", "N/A") << std::endl;
  std::cout << "OS: " << pt.get<std::string>("distribution", "N/A") << std::endl;
}

void
TEST_get_total_devices(device::id_type id, std::shared_ptr<device>& sdev, arg_type& arg)
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
TEST_get_bdf_info_and_get_device_id(device::id_type id, std::shared_ptr<device>& sdev, arg_type& arg)
{
  auto is_user = arg[0];
  auto devinfo = get_total_devices(is_user);
  for (device::id_type i = 0; i < devinfo.first; i++) {
    auto info = get_bdf_info(i);
    auto bdf = bdf_info2str(info);
    std::cout << "device[" << i << "]: " << bdf << std::endl;
    auto dev = get_userpf_device(i);
    auto devid = device_query<query::pcie_device>(dev);
    std::cout << "device[" << bdf << "]: 0x" << std::hex << devid << std::dec << std::endl;

  }
}

void
TEST_get_mgmtpf_device(device::id_type id, std::shared_ptr<device>& sdev, arg_type& arg)
{
  auto devinfo = get_total_devices(false);
  for (device::id_type i = 0; i < devinfo.first; i++)
    auto dev = get_mgmtpf_device(i);
}

template <typename QueryRequestType>
void
TEST_query_userpf(device::id_type id, std::shared_ptr<device>& sdev, arg_type& arg)
{
  auto query_result = device_query<QueryRequestType>(sdev);
  std::cout << "dev[" << id << "]." << QueryRequestType::name() << ": "
    << QueryRequestType::to_string(query_result) << std::endl;
}

void
TEST_create_destroy_device(device::id_type id, std::shared_ptr<device>& sdev, arg_type& arg)
{
  auto dev1 = get_userpf_device(id);
  auto dev2 = get_userpf_device(id);
}

void
TEST_create_destroy_hw_context(device::id_type id, std::shared_ptr<device>& sdev, arg_type& arg)
{
  // Close existing device
  sdev.reset();

  // Try opening device and creating ctx twice
  {
    auto dev = get_userpf_device(id);
    hw_ctx hwctx{dev.get()};
  }
  {
    auto dev = get_userpf_device(id);
    hw_ctx hwctx{dev.get()};
  }
}

void
TEST_create_destroy_virtual_context(device::id_type id, std::shared_ptr<device>& sdev, arg_type& arg)
{
  auto dev = sdev.get();
  auto device_id = device_query<query::pcie_device>(dev);
  int is_negative = static_cast<unsigned int>(arg[0]);
  int num_virt_ctx;

  // XDNA driver by default supports 6 virtual context on npu1 and 32 virtual context on npu4
  if (device_id == npu1_device_id)
    num_virt_ctx = 6;
  else
    num_virt_ctx = 32;

  if (is_negative)
    num_virt_ctx += 1;

  std::cout << "Creating " << num_virt_ctx << " contexts" << std::endl;
  // Try opening device and creating ctx twice
  {
    std::vector<std::unique_ptr<hw_ctx>> ctxs;
    for (int i = 0; i < num_virt_ctx; i++)
      ctxs.push_back(std::make_unique<hw_ctx>(dev));
  }
}

void
TEST_multi_context_io_test(device::id_type id, std::shared_ptr<device>& sdev, arg_type& arg)
{
  auto dev = sdev.get();
  auto device_id = device_query<query::pcie_device>(dev);
  int num_virt_ctx = static_cast<unsigned int>(arg[0]);

  multi_thread threads(num_virt_ctx, TEST_io_latency);
  threads.run_test(id, sdev, {IO_TEST_NORMAL_RUN, IO_TEST_IOCTL_WAIT, 3000});
}

void
TEST_create_free_debug_bo(device::id_type id, std::shared_ptr<device>& sdev, arg_type& arg)
{
  auto dev = sdev.get();
  auto boflags = XRT_BO_FLAGS_CACHEABLE;
  auto ext_boflags = dev_filter_is_aie4(id, dev) ? (XRT_BO_USE_UC_DEBUG << 4) : (XRT_BO_USE_DEBUG << 4);
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
get_and_show_bo_properties(device* dev, buffer_handle *boh)
{
  buffer_handle::properties properties = boh->get_properties();
  std::cout << std::hex
    << "\tbo flags: 0x" << properties.flags << "\n"
    << "\tbo paddr: 0x" << properties.paddr << "\n"
    << "\tbo kmhdl: 0x" << properties.kmhdl << "\n"
    << "\tbo size: 0x" << properties.size << std::dec << std::endl;
}

void
TEST_create_free_bo(device::id_type id, std::shared_ptr<device>& sdev, arg_type& arg)
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

void
TEST_create_free_internal_bo(device::id_type id, std::shared_ptr<device>& sdev, arg_type& arg)
{
  auto dev = sdev.get();
  auto boflags = XRT_BO_FLAGS_HOST_ONLY;
  auto ext_boflags = XRT_BO_USE_CTRLPKT << 4;
  auto size = 0x4000;
  auto bo = dev->alloc_bo(size, get_bo_flags(boflags, ext_boflags));
  auto [total, internal, heap] = get_bo_usage(dev, getpid());
  uint64_t expected_total = size;
  uint64_t expected_internal = size;
  uint64_t expected_heap = 0;
  if (dev_filter_is_aie2(id, dev)) {
    // Add heap size
    expected_total += 64 * 1024 * 1024;
    expected_internal += 64 * 1024 * 1024;
  }
  if (total != expected_total || internal != expected_internal || heap != expected_heap)
    throw std::runtime_error("BO usage mis-match");
}

void
TEST_create_free_uptr_bo(device::id_type id, std::shared_ptr<device>& sdev, arg_type& arg)
{
  auto dev = sdev.get();
  uint32_t boflags = static_cast<unsigned int>(arg[0]);
  uint32_t ext_boflags = static_cast<unsigned int>(arg[1]);
  arg_type bos_size(arg.begin() + 2, arg.end());
  std::vector<std::unique_ptr<bo>> bos;
  const uint64_t fill = 0x55aa55aa55aa55aa;
  std::vector< std::vector<char> > bufs;
  static long page_size = 0;

  if (!page_size)
    page_size = sysconf(_SC_PAGESIZE);

  for (auto& size : bos_size) {
    if (size < 8)
      throw std::runtime_error("User ptr BO size too small");
    bufs.emplace_back(size + page_size); // allow page size align

    auto addr = reinterpret_cast<uintptr_t>(bufs.back().data());
    auto p = reinterpret_cast<uint64_t*>((addr + page_size - 1) & ~(page_size - 1));
    *p = fill;
    bos.push_back(std::make_unique<bo>(dev, p, static_cast<size_t>(size), boflags, ext_boflags));
  }

  for (auto& bo : bos) {
    auto p = reinterpret_cast<uint64_t*>(bo->map());
    if (*p != fill) {
      printf("User ptr BO content is %lx@%p\n", *p, p);
      throw std::runtime_error("User ptr BO content mis-match");
    }
    get_and_show_bo_properties(dev, bo->get());
  }
}

void
TEST_sync_bo(device::id_type id, std::shared_ptr<device>& sdev, arg_type& arg)
{
  auto boflags = static_cast<unsigned int>(arg[0]);
  auto ext_boflags = static_cast<unsigned int>(arg[1]);
  auto size = static_cast<size_t>(arg[2]);
  bo bo{sdev.get(), size, boflags, ext_boflags};

  auto start = clk::now();
  bo.get()->sync(buffer_handle::direction::host2device, size / 2, 0);
  bo.get()->sync(buffer_handle::direction::device2host, size / 2, size / 2);
  auto end = clk::now();

  get_speed_and_print("sync", size, start, end);
}

void
TEST_sync_bo_off_size(device::id_type id, std::shared_ptr<device>& sdev, arg_type& arg)
{
  auto boflags = static_cast<unsigned int>(arg[0]);
  auto ext_boflags = static_cast<unsigned int>(arg[1]);
  auto size = static_cast<size_t>(arg[2]);
  auto sync_offset = static_cast<size_t>(arg[3]);
  auto sync_size = static_cast<size_t>(arg[4]);
  bo bo{sdev.get(), size, boflags, ext_boflags};

  auto start = clk::now();
  bo.get()->sync(buffer_handle::direction::host2device, sync_size, sync_offset);
  auto end = clk::now();

  get_speed_and_print("sync", sync_size, start, end);
}

void
TEST_map_read_bo(device::id_type id, std::shared_ptr<device>& sdev, arg_type& arg)
{
  auto dev = sdev.get();
  auto size = static_cast<size_t>(arg[0]);
  auto bo_hdl = dev->alloc_bo(size, get_bo_flags(XCL_BO_FLAGS_HOST_ONLY, 0));

  auto buf = bo_hdl->map(buffer_handle::map_type::read);
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
  auto start = clk::now();
  memcpy(dst, src, size);
  auto end = clk::now();
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

void
TEST_map_bo(device::id_type id, std::shared_ptr<device>& sdev, arg_type& arg)
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
TEST_open_close_cu_context(device::id_type id, std::shared_ptr<device>& sdev, arg_type& arg)
{
  auto dev = sdev.get();
  hw_ctx hwctx{dev};

  for (auto& ip : get_binary_ip_name2index(dev)) {
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
TEST_create_destroy_hw_queue(device::id_type id, std::shared_ptr<device>& sdev, arg_type& arg)
{
  hw_ctx hwctx{sdev.get()};
  // Test to create > 1 queues
  auto hwq = hwctx.get()->get_hw_queue();
  auto hwq2 = hwctx.get()->get_hw_queue();
}

// List of all test cases
std::vector<test_case> test_list {
  test_case{ "get_xrt_info", {},
    TEST_POSITIVE, no_dev_filter, TEST_get_xrt_info, {}
  },
  test_case{ "get_os_info", {},
    TEST_POSITIVE, no_dev_filter, TEST_get_os_info, {}
  },
  test_case{ "get_total_devices", {},
    TEST_POSITIVE, no_dev_filter, TEST_get_total_devices, {true}
  },
  //test_case{ "get_total_devices(mgmtpf)", {},
  //  TEST_POSITIVE, no_dev_filter, TEST_get_total_devices, {false}
  //},
  test_case{ "get_bdf_info_and_get_device_id", {},
    TEST_POSITIVE, no_dev_filter, TEST_get_bdf_info_and_get_device_id, {true}
  },
  //test_case{ "get_bdf_info_and_get_device_id(mgmtpf)", {},
  //  TEST_POSITIVE, no_dev_filter, TEST_get_bdf_info_and_get_device_id, {false}
  //},
  //test_case{ "get_mgmtpf_device", {},
  //  TEST_POSITIVE, no_dev_filter, TEST_get_mgmtpf_device, {}
  //},
  test_case{ "query(pcie_vendor)", {},
    TEST_POSITIVE, dev_filter_xdna, TEST_query_userpf<query::pcie_vendor>, {}
  },
  //test_case{ "non_xdna_userpf: query(pcie_vendor)", {},
  //  TEST_POSITIVE, dev_filter_not_xdna, TEST_query_userpf<query::pcie_vendor>, {}
  //},
  test_case{ "query(rom_vbnv)", {},
    TEST_POSITIVE, dev_filter_xdna, TEST_query_userpf<query::rom_vbnv>, {}
  },
  test_case{ "query(rom_fpga_name)", {},
    TEST_NEGATIVE, dev_filter_xdna, TEST_query_userpf<query::rom_fpga_name>, {}
  },
  // get async error in multi thread before running any other tests
  // there may or may not be async error.
  test_case{ "get async error in multithread - INITIAL", {},
    TEST_POSITIVE, dev_filter_xdna, TEST_async_error_multi, {false}
  },
  //test_case{ "non_xdna_userpf: query(rom_vbnv)", {},
  //  TEST_POSITIVE, dev_filter_not_xdna, TEST_query_userpf<query::rom_vbnv>, {}
  //},
  test_case{ "create_destroy_hw_context", {},
    TEST_POSITIVE, dev_filter_is_aie, TEST_create_destroy_hw_context, {}
  },
  test_case{ "create_invalid_bo", {},
    TEST_NEGATIVE, dev_filter_xdna, TEST_create_free_bo, {XCL_BO_FLAGS_P2P, 0, 128}
  },
  test_case{ "create_and_free_exec_buf_bo", {},
    TEST_POSITIVE, dev_filter_xdna, TEST_create_free_bo, {XCL_BO_FLAGS_EXECBUF, 0, 128}
  },
  test_case{ "create_and_free_dpu_sequence_bo 1 bo", {},
    TEST_POSITIVE, dev_filter_xdna, TEST_create_free_bo, {XCL_BO_FLAGS_CACHEABLE, 0, 128}
  },
  test_case{ "create_and_free_dpu_sequence_bo multiple bos", {},
    TEST_POSITIVE, dev_filter_xdna, TEST_create_free_bo,
    {XCL_BO_FLAGS_CACHEABLE, 0, 0x2000, 0x400, 0x3000, 0x100}
  },
  test_case{ "create_and_free_input_output_bo 1 page", {},
    TEST_POSITIVE, dev_filter_xdna, TEST_create_free_bo, {XCL_BO_FLAGS_HOST_ONLY, 0, 128}
  },
  test_case{ "create_and_free_input_output_bo multiple pages", {},
    TEST_POSITIVE, dev_filter_xdna, TEST_create_free_bo,
    {XCL_BO_FLAGS_HOST_ONLY, 0, 0x10000, 0x23000, 0x2000}
  },
  test_case{ "create_and_free_input_output_bo huge pages", {},
    TEST_POSITIVE, dev_filter_is_aie, TEST_create_free_bo,
    {XCL_BO_FLAGS_HOST_ONLY, 0, 0x140000000}
  },
  test_case{ "sync_bo for dpu sequence bo", {},
    TEST_POSITIVE, dev_filter_xdna, TEST_sync_bo, {XCL_BO_FLAGS_CACHEABLE, 0, 128}
  },
  test_case{ "sync_bo for input_output", {},
    TEST_POSITIVE, dev_filter_xdna, TEST_sync_bo, {XCL_BO_FLAGS_HOST_ONLY, 0, 128}
  },
  test_case{ "map dpu sequence bo and test perf", {},
    TEST_POSITIVE, dev_filter_xdna, TEST_map_bo, {XCL_BO_FLAGS_CACHEABLE, 0, 361264 /*0x10000*/}
  },
  test_case{ "map input_output bo and test perf", {},
    TEST_POSITIVE, dev_filter_xdna, TEST_map_bo, {XCL_BO_FLAGS_HOST_ONLY, 0, 361264}
  },
  test_case{ "map bo for read only", {},
    TEST_NEGATIVE, dev_filter_xdna, TEST_map_read_bo, {0x1000}
  },
  test_case{ "map exec_buf_bo and test perf", {},
    TEST_POSITIVE, dev_filter_xdna, TEST_create_free_bo, {XCL_BO_FLAGS_EXECBUF, 0, 0x1000}
  },
  test_case{ "open_close_cu_context", {},
    TEST_POSITIVE, dev_filter_is_aie2, TEST_open_close_cu_context, {}
  },
  test_case{ "create_destroy_hw_queue", {},
    TEST_POSITIVE, dev_filter_xdna, TEST_create_destroy_hw_queue, {}
  },
  // Keep bad run before normal run to test recovery of hw ctx
  test_case{ "io test async error", {},
    TEST_POSITIVE, dev_filter_is_npu4, TEST_async_error_io, {}
  },
  test_case{ "io test real kernel good run", {},
    TEST_POSITIVE, dev_filter_xdna, TEST_io, { IO_TEST_NORMAL_RUN, 1 }
  },
  test_case{ "io test with intruction code invalid address access", {},
    TEST_POSITIVE, dev_filter_is_npu4, TEST_instr_invalid_addr_io, {}
  },
  test_case{ "measure no-op kernel latency", {},
    TEST_POSITIVE, dev_filter_is_aie, TEST_io_latency, { IO_TEST_NOOP_RUN, IO_TEST_IOCTL_WAIT, 32000 }
  },
  test_case{ "measure real kernel latency", {},
    TEST_POSITIVE, dev_filter_is_aie, TEST_io_latency, { IO_TEST_NORMAL_RUN, IO_TEST_IOCTL_WAIT, 32000 }
  },
  test_case{ "create and free debug bo", {-1, -1},
    TEST_POSITIVE, dev_filter_xdna, TEST_create_free_debug_bo, { 0x1000 }
  },
  test_case{ "create and free large debug bo", {-1, -1},
    TEST_POSITIVE, dev_filter_xdna, TEST_create_free_debug_bo, { 0x100000 }
  },
  test_case{ "multi-command io test real kernel good run", {},
    TEST_POSITIVE, dev_filter_is_aie2, TEST_io, { IO_TEST_NORMAL_RUN, 3 }
  },
  test_case{ "measure no-op kernel throughput command", {},
    TEST_POSITIVE, dev_filter_is_aie, TEST_io_throughput, { IO_TEST_NOOP_RUN, IO_TEST_IOCTL_WAIT, 32000 }
  },
  test_case{ "export import BO", {},
    TEST_POSITIVE, dev_filter_is_aie2, TEST_export_import_bo, {}
  },
  test_case{ "ELF io test real kernel good run", {},
    TEST_POSITIVE, dev_filter_is_aie2, TEST_elf_io, { IO_TEST_NORMAL_RUN, 1 }
  },
  test_case{ "Cmd fencing (user space side)", {},
    TEST_POSITIVE, dev_filter_xdna, TEST_cmd_fence_host, {}
  },
  test_case{ "io test no op with duplicated BOs", {},
    TEST_POSITIVE, dev_filter_is_aie2, TEST_noop_io_with_dup_bo, {}
  },
  test_case{ "measure no-op kernel latency chained command", {},
    TEST_POSITIVE, dev_filter_is_aie, TEST_io_runlist_latency, { IO_TEST_NOOP_RUN, IO_TEST_IOCTL_WAIT, 32000 }
  },
  test_case{ "measure no-op kernel throughput chained command", {},
    TEST_POSITIVE, dev_filter_is_aie, TEST_io_runlist_throughput, { IO_TEST_NOOP_RUN, IO_TEST_IOCTL_WAIT, 32000 }
  },
  test_case{ "measure no-op kernel latency (polling)", {},
    TEST_POSITIVE, dev_filter_is_aie, TEST_io_latency, { IO_TEST_NOOP_RUN, IO_TEST_POLL_WAIT, 32000 }
  },
  test_case{ "measure no-op kernel throughput (polling)", {},
    TEST_POSITIVE, dev_filter_is_aie, TEST_io_throughput, { IO_TEST_NOOP_RUN, IO_TEST_POLL_WAIT, 32000 }
  },
  test_case{ "measure no-op kernel latency chained command (polling)", {},
    TEST_POSITIVE, dev_filter_is_aie, TEST_io_runlist_latency, { IO_TEST_NOOP_RUN, IO_TEST_POLL_WAIT, 32000 }
  },
  test_case{ "measure no-op kernel throughput chained command (polling)", {},
    TEST_POSITIVE, dev_filter_is_aie, TEST_io_runlist_throughput, { IO_TEST_NOOP_RUN, IO_TEST_POLL_WAIT, 32000 }
  },
  test_case{ "Cmd fencing (driver side)", {-1, -1},
    TEST_POSITIVE, dev_filter_is_aie2, TEST_cmd_fence_device, {}
  },
  test_case{ "sync_bo for input_output 1MiB BO", {},
    TEST_POSITIVE, dev_filter_xdna, TEST_sync_bo, {XCL_BO_FLAGS_HOST_ONLY, 0, 0x100000}
  },
  test_case{ "sync_bo for input_output 1MiB BO w/ offset and size", {},
    TEST_POSITIVE, dev_filter_xdna, TEST_sync_bo_off_size, {XCL_BO_FLAGS_HOST_ONLY, 0, 0x100000, 0x1004, 0x3c}
  },
  test_case{ "export import BO in single process", {},
    TEST_POSITIVE, dev_filter_is_aie2, TEST_export_import_bo_single_proc, {}
  },
  test_case{ "multi-command ELF io test real kernel good run", {},
    TEST_POSITIVE, dev_filter_is_aie2, TEST_elf_io, { IO_TEST_NORMAL_RUN, 3 }
  },
  test_case{ "virtual context test", {},
    TEST_POSITIVE, dev_filter_is_aie2, TEST_create_destroy_virtual_context, { 0 }
  },
  test_case{ "virtual context bad test", {},
    TEST_NEGATIVE, dev_filter_is_aie2, TEST_create_destroy_virtual_context, { 1 }
  },
  test_case{ "Multi context IO test 1 (npu1)", {},
    TEST_POSITIVE, dev_filter_is_npu1, TEST_multi_context_io_test, { 2 }
  },
  test_case{ "Multi context IO test 2 (npu1)", {},
    TEST_POSITIVE, dev_filter_is_npu1, TEST_multi_context_io_test, { 4 }
  },
  test_case{ "Multi context IO test 3 (npu1)", {},
    TEST_POSITIVE, dev_filter_is_npu1, TEST_multi_context_io_test, { 6 }
  },
  test_case{ "Multi context IO test 1 (npu4)", {},
    TEST_POSITIVE, dev_filter_is_npu4, TEST_multi_context_io_test, { 2 }
  },
  test_case{ "Multi context IO test 2 (npu4)", {},
    TEST_POSITIVE, dev_filter_is_npu4, TEST_multi_context_io_test, { 4 }
  },
  test_case{ "Multi context IO test 3 (npu4)", {},
    TEST_POSITIVE, dev_filter_is_npu4, TEST_multi_context_io_test, { 16 }
  },
  test_case{ "Multi context IO test 4 (npu4)", {},
    TEST_POSITIVE, skip_dev_filter, TEST_multi_context_io_test, { 20 }
  },
  test_case{ "Create and destroy devices", {},
    TEST_POSITIVE, dev_filter_is_aie2, TEST_create_destroy_device, {}
  },
  test_case{ "multi-command preempt ELF io test real kernel good run", {},
    TEST_POSITIVE, dev_filter_is_npu4_and_amdxdna_drv, TEST_preempt_elf_io, { IO_TEST_FORCE_PREEMPTION, 8 }
  },
  test_case{ "create and free user pointer bo", {},
    TEST_POSITIVE, dev_filter_is_xdna_and_amdxdna_drv, TEST_create_free_uptr_bo, {XCL_BO_FLAGS_HOST_ONLY, 0, 128}
  },
  test_case{ "io test with user pointer BOs", {},
    TEST_POSITIVE, dev_filter_is_aie2_and_amdxdna_drv, TEST_io_with_ubuf_bo, {}
  },
  test_case{ "Real kernel delay run for auto-suspend/resume", {},
    TEST_POSITIVE, dev_filter_is_aie2, TEST_io_suspend_resume, {}
  },
  test_case{ "io test timeout run for context health report", {},
    TEST_POSITIVE, dev_filter_is_npu4, TEST_io_timeout, {}
  },
  //test_case{ "io test no-op kernel good run", {},
  //  TEST_POSITIVE, dev_filter_is_aie2, TEST_io, { IO_TEST_NOOP_RUN, 1 }
  //},
  test_case{ "multi-command preempt full ELF io test real kernel good run", {},
    TEST_POSITIVE, dev_filter_is_npu4_and_amdxdna_drv, TEST_preempt_full_elf_io, { IO_TEST_FORCE_PREEMPTION, 8 }
  },
  // get async error in multi thread after async error has raised.
  test_case{ "get async error in multithread - HAS ASYNC ERROR", {},
    TEST_POSITIVE, dev_filter_is_npu4, TEST_async_error_multi, {true}
  },
  test_case{ "gemm and debug BO", {},
    TEST_POSITIVE, dev_filter_is_npu4, TEST_io_gemm, {}
  },
  test_case{ "create and free internal bo", {},
    TEST_POSITIVE, dev_filter_is_aie, TEST_create_free_internal_bo, {}
  },
  test_case{ "export BO then close device", {},
    TEST_POSITIVE, dev_filter_is_aie2, TEST_export_bo_then_close_device, {}
  },
  test_case{ "get AIE coredump and check registers", {},
    TEST_POSITIVE, dev_filter_is_npu4, TEST_io_coredump, {}
  },
  test_case{ "failed chained command", {},
    TEST_POSITIVE, dev_filter_is_npu4, TEST_io_runlist_bad_cmd, {false}
  },
  test_case{ "timed out chained command", {},
    TEST_POSITIVE, dev_filter_is_npu4, TEST_io_runlist_bad_cmd, {true}
  },
};

void
print_available_tests()
{
  std::cout << "Available Test Cases:\n";
  for (size_t i = 0; i < test_list.size(); i++) {
    std::cout << "  #" << i << " - " << test_list[i].name << "\n";
  }
  std::cout << std::endl;
}

// Test case executor implementation

bool
is_negative_test(const test_case& test)
{
  if (current_kern.major == 0)
    return test.is_negative;
  if (test.k_ver.major == -1)
    return !test.is_negative;
  if (current_kern.major < test.k_ver.major)
    return !test.is_negative;
  if (current_kern.major == test.k_ver.major && current_kern.minor < test.k_ver.minor)
    return !test.is_negative;
  return test.is_negative;
}

void
run_test(int id, const test_case& test, bool force, const device::id_type& num_of_devices)
{
  bool failed = is_negative_test(test);
  bool skipped = true;

  std::cout << "====== " << id << ": " << test.name << " started =====" << std::endl;
  try {
    if (test.dev_filter == no_dev_filter) { // system test
      skipped = false;
      std::shared_ptr<device> dev = nullptr;
      test.func(0, dev, test.arg);
    } else { // per user device test
      for (device::id_type i = 0; i < num_of_devices; i++) {
        auto dev = get_userpf_device(i);
        if (!force && !test.dev_filter(i, dev.get()))
          continue;
        skipped = false;
        test.func(i, dev, test.arg);
      }
    }
  }
  catch (const std::exception& ex) {
    skipped = false;
    std::cout << ex.what() << std::endl;
    failed = !failed;
  }

  std::string result;
  if (skipped)
    result = "skipped";
  else
    result = failed ? "\x1b[5m\x1b[31mFAILED\x1b[0m" : "passed ";
  std::cout << "====== " << id << ": " << test.name << " " << result << " =====" << std::endl;

  if (skipped)
    test_skipped.push_back(id);
  else if (failed)
    test_failed.push_back(id);
  else
    test_passed.push_back(id);
}

void
run_all_test(std::vector<int>& tests)
{
  device::id_type total_dev = 0;

  try {
    auto devinfo = get_total_devices(true);
    total_dev = devinfo.second;
  } catch (const std::runtime_error& e) {
    std::cout << e.what();
  }

  if (total_dev == 0) {
    std::cout << "No testable devices on this machine. Failing all tests.\n";
    if (tests.empty()) {
      int id = 0;
      for (const auto& t : test_list)
        test_failed.push_back(id++);
    } else {
      test_failed = tests;
    }
    return;
  }

  // Run all tests
  if (tests.empty()) {
    int id = 0;
    for (const auto& t : test_list) {
      run_test(id++, t, false, total_dev);
      std::cout << std::endl;
    }
  }

  // Run specified tests
  for (auto id : tests) {
    const auto& t = test_list[id];
    run_test(id, t, true, total_dev);
    std::cout << std::endl;
  }
}

int
get_kernel_version(int *major, int *minor)
{
  struct utsname buffer;

  if (uname(&buffer) != 0) {
      perror("uname");
      return -EFAULT;
  }

  std::string version = buffer.release;
  std::stringstream version_stream(version);
  char dot;
  if (!(version_stream >> *major >> dot >> *minor)) {
      std::cout << "Failed to parse kernel version: " << version << std::endl;
      return -EINVAL;
  }
  return 0;
}

int
get_test_case_index(const char *arg)
{
  int idx;
  size_t pos;
  bool is_idx = true;

  try {
    idx = std::stoi(arg, &pos, 10);
  }
  catch (...) {
    is_idx = false;
  }
  if (arg[pos] != '\0')
    is_idx = false;

  if (is_idx)
    return idx;

  idx = 0;
  for (const auto& t : test_list) {
    if (t.name.compare(arg) == 0)
      return idx;
    idx++;
  }
  std::cout << "Test case not found: " << arg << std::endl;
  return -1;
}

int
main(int argc, char **argv)
{
  std::string program = std::filesystem::path(argv[0]).filename();

  int option;
  while ((option = getopt(argc, argv, ":hx:k")) != -1) {
    switch (option) {
    case 'h':
      usage(program);
      print_available_tests();
      return 0;
    case 'x': {
      std::ifstream xclbin(optarg);
      if (xclbin) {
        xclbin_path = optarg;
        std::cout << "Using xclbin file: " << xclbin_path << std::endl;
        break;
      } else {
        std::cout << "Failed to open xclbin file: " << optarg << std::endl;
        return 1;
      }
    }
    case 'k': {
      if (get_kernel_version(&current_kern.major, &current_kern.minor))
        return 1;
      std::cout << "Evaluating test result based on kernel version: "
        << current_kern.major << "." << current_kern.minor << std::endl;
      break;
    }
    case '?':
      std::cout << "Unknown option: " << static_cast<char>(optopt) << std::endl;
      return 1;
    case ':':
      std::cout << "Missing value for option: " << argv[optind-1] << std::endl;
      return 1;
    default:
      usage(program);
      return 1;
    }
  }

  std::vector<int> tests;
  for (int i = optind; i < argc; i++) {
    int idx = get_test_case_index(argv[i]);
    if (idx >= 0 && idx < test_list.size()) {
      tests.push_back(idx);
    } else {
      std::cout << "Invalid test index : " << idx << std::endl;
      return 1;
    }
  }

  cur_path = dirname(argv[0]);
  set_xrt_path();

  run_all_test(tests);

  std::cout << test_skipped.size() << "\ttest(s) skipped: ";
  for (int id : test_skipped)
    std::cout << id << " ";
  std::cout << std::endl;

  if (test_passed.size() + test_failed.size() == 0)
    return 0;

  std::cout << test_passed.size() + test_failed.size() << "\ttest(s) executed" << std::endl;
  if (test_failed.size() == 0) {
    std::cout << "ALL " << test_passed.size() << " executed test(s) PASSED!" << std::endl;
    return 0;
  }
  std::cout << test_failed.size() << "\ttest(s) \x1b[5m\x1b[31mFAILED\x1b[0m: ";
  for (int id : test_failed)
    std::cout << id << " ";
  std::cout << std::endl;
  return 1;
}

// vim: ts=2 sw=2 expandtab

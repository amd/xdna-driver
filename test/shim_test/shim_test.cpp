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

#include <array>
#include <algorithm>
#include <cctype>
#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <functional>
#include <optional>
#include <type_traits>
#include <vector>
#include <iostream>
#include <sstream>
#include <string>
#include <dirent.h>
#include <sys/stat.h>

#include <libgen.h>
#include <sys/utsname.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <sys/ioctl.h>

// FIXME
#include "../../src/include/uapi/drm_local/amdxdna_accel.h"
// end of FIXME

struct driver_version {
  unsigned int major;
  unsigned int minor;
};

driver_version current_drv;
std::string cur_path;
std::string xclbin_path;
int base_write_speed;
int base_read_speed;

void TEST_export_import_bo(device::id_type, std::shared_ptr<device>&, arg_type&);
void TEST_export_import_bo_single_proc(device::id_type, std::shared_ptr<device>&, arg_type&);
void TEST_export_bo_then_close_device(device::id_type, std::shared_ptr<device>&, arg_type&);
void TEST_io(device::id_type, std::shared_ptr<device>&, arg_type&);
void TEST_io_timeout(device::id_type, std::shared_ptr<device>&, arg_type&);
void TEST_io_gemm(device::id_type, std::shared_ptr<device>&, arg_type&);
void TEST_async_error_io(device::id_type id, std::shared_ptr<device>& sdev, arg_type& arg);
void TEST_async_error_aie4_io(device::id_type id, std::shared_ptr<device>& sdev, arg_type& arg);
void TEST_tdr_timeout_and_abort(device::id_type id, std::shared_ptr<device>& sdev, arg_type& arg);
void TEST_tdr_partial_chain_abort(device::id_type id, std::shared_ptr<device>& sdev, arg_type& arg);
void TEST_tdr_not_yet_published_retried(device::id_type id, std::shared_ptr<device>& sdev, arg_type& arg);
void TEST_async_error_multi(device::id_type id, std::shared_ptr<device>& sdev, arg_type& arg);
void TEST_instr_invalid_addr_io(device::id_type id, std::shared_ptr<device>& sdev, arg_type& arg);
void TEST_io_latency(device::id_type, std::shared_ptr<device>&, arg_type&);
void TEST_io_throughput(device::id_type, std::shared_ptr<device>&, arg_type&);
void TEST_io_runlist_latency(device::id_type, std::shared_ptr<device>&, arg_type&);
void TEST_io_runlist_throughput(device::id_type, std::shared_ptr<device>&, arg_type&);
void TEST_io_runlist_bad_cmd(device::id_type, std::shared_ptr<device>&, arg_type&);
void TEST_noop_io_with_dup_bo(device::id_type, std::shared_ptr<device>&, arg_type&);
void TEST_io_with_ubuf_bo(device::id_type, std::shared_ptr<device>&, arg_type&);
void TEST_write_to_readonly_uptr_bo(device::id_type, std::shared_ptr<device>&, arg_type&);
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
void TEST_app_health_query_multi_ctx(device::id_type, std::shared_ptr<device>&, arg_type&);
void TEST_query_hw_contexts(device::id_type, std::shared_ptr<device>&, arg_type&);
void TEST_hw_context_all(device::id_type, std::shared_ptr<device>&, arg_type&);
void TEST_query_telemetry(device::id_type, std::shared_ptr<device>&, arg_type&);
void TEST_query_telemetry_short_buf(device::id_type, std::shared_ptr<device>&, arg_type&);
void TEST_io_coredump(device::id_type, std::shared_ptr<device>&, arg_type&);
void TEST_io_aie_mem(device::id_type, std::shared_ptr<device>&, arg_type&);
void TEST_io_aie_reg(device::id_type, std::shared_ptr<device>&, arg_type&);
void TEST_dpm_noop_no_qos(device::id_type, std::shared_ptr<device>&, arg_type&);
void TEST_dpm_power_modes(device::id_type, std::shared_ptr<device>&, arg_type&);
void TEST_dpm_refcount_scaling(device::id_type, std::shared_ptr<device>&, arg_type&);
void TEST_certlog_attach_detach(device::id_type, std::shared_ptr<device>&, arg_type&);
void TEST_certlog_multi_uc(device::id_type, std::shared_ptr<device>&, arg_type&);
void TEST_certlog_num_ucs_overflow(device::id_type, std::shared_ptr<device>&, arg_type&);
void TEST_certlog_invalid_uc_index(device::id_type, std::shared_ptr<device>&, arg_type&);
void TEST_certlog_payload_overflow(device::id_type, std::shared_ptr<device>&, arg_type&);
void TEST_df_bw(device::id_type, std::shared_ptr<device>&, arg_type&);
void TEST_aie4_flr(device::id_type, std::shared_ptr<device>&, arg_type&);
void TEST_aie4_pf_flr(device::id_type, std::shared_ptr<device>&,
                      std::shared_ptr<device>&);

inline void
set_xrt_path()
{
  setenv("XILINX_XRT", (cur_path + "/../").c_str(), true);
}

#define NUM_STRESS_IO 32000
#define TEST_POSITIVE false
#define TEST_NEGATIVE true

void
usage(const std::string& prog)
{
  std::cout << "\nUsage: " << prog << " [options] [test case ID/name separated by spaces]\n";
  std::cout << "Options:\n";
  std::cout << "\t" << "-h" << ": print this help message and available test cases\n";
  std::cout << "\t" << "-k" << ": evaluate test result based on driver version\n";
  std::cout << "\t" << "-x <xclbin_path>" << ": run test cases with specified xclbin file\n";
  std::cout << "Device node: <bus>/devices/<dev>/accel; PCI also drm/renderD* (virtio guest)\n";
  std::cout << std::endl;
}

// Hardware platform and driver type enums for test case filtering.
// Any device can belong to only 1 hw_type, no overlap.
enum hw_type {
  non_npu,  // non-xdna device
  npu1,     // AIE2, device_id 0x1502
  npu4,     // AIE2, device_id 0x17f0
  npu3,     // AIE4 classic, device_id 0x17f1 / 0x1b0a (classic only)
  npu3vf,   // AIE4 VF, device_id 0x17f3 / 0x1b0c (SRIOV VF only)
  ve2,      // VE2 edge, device_id 0xb052
};

enum drv_type {
  amdxdna,  // native amdxdna kernel driver
};

// Definition of one test case
struct test_case {
  const std::string name;
  /*
   * drv_ver = { 0, 0 }: test should behave as expected
   * drv_ver = { m, n }: test does not behave as expected until m.n driver
   */
  const driver_version drv_ver;
  bool is_negative;
  std::vector<hw_type> hw_list;    // empty = system test (no device loop)
  std::vector<drv_type> drv_list;  // empty = any driver
  void (*func)(device::id_type id, std::shared_ptr<device>& dev, arg_type& arg);
  arg_type arg;
};

// For overall test result evaluation
std::vector<int> test_passed;
std::vector<int> test_skipped;
std::vector<int> test_failed;

// Per-enum hw filter entry: nullptr check for non_npu (special case)
struct hw_filter_entry {
  hw_type hw;
  bool (*check)(device::id_type, device*);
};

struct drv_filter_entry {
  drv_type drv;
  bool (*check)(device::id_type, device*);
};

// Per-enum hw check functions — implement device ID logic directly
bool
dev_filter_is_npu1(device::id_type id, device* dev)
{
  return device_query<query::pcie_device>(dev) == npu1_device_id;
}

bool
dev_filter_is_npu4(device::id_type id, device* dev)
{
  return device_query<query::pcie_device>(dev) == npu4_device_id;
}

bool
dev_filter_is_npu3(device::id_type id, device* dev)
{
  auto device_id = device_query<query::pcie_device>(dev);
  return device_id == npu3_device_id || device_id == npu3a_device_id;
}

bool
dev_filter_is_npu3vf(device::id_type id, device* dev)
{
  auto device_id = device_query<query::pcie_device>(dev);
  return device_id == npu3_device_id1 || device_id == npu3a_device_id1;
}

bool
dev_filter_is_ve2(device::id_type id, device* dev)
{
  return device_query<query::pcie_device>(dev) == npu_ve2_device_id;
}

// hw_filter_table: non_npu is entry 0 with nullptr check (special case handled by
// dev_filter_is_non_npu). All other entries have a dedicated check function.
// When adding a new hw_type, add it here and dev_filter_is_non_npu auto-updates.
static const hw_filter_entry hw_filter_table[] = {
  { non_npu, nullptr              },
  { npu1,    dev_filter_is_npu1   },
  { npu4,    dev_filter_is_npu4   },
  { npu3,    dev_filter_is_npu3   },
  { npu3vf,  dev_filter_is_npu3vf},
  { ve2,     dev_filter_is_ve2    },
};

// driver checker
bool
drv_filter_is_amdxdna(device::id_type id, device* dev)
{
  query::sub_device_path::args query_arg = {std::string(""), 0};
  auto sysfs = device_query<query::sub_device_path>(dev, query_arg);
  auto drv_path = std::filesystem::read_symlink(sysfs + "/driver");
  return drv_path.filename() == "amdxdna";
}

static const drv_filter_entry drv_filter_table[] = {
  { amdxdna, drv_filter_is_amdxdna },
};

// dev_filter_is_non_npu: iterates hw_filter_table from entry 1 onward,
// returns true if none of the known NPU checkers match.
bool
dev_filter_is_non_npu(device::id_type id, device* dev)
{
  for (size_t i = 1; i < std::size(hw_filter_table); i++) {
    if (hw_filter_table[i].check(id, dev))
      return false;
  }
  return true;
}

// Overall evaluation functions
bool
match_hw(const std::vector<hw_type>& hw_list, device::id_type id, device* dev)
{
  if (hw_list.empty())
    throw std::runtime_error("match_hw: hw_list must not be empty");
  for (auto hw : hw_list) {
    if (hw == non_npu) {
      if (dev_filter_is_non_npu(id, dev))
        return true;
      continue;
    }
    for (const auto& entry : hw_filter_table) {
      if (entry.hw == hw && entry.check(id, dev))
        return true;
    }
  }
  return false;
}

bool
match_drv(const std::vector<drv_type>& drv_list, device::id_type id, device* dev)
{
  if (drv_list.empty())
    return true;
  for (auto drv : drv_list) {
    for (const auto& entry : drv_filter_table) {
      if (entry.drv == drv && entry.check(id, dev))
        return true;
    }
  }
  return false;
}

static void TEST_async_error_io_any(device::id_type id, std::shared_ptr<device>& sdev, arg_type& arg)
{
  if (dev_filter_is_npu4(id, sdev.get()))
    TEST_async_error_io(id, sdev, arg);
  else if (dev_filter_is_npu3(id, sdev.get()) || dev_filter_is_npu3vf(id, sdev.get()))
    TEST_async_error_aie4_io(id, sdev, arg);
  else
    throw std::runtime_error("async error io test: device is neither NPU4 nor NPU3");
}

std::string
get_device_sysfs(device* dev)
{
  query::sub_device_path::args query_arg = {std::string(""), 0};
  return device_query<query::sub_device_path>(dev, query_arg);
}

std::string
get_sysfs_path(device* dev)
{
  return get_device_sysfs(dev) + "/accel";
}

namespace {

namespace fs = std::filesystem;

static std::string
sysfs_device_basename(const std::string& device_sysfs)
{
  const auto pos = device_sysfs.find_last_of('/');
  return (pos == std::string::npos) ? device_sysfs : device_sysfs.substr(pos + 1);
}

static bool
sysfs_dir_exists(const std::string& path)
{
  std::error_code ec;
  return fs::is_directory(fs::path(path), ec);
}

/*
 * Resolve .../sys/bus/<bus>/devices/<name> for the NPU device.
 * Prefer the path from sub_device_path when it exists; otherwise probe pci,
 * platform, and rpmsg buses using the same device name.
 * Mgmt PF devices have no user handle, so sub_device_path throws; fall back
 * to pcie_bdf (function0 query) to build the PCI sysfs path.
 */
static std::optional<std::string>
resolve_device_sysfs(device* dev)
{
  static const char* const bus_roots[] = {
    "/sys/bus/pci/devices/",
    "/sys/bus/platform/devices/",
    "/sys/bus/rpmsg/devices/",
  };

  try {
    const std::string from_query = get_device_sysfs(dev);
    if (sysfs_dir_exists(from_query))
      return from_query;

    const std::string name = sysfs_device_basename(from_query);
    if (!name.empty()) {
      for (const char* root : bus_roots) {
        const std::string candidate = std::string(root) + name;
        if (sysfs_dir_exists(candidate))
          return candidate;
      }
    }
  } catch (const std::exception&) {
    // e.g. mgmt PF: "No device handle"
  }

  try {
    auto bdf = device_query<query::pcie_bdf>(dev);
    char buf[32];
    snprintf(buf, sizeof(buf), "%04x:%02x:%02x.%x",
      std::get<0>(bdf), std::get<1>(bdf), std::get<2>(bdf), std::get<3>(bdf));
    const std::string candidate = std::string("/sys/bus/pci/devices/") + buf;
    if (sysfs_dir_exists(candidate))
      return candidate;
  } catch (const std::exception&) {
  }
  return std::nullopt;
}

/*
 * First sysfs child under <device_sysfs>/<subsys> whose name starts with @prefix.
 * @dev_root is prepended to that name (/dev/accel/ or /dev/dri/).
 * When @numeric_suffix is true, the part after @prefix must be digits (renderD128).
 */
static std::optional<std::string>
bus_subsys_devnode(const std::string& device_sysfs, const char* subsys,
                   const char* prefix, const char* dev_root,
                   bool numeric_suffix)
{
  const std::string dir = device_sysfs + "/" + subsys;
  DIR* raw = opendir(dir.c_str());
  if (!raw)
    return std::nullopt;
  struct dir_guard {
    DIR* d;
    explicit dir_guard(DIR* p) : d(p) {}
    ~dir_guard() { if (d) closedir(d); }
  } guard(raw);
  const size_t psz = strlen(prefix);

  while (auto entry = readdir(guard.d)) {
    const std::string name{entry->d_name};
    if (name == "." || name == "..")
      continue;
    if (name.size() <= psz || name.compare(0, psz, prefix) != 0)
      continue;
    if (numeric_suffix) {
      const std::string suffix = name.substr(psz);
      if (suffix.empty() ||
          !std::all_of(suffix.begin(), suffix.end(),
                       [](unsigned char c) { return std::isdigit(c); }))
        continue;
    }
    return std::string(dev_root) + name;
  }
  return std::nullopt;
}

static bool
is_pci_sysfs_device(const std::string& device_sysfs)
{
  static constexpr char k_pci_prefix[] = "/sys/bus/pci/devices/";
  return device_sysfs.compare(0, sizeof(k_pci_prefix) - 1, k_pci_prefix) == 0;
}

} // namespace

// Resolves the device-node path (e.g. /dev/accel/accel0) for dev.
// Throws std::runtime_error on failure (missing sysfs or accel entry).
std::string
resolve_accel_node_path(device* dev)
{
  const auto device_sysfs = resolve_device_sysfs(dev);
  if (!device_sysfs) {
    throw std::runtime_error(
      "Failed to resolve device sysfs (tried sub_device_path and "
      "/sys/bus/pci|platform|rpmsg/devices/<name>)");
  }

  const std::string& sysfs = *device_sysfs;
  const bool pci = is_pci_sysfs_device(sysfs);

  /* platform/rpmsg and bare-metal PCI amdxdna: .../accel/accel* -> /dev/accel/accel* */
  std::optional<std::string> node =
    bus_subsys_devnode(sysfs, "accel", "accel", "/dev/accel/", false);
  /* PCI only: KVM virtio-gpu NPU exposes .../drm/renderD* -> /dev/dri/renderD* */
  if (!node && pci)
    node = bus_subsys_devnode(sysfs, "drm", "renderD", "/dev/dri/", true);

  if (!node) {
    std::string tried = sysfs + "/accel";
    if (pci)
      tried += ", " + sysfs + "/drm/renderD*";
    throw std::runtime_error("Failed to resolve device node for " + sysfs + " (tried " + tried + ")");
  }
  return *node;
}

// open() flags for an accel/render node path.
int
accel_node_open_flags(const std::string& accel_node)
{
  return (accel_node.rfind("/dev/dri/", 0) == 0) ? O_RDWR : O_RDONLY;
}

// Returns an open fd for the accel device node corresponding to dev. Caller must close(fd).
// Throws std::runtime_error on failure (opendir, missing accel entry, or open).
//
// NOTE: single-open-per-process means this MUST NOT be called from a process
// that already holds the device open via the shim - the driver rejects the
// second open with EBUSY. The bo_usage / driver_version helpers below call it
// only from a short-lived forked child (distinct pid), so the open succeeds.
int
open_accel_fd(device* dev)
{
  const std::string accel_node = resolve_accel_node_path(dev);
  int fd = open(accel_node.c_str(), accel_node_open_flags(accel_node));
  if (fd < 0) {
    throw std::runtime_error("open failed: " + accel_node + ": " + std::string(std::strerror(errno)));
  }
  return fd;
}

void
trigger_pci_flr(device* dev)
{
  const auto device_sysfs = resolve_device_sysfs(dev);
  if (!device_sysfs) {
    throw std::runtime_error(
      "Failed to resolve device sysfs for PCI FLR (tried sub_device_path and "
      "/sys/bus/pci/devices/<name>)");
  }
  if (!is_pci_sysfs_device(*device_sysfs)) {
    throw std::runtime_error("PCI FLR requires a PCI device, got " + *device_sysfs);
  }

  const std::string reset_path = *device_sysfs + "/reset";
  std::ofstream ofs(reset_path);
  if (!ofs) {
    throw std::runtime_error(
      "Cannot open " + reset_path + " for write (needs root?)");
  }
  ofs << "1";
  ofs.flush();
  if (!ofs)
    throw std::runtime_error("Failed to write PCI FLR to " + reset_path);
}

unsigned int
get_sriov_numvfs(device* dev)
{
  const auto device_sysfs = resolve_device_sysfs(dev);
  if (!device_sysfs)
    throw std::runtime_error("Failed to resolve device sysfs for sriov_numvfs");

  const std::string path = *device_sysfs + "/sriov_numvfs";
  std::ifstream ifs(path);
  if (!ifs)
    throw std::runtime_error("Cannot read " + path);
  unsigned int n = 0;
  ifs >> n;
  if (!ifs)
    throw std::runtime_error("Failed to parse " + path);
  return n;
}

// Run op(fd) in a short-lived forked child and return its POD result.
//
// Some helpers need a raw ioctl, but the shim already holds the device open and
// the driver allows only one open per process, so a second open() from this
// process is rejected with EBUSY. The child has a distinct pid, so its open()
// of the node is allowed. The child opens a fresh fd via open_accel_fd(),
// touches nothing else of the inherited shim state, computes the result, and
// pipes it back to the parent as raw bytes (hence the trivially-copyable
// requirement). Per-pid/per-fd ioctls (BO_USAGE filters by the pid argument,
// drm_version is generic) return the same data from the child as the parent.
template <typename T>
T
fork_query(device* dev, const std::function<T(int fd)>& op)
{
  static_assert(std::is_trivially_copyable<T>::value,
    "fork_query<T>: T crosses a pipe as raw bytes and must be trivially copyable");

  int pipefd[2];
  if (pipe(pipefd) == -1)
    throw std::runtime_error(std::string("pipe() failed: ") + std::strerror(errno));

  pid_t child = fork();
  if (child == -1) {
    close(pipefd[0]);
    close(pipefd[1]);
    throw std::runtime_error(std::string("fork() failed: ") + std::strerror(errno));
  }

  if (child == 0) {
    // Child: do not touch any inherited shim state beyond a fresh fd.
    close(pipefd[0]);
    int rc = 1;
    try {
      int fd = open_accel_fd(dev);
      T result = op(fd);
      close(fd);
      if (write(pipefd[1], &result, sizeof(result)) == static_cast<ssize_t>(sizeof(result)))
        rc = 0;
    } catch (...) {
      rc = 1;
    }
    close(pipefd[1]);
    _exit(rc);
  }

  // Parent: read the full result (EINTR/short-read safe), then reap the child
  // on every path so there is no fd leak or unreaped child even on error.
  close(pipefd[1]);
  T result{};
  auto buf = reinterpret_cast<char*>(&result);
  size_t got = 0;
  while (got < sizeof(result)) {
    ssize_t n = read(pipefd[0], buf + got, sizeof(result) - got);
    if (n < 0) {
      if (errno == EINTR)
        continue;
      break;            // real read error
    }
    if (n == 0)
      break;            // premature EOF: child exited before writing all
    got += static_cast<size_t>(n);
  }
  close(pipefd[0]);

  int status = 0;
  while (waitpid(child, &status, 0) == -1 && errno == EINTR)
    ;

  if (got != sizeof(result) || !WIFEXITED(status) || WEXITSTATUS(status) != 0)
    throw std::runtime_error("forked query child failed");

  return result;
}

// Query BO usage for the given pid via a forked child (see fork_query).
std::tuple<uint64_t, uint64_t, uint64_t>
get_bo_usage(device* dev, int pid)
{
  auto usage = fork_query<amdxdna_drm_bo_usage>(dev, [pid](int fd) {
    amdxdna_drm_bo_usage u = { .pid = pid };
    amdxdna_drm_get_array arg = {
      .param = DRM_AMDXDNA_BO_USAGE,
      .element_size = sizeof(u),
      .num_element = 1,
      .buffer = reinterpret_cast<uintptr_t>(&u)
    };
    if (::ioctl(fd, DRM_IOCTL_AMDXDNA_GET_ARRAY, &arg) == -1)
      throw std::runtime_error("ioctl(DRM_IOCTL_AMDXDNA_GET_ARRAY) failed");
    return u;
  });

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
    auto info = get_bdf_info(i, is_user);
    auto bdf = bdf_info2str(info);
    std::cout << "device[" << i << "]: " << bdf << std::endl;
    auto dev = is_user ? get_userpf_device(i) : get_mgmtpf_device(i);
    try {
      auto devid = device_query<query::pcie_device>(dev);
      std::cout << "device[" << bdf << "]: 0x" << std::hex << devid << std::dec << std::endl;
    }
    catch (const query::no_such_key&) {
      // VE2 zocl edge device — not a shim_test xdna target.
      continue;
    }
  }
}

void
TEST_get_mgmtpf_device(device::id_type id, std::shared_ptr<device>& sdev, arg_type& arg)
{
  auto devinfo = get_total_devices(false);
  for (device::id_type i = 0; i < devinfo.first; i++)
    auto dev = get_mgmtpf_device(i);
}

// PFs are mgmt devices (is_user=false), so run_test() never passes them in.
// Walk get_mgmtpf_device() and return the first AIE4 PF (0x17f2 / 0x1b0b).
// Match on pcie_device only: is_xdna_dev/is_amdxdna_drv are userpf-oriented and
// can throw or fail on mgmt devices even when the PF is present.
std::shared_ptr<device>
find_aie4_pf()
{
  auto n = get_total_devices(false).first;
  for (device::id_type i = 0; i < n; i++) {
    auto pf = get_mgmtpf_device(i);
    uint16_t devid = 0;
    try {
      devid = device_query<query::pcie_device>(pf.get());
    } catch (const std::exception&) {
      continue;
    }
    if (devid != npu3_pf_device_id && devid != npu3a_pf_device_id)
      continue;
    auto bdf = get_bdf_info(i, false);
    std::cout << "found AIE4 PF[" << i << "]: " << bdf_info2str(bdf)
              << " (0x" << std::hex << devid << std::dec << ")" << std::endl;
    return pf;
  }
  throw std::runtime_error("No AIE4 PF device found (0x17f2/0x1b0b)");
}

// Resolve the AIE4 PF and check sriov_numvfs around FLR. Workload + timing live
// in TEST_aie4_pf_flr (io_test.cpp); PF discovery helpers stay here.
// run_test() invokes this once per matching AIE4 VF; skip after the first so we
// only issue one PF FLR per test case.
void
TEST_aie4_pf_flr_entry(device::id_type id, std::shared_ptr<device>& sdev, arg_type& arg)
{
  for (device::id_type i = 0; i < id; i++) {
    try {
      auto earlier = get_userpf_device(i);
      if (dev_filter_is_npu3vf(i, earlier.get()))
        return;
    } catch (const std::exception&) {
      continue;
    }
  }

  auto pf = find_aie4_pf();
  auto numvfs_before = get_sriov_numvfs(pf.get());
  std::cout << "sriov_numvfs before PF FLR: " << numvfs_before << std::endl;
  if (!numvfs_before)
    throw std::runtime_error("PF FLR: expected at least one VF before reset");

  TEST_aie4_pf_flr(id, sdev, pf);

  auto numvfs_after = get_sriov_numvfs(pf.get());
  std::cout << "sriov_numvfs after PF FLR: " << numvfs_after << std::endl;
  if (numvfs_after != numvfs_before) {
    throw std::runtime_error("PF FLR: sriov_numvfs changed from " +
      std::to_string(numvfs_before) + " to " + std::to_string(numvfs_after));
  }
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
TEST_create_destroy_max_context(device::id_type id, std::shared_ptr<device>& sdev, arg_type& arg)
{
  auto dev = sdev.get();
  int is_negative = static_cast<unsigned int>(arg[0]);
  int num_ctx;

  // XDNA driver by default supports maximum 6 contexts on npu1, 128 on npu3, and 16 on npu4
  if (dev_filter_is_npu1(id, dev))
    num_ctx = 6;
  else if (dev_filter_is_npu3(id, dev) || dev_filter_is_npu3vf(id, dev))
    num_ctx = 128;
  else
    num_ctx = 16;

  if (is_negative)
    num_ctx = 10000;

  std::cout << "Creating " << num_ctx << " contexts" << std::endl;
  {
    std::vector<std::unique_ptr<hw_ctx>> ctxs;
    for (int i = 0; i < num_ctx; i++)
      ctxs.push_back(std::make_unique<hw_ctx>(dev));
  }
}

void
TEST_multi_context_io_test(device::id_type id, std::shared_ptr<device>& sdev, arg_type& arg)
{
  auto dev = sdev.get();
  int num_ctx;

  const std::array<int, 3> ctx = [&]() {
    if (dev_filter_is_npu1(id, dev))
      return std::array<int, 3>{2, 4, 6};
    if (dev_filter_is_npu3(id, dev) || dev_filter_is_npu3vf(id, dev))
      return std::array<int, 3>{4, 8, 32};
    return std::array<int, 3>{4, 8, 16};
  }();

  num_ctx = ctx[arg[0]];

  multi_thread threads(num_ctx, TEST_io_latency);
  threads.run_test(id, sdev, {IO_TEST_NORMAL_RUN, IO_TEST_IOCTL_WAIT, 3000});
}

void
TEST_create_free_debug_bo(device::id_type id, std::shared_ptr<device>& sdev, arg_type& arg)
{
  auto dev = sdev.get();
  auto boflags = XRT_BO_FLAGS_CACHEABLE;
  auto ext_boflags = (dev_filter_is_npu3(id, dev) || dev_filter_is_npu3vf(id, dev)) ?
    (XRT_BO_USE_UC_DEBUG << 4) : (XRT_BO_USE_DEBUG << 4);
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
TEST_create_free_uc_log_bo(device::id_type id, std::shared_ptr<device>& sdev, arg_type& arg)
{
  auto dev = sdev.get();
  auto boflags = XRT_BO_FLAGS_CARVEOUT;
  auto ext_boflags = XRT_BO_USE_LOG << 4;
  auto size = static_cast<size_t>(arg[0]);

  hw_ctx hwctx{dev};
  auto bo = hwctx.get()->alloc_bo(size, get_bo_flags(boflags, ext_boflags));

  auto buf = static_cast<uint8_t *>(bo->map(buffer_handle::map_type::write));
  std::memset(buf, 0, size);
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
  auto dev_boflags = XCL_BO_FLAGS_CACHEABLE;
  size_t size = 0x4000;
  auto ext_bo = std::make_unique<bo>(dev, size * 5, boflags, 0);
  auto int_bo = std::make_unique<bo>(dev, size * 3, boflags, ext_boflags);
  auto dev_bo = std::make_unique<bo>(dev, size, dev_boflags, 0);
  auto [total, internal, heap] = get_bo_usage(dev, getpid());

  uint64_t expected_total, expected_internal, expected_heap;

  if (dev_filter_is_npu1(id, dev) || dev_filter_is_npu4(id, dev)) {
    expected_total = int_bo->size() + ext_bo->size();
    expected_internal = int_bo->size();
    // Add default heap size and don't count dev bo
    expected_total += 64 * 1024 * 1024;
    expected_internal += 64 * 1024 * 1024;
    // Dev bo goes to heap usage
    expected_heap = size;
  } else {
    expected_total = int_bo->size() + ext_bo->size() + dev_bo->size();
    expected_internal = int_bo->size() + dev_bo->size();
    // No heap at all
    expected_heap = 0;
  }
  if (total != expected_total || internal != expected_internal || heap != expected_heap) {
    std::cout << "expected total: " << expected_total << ", real: " << total << "\n"
              << "expected internal: " << expected_internal << ", real: " << internal << "\n"
              << "expected heap: " << expected_heap << ", real: " << heap << "\n"
              << std::endl;
    throw std::runtime_error("BO usage mis-match");
  }
}

// Dev heap chunk granularity (see get_heap_num_pages()/heap_page_size in the
// shim). A dev BO larger than one chunk necessarily spans multiple heap chunks.
// npu4 additionally caps the total heap at dev_heap_max_size, so a BO larger
// than that can never be allocated there; aie4 has no such cap, and npu1 has a
// single fixed chunk so no cross-chunk BO can be allocated at all.
constexpr size_t dev_heap_chunk_size = 64ul * 1024 * 1024;
constexpr size_t dev_heap_max_size = 512ul * 1024 * 1024;

// Fill the whole dev BO with an index-derived pattern, round-trip it through
// sync (which drives the kernel's per-chunk pin/vmap walk), then verify every
// qword. Any error in the cross-chunk contiguous mapping shows up as a
// mismatch or SIGBUS.
static void
dev_bo_fill_and_verify(bo& b, size_t size)
{
  auto p = reinterpret_cast<volatile uint64_t *>(b.map());
  size_t n = size / sizeof(uint64_t);
  const uint64_t seed = 0x5a5a5a5a5a5a5a5aull;

  for (size_t i = 0; i < n; i++)
    p[i] = i ^ seed;
  b.get()->sync(buffer_handle::direction::host2device, size, 0);
  b.get()->sync(buffer_handle::direction::device2host, size, 0);
  for (size_t i = 0; i < n; i++) {
    if (p[i] != (i ^ seed))
      throw std::runtime_error("dev BO content mismatch at qword " + std::to_string(i));
  }
}

// Cheaper verification for the stress loop: only touch the qwords straddling
// every chunk boundary (last qword of a chunk and first qword of the next)
// plus the last qword of the BO. This is where a broken cross-chunk mapping
// would surface without paying to write the whole BO on every iteration.
static void
dev_bo_verify_boundaries(bo& b, size_t size)
{
  auto base = reinterpret_cast<volatile uint8_t *>(b.map());
  std::vector<size_t> offs;

  for (size_t o = dev_heap_chunk_size; o < size; o += dev_heap_chunk_size) {
    offs.push_back(o - sizeof(uint64_t));
    offs.push_back(o);
  }
  offs.push_back(size - sizeof(uint64_t));

  for (auto o : offs)
    *reinterpret_cast<volatile uint64_t *>(base + o) = o ^ 0xdeadbeefull;
  b.get()->sync(buffer_handle::direction::host2device, size, 0);
  b.get()->sync(buffer_handle::direction::device2host, size, 0);
  for (auto o : offs) {
    auto v = *reinterpret_cast<volatile uint64_t *>(base + o);
    if (v != (o ^ 0xdeadbeefull))
      throw std::runtime_error("dev BO boundary mismatch at offset " + std::to_string(o));
  }
}

// npu1 (birman) has a single fixed dev heap chunk and cannot back a dev BO
// that spans more than one chunk. It has no cross-chunk dev heap support.
static bool
dev_heap_supports_cross_chunk(device::id_type id, device* dev)
{
  return !dev_filter_is_npu1(id, dev);
}

// On platforms without cross-chunk support (npu1), allocating a cross-chunk
// dev BO must fail. Treat that failure as the expected, passing outcome and
// flag an unexpected success. Only the allocation is attempted here -- the
// BO's contents are never touched, so there is no SIGBUS risk on a partially
// backed heap.
static void
dev_bo_expect_cross_chunk_rejected(device* dev, size_t size)
{
  try {
    bo dev_bo{dev, size, XCL_BO_FLAGS_CACHEABLE, 0};
  } catch (const std::exception& ex) {
    std::cout << "cross-chunk dev BO rejected as expected: " << ex.what() << std::endl;
    return;
  }
  throw std::runtime_error("cross-chunk dev BO unexpectedly allocated");
}

// Allocate a single dev BO larger than one heap chunk so it spans multiple
// chunks, then verify its contents end to end. arg[0] is the BO size; use
// size > dev_heap_chunk_size (e.g. 128MB to cross two chunks, 512MB to span the
// whole npu4 heap, >512MB to exceed the npu4 cap on aie4). On npu1 the same
// allocation is expected to be rejected.
void
TEST_dev_bo_cross_heap(device::id_type id, std::shared_ptr<device>& sdev, arg_type& arg)
{
  auto dev = sdev.get();
  auto size = static_cast<size_t>(arg[0]);

  if (size <= dev_heap_chunk_size)
    throw std::runtime_error("cross-heap dev BO size must exceed one chunk");

  if (!dev_heap_supports_cross_chunk(id, dev)) {
    dev_bo_expect_cross_chunk_rejected(dev, size);
    return;
  }

  bo dev_bo{dev, size, XCL_BO_FLAGS_CACHEABLE, 0};

  // dev_mem_base is chunk aligned, so the number of chunk boundaries the BO's
  // device address range crosses is a direct division. A size larger than one
  // chunk guarantees at least one crossing.
  auto start = dev_bo.paddr();
  auto crossed = (start + size - 1) / dev_heap_chunk_size - start / dev_heap_chunk_size;
  std::cout << "dev BO size 0x" << std::hex << size << " at 0x" << start << std::dec
            << " spans " << (crossed + 1) << " heap chunks" << std::endl;
  if (crossed < 1)
    throw std::runtime_error("dev BO did not cross a heap chunk boundary");

  dev_bo_fill_and_verify(dev_bo, size);
}

// Negative test (npu4): a dev BO larger than npu4's max heap size can never be
// backed and must fail to allocate. arg[0] is the (too large) size.
void
TEST_dev_bo_over_max(device::id_type id, std::shared_ptr<device>& sdev, arg_type& arg)
{
  auto dev = sdev.get();
  auto size = static_cast<size_t>(arg[0]);

  bo dev_bo{dev, size, XCL_BO_FLAGS_CACHEABLE, 0};
}

// Stress: repeatedly allocate and free cross-heap dev BOs, verifying the
// chunk boundaries each time. Exercises heap expansion, drm_mm reuse after
// free, and the kernel's find-heap-chunk walk under churn. arg[0] is the BO
// size, arg[1] the iteration count.
void
TEST_dev_bo_cross_heap_stress(device::id_type id, std::shared_ptr<device>& sdev, arg_type& arg)
{
  auto dev = sdev.get();
  auto size = static_cast<size_t>(arg[0]);
  auto iters = static_cast<size_t>(arg[1]);

  if (size <= dev_heap_chunk_size)
    throw std::runtime_error("cross-heap dev BO size must exceed one chunk");

  if (!dev_heap_supports_cross_chunk(id, dev)) {
    dev_bo_expect_cross_chunk_rejected(dev, size);
    return;
  }

  for (size_t i = 0; i < iters; i++) {
    bo dev_bo{dev, size, XCL_BO_FLAGS_CACHEABLE, 0};
    dev_bo_verify_boundaries(dev_bo, size);
  }

  // Also hold several cross-heap dev BOs live at once, then verify each, to
  // exercise multiple large BOs coexisting in the expanded heap.
  size_t live = dev_heap_max_size / size;
  if (live > 1) {
    std::vector<std::unique_ptr<bo>> bos;
    for (size_t i = 0; i < live; i++)
      bos.push_back(std::make_unique<bo>(dev, size, XCL_BO_FLAGS_CACHEABLE, 0));
    for (auto& b : bos)
      dev_bo_verify_boundaries(*b, size);
  }
}

void
TEST_create_free_mmaped_uptr_bo(device::id_type id, std::shared_ptr<device>& sdev, arg_type& arg)
{
  size_t size = 1ul * 1024 * 1024 * 1024;

  // Expect to pass
  try {
    mmapped_file f(size, true);
    auto buf = std::make_unique<bo>(sdev.get(), f.get(), size, XCL_BO_FLAGS_HOST_ONLY, 0);
  } catch (const std::system_error& e) {
    std::cout << e.what() << std::endl;
    throw std::runtime_error("mmaped user ptr BO test has failed");
  }
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

constexpr uint32_t HWCTX_QUERY_CAPACITY = 64;

struct hwctx_info_probe {
  int ret;
  int err;
  uint32_t bytes_written;
  bool found_self;
};

struct hwctx_array_probe {
  int ret;
  int err;
  uint32_t num_element;
  uint32_t element_size;
  bool found_self;
};

void
TEST_query_hw_contexts(device::id_type id, std::shared_ptr<device>& sdev, arg_type& arg)
{
  // Create a context so the query returns an entry to validate.
  hw_ctx hwctx{sdev.get()};

  auto probe = fork_query<hwctx_info_probe>(sdev.get(), [](int fd) {
    std::array<amdxdna_drm_query_hwctx, HWCTX_QUERY_CAPACITY> entries{};
    const uint32_t in_size = entries.size() * sizeof(entries[0]);
    amdxdna_drm_get_info info = {
      .param = DRM_AMDXDNA_QUERY_HW_CONTEXTS,
      .buffer_size = in_size,
      .buffer = reinterpret_cast<uintptr_t>(entries.data()),
    };

    hwctx_info_probe r{};
    r.ret = ::ioctl(fd, DRM_IOCTL_AMDXDNA_GET_INFO, &info);
    r.err = errno;
    if (r.ret == 0) {
      // QUERY_HW_CONTEXTS reports the leftover capacity in buffer_size.
      r.bytes_written = in_size - info.buffer_size;
      const uint32_t n = r.bytes_written / sizeof(entries[0]);
      const __s64 self_pid = getppid();
      for (uint32_t i = 0; i < n && i < entries.size(); i++) {
        if (entries[i].pid == self_pid) {
          r.found_self = true;
          break;
        }
      }
    }
    return r;
  });

  if (probe.ret == -1)
    throw std::runtime_error(
      "ioctl(QUERY_HW_CONTEXTS) failed: " + std::string(std::strerror(probe.err)));
  if (probe.bytes_written > HWCTX_QUERY_CAPACITY * sizeof(amdxdna_drm_query_hwctx))
    throw std::runtime_error("QUERY_HW_CONTEXTS wrote more than the input buffer");
  if (probe.bytes_written % sizeof(amdxdna_drm_query_hwctx))
    throw std::runtime_error("QUERY_HW_CONTEXTS byte count not element-aligned");
  if (!probe.found_self)
    throw std::runtime_error("QUERY_HW_CONTEXTS did not report the created context");
}

void
TEST_hw_context_all(device::id_type id, std::shared_ptr<device>& sdev, arg_type& arg)
{
  // Create a context so the query returns an entry to validate.
  hw_ctx hwctx{sdev.get()};

  auto probe = fork_query<hwctx_array_probe>(sdev.get(), [](int fd) {
    std::array<amdxdna_drm_hwctx_entry, HWCTX_QUERY_CAPACITY> entries{};
    amdxdna_drm_get_array array = {
      .param = DRM_AMDXDNA_HW_CONTEXT_ALL,
      .element_size = sizeof(entries[0]),
      .num_element = static_cast<uint32_t>(entries.size()),
      .buffer = reinterpret_cast<uintptr_t>(entries.data()),
    };

    hwctx_array_probe r{};
    r.ret = ::ioctl(fd, DRM_IOCTL_AMDXDNA_GET_ARRAY, &array);
    r.err = errno;
    if (r.ret == 0) {
      r.num_element = array.num_element;
      r.element_size = array.element_size;
      const __s64 self_pid = getppid();
      for (uint32_t i = 0; i < array.num_element && i < entries.size(); i++) {
        if (entries[i].pid == self_pid) {
          r.found_self = true;
          break;
        }
      }
    }
    return r;
  });

  if (probe.ret == -1)
    throw std::runtime_error(
      "ioctl(HW_CONTEXT_ALL) failed: " + std::string(std::strerror(probe.err)));
  if (probe.num_element > HWCTX_QUERY_CAPACITY)
    throw std::runtime_error("HW_CONTEXT_ALL num_element exceeds input");
  if (probe.element_size == 0 || probe.element_size > sizeof(amdxdna_drm_hwctx_entry))
    throw std::runtime_error("HW_CONTEXT_ALL element_size out of range");
  if (!probe.found_self)
    throw std::runtime_error("HW_CONTEXT_ALL did not report the created context");
}

// Fetch per-context and total memory usage through the query keys
// (query::aie_partition_info and query::total_mem_usage) instead of issuing the
// raw DRM_AMDXDNA_BO_USAGE ioctl. These keys go through the shim's already-open
// device fd, so no forked helper is needed. A partition entry (and thus a
// non-zero memory_usage / a process_name) only exists while a hw context is
// live, so create one and allocate a known amount of BO memory to bound the
// reported usage from below. Exact total/internal/heap accounting is covered
// separately by TEST_create_free_internal_bo.
void
TEST_query_memory_usage(device::id_type id, std::shared_ptr<device>& sdev, arg_type& arg)
{
  auto dev = sdev.get();

  // A live context is required for this process to appear in aie_partition_info.
  hw_ctx hwctx{dev};

  // Allocate application (SHARE) and internal (CMD) BOs so this process has a
  // known, non-zero BO footprint counted in total_usage.
  auto boflags = XRT_BO_FLAGS_HOST_ONLY;
  auto ext_boflags = XRT_BO_USE_CTRLPKT << 4;
  size_t size = 0x4000;
  auto ext_bo = std::make_unique<bo>(dev, size * 5, boflags, 0);
  auto int_bo = std::make_unique<bo>(dev, size * 3, boflags, ext_boflags);
  const uint64_t bo_bytes = ext_bo->size() + int_bo->size();

  const int self_pid = static_cast<int>(getpid());

  // Per-context memory_usage and process_name via aie_partition_info.
  const auto partitions = device_query<query::aie_partition_info>(dev);
  uint64_t self_mem = 0;
  bool found_self = false;
  for (const auto& p : partitions) {
    if (p.pid != self_pid)
      continue;
    found_self = true;
    self_mem = p.memory_usage;

    // process_name is copied from the driver-provided hwctx entry name. A new
    // shim on an older staging driver reads it back empty (-> "N/A"), so only
    // validate it when populated. current->comm is capped at 15 chars, matching
    // the value the kernel stores, so /proc/self/comm is an exact reference.
    if (!p.process_name.empty()) {
      std::string comm;
      std::ifstream comm_file("/proc/self/comm");
      if (!std::getline(comm_file, comm))
        throw std::runtime_error("failed to read /proc/self/comm to verify process_name");
      if (p.process_name != comm)
        throw std::runtime_error("process_name mismatch: got '" + p.process_name +
                                 "', expected '" + comm + "'");
    }
    break;
  }

  if (!found_self)
    throw std::runtime_error("aie_partition_info did not report this process's context");

  // memory_usage is the owning process's total BO footprint (S + C + H); it must
  // at least cover the BOs allocated above.
  if (self_mem < bo_bytes) {
    std::cout << "memory_usage " << self_mem << " < allocated BO bytes " << bo_bytes
              << std::endl;
    throw std::runtime_error("aie_partition_info memory_usage too small");
  }

  // total_mem_usage aggregates unique PIDs, so the device-wide total must be at
  // least this process's own usage.
  const uint64_t total = device_query<query::total_mem_usage>(dev);
  if (total < self_mem) {
    std::cout << "total_mem_usage " << total << " < this process memory_usage "
              << self_mem << std::endl;
    throw std::runtime_error("total_mem_usage smaller than per-process usage");
  }
}

constexpr uint32_t TELEMETRY_DATA_SIZE = 256 * 1024;
// Upper bound on the firmware-context-id to driver-context-id map the driver
// places at the head of the telemetry buffer. AIE4 sizes this map to
// MAX_NUM_HW_CTX (1024, one slot per possible firmware context id); AIE2p uses
// a smaller map. Keep this at the largest supported map so the probe buffer is
// big enough and the capacity check does not false-fail on AIE4.
constexpr uint32_t TELEMETRY_MAP_CAPACITY = 1024;
// aie4 selects a telemetry category via the type field; older NPUs require 0.
constexpr uint32_t AIE4_TELEMETRY_PERF_COUNTER = 1;

struct telemetry_probe {
  int ret;
  int err;
  uint32_t map_num_elements;
};

void
TEST_query_telemetry(device::id_type id, std::shared_ptr<device>& sdev, arg_type& arg)
{
  uint32_t type = (dev_filter_is_npu3(id, sdev.get()) || dev_filter_is_npu3vf(id, sdev.get())) ?
    AIE4_TELEMETRY_PERF_COUNTER : 0;

  auto probe = fork_query<telemetry_probe>(sdev.get(), [type](int fd) {
    const uint32_t buf_sz = sizeof(amdxdna_drm_query_telemetry_header) +
                            TELEMETRY_MAP_CAPACITY * sizeof(uint32_t) +
                            TELEMETRY_DATA_SIZE;
    // uint32_t storage guarantees alignment for the telemetry header.
    std::vector<uint32_t> buf(buf_sz / sizeof(uint32_t), 0);
    auto *hdr = reinterpret_cast<amdxdna_drm_query_telemetry_header *>(buf.data());
    hdr->type = type;

    amdxdna_drm_get_info info = {
      .param = DRM_AMDXDNA_QUERY_TELEMETRY,
      .buffer_size = buf_sz,
      .buffer = reinterpret_cast<uintptr_t>(buf.data()),
    };

    telemetry_probe r{};
    r.ret = ::ioctl(fd, DRM_IOCTL_AMDXDNA_GET_INFO, &info);
    r.err = errno;
    r.map_num_elements = hdr->map_num_elements;
    return r;
  });

  if (probe.ret == -1)
    throw std::runtime_error(
      "ioctl(QUERY_TELEMETRY) failed: " + std::string(std::strerror(probe.err)));

  if (probe.map_num_elements > TELEMETRY_MAP_CAPACITY)
    throw std::runtime_error("QUERY_TELEMETRY: map_num_elements > capacity");
}

void
TEST_query_telemetry_short_buf(device::id_type id, std::shared_ptr<device>& sdev, arg_type& arg)
{
  // Negative case: a header-only buffer must fail EINVAL.
  int err = fork_query<int>(sdev.get(), [](int fd) {
    amdxdna_drm_query_telemetry_header hdr{};
    amdxdna_drm_get_info info = {
      .param = DRM_AMDXDNA_QUERY_TELEMETRY,
      .buffer_size = sizeof(hdr),
      .buffer = reinterpret_cast<uintptr_t>(&hdr),
    };
    if (::ioctl(fd, DRM_IOCTL_AMDXDNA_GET_INFO, &info) == -1)
      return errno;
    return 0;
  });

  if (err != EINVAL)
    throw std::runtime_error(
      "QUERY_TELEMETRY with header-only buffer should fail EINVAL, got "
      + std::to_string(err));
}

struct attribute_state_probe {
  int ret;
  int err;
  uint8_t state;
};

void
TEST_query_frame_boundary_preempt(device::id_type id, std::shared_ptr<device>& sdev, arg_type& arg)
{
  auto probe = fork_query<attribute_state_probe>(sdev.get(), [](int fd) {
    amdxdna_drm_attribute_state state{};
    amdxdna_drm_get_info info = {
      .param = DRM_AMDXDNA_GET_FRAME_BOUNDARY_PREEMPT_STATE,
      .buffer_size = sizeof(state),
      .buffer = reinterpret_cast<uintptr_t>(&state),
    };

    attribute_state_probe r{};
    r.ret = ::ioctl(fd, DRM_IOCTL_AMDXDNA_GET_INFO, &info);
    r.err = errno;
    r.state = state.state;
    return r;
  });

  if (probe.ret == -1)
    throw std::runtime_error(
      "ioctl(GET_FRAME_BOUNDARY_PREEMPT_STATE) failed: " + std::string(std::strerror(probe.err)));
  if (probe.state > 1)
    throw std::runtime_error("GET_FRAME_BOUNDARY_PREEMPT_STATE returned non-boolean state");
  if ((dev_filter_is_npu3(id, sdev.get()) || dev_filter_is_npu3vf(id, sdev.get())) &&
      probe.state != 1)
    throw std::runtime_error("aie4 GET_FRAME_BOUNDARY_PREEMPT_STATE expected enabled");
}

// List of all test cases
std::vector<test_case> test_list {
  test_case{ "get_xrt_info", {},
    TEST_POSITIVE, {}, {}, TEST_get_xrt_info, {}
  },
  test_case{ "get_os_info", {},
    TEST_POSITIVE, {}, {}, TEST_get_os_info, {}
  },
  test_case{ "get_total_devices", {},
    TEST_POSITIVE, {}, {}, TEST_get_total_devices, {true}
  },
  test_case{ "get_total_devices(mgmtpf)", {},
    TEST_POSITIVE, {}, {}, TEST_get_total_devices, {false}
  },
  test_case{ "get_bdf_info_and_get_device_id", {},
    TEST_POSITIVE, {}, {}, TEST_get_bdf_info_and_get_device_id, {true}
  },
  test_case{ "get_bdf_info_and_get_device_id(mgmtpf)", {},
    TEST_POSITIVE, {}, {}, TEST_get_bdf_info_and_get_device_id, {false}
  },
  test_case{ "get_mgmtpf_device", {},
    TEST_POSITIVE, {}, {}, TEST_get_mgmtpf_device, {}
  },
  test_case{ "query(pcie_vendor)", {},
    TEST_POSITIVE, {npu1, npu4, npu3, npu3vf, ve2}, {}, TEST_query_userpf<query::pcie_vendor>, {}
  },
  //test_case{ "non_xdna_userpf: query(pcie_vendor)", {},
  //  TEST_POSITIVE, {non_npu}, {}, TEST_query_userpf<query::pcie_vendor>, {}
  //},
  test_case{ "query(rom_vbnv)", {},
    TEST_POSITIVE, {npu1, npu4, npu3, npu3vf, ve2}, {}, TEST_query_userpf<query::rom_vbnv>, {}
  },
  test_case{ "query(rom_fpga_name)", {},
    TEST_NEGATIVE, {npu1, npu4, npu3, npu3vf, ve2}, {}, TEST_query_userpf<query::rom_fpga_name>, {}
  },
  // get async error in multi thread before running any other tests
  // there may or may not be async error.
  test_case{ "get async error in multithread - INITIAL", {},
    TEST_POSITIVE, {npu1, npu4, npu3, npu3vf, ve2}, {}, TEST_async_error_multi, {false}
  },
  //test_case{ "non_xdna_userpf: query(rom_vbnv)", {},
  //  TEST_POSITIVE, {non_npu}, {}, TEST_query_userpf<query::rom_vbnv>, {}
  //},
  test_case{ "create_destroy_hw_context", {},
    TEST_POSITIVE, {npu1, npu4, npu3, npu3vf, ve2}, {}, TEST_create_destroy_hw_context, {}
  },
  test_case{ "create_invalid_bo", {},
    TEST_NEGATIVE, {npu1, npu4, npu3, npu3vf, ve2}, {}, TEST_create_free_bo, {XCL_BO_FLAGS_P2P, 0, 128}
  },
  test_case{ "create_and_free_exec_buf_bo", {},
    TEST_POSITIVE, {npu1, npu4, npu3, npu3vf, ve2}, {}, TEST_create_free_bo, {XCL_BO_FLAGS_EXECBUF, 0, 128}
  },
  test_case{ "create_and_free_dpu_sequence_bo 1 bo", {},
    TEST_POSITIVE, {npu1, npu4, npu3, npu3vf, ve2}, {}, TEST_create_free_bo, {XCL_BO_FLAGS_CACHEABLE, 0, 128}
  },
  test_case{ "create_and_free_dpu_sequence_bo multiple bos", {},
    TEST_POSITIVE, {npu1, npu4, npu3, npu3vf, ve2}, {}, TEST_create_free_bo,
    {XCL_BO_FLAGS_CACHEABLE, 0, 0x2000, 0x400, 0x3000, 0x100}
  },
  test_case{ "create_and_free_input_output_bo 1 page", {},
    TEST_POSITIVE, {npu1, npu4, npu3, npu3vf, ve2}, {}, TEST_create_free_bo, {XCL_BO_FLAGS_HOST_ONLY, 0, 128}
  },
  test_case{ "create_and_free_input_output_bo multiple pages", {},
    TEST_POSITIVE, {npu1, npu4, npu3, npu3vf, ve2}, {}, TEST_create_free_bo,
    {XCL_BO_FLAGS_HOST_ONLY, 0, 0x10000, 0x23000, 0x2000}
  },
  test_case{ "create_and_free_input_output_bo huge pages", {},
    TEST_POSITIVE, {npu1, npu4, npu3, npu3vf, ve2}, {}, TEST_create_free_bo,
    {XCL_BO_FLAGS_HOST_ONLY, 0, 0x140000000}
  },
  test_case{ "sync_bo for dpu sequence bo", {},
    TEST_POSITIVE, {npu1, npu4, npu3, npu3vf, ve2}, {}, TEST_sync_bo, {XCL_BO_FLAGS_CACHEABLE, 0, 128}
  },
  test_case{ "sync_bo for input_output", {},
    TEST_POSITIVE, {npu1, npu4, npu3, npu3vf, ve2}, {}, TEST_sync_bo, {XCL_BO_FLAGS_HOST_ONLY, 0, 128}
  },
  test_case{ "map dpu sequence bo and test perf", {},
    TEST_POSITIVE, {npu1, npu4, npu3, npu3vf, ve2}, {}, TEST_map_bo, {XCL_BO_FLAGS_CACHEABLE, 0, 361264 /*0x10000*/}
  },
  test_case{ "map input_output bo and test perf", {},
    TEST_POSITIVE, {npu1, npu4, npu3, npu3vf, ve2}, {}, TEST_map_bo, {XCL_BO_FLAGS_HOST_ONLY, 0, 361264}
  },
  test_case{ "map bo for read only", {},
    TEST_NEGATIVE, {npu1, npu4, npu3, npu3vf}, {}, TEST_map_read_bo, {0x1000}
  },
  test_case{ "map exec_buf_bo and test perf", {},
    TEST_POSITIVE, {npu1, npu4, npu3, npu3vf, ve2}, {}, TEST_create_free_bo, {XCL_BO_FLAGS_EXECBUF, 0, 0x1000}
  },
  test_case{ "open_close_cu_context", {},
    TEST_POSITIVE, {npu1, npu4}, {}, TEST_open_close_cu_context, {}
  },
  test_case{ "create_destroy_hw_queue", {},
    TEST_POSITIVE, {npu1, npu4, npu3, npu3vf, ve2}, {}, TEST_create_destroy_hw_queue, {}
  },
  // Keep bad run before normal run to test recovery of hw ctx
  test_case{ "io test async error", {},
    TEST_POSITIVE, {npu4, npu3, npu3vf}, {}, TEST_async_error_io_any, {}
  },
  test_case{ "io test TDR: faulting head times out, queued jobs abort", {},
    TEST_POSITIVE, {npu3, npu3vf}, {}, TEST_tdr_timeout_and_abort, {}
  },
  test_case{ "io test TDR: partial chain interrupted mid-publish is aborted", {},
    TEST_POSITIVE, {npu3, npu3vf}, {}, TEST_tdr_partial_chain_abort, {}
  },
  test_case{ "io test TDR: not-yet-published submit is retried across reset", {},
    TEST_POSITIVE, {npu3, npu3vf}, {}, TEST_tdr_not_yet_published_retried, {}
  },
  test_case{ "io test real kernel good run", {},
    TEST_POSITIVE, {npu1, npu4, npu3, npu3vf, ve2}, {}, TEST_io, { IO_TEST_NORMAL_RUN, 1 }
  },
  test_case{ "io test with instruction code invalid address access", {},
    TEST_POSITIVE, {npu4, npu3, npu3vf}, {}, TEST_instr_invalid_addr_io, {}
  },
  test_case{ "measure no-op kernel latency", {},
    TEST_POSITIVE, {npu1, npu4, npu3, npu3vf, ve2}, {}, TEST_io_latency, { IO_TEST_NOOP_RUN, IO_TEST_IOCTL_WAIT, NUM_STRESS_IO }
  },
  test_case{ "measure real kernel latency", {},
    TEST_POSITIVE, {npu1, npu4, npu3, npu3vf, ve2}, {}, TEST_io_latency, { IO_TEST_NORMAL_RUN, IO_TEST_IOCTL_WAIT, NUM_STRESS_IO }
  },
  test_case{ "create and free debug bo", {},
    TEST_POSITIVE, {npu1, npu4, npu3, npu3vf}, {}, TEST_create_free_debug_bo, { 0x1000 }
  },
  test_case{ "create and free large debug bo", {},
    TEST_POSITIVE, {npu1, npu4, npu3, npu3vf}, {}, TEST_create_free_debug_bo, { 0x100000 }
  },
  test_case{ "create and free uc_log bo", {},
    TEST_POSITIVE, {npu3, npu3vf, ve2}, {}, TEST_create_free_uc_log_bo, { 0x10000 }
  },
  test_case{ "create and free large uc_log bo", {},
    TEST_POSITIVE, {npu3, npu3vf, ve2}, {}, TEST_create_free_uc_log_bo, { 0x100000 }
  },
  test_case{ "multi-command io test real kernel good run", {},
    TEST_POSITIVE, {npu1, npu4, npu3, npu3vf, ve2}, {}, TEST_io, { IO_TEST_NORMAL_RUN, 3 }
  },
  test_case{ "measure no-op kernel throughput command", {},
    TEST_POSITIVE, {npu1, npu4, npu3, npu3vf, ve2}, {}, TEST_io_throughput, { IO_TEST_NOOP_RUN, IO_TEST_IOCTL_WAIT, NUM_STRESS_IO }
  },
  test_case{ "export import BO", {},
    TEST_POSITIVE, {npu1, npu4, npu3, npu3vf, ve2}, {}, TEST_export_import_bo, {}
  },
  test_case{ "ELF io test real kernel good run", {},
    TEST_POSITIVE, {npu1, npu4}, {}, TEST_elf_io, { IO_TEST_NORMAL_RUN, 1 }
  },
  test_case{ "Cmd fencing (user space side)", {},
    TEST_POSITIVE, {npu1, npu4, npu3, npu3vf}, {}, TEST_cmd_fence_host, {}
  },
  test_case{ "io test no op with duplicated BOs", {},
    TEST_POSITIVE, {npu1, npu4, npu3, npu3vf, ve2}, {}, TEST_noop_io_with_dup_bo, {}
  },
  test_case{ "measure no-op kernel latency chained command", {},
    TEST_POSITIVE, {npu1, npu4, npu3, npu3vf, ve2}, {}, TEST_io_runlist_latency, { IO_TEST_NOOP_RUN, IO_TEST_IOCTL_WAIT, NUM_STRESS_IO }
  },
  test_case{ "measure no-op kernel throughput chained command", {},
    TEST_POSITIVE, {npu1, npu4, npu3, npu3vf}, {}, TEST_io_runlist_throughput, { IO_TEST_NOOP_RUN, IO_TEST_IOCTL_WAIT, NUM_STRESS_IO }
  },
  test_case{ "measure no-op kernel latency (polling)", {},
    TEST_POSITIVE, {npu1, npu4, npu3, npu3vf}, {}, TEST_io_latency, { IO_TEST_NOOP_RUN, IO_TEST_POLL_WAIT, NUM_STRESS_IO }
  },
  test_case{ "measure no-op kernel throughput (polling)", {},
    TEST_POSITIVE, {npu1, npu4, npu3, npu3vf}, {}, TEST_io_throughput, { IO_TEST_NOOP_RUN, IO_TEST_POLL_WAIT, NUM_STRESS_IO }
  },
  test_case{ "measure no-op kernel latency chained command (polling)", {},
    TEST_POSITIVE, {npu1, npu4, npu3, npu3vf}, {}, TEST_io_runlist_latency, { IO_TEST_NOOP_RUN, IO_TEST_POLL_WAIT, NUM_STRESS_IO }
  },
  test_case{ "measure no-op kernel throughput chained command (polling)", {},
    TEST_POSITIVE, {npu1, npu4, npu3, npu3vf}, {}, TEST_io_runlist_throughput, { IO_TEST_NOOP_RUN, IO_TEST_POLL_WAIT, NUM_STRESS_IO }
  },
  test_case{ "Cmd fencing (driver side)", {},
    TEST_POSITIVE, {npu1, npu4, npu3, npu3vf}, {}, TEST_cmd_fence_device, {}
  },
  test_case{ "sync_bo for input_output 1MiB BO", {},
    TEST_POSITIVE, {npu1, npu4, npu3, npu3vf, ve2}, {}, TEST_sync_bo, {XCL_BO_FLAGS_HOST_ONLY, 0, 0x100000}
  },
  test_case{ "sync_bo for input_output 1MiB BO w/ offset and size", {},
    TEST_POSITIVE, {npu1, npu4, npu3, npu3vf, ve2}, {}, TEST_sync_bo_off_size, {XCL_BO_FLAGS_HOST_ONLY, 0, 0x100000, 0x1004, 0x3c}
  },
  test_case{ "export import BO in single process", {},
    TEST_POSITIVE, {npu1, npu4, npu3, npu3vf, ve2}, {}, TEST_export_import_bo_single_proc, {}
  },
  test_case{ "multi-command ELF io test real kernel good run", {},
    TEST_POSITIVE, {npu1, npu4}, {}, TEST_elf_io, { IO_TEST_NORMAL_RUN, 3 }
  },
  test_case{ "max context test", {},
    TEST_POSITIVE, {npu1, npu4, npu3, npu3vf, ve2}, {}, TEST_create_destroy_max_context, { 0 }
  },
  test_case{ "max context bad test", {},
    TEST_NEGATIVE, {npu1, npu4, npu3, npu3vf, ve2}, {}, TEST_create_destroy_max_context, { 1 }
  },
  test_case{ "Multi context IO test 1", {},
    TEST_POSITIVE, {npu1, npu4, npu3, npu3vf, ve2}, {}, TEST_multi_context_io_test, { 0 }
  },
  test_case{ "Multi context IO test 2", {},
    TEST_POSITIVE, {npu1, npu4, npu3, npu3vf, ve2}, {}, TEST_multi_context_io_test, { 1 }
  },
  test_case{ "Multi context IO test 3", {},
    TEST_POSITIVE, {npu1, npu4, npu3, npu3vf, ve2}, {}, TEST_multi_context_io_test, { 2 }
  },
  test_case{ "Create and destroy devices", {},
    TEST_POSITIVE, {npu1, npu4, npu3, npu3vf, ve2}, {}, TEST_create_destroy_device, {}
  },
  test_case{ "multi-command preempt ELF io test real kernel good run", {},
    TEST_POSITIVE, {npu4}, {amdxdna}, TEST_preempt_elf_io, { IO_TEST_FORCE_PREEMPTION, 8 }
  },
  test_case{ "create and free user pointer bo", {},
    TEST_POSITIVE, {npu1, npu4, npu3, npu3vf}, {}, TEST_create_free_uptr_bo, {XCL_BO_FLAGS_HOST_ONLY, 0, 128}
  },
  test_case{ "io test with user pointer BOs", {},
    TEST_POSITIVE, {npu1, npu4, npu3, npu3vf}, {}, TEST_io_with_ubuf_bo, {}
  },
  test_case{ "multi-command preempt full ELF io test real kernel good run", {},
    TEST_POSITIVE, {npu4, npu3}, {amdxdna}, TEST_preempt_full_elf_io, { IO_TEST_FORCE_PREEMPTION, 8 }
  },
  test_case{ "Real kernel delay run for auto-suspend/resume", {},
    TEST_POSITIVE, {npu1, npu4, npu3, npu3vf, ve2}, {}, TEST_io_suspend_resume, {}
  },
  test_case{ "io test timeout run for context health report", {},
    TEST_POSITIVE, {npu4, npu3, npu3vf}, {}, TEST_io_timeout, {}
  },
  test_case{ "app health query multi-context with and without ctx-id filter", {},
    TEST_POSITIVE, {npu4}, {amdxdna}, TEST_app_health_query_multi_ctx, {}
  },
  test_case{ "query hw_contexts (get_info)", {},
    TEST_POSITIVE, {npu1, npu4, npu3, npu3vf}, {amdxdna}, TEST_query_hw_contexts, {}
  },
  test_case{ "hw_context_all (get_array)", {},
    TEST_POSITIVE, {npu1, npu4, npu3, npu3vf}, {amdxdna}, TEST_hw_context_all, {}
  },
  test_case{ "query memory usage (total_mem_usage/aie_partition_info)", {},
    TEST_POSITIVE, {npu1, npu4, npu3, npu3vf}, {amdxdna}, TEST_query_memory_usage, {}
  },
  test_case{ "query telemetry", {},
    TEST_POSITIVE, {npu1, npu4, npu3}, {amdxdna}, TEST_query_telemetry, {}
  },
  test_case{ "query telemetry header-only buffer fails", {},
    TEST_POSITIVE, {npu1, npu4, npu3}, {amdxdna}, TEST_query_telemetry_short_buf, {}
  },
  test_case{ "query frame boundary preempt state (get_info)", {},
    TEST_POSITIVE, {npu1, npu4, npu3, npu3vf}, {amdxdna}, TEST_query_frame_boundary_preempt, {}
  },
  //test_case{ "io test no-op kernel good run", {},
  //  TEST_POSITIVE, {npu1, npu4}, {}, TEST_io, { IO_TEST_NOOP_RUN, 1 }
  //},
  // get async error in multi thread after async error has raised.
  test_case{ "get async error in multithread - HAS ASYNC ERROR", {},
    TEST_POSITIVE, {npu4, npu3, npu3vf}, {}, TEST_async_error_multi, {true}
  },
  test_case{ "gemm and debug BO", {},
    TEST_POSITIVE, {npu4, npu3, npu3vf}, {}, TEST_io_gemm, {}
  },
  test_case{ "create and free internal bo", {},
    TEST_POSITIVE, {npu1, npu4, npu3, npu3vf}, {amdxdna}, TEST_create_free_internal_bo, {}
  },
  // npu4 and npu3 back the dev heap with multiple, expandable chunks, so
  // cross-chunk dev BOs work. npu1 has a single fixed chunk, so the same
  // allocation is expected to be rejected -- the test handles that internally
  // and still passes. Filter on device type only (not the amdxdna driver) so
  // these also run on the QEMU guest where the NPU is a virtio-gpu device.
  test_case{ "dev BO crossing two heap chunks (128MB)", {},
    TEST_POSITIVE, {npu1, npu4, npu3, npu3vf, ve2}, {}, TEST_dev_bo_cross_heap, { 128ul * 1024 * 1024 }
  },
  test_case{ "dev BO spanning the whole heap (512MB)", {},
    TEST_POSITIVE, {npu1, npu4, npu3, npu3vf, ve2}, {}, TEST_dev_bo_cross_heap, { 512ul * 1024 * 1024 }
  },
  test_case{ "dev BO cross-heap alloc/free stress", {},
    TEST_POSITIVE, {npu1, npu4, npu3, npu3vf, ve2}, {}, TEST_dev_bo_cross_heap_stress,
    { 128ul * 1024 * 1024, 100 }
  },
  // npu4 caps the dev heap at 512MB, so a larger BO must be rejected.
  test_case{ "dev BO larger than max heap rejected (npu4)", {},
    TEST_NEGATIVE, {npu4}, {}, TEST_dev_bo_over_max, { 576ul * 1024 * 1024 }
  },
  // npu3 and ve2 have no 512MB heap cap, so the same over-512MB BO must allocate fine.
  test_case{ "dev BO larger than 512MB accepted (aie4)", {},
    TEST_POSITIVE, {npu3, npu3vf, ve2}, {}, TEST_dev_bo_cross_heap, { 576ul * 1024 * 1024 }
  },
  test_case{ "export BO then close device", {},
    TEST_POSITIVE, {npu1, npu4, npu3, npu3vf, ve2}, {}, TEST_export_bo_then_close_device, {}
  },
  test_case{ "get AIE coredump and check registers", {},
    TEST_POSITIVE, {npu4}, {amdxdna}, TEST_io_coredump, {}
  },
  test_case{ "AIE MEM read/write", {},
    TEST_POSITIVE, {npu4}, {amdxdna}, TEST_io_aie_mem, {}
  },
  test_case{ "AIE REG read/write", {},
    TEST_POSITIVE, {npu4}, {amdxdna}, TEST_io_aie_reg, {}
  },
  test_case{ "failed chained command", {},
    TEST_POSITIVE, {npu4, npu3, npu3vf}, {}, TEST_io_runlist_bad_cmd, {false}
  },
  test_case{ "timed out chained command", {},
    TEST_POSITIVE, {npu4, npu3, npu3vf}, {}, TEST_io_runlist_bad_cmd, {true}
  },
  test_case{ "create and free user ptr BO with mmapped ptr", {},
    TEST_POSITIVE, {npu1, npu4, npu3, npu3vf}, {}, TEST_create_free_mmaped_uptr_bo, {}
  },
  test_case{ "DPM noop (no QoS)", {},
    TEST_POSITIVE, {npu4}, {amdxdna}, TEST_dpm_noop_no_qos, {}
  },
  test_case{ "DPM refcount scaling", {},
    TEST_POSITIVE, {npu4}, {amdxdna}, TEST_dpm_refcount_scaling, {}
  },
  test_case{ "DPM power modes", {},
    TEST_POSITIVE, {npu4}, {amdxdna}, TEST_dpm_power_modes, {}
  },
  test_case{ "CERT log: attach/detach", {},
    TEST_POSITIVE, {npu3, npu3vf}, {}, TEST_certlog_attach_detach, {}
  },
  test_case{ "CERT log: max num_ucs", {},
    TEST_POSITIVE, {npu3, npu3vf}, {}, TEST_certlog_multi_uc, {}
  },
  test_case{ "CERT log: num_ucs > AIE4_MAX_NUM_CERTS rejected", {},
    TEST_POSITIVE, {npu3, npu3vf}, {}, TEST_certlog_num_ucs_overflow, {}
  },
  test_case{ "CERT log: out-of-range uc index rejected", {},
    TEST_POSITIVE, {npu3, npu3vf}, {}, TEST_certlog_invalid_uc_index, {}
  },
  test_case{ "CERT log: payload overflow rejected", {},
    TEST_POSITIVE, {npu3, npu3vf}, {}, TEST_certlog_payload_overflow, {}
  },
  test_case{ "NPU write to read-only user pointer BO is rejected", {},
    TEST_NEGATIVE, {npu1, npu4, npu3, npu3vf}, {amdxdna}, TEST_write_to_readonly_uptr_bo, {}
  },
  test_case{ "df_bw 1GB shim DMA loopback", {},
    TEST_POSITIVE, {npu4, npu3, npu3vf}, {}, TEST_df_bw, {}
  },
  // Disable until fw FLR bug is fixed
  // test_case{ "AIE4 Classic/VF FLR then recovers hwctx", {},
    // TEST_POSITIVE, {npu3, npu3vf}, {amdxdna}, TEST_aie4_flr, {}
  // },
  // npu3vf only as for PF FLR device must be in SRIOV mode
  // test_case{ "AIE4 PF FLR", {},
    // TEST_POSITIVE, {npu3vf}, {amdxdna}, TEST_aie4_pf_flr_entry, {}
  // },
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
  if (current_drv.major == 0 && current_drv.minor == 0)
    return test.is_negative;

  if (current_drv.major > test.drv_ver.major ||
      (current_drv.major == test.drv_ver.major &&
       current_drv.minor >= test.drv_ver.minor))
    return test.is_negative;

  return true;
}

void
run_test(int id, const test_case& test, bool force, const device::id_type& num_of_devices)
{
  bool failed = is_negative_test(test);
  bool skipped = true;

  std::cout << "====== " << id << ": " << test.name << " started =====" << std::endl;
  try {
    if (test.hw_list.empty()) { // system test
      skipped = false;
      std::shared_ptr<device> dev = nullptr;
      test.func(0, dev, test.arg);
    } else { // per user device test
      for (device::id_type i = 0; i < num_of_devices; i++) {
        auto dev = get_userpf_device(i);
        // Skip userpf devices without pcie_device (e.g. VE2 zocl edge device).
        try {
          device_query<query::pcie_device>(dev.get());
        }
        catch (const query::no_such_key&) {
          continue;
        }
        if (!force && !(match_hw(test.hw_list, i, dev.get()) && match_drv(test.drv_list, i, dev.get())))
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

struct drv_version { unsigned int major; unsigned int minor; };

int
get_driver_version(unsigned int *major, unsigned int *minor, device::id_type device_index = 0)
{
  // Resolve the node via a shim device, then read drm_version from a forked
  // child (distinct pid -> open() allowed under single-open). drm_version is a
  // generic per-fd ioctl, so any fd to the node returns the same KMD version.
  auto sdev = get_userpf_device(device_index);

  auto ver = fork_query<drv_version>(sdev.get(), [](int fd) {
    drm_version version = {};
    char name[128];
    char date[128];
    char desc[256];
    version.name_len = sizeof(name);
    version.name = name;
    version.date_len = sizeof(date);
    version.date = date;
    version.desc_len = sizeof(desc);
    version.desc = desc;
    if (::ioctl(fd, DRM_IOCTL_VERSION, &version) == -1)
      throw std::runtime_error("ioctl(DRM_IOCTL_VERSION) failed");
    return drv_version{
      static_cast<unsigned int>(version.version_major),
      static_cast<unsigned int>(version.version_minor)
    };
  });

  *major = ver.major;
  *minor = ver.minor;

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
      try {
        get_driver_version(&current_drv.major, &current_drv.minor);
      } catch (const std::exception& e) {
        std::cerr << "Caught std::exception: " << e.what() << std::endl;
        return 1;
      } catch (...) {
        std::cerr << "Caught unknown exception" << std::endl;
        return 1;
      }
      std::cout << "Evaluating test result based on driver version: "
        << current_drv.major << "." << current_drv.minor << std::endl;
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

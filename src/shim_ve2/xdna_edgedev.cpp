// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2025, Advanced Micro Devices, Inc. All rights reserved.

#include "drm_local/amdxdna_accel.h"
#include "core/common/config_reader.h"
#include "xdna_device.h"
#include "xdna_edgedev.h"

namespace {
std::string
ioctl_cmd2name(unsigned long cmd)
{
  switch(cmd) {
  case DRM_IOCTL_AMDXDNA_CREATE_CTX:
    return "DRM_IOCTL_AMDXDNA_CREATE_CTX";
  case DRM_IOCTL_AMDXDNA_DESTROY_CTX:
    return "DRM_IOCTL_AMDXDNA_DESTROY_CTX";
  case DRM_IOCTL_AMDXDNA_CONFIG_CTX:
    return "DRM_IOCTL_AMDXDNA_CONFIG_CTX";
  case DRM_IOCTL_AMDXDNA_CREATE_BO:
    return "DRM_IOCTL_AMDXDNA_CREATE_BO";
  case DRM_IOCTL_AMDXDNA_GET_BO_INFO:
    return "DRM_IOCTL_AMDXDNA_GET_BO_INFO";
  case DRM_IOCTL_AMDXDNA_SYNC_BO:
    return "DRM_IOCTL_AMDXDNA_SYNC_BO";
  case DRM_IOCTL_AMDXDNA_EXEC_CMD:
    return "DRM_IOCTL_AMDXDNA_EXEC_CMD";
  case DRM_IOCTL_AMDXDNA_WAIT_CMD:
    return "DRM_IOCTL_AMDXDNA_WAIT_CMD";
  case DRM_IOCTL_AMDXDNA_GET_INFO:
    return "DRM_IOCTL_AMDXDNA_GET_INFO";
  case DRM_IOCTL_AMDXDNA_SET_STATE:
    return "DRM_IOCTL_AMDXDNA_SET_STATE";
  case DRM_IOCTL_GEM_CLOSE:
    return "DRM_IOCTL_GEM_CLOSE";
  case DRM_IOCTL_PRIME_HANDLE_TO_FD:
    return "DRM_IOCTL_PRIME_HANDLE_TO_FD";
  case DRM_IOCTL_PRIME_FD_TO_HANDLE:
    return "DRM_IOCTL_PRIME_FD_TO_HANDLE";
  }

  return "UNKNOWN(" + std::to_string(cmd) + ")";
}
}

namespace shim_xdna_edge {

static std::fstream sysfs_open_path(const std::string& path, std::string& err,
                                                bool write, bool binary)
{
    std::fstream fs;
    std::ios::openmode mode = write ? std::ios::out : std::ios::in;

    if (binary)
        mode |= std::ios::binary;

    err.clear();
    fs.open(path, mode);
    if (!fs.is_open()) {
        std::stringstream ss;
        ss << "Failed to open " << path << " for "
            << (binary ? "binary " : "")
            << (write ? "writing" : "reading") << ": "
            << strerror(errno) << std::endl;
        err = ss.str();
    }
    return fs;
}

std::string xdna_edgedev::get_sysfs_path(const std::string& entry) const
{
    return m_sysfs_name + entry;
}

std::fstream xdna_edgedev::sysfs_open(const std::string& entry,
    std::string& err, bool write, bool binary) const
{
    return sysfs_open_path(get_sysfs_path(entry), err, write, binary);
}

void xdna_edgedev::sysfs_put(const std::string& entry, std::string& err_msg,
    const std::string& input)
{
    std::fstream fs = sysfs_open(entry, err_msg, true, false);
    if (!err_msg.empty())
        return;
    fs << input;
}

void xdna_edgedev::sysfs_put(const std::string& entry, std::string& err_msg,
    const std::vector<char>& buf)
{
    std::fstream fs = sysfs_open(entry, err_msg, true, true);
    if (!err_msg.empty())
        return;
    fs.write(buf.data(), buf.size());
}

void xdna_edgedev::sysfs_get(const std::string& entry, std::string& err_msg,
    std::vector<char>& buf) const
{
    std::fstream fs = sysfs_open(entry, err_msg, false, true);
    if (!err_msg.empty())
        return;
    buf.insert(std::end(buf),std::istreambuf_iterator<char>(fs),
        std::istreambuf_iterator<char>());
}

void xdna_edgedev::sysfs_get(const std::string& entry, std::string& err_msg,
    std::vector<std::string>& sv) const
{
    std::fstream fs = sysfs_open(entry, err_msg, false, false);
    if (!err_msg.empty())
        return;

    sv.clear();
    std::string line;
    while (std::getline(fs, line))
        sv.push_back(line);
}

void xdna_edgedev::sysfs_get(const std::string& entry, std::string& err_msg,
    std::vector<uint64_t>& iv) const
{
    uint64_t n;
    std::vector<std::string> sv;

    iv.clear();

    sysfs_get(entry, err_msg, sv);
    if (!err_msg.empty())
        return;

    char *end;
    for (auto& s : sv) {
        std::stringstream ss;

        if (s.empty()) {
            ss << "Reading " << get_sysfs_path(entry) << ", ";
            ss << "can't convert empty string to integer" << std::endl;
            err_msg = ss.str();
            break;
        }
        n = std::strtoull(s.c_str(), &end, 0);
        if (*end != '\0') {
            ss << "Reading " << get_sysfs_path(entry) << ", ";
            ss << "failed to convert string to integer: " << s << std::endl;
            err_msg = ss.str();
            break;
        }
        iv.push_back(n);
    }
}

void xdna_edgedev::sysfs_get(const std::string& entry, std::string& err_msg,
    std::string& s) const
{
    std::vector<std::string> sv;

    sysfs_get(entry, err_msg, sv);
    if (!sv.empty())
        s = sv[0];
    else
        s = ""; // default value
}

std::string
xdna_edgedev::get_edge_devname()
{
  const std::string of_node_name{"telluride_drm"};
  const std::string base_path = "/sys/class/accel";
  const std::regex accel_regex("accel.*");
  std::string accel_devname;

  namespace fs = std::filesystem;
  try {
    for (const auto& entry : fs::directory_iterator(base_path)) {
      if (fs::is_directory(entry) && std::regex_match(entry.path().filename().string(), accel_regex)) {
        const std::string accel_file_path = entry.path().string() + "/device/of_node/name";
        if (fs::exists(accel_file_path)) {
          std::ifstream accel_file(accel_file_path);
          std::string name;
          std::getline(accel_file, name);
          if (name == of_node_name) {
            return entry.path().filename().string();
          }
        }
      }
    }
  }
  catch (std::exception &e) {
    // Choosing default accel
    accel_devname = "accel0";
  }

  if (accel_devname.empty())
    accel_devname = "accel0";

  return accel_devname;
}

std::shared_ptr<xdna_edgedev>
xdna_edgedev::get_edgedev()
{
  // This is based on the fact that on edge devices, we only have one DRM
  // device, which is named as accel* (eg: accel0).
  // This path is reliable. It is the same for ARM32 and ARM64.
  static const std::string sysfs_name = "/sys/class/accel/" + get_edge_devname() + "/device/";
  static const std::string dev_name = "/dev/accel/" + get_edge_devname();
  //static xdna_edgedev edev(sysfs_name, dev_name);
  static std::shared_ptr<xdna_edgedev> edev = std::make_shared<xdna_edgedev>(sysfs_name, dev_name);

  return edev;
}

xdna_edgedev::
xdna_edgedev(std::string sysfs_name, std::string dev_name)
  : m_sysfs_name(std::move(sysfs_name))
  , m_dev_name(std::move(dev_name))
{
  shim_debug("Created AIARM edgedev");
}

xdna_edgedev::
~xdna_edgedev()
{
  shim_debug("Destroying AIARM edgedev");
}

void
xdna_edgedev::
open() const
{
  int fd;
  const std::lock_guard<std::mutex> lock(m_lock);
  std::cout << __func__ << " : DEV name  " << m_dev_name.c_str() <<
		std::endl;
  if (m_dev_users == 0) {
    if (std::filesystem::exists(m_dev_name.c_str())) {
      fd = ::open(m_dev_name.c_str(), O_RDWR);
      if (fd < 0)
        shim_err(EINVAL, "Failed to open edge device %s",
		 m_dev_name.c_str());
	else
	  shim_debug("Device opened, fd=%d", fd);
    }
    /*
     * Aiarm node is not present in some platforms static dtb, it gets loaded
     * using overlay dtb, drm device node is not created until aiarm is present
     * So if enable_flat is set return 1 valid device
     */
    else if (xrt_core::config::get_enable_flat())
      shim_debug("Device opened as a flat platform, fd=%d", fd);

    std::vector<char> name(128,0);
    std::vector<char> desc(512,0);
    std::vector<char> date(128,0);
    
    const char* name_str = "amdxdna_ve2";
    const char* desc_str = "This driver is for VE2 device";
    const char* date_str = "02042025";
    // Copy the constant strings into the vectors
    std::copy(name_str, name_str + strlen(name_str), name.begin());
    std::copy(desc_str, desc_str + strlen(desc_str), desc.begin());
    std::copy(date_str, date_str + strlen(date_str), date.begin());

    drm_version version;
    std::memset(&version, 0, sizeof(version));
    version.name = name.data();
    version.name_len = 128;
    version.desc = desc.data();
    version.desc_len = 512;
    version.date = date.data();
    version.date_len = 128;

    int result;
    result = ::ioctl(fd, DRM_IOCTL_VERSION, &version);
    if (result) {
      ::close(fd);
      shim_err(EINVAL, "Failed to open edge device %s", m_dev_name.c_str());
    }
    result = std::strncmp(version.name, "AIARM", 5);
    // Publish the fd for other threads to use.
    m_dev_fd = fd;
   }
   ++m_dev_users;
}

void
xdna_edgedev::
close() const
{
  int fd;
  const std::lock_guard<std::mutex> lock(m_lock);

  --m_dev_users;
  if (m_dev_users == 0) {
    // Stop new users of the fd from other threads.
    fd = m_dev_fd;
    m_dev_fd = -1;
    // Kernel will wait for existing users to quit.
    ::close(fd);
    shim_debug("Device closed, fd=%d", fd);
  }
}

void
xdna_edgedev::
ioctl(unsigned long cmd, void* arg) const
{
  if (::ioctl(m_dev_fd, cmd, arg) == -1)
    shim_err(errno, "%s IOCTL failed", ioctl_cmd2name(cmd).c_str());
}

void*
xdna_edgedev::
mmap(void *addr, size_t len, int prot, int flags, off_t offset) const
{
  void* ret = ::mmap(addr, len, prot, flags, m_dev_fd, offset);

  if (ret == reinterpret_cast<void*>(-1))
    shim_err(errno, "mmap(addr=%p, len=%ld, prot=%d, flags=%d, offset=%ld) failed", addr, len, prot, flags, offset);
  return ret;
}

void
xdna_edgedev::
munmap(void* addr, size_t len) const
{
  ::munmap(addr, len);
}

} // namespace shim_xdna_edge


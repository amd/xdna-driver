// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2022-2025, Advanced Micro Devices, Inc. All rights reserved.

#include "device.h"
#include "pcidev.h"
#include "pcidrv.h"
#include "shim_debug.h"
#include "core/common/trace.h"

namespace shim_xdna {

pdev::
pdev(std::shared_ptr<const platform_drv>& driver, const std::string& sysfs_name)
  : m_driver(driver)
  , xrt_core::pci::dev(driver->get_pdrv(), sysfs_name)
{
  m_is_ready = true; // We're always ready
  shim_debug("Created pcidev (%s)", m_sysfs_name.c_str());
}

pdev::
~pdev()
{
  shim_debug("Destroying pcidev (%s)", m_sysfs_name.c_str());
}

xrt_core::device::handle_type
pdev::
create_shim(xrt_core::device::id_type id) const
{
  auto s = new shim(id);
  return static_cast<xrt_core::device::handle_type>(s);
}

void
pdev::
open() const
{
  const std::lock_guard<std::mutex> lock(m_lock);

  if (m_dev_users == 0) {
    m_driver->drv_open(m_sysfs_name);
    try {
      on_first_open();
    } catch (...) {
      m_driver->drv_close();
      throw;
    }
  }
  ++m_dev_users;
}

void
pdev::
close() const
{
  const std::lock_guard<std::mutex> lock(m_lock);

  --m_dev_users;
  if (m_dev_users == 0) {
    try {
      on_last_close();
      m_driver->drv_close();
    } catch (const xrt_core::system_error& e) {
      shim_debug("Failed to close device: %s", e.what());
    }
  }
}

void*
pdev::
mmap(void *addr, size_t len, int prot, int flags, off_t offset) const
{
  return m_driver->drv_mmap(addr, len, prot, flags, offset);
}

void
pdev::
munmap(void* addr, size_t len) const
{
  m_driver->drv_munmap(addr, len);
}

void
pdev::
drv_ioctl(drv_ioctl_cmd cmd, void* arg) const
{
  m_driver->drv_ioctl(cmd, arg);
}

std::shared_ptr<xrt_core::device>
pdev::
create_device(xrt_core::device::handle_type handle, xrt_core::device::id_type id) const
{
  return std::make_shared<device>(*this, handle, id);
}

void
pdev::
sysfs_get(const std::string& subdev, const std::string& entry, std::string& err,
  std::vector<std::string>& sv)
{
  std::vector<char> data;
  sysfs_get(subdev, entry, err, data);
  if (!err.empty())
    return;

  sv.clear();
  std::string line;
  std::istringstream iss(std::string(data.begin(), data.end()));
  while (std::getline(iss, line))
    sv.push_back(line);
}

void
pdev::
sysfs_get(const std::string& subdev, const std::string& entry, std::string& err,
  std::vector<uint64_t>& iv)
{
  std::vector<std::string> sv;
  sysfs_get(subdev, entry, err, sv);
  if (!err.empty())
    return;

  std::stringstream ss;
  for (auto& s : sv) {
    if (s.empty()) {
      ss << "Reading " << entry << ", ";
      ss << "can't convert empty string to integer" << std::endl;
      break;
    }
    char* end = nullptr;
    auto n = std::strtoull(s.c_str(), &end, 0);
    if (*end != '\0') {
      ss << "Reading " << entry << ", ";
      ss << "failed to convert string to integer: " << s << std::endl;
      break;
    }
    iv.push_back(n);
  }
  err = ss.str();
}

void
pdev::
sysfs_get(const std::string& subdev, const std::string& entry, std::string& err,
  std::string& s)
{
  std::vector<std::string> sv;
  sysfs_get(subdev, entry, err, sv);
  if (!sv.empty())
    s = sv[0];
  else
    s = ""; // default value
}

void
pdev::
sysfs_get(const std::string& subdev, const std::string& entry, std::string& err,
  std::vector<char>& buf)
{
  std::stringstream ss;
  std::vector<char> data(4096); // Maximum 4k data read from sysfs node

  if (!subdev.empty()) {
    ss << "Can't support non-empty subdev: " << subdev << std::endl;
    err = ss.str();
    return;
  }

  get_sysfs_arg arg = {
    .sysfs_node = entry,
    .data = data,
    .real_size = 0
  };
  try {
    drv_ioctl(drv_ioctl_cmd::get_sysfs, &arg);
  } catch (const xrt_core::system_error& e) {
    ss << "Failed to read sysfs node: " << entry << ": " << e.what() << std::endl;
    err = ss.str();
    return;
  }
  buf.assign(data.begin(), data.begin() + arg.real_size);
}

void
pdev::
sysfs_put(const std::string& subdev, const std::string& entry, std::string& err,
  const std::string& input)
{
  auto p = input.c_str();
  std::vector<char> data(p, p + input.size());
  sysfs_put(subdev, entry, err, data);
}

void
pdev::
sysfs_put(const std::string& subdev, const std::string& entry, std::string& err,
  const unsigned int& buf)
{
  auto p = reinterpret_cast<const char*>(&buf);
  std::vector<char> data(p, p + sizeof(buf));
  sysfs_put(subdev, entry, err, data);
}

void
pdev::
sysfs_put(const std::string& subdev, const std::string& entry, std::string& err,
  const std::vector<char>& buf)
{
  std::stringstream ss;
  put_sysfs_arg arg = {
    .sysfs_node = entry,
    .data = buf,
  };
  try {
    drv_ioctl(drv_ioctl_cmd::put_sysfs, &arg);
  } catch (const xrt_core::system_error& e) {
    ss << "Failed to write sysfs node: " << entry << ": " << e.what() << std::endl;
  }
  err = ss.str();
}

}

// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2022-2024, Advanced Micro Devices, Inc. All rights reserved.

#include "bo.h"
#include "shim_debug.h"
#include "core/common/memalign.h"
#include <unistd.h>

namespace {

uint32_t
alloc_drm_bo(const shim_xdna::pdev& dev, amdxdna_bo_type type, void* buf, size_t size)
{
  amdxdna_drm_create_bo cbo = {
    .type = type,
    .vaddr = reinterpret_cast<uintptr_t>(buf),
    .size = size,
  };
  dev.ioctl(DRM_IOCTL_AMDXDNA_CREATE_BO, &cbo);
  return cbo.handle;
}

void
free_drm_bo(const shim_xdna::pdev& dev, uint32_t boh)
{
    drm_gem_close close_bo = {boh, 0};
    dev.ioctl(DRM_IOCTL_GEM_CLOSE, &close_bo);
}

void
get_drm_bo_info(const shim_xdna::pdev& dev, uint32_t boh, amdxdna_drm_get_bo_info* bo_info)
{
  bo_info->handle = boh;
  dev.ioctl(DRM_IOCTL_AMDXDNA_GET_BO_INFO, bo_info);
}

void*
map_drm_bo(const shim_xdna::pdev& dev, size_t size, int prot, uint64_t offset)
{
  return dev.mmap(size, prot, MAP_SHARED | MAP_LOCKED, offset);
}

void
unmap_drm_bo(const shim_xdna::pdev& dev, void* addr, size_t size)
{
  dev.munmap(addr, size);
}

}

namespace shim_xdna {

bo::drm_bo::
drm_bo(bo& parent, const amdxdna_drm_get_bo_info& bo_info)
  : m_parent(parent)
  , m_handle(bo_info.handle)
  , m_map_offset(bo_info.map_offset)
  , m_vaddr(bo_info.vaddr)
  , m_xdna_addr(bo_info.xdna_addr)
{
}

bo::drm_bo::
~drm_bo()
{
  if (m_handle == AMDXDNA_INVALID_BO_HANDLE)
    return;
  free_drm_bo(m_parent.m_pdev, m_handle);
}

std::string
bo::
type_to_name(amdxdna_bo_type t)
{
  switch (t) {
  case AMDXDNA_BO_SHMEM:
    return std::string("AMDXDNA_BO_SHMEM");
  case AMDXDNA_BO_DEV_HEAP:
    return std::string("AMDXDNA_BO_DEV_HEAP");
  case AMDXDNA_BO_DEV:
    return std::string("AMDXDNA_BO_DEV");
  case AMDXDNA_BO_CMD:
    return std::string("AMDXDNA_BO_CMD");
  }
  return std::string("BO_UNKNOWN");
}

amdxdna_bo_type
bo::
flag_to_type(uint64_t bo_flags)
{
  auto flag = xcl_bo_flags{bo_flags}.flags;
  // Support 8 flags on the highest byte
  switch (flag & 0xff000000) {
  case XCL_BO_FLAGS_NONE:
  case XCL_BO_FLAGS_HOST_ONLY:
    return AMDXDNA_BO_SHMEM;
  case XCL_BO_FLAGS_CACHEABLE:
    return AMDXDNA_BO_DEV;
  case XCL_BO_FLAGS_EXECBUF:
    return AMDXDNA_BO_CMD;
  default:
    break;
  }
  return AMDXDNA_BO_INVALID;
}

std::string
bo::
describe() const
{
  std::string desc = "type=";
  desc += type_to_name(m_type);
  desc += ", ";
  desc += "drm_bo=";
  desc += std::to_string(m_bo->m_handle);
  desc += ", ";
  desc += "size=";
  desc += std::to_string(m_size);
  return desc;
}

void
bo::
alloc_buf(size_t align)
{
  size_t a = align;

  if (a == 0)
    a = getpagesize();

  m_private_buf = xrt_core::aligned_alloc(a, m_size);
  m_buf = m_private_buf.get();
}

void
bo::
alloc_bo()
{
  uint32_t boh = alloc_drm_bo(m_pdev, m_type, m_buf, m_size);

  amdxdna_drm_get_bo_info bo_info = {};
  get_drm_bo_info(m_pdev, boh, &bo_info);
  m_bo = std::make_unique<bo::drm_bo>(*this, bo_info);
}

bo::
bo(const device& device, size_t size, uint64_t flags, amdxdna_bo_type type)
  : m_pdev(device.get_pdev())
  , m_size(size)
  , m_flags(flags)
  , m_type(type)
{
}

bo::
~bo()
{
}

bo::properties
bo::
get_properties() const
{
  return { m_flags, m_size, get_paddr() };
}

void*
bo::
map(bo::map_type type)
{
  if (m_bo->m_map_offset != AMDXDNA_INVALID_ADDR) {
    int prot = (type == bo::map_type::write ? (PROT_READ | PROT_WRITE) : PROT_READ);
    return map_drm_bo(m_pdev, m_size, prot, m_bo->m_map_offset);
  }
  return m_buf;
}

void
bo::
unmap(void* addr)
{
  if (m_bo->m_map_offset != AMDXDNA_INVALID_ADDR)
    unmap_drm_bo(m_pdev, addr, m_size);
}

uint64_t
bo::
get_paddr() const
{
  if (m_bo->m_xdna_addr != AMDXDNA_INVALID_ADDR)
    return m_bo->m_xdna_addr;
  return reinterpret_cast<uintptr_t>(m_buf);
}

void
bo::
set_cmd_id(uint64_t id)
{
  m_cmd_id = id;
}

uint64_t
bo::
get_cmd_id() const
{
  return m_cmd_id;
}

uint32_t
bo::
get_drm_bo_handle() const
{
  return m_bo->m_handle;
}

} // namespace shim_xdna

// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2022-2025, Advanced Micro Devices, Inc. All rights reserved.

#include "bo.h"
#include "shim_debug.h"
#include <unistd.h>

namespace {

void *
map_parent_range(size_t size)
{
  auto p = ::mmap(0, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (!p)
    shim_err(errno, "mmap(len=%ld) failed", size);

  return p;
}

void*
map_drm_bo(const shim_xdna::pdev& dev, void *addr, size_t size, int prot, int flags, uint64_t offset)
{
  return dev.mmap(addr, size, prot, flags, offset);
}

void
unmap_drm_bo(const shim_xdna::pdev& dev, void* addr, size_t size)
{
  dev.munmap(addr, size);
}

void
attach_dbg_drm_bo(const shim_xdna::pdev& dev, uint32_t boh, uint32_t ctx_id)
{
  amdxdna_drm_config_ctx adbo = {
    .handle = ctx_id,
    .param_type = DRM_AMDXDNA_CTX_ASSIGN_DBG_BUF,
    .param_val = boh,
  };
  dev.ioctl(DRM_IOCTL_AMDXDNA_CONFIG_CTX, &adbo);
}

void
detach_dbg_drm_bo(const shim_xdna::pdev& dev, uint32_t boh, uint32_t ctx_id)
{
  amdxdna_drm_config_ctx adbo = {
    .handle = ctx_id,
    .param_type = DRM_AMDXDNA_CTX_REMOVE_DBG_BUF,
    .param_val = boh,
  };
  dev.ioctl(DRM_IOCTL_AMDXDNA_CONFIG_CTX, &adbo);
}

int
export_drm_bo(const shim_xdna::pdev& dev, uint32_t boh)
{
  drm_prime_handle exp_bo = {boh, DRM_RDWR | DRM_CLOEXEC, -1};
  dev.ioctl(DRM_IOCTL_PRIME_HANDLE_TO_FD, &exp_bo);
  return exp_bo.fd;
}

uint32_t
import_drm_bo(const shim_xdna::pdev& dev, const shim_xdna::shared& share,
  int *type, size_t *size)
{
  xrt_core::shared_handle::export_handle fd = share.get_export_handle();
  drm_prime_handle imp_bo = {AMDXDNA_INVALID_BO_HANDLE, 0, fd};
  dev.ioctl(DRM_IOCTL_PRIME_FD_TO_HANDLE, &imp_bo);

  *type = AMDXDNA_BO_SHARE;
  *size = lseek(fd, 0, SEEK_END);
  lseek(fd, 0, SEEK_SET);

  return imp_bo.handle;
}

bool
is_power_of_two(size_t x)
{
    return (x > 0) && ((x & (x - 1)) == 0);
}

void *
addr_align(void *p, size_t align)
{
    if (!is_power_of_two(align))
        shim_err(EINVAL, "Alignment 0x%lx is not power of two", align);

    return (void *)(((uintptr_t)p + align) & ~(align - 1));
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
  try {
    m_parent.free_drm_bo(m_handle);
  } catch (const xrt_core::system_error& e) {
    shim_debug("Failed to free DRM BO: %s", e.what());
  }
}

std::string
bo::
type_to_name() const
{
  switch (m_type) {
  case AMDXDNA_BO_SHARE:
    return std::string("AMDXDNA_BO_SHARE");
  case AMDXDNA_BO_DEV_HEAP:
    return std::string("AMDXDNA_BO_DEV_HEAP");
  case AMDXDNA_BO_DEV:
    if (xcl_bo_flags{m_flags}.use == XRT_BO_USE_DEBUG)
      return std::string("AMDXDNA_BO_DEV_DEBUG");
    return std::string("AMDXDNA_BO_DEV");
  case AMDXDNA_BO_CMD:
    return std::string("AMDXDNA_BO_CMD");
  }
  return std::string("BO_UNKNOWN");
}

std::string
to_hex_string(uint64_t num) {
  std::stringstream ss;
  ss << "0x" << std::hex << num;
  return ss.str();
}

std::string
bo::
describe() const
{
  std::string desc = "type=";
  desc += type_to_name();
  desc += ", ";
  desc += "drm_bo=";
  desc += std::to_string(m_bo->m_handle);

  desc += ", ";
  desc += "size=";
  desc += to_hex_string(m_aligned_size);

  desc += ", ";
  desc += "paddr=";
  desc += to_hex_string(m_bo->m_xdna_addr);

  desc += ", ";
  desc += "vaddr=";
  desc += to_hex_string(m_bo->m_vaddr);
  return desc;
}

void
bo::
mmap_bo()
{
  if (m_bo->m_map_offset == AMDXDNA_INVALID_ADDR) {
    m_aligned = reinterpret_cast<void *>(m_bo->m_vaddr);
    return;
  }

  if (m_alignment == 0) {
    m_aligned = map_drm_bo(m_pdev, nullptr, m_aligned_size, PROT_READ | PROT_WRITE,
      MAP_SHARED | MAP_LOCKED, m_bo->m_map_offset);
    return;
  }

  /*
   * Handle special alignment
   * The first mmap() is just for reserved a range in user vritual address space.
   * The second mmap() uses an aligned addr as the first argument in mmap syscall.
   */
  m_parent_size = m_alignment - 1 + m_aligned_size;
  m_parent = map_parent_range(m_parent_size);
  auto aligned = addr_align(m_parent, m_alignment);
  m_aligned = map_drm_bo(m_pdev, aligned, m_aligned_size, PROT_READ | PROT_WRITE,
    MAP_SHARED | MAP_LOCKED | MAP_FIXED, m_bo->m_map_offset);
}

void
bo::
munmap_bo()
{
  shim_debug("Unmap BO, aligned %p parent %p", m_aligned, m_parent);
  if (m_bo->m_map_offset == AMDXDNA_INVALID_ADDR)
      return;

  unmap_drm_bo(m_pdev, m_aligned, m_aligned_size);
  if (m_parent)
      unmap_drm_bo(m_pdev, m_parent, m_parent_size);
}

void
bo::
alloc_bo()
{
  uint32_t boh = alloc_drm_bo(m_type, m_aligned_size);

  amdxdna_drm_get_bo_info bo_info = {};
  try {
    get_drm_bo_info(boh, &bo_info);
    m_bo = std::make_unique<bo::drm_bo>(*this, bo_info);
  } catch (...) {
    free_drm_bo(boh);
    throw;
  }
}

void
bo::
import_bo()
{
  uint32_t boh = import_drm_bo(m_pdev, m_import, &m_type, &m_aligned_size);

  amdxdna_drm_get_bo_info bo_info = {};
  get_drm_bo_info(boh, &bo_info);
  m_bo = std::make_unique<bo::drm_bo>(*this, bo_info);
}

void
bo::
free_bo()
{
  m_bo.reset();
}

bo::
bo(const pdev& pdev, xrt_core::hwctx_handle::slot_id ctx_id,
  size_t size, uint64_t flags, int type)
  : m_pdev(pdev)
  , m_aligned_size(size)
  , m_flags(flags)
  , m_type(type)
  , m_import(-1)
  , m_owner_ctx_id(ctx_id)
{
  // Device mem heap must align at 64MB boundary.
  if (m_type == AMDXDNA_BO_DEV_HEAP)
    m_alignment = 64 * 1024 * 1024;
}

bo::
bo(const pdev& pdev, xrt_core::shared_handle::export_handle ehdl)
  : m_pdev(pdev)
  , m_import(ehdl)
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
  return { m_flags, m_aligned_size, get_paddr(), get_drm_bo_handle() };
}

void*
bo::
map(bo::map_type type)
{
  if (type != bo::map_type::write)
    shim_err(EINVAL, "Not support map BO as readonly. Type must be bo::map_type::write");
  return m_aligned;
}

void
bo::
unmap(void* addr)
{
}

uint64_t
bo::
get_paddr() const
{
  if (m_bo->m_xdna_addr != AMDXDNA_INVALID_ADDR)
    return m_bo->m_xdna_addr;
  return reinterpret_cast<uintptr_t>(m_aligned);
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

void
bo::
attach_to_ctx()
{
  if (m_owner_ctx_id == AMDXDNA_INVALID_CTX_HANDLE)
    return;

  auto boh = get_drm_bo_handle();
  shim_debug("Attaching drm_bo %d to ctx: %d", boh, m_owner_ctx_id);
  attach_dbg_drm_bo(m_pdev, boh, m_owner_ctx_id);
}

void
bo::
detach_from_ctx()
{
  if (m_owner_ctx_id == AMDXDNA_INVALID_CTX_HANDLE)
    return;

  auto boh = get_drm_bo_handle();
  shim_debug("Detaching drm_bo %d from ctx: %d", boh, m_owner_ctx_id);
  detach_dbg_drm_bo(m_pdev, boh, m_owner_ctx_id);
}

std::unique_ptr<xrt_core::shared_handle>
bo::
share() const
{
  auto boh = get_drm_bo_handle();
  auto fd = export_drm_bo(m_pdev, boh);
  shim_debug("Exported bo %d to fd %d", boh, fd);
  return std::make_unique<shared>(fd);
}

int
bo::
get_type() const
{
  return m_type;
}

uint32_t
bo::
alloc_drm_bo(int type, size_t size)
{
  amdxdna_drm_create_bo cbo = {
    .udma_fd = 0,
    .size = size,
    .type = static_cast<uint32_t>(type),
  };
  m_pdev.ioctl(DRM_IOCTL_AMDXDNA_CREATE_BO, &cbo);
  return cbo.handle;
}

void
bo::
get_drm_bo_info(uint32_t boh, amdxdna_drm_get_bo_info* bo_info)
{
  bo_info->handle = boh;
  m_pdev.ioctl(DRM_IOCTL_AMDXDNA_GET_BO_INFO, bo_info);
}

void
bo::
free_drm_bo(uint32_t boh)
{
  drm_gem_close close_bo = {boh, 0};
  m_pdev.ioctl(DRM_IOCTL_GEM_CLOSE, &close_bo);
}

} // namespace shim_xdna

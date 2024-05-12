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

void
attach_dbg_drm_bo(const shim_xdna::pdev& dev, uint32_t boh, uint32_t ctx_id)
{
  amdxdna_drm_config_hwctx adbo = {
    .handle = ctx_id,
    .param_type = DRM_AMDXDNA_HWCTX_ASSIGN_DBG_BUF,
    .param_val = boh,
  };
  dev.ioctl(DRM_IOCTL_AMDXDNA_CONFIG_HWCTX, &adbo);
}

void
detach_dbg_drm_bo(const shim_xdna::pdev& dev, uint32_t boh, uint32_t ctx_id)
{
  amdxdna_drm_config_hwctx adbo = {
    .handle = ctx_id,
    .param_type = DRM_AMDXDNA_HWCTX_REMOVE_DBG_BUF,
    .param_val = boh,
  };
  dev.ioctl(DRM_IOCTL_AMDXDNA_CONFIG_HWCTX, &adbo);
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
  amdxdna_bo_type *type, size_t *size)
{
  xrt_core::shared_handle::export_handle fd = share.get_export_handle();
  drm_prime_handle imp_bo = {AMDXDNA_INVALID_BO_HANDLE, 0, fd};
  dev.ioctl(DRM_IOCTL_PRIME_FD_TO_HANDLE, &imp_bo);

  *type = AMDXDNA_BO_SHMEM;
  *size = lseek(fd, 0, SEEK_END);
  lseek(fd, 0, SEEK_SET);

  return imp_bo.handle;
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
    free_drm_bo(m_parent.m_pdev, m_handle);
  } catch (const xrt_core::system_error& e) {
    shim_debug("Failed to free DRM BO: %s", e.what());
  }
}

std::string
bo::
type_to_name() const
{
  switch (m_type) {
  case AMDXDNA_BO_SHMEM:
    return std::string("AMDXDNA_BO_SHMEM");
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

void
bo::
import_bo()
{
  uint32_t boh = import_drm_bo(m_pdev, m_import, &m_type, &m_size);

  amdxdna_drm_get_bo_info bo_info = {};
  get_drm_bo_info(m_pdev, boh, &bo_info);
  m_bo = std::make_unique<bo::drm_bo>(*this, bo_info);
}

void
bo::
free_bo()
{
  m_bo.reset();
}

bo::
bo(const device& device, xrt_core::hwctx_handle::slot_id ctx_id,
  size_t size, uint64_t flags, amdxdna_bo_type type)
  : m_pdev(device.get_pdev())
  , m_size(size)
  , m_flags(flags)
  , m_type(type)
  , m_import(-1)
  , m_owner_ctx_id(ctx_id)
{
}

bo::
bo(const device& device, xrt_core::shared_handle::export_handle ehdl)
  : m_pdev(device.get_pdev())
  , m_import(ehdl)
{
}

bo::
~bo()
{
  if (m_mmap_cnt)
    shim_debug("Non-zero mmap cnt: %d", m_mmap_cnt.load());
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
    void *p = map_drm_bo(m_pdev, m_size, prot, m_bo->m_map_offset);
    m_mmap_cnt++;
    return p;
  }
  return m_buf;
}

void
bo::
unmap(void* addr)
{
  if (m_mmap_cnt > 0) {
    unmap_drm_bo(m_pdev, addr, m_size);
    m_mmap_cnt--;
  }
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

void
bo::
attach_to_ctx()
{
  if (m_owner_ctx_id == AMDXDNA_INVALID_CTX_HANDLE)
    return;

  // Currently, only debug BO is supported.
  if (xcl_bo_flags{m_flags}.use != XRT_BO_USE_DEBUG)
    shim_err(EINVAL, "Bad BO type to attach to HW ctx");

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

  // Currently, only debug BO is supported.
  if (xcl_bo_flags{m_flags}.use != XRT_BO_USE_DEBUG)
    shim_err(EINVAL, "Bad BO type to detach from HW ctx");

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

} // namespace shim_xdna

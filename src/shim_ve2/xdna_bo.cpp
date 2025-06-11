// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2025, Advanced Micro Devices, Inc. All rights reserved.

#include <unistd.h>

#include "core/common/query_requests.h"
#include "xdna_bo.h"

namespace shim_xdna_edge {
static void
init_metadata_buffer(xdna_bo& mdata_base_bo,
		     uint32_t boh,
		     uint32_t total_cols,
		     uint32_t flag,
		     std::map<uint32_t, size_t> buf_sizes,
		     bool attach)
{
  struct fw_buffer_metadata *mdata =
      reinterpret_cast<struct fw_buffer_metadata*>(mdata_base_bo.map(xrt_core::buffer_handle::map_type::write));

  if (flag == XRT_BO_USE_DEBUG || flag == XRT_BO_USE_UC_DEBUG)
    mdata->buf_type = AMDXDNA_FW_BUF_DEBUG;
  if (flag == XRT_BO_USE_DTRACE)
    mdata->buf_type = AMDXDNA_FW_BUF_TRACE;
  if (flag == XRT_BO_USE_LOG)
    mdata->buf_type = AMDXDNA_FW_BUF_LOG;

  if (attach) {
    mdata->num_ucs = total_cols;
    mdata->bo_handle = boh;
    for (const auto& pair : buf_sizes) {
      mdata->uc_info[pair.first].index = pair.first;
      mdata->uc_info[pair.first].size = pair.second;
    }
  }
}

static void
config_drm_bo(std::shared_ptr<xdna_edgedev> m_edev,
	      uint32_t ctx_id,
	      uint32_t mdata_boh,
	      uint32_t mdata_size,
	      bool attach)
{
  amdxdna_drm_config_ctx adbo;
  adbo.handle = ctx_id;
  adbo.param_val = mdata_boh;
  adbo.param_val_size = mdata_size;

  if (attach)
    adbo.param_type = DRM_AMDXDNA_CTX_ASSIGN_DBG_BUF;
  else
    adbo.param_type = DRM_AMDXDNA_CTX_REMOVE_DBG_BUF;

  m_edev->ioctl(DRM_IOCTL_AMDXDNA_CONFIG_CTX, &adbo);
}

static uint32_t
get_total_cols(const xrt_core::device *device, xrt_core::hwctx_handle::slot_id ctx_id)
{
  uint32_t total_cols = 0;
  auto data = xrt_core::device_query_default<xrt_core::query::aie_partition_info>(device, {});

  for (const auto& entry : data) {
    if (std::stoi(entry.metadata.id) == ctx_id) {
      total_cols = entry.num_cols;
      break;
    }
  }
  return total_cols;
}

std::string
xdna_bo::
type_to_name() const
{
  switch (m_type) {
  case AMDXDNA_BO_SHARE:
    return std::string("AMDXDNA_BO_SHARE");
  case AMDXDNA_BO_DEV_HEAP:
    return std::string("AMDXDNA_BO_DEV_HEAP");
  case AMDXDNA_BO_DEV:
    if (xcl_bo_flags{m_flags}.use == XRT_BO_USE_DEBUG ||
        xcl_bo_flags{m_flags}.use == XRT_BO_USE_UC_DEBUG)
      return std::string("AMDXDNA_BO_DEV_DEBUG");
    return std::string("AMDXDNA_BO_DEV");
  case AMDXDNA_BO_CMD:
    return std::string("AMDXDNA_BO_CMD");
  }
  return std::string("BO_UNKNOWN");
}

std::string
xdna_bo::
describe() const
{
  std::string desc = "type=";
  desc += type_to_name();
  desc += ", ";
  desc += "drm_bo=";
  desc += std::to_string(m_handle);
  desc += ", ";
  desc += "size=";
  desc += std::to_string(m_aligned_size);
  return desc;
}

xdna_bo::
xdna_bo(const device_xdna& device, xrt_core::hwctx_handle::slot_id ctx_id,
  size_t size, uint64_t flags, uint32_t type)
  : m_core_device(&device)
  , m_edev(device.get_edev())
  , m_aligned_size(size)
  , m_flags(flags)
  , m_type(type)
  , m_import(-1)
  , m_owner_ctx_id(ctx_id)
  , m_map_offset(0)
{
  alloc_bo();
  if (m_type == AMDXDNA_BO_SHARE)
    sync(direction::host2device, size, 0);

  xcl_bo_flags xflags{ m_flags };
  if (xflags.use == XRT_BO_USE_DEBUG || xflags.use == XRT_BO_USE_DTRACE ||
      xflags.use == XRT_BO_USE_LOG || xflags.use == XRT_BO_USE_UC_DEBUG)
    attach_to_ctx(xflags.use);

  shim_debug("Allocated DRM BO (userptr=0x%lx, size=%ld, flags=0x%llx, type=%d, drm_bo=%d)",
	     m_ptr, m_aligned_size, m_flags, m_type, get_drm_bo_handle());
}

xdna_bo::
xdna_bo(const device_xdna& device, xrt_core::shared_handle::export_handle ehdl)
  : m_edev(device.get_edev())
  , m_import(ehdl)
{
  uint32_t boh = shim_xdna_edge::xdna_bo::import_drm_bo(m_import, &m_type, &m_aligned_size);
  shim_xdna_edge::xdna_bo::get_drm_bo_info(boh);
}

// SAIF TODO FIXME
#if 0
xdna_bo::
xdna_bo(const device_xdna& device, const amdxdna_drm_get_bo_info& bo_info)
	: m_edev(device.get_edev())
	, m_handle(bo_info.handle)
	, m_map_offset(bo_info.map_offset)
	, m_vaddr(bo_info.vaddr)
	, m_xdna_addr(bo_info.xdna_addr)
{
}
#endif

xdna_bo::
~xdna_bo()
{
  if (m_handle == 1)
	return;

  xcl_bo_flags xflags{ m_flags };
  if (xflags.use == XRT_BO_USE_DEBUG || xflags.use == XRT_BO_USE_DTRACE ||
      xflags.use == XRT_BO_USE_LOG || xflags.use == XRT_BO_USE_UC_DEBUG)
    detach_from_ctx(xflags.use);

  drm_gem_close close_bo = {m_handle, 0};
  m_edev->ioctl(DRM_IOCTL_GEM_CLOSE, &close_bo);
}

void
xdna_bo::
mmap_bo(bool is_write)
{
  m_ptr = m_edev->mmap(0, m_aligned_size, (is_write ? (PROT_READ|PROT_WRITE) : PROT_READ),
		       MAP_SHARED | MAP_LOCKED, m_map_offset);

  shim_debug("%s: mmap return %p", __func__, m_ptr);
}

void
xdna_bo::
munmap_bo()
{
  shim_debug("Unmap BO, aligned %p", m_ptr);
  if (m_map_offset == AMDXDNA_INVALID_ADDR)
      return;

  m_edev->munmap(m_ptr, m_aligned_size);
}

void
xdna_bo::
alloc_bo()
{
  amdxdna_drm_create_bo cbo = {
    .size = m_aligned_size,
    .type = m_type,
  };
  m_edev->ioctl(DRM_IOCTL_AMDXDNA_CREATE_BO, &cbo);

  // Cache the BO info here
  get_drm_bo_info(cbo.handle);
#if 0
  uint32_t boh = alloc_drm_bo(m_pdev, m_type, NULL, m_aligned_size);

  amdxdna_drm_get_bo_info bo_info = {};
  get_drm_bo_info(m_pdev, boh, &bo_info);
  m_bo = std::make_unique<bo::drm_bo>(*this, bo_info);
  m_pdev.insert_hdl_mapping(boh, reinterpret_cast<uint64_t>(this));
#endif
}

void
xdna_bo::
free_bo()
{
#if 0
  m_pdev.remove_hdl_mapping(get_drm_bo_handle());
  m_bo.reset();
#endif
}

xdna_bo::properties
xdna_bo::
get_properties() const
{
  return xrt_core::buffer_handle::properties{m_flags, m_aligned_size, get_paddr(), get_drm_bo_handle()};
}

uint64_t
xdna_bo::
get_paddr() const
{
  if (m_xdna_addr != AMDXDNA_INVALID_ADDR)
    return m_xdna_addr;

  return reinterpret_cast<uintptr_t>(m_ptr);
}

void
xdna_bo::
set_cmd_id(uint64_t id)
{
  m_cmd_id = id;
}

uint64_t
xdna_bo::
get_cmd_id() const
{
  return m_cmd_id;
}

void
xdna_bo::
get_drm_bo_info(uint32_t boh)
{
  amdxdna_drm_get_bo_info bo_info = {};
  bo_info.handle = boh;
  m_edev->ioctl(DRM_IOCTL_AMDXDNA_GET_BO_INFO, &bo_info);

  m_handle = bo_info.handle;
  m_map_offset = bo_info.map_offset;
  m_vaddr = bo_info.vaddr;
  m_xdna_addr = bo_info.xdna_addr;
}

void
xdna_bo::
bind_at(size_t pos, const xrt_core::buffer_handle* bh, size_t offset, size_t size)
{
  auto boh = reinterpret_cast<const xdna_bo*>(bh);
  std::lock_guard<std::mutex> lg(m_args_map_lock);

  if (m_type != AMDXDNA_BO_CMD)
    shim_err(EINVAL, "Can't call bind_at() on non-cmd BO");

  if (!pos)
    m_args_map.clear();

  if (boh->get_type() != AMDXDNA_BO_CMD) {
    auto h = boh->get_drm_bo_handle();
    m_args_map[pos] = h;
    shim_debug("Added arg BO %d to cmd BO %d", h, get_drm_bo_handle());
  } else {
    const size_t max_args_order = 6;
    const size_t max_args = 1 << max_args_order;
    size_t key = pos << max_args_order;
    uint32_t hs[max_args];
    auto arg_cnt = boh->get_arg_bo_handles(hs, max_args);
    std::string bohs;
    for (int i = 0; i < arg_cnt; i++) {
	m_args_map[key + i] = hs[i];
	bohs += std::to_string(hs[i]) + " ";
    }
    shim_debug("Added arg BO %s to cmd BO %d", bohs.c_str(), get_drm_bo_handle());
  }
}

uint32_t
xdna_bo::
get_arg_bo_handles(uint32_t *handles, size_t num) const
{
  std::lock_guard<std::mutex> lg(m_args_map_lock);

  auto sz = m_args_map.size();
  if (sz > num)
    shim_err(E2BIG, "There are %ld BO args, provided buffer can hold only %ld", sz, num);

  for (auto m : m_args_map)
    *(handles++) = m.second;

  return sz;
}

uint32_t
xdna_bo::
get_drm_bo_handle() const
{
  return m_handle;
}

void
xdna_bo::
config(xrt_core::hwctx_handle* ctx, const std::map<uint32_t, size_t>& buf_sizes)
{
  if (m_owner_ctx_id == AMDXDNA_INVALID_CTX_HANDLE)
    return;

  xcl_bo_flags xflags{ m_flags };
  auto boh = get_drm_bo_handle();
  auto total_cols = get_total_cols(m_core_device, m_owner_ctx_id);
  auto mdata_size = sizeof(struct fw_buffer_metadata) + total_cols * sizeof(struct uc_info_entry);

  auto xdev = static_cast<const device_xdna*>(m_core_device);
  xdna_bo mdata_bo = xdna_bo(*xdev, m_owner_ctx_id, mdata_size, XCL_BO_FLAGS_CACHEABLE, AMDXDNA_BO_DEV);
  init_metadata_buffer(mdata_bo, boh, total_cols, xflags.use, buf_sizes, true);

  shim_debug("Configuring BO %d on ctx: %d", boh, m_owner_ctx_id);
  config_drm_bo(m_edev, m_owner_ctx_id, mdata_bo.get_drm_bo_handle(), mdata_size, true);
}

void
xdna_bo::
attach_to_ctx(uint32_t flag)
{
  if (m_owner_ctx_id == AMDXDNA_INVALID_CTX_HANDLE)
    return;

  auto boh = get_drm_bo_handle();
  uint32_t total_cols = get_total_cols(m_core_device, m_owner_ctx_id);
  if(total_cols == 0)
    throw xrt_core::error(-EINVAL, "attach_to_ctx: partition info not found");

  auto buf_size = get_properties().size;
  std::map<uint32_t, size_t> buf_sizes;
  for (int i = 0; i < total_cols; ++i)
    buf_sizes[i] = buf_size / total_cols;

  auto mdata_size = sizeof(struct fw_buffer_metadata) + total_cols * sizeof(struct uc_info_entry);
  auto xdev = static_cast<const device_xdna*>(m_core_device);
  xdna_bo mdata_bo = xdna_bo(*xdev, m_owner_ctx_id, mdata_size, XCL_BO_FLAGS_CACHEABLE, AMDXDNA_BO_DEV);
  init_metadata_buffer(mdata_bo, boh, total_cols, flag, buf_sizes, true);
  shim_debug("Attaching drm_bo %d to ctx: %d", boh, m_owner_ctx_id);
  config_drm_bo(m_edev, m_owner_ctx_id, mdata_bo.get_drm_bo_handle(), mdata_size, true);
}

void
xdna_bo::
detach_from_ctx(uint32_t flag)
{
  if (m_owner_ctx_id == AMDXDNA_INVALID_CTX_HANDLE)
    return;

  auto boh = get_drm_bo_handle();
  auto mdata_size = sizeof(struct fw_buffer_metadata);
  auto xdev = static_cast<const device_xdna*>(m_core_device);
  xdna_bo mdata_bo = xdna_bo(*xdev, m_owner_ctx_id, mdata_size, XCL_BO_FLAGS_CACHEABLE, AMDXDNA_BO_DEV);
  init_metadata_buffer(mdata_bo, 0, 0, flag, std::map<uint32_t, size_t>{}, false);
  shim_debug("Detaching drm_bo %d from ctx: %d", boh, m_owner_ctx_id);
  config_drm_bo(m_edev, m_owner_ctx_id, mdata_bo.get_drm_bo_handle(), mdata_size, false);
}

std::unique_ptr<xrt_core::shared_handle>
xdna_bo::
share() const
{
  auto boh = get_drm_bo_handle();
  auto fd = export_drm_bo(boh);
  shim_debug("Exported bo %d to fd %d", boh, fd);
  return std::make_unique<shared>(fd);
}

uint32_t
xdna_bo::
get_type() const
{
  return m_type;
}

void *
xdna_bo::
map(map_type m_type)
{
  mmap_bo(m_type == xrt_core::buffer_handle::map_type::write);

  return m_ptr;
}

void
xdna_bo::
unmap(void *addr)
{
  munmap_bo();
}

void
xdna_bo::
sync(direction dir, size_t size, size_t offset)
{
  auto boh = get_drm_bo_handle();
  __u32 direction = static_cast<__u32>(dir);
  amdxdna_drm_sync_bo sync_bo = {boh, direction, offset, size};
  m_edev->ioctl(DRM_IOCTL_AMDXDNA_SYNC_BO, &sync_bo);
}

int
xdna_bo::
export_drm_bo(uint32_t boh) const
{
  drm_prime_handle exp_bo = {boh, DRM_RDWR | DRM_CLOEXEC, -1};
  m_edev->ioctl(DRM_IOCTL_PRIME_HANDLE_TO_FD, &exp_bo);
  return exp_bo.fd;
}

uint32_t
xdna_bo::
import_drm_bo(const shim_xdna_edge::shared& share,uint32_t *type, size_t *size) const
{
  xrt_core::shared_handle::export_handle fd = share.get_export_handle();
  drm_prime_handle imp_bo = {AMDXDNA_INVALID_BO_HANDLE, 0, fd};
  m_edev->ioctl(DRM_IOCTL_PRIME_FD_TO_HANDLE, &imp_bo);
  *type = AMDXDNA_BO_SHARE;
  *size = lseek(fd, 0, SEEK_END);
  lseek(fd, 0, SEEK_SET);

  return imp_bo.handle;
}

} // namespace shim_xdna

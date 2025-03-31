// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2025, Advanced Micro Devices, Inc. All rights reserved.

#include "bo.h"
#include "pcidev.h"
#include "drm_local/amdxdna_accel.h"
#include "amdxdna_proto.h"

#include <drm/virtgpu_drm.h>

namespace {

int
flag_to_type(uint64_t bo_flags)
{
  auto flags = xcl_bo_flags{bo_flags};
  auto boflags = (static_cast<uint32_t>(flags.boflags) << 24);
  switch (boflags) {
  case XCL_BO_FLAGS_HOST_ONLY:
    return AMDXDNA_BO_SHARE;
  case XCL_BO_FLAGS_CACHEABLE:
    return AMDXDNA_BO_DEV;
  case XCL_BO_FLAGS_EXECBUF:
    return AMDXDNA_BO_CMD;
  default:
    break;
  }
  return AMDXDNA_BO_INVALID;
}

std::pair<uint32_t, uint32_t>
drm_bo_alloc(const shim_xdna::pdev& dev, size_t size)
{
  drm_virtgpu_resource_create_blob args = {
    .blob_mem   = VIRTGPU_BLOB_MEM_GUEST,
    .blob_flags = VIRTGPU_BLOB_FLAG_USE_MAPPABLE,
    .size       = size,
  };
  dev.ioctl(DRM_IOCTL_VIRTGPU_RESOURCE_CREATE_BLOB, &args);
  return {args.bo_handle, args.res_handle};
}

void
drm_bo_free(const shim_xdna::pdev& dev, uint32_t boh)
{
  if (boh == AMDXDNA_INVALID_BO_HANDLE)
    return;

  drm_gem_close close_bo = {
    .handle = boh
  };
  dev.ioctl(DRM_IOCTL_GEM_CLOSE, &close_bo);
}

uint64_t
drm_bo_get_map_offset(const shim_xdna::pdev& dev, uint32_t boh)
{
  if (boh == AMDXDNA_INVALID_BO_HANDLE)
    return AMDXDNA_INVALID_ADDR;

  drm_virtgpu_map args = {
    .handle = boh,
  };
  dev.ioctl(DRM_IOCTL_VIRTGPU_MAP, &args);
  return args.offset;
}

std::pair<uint32_t, uint64_t>
host_bo_alloc(const shim_xdna::pdev& dev, int type, size_t size, uint32_t res_id, uint64_t align)
{
  const shim_xdna::pdev_virtio& vdev = static_cast<const shim_xdna::pdev_virtio&>(dev);
  amdxdna_ccmd_create_bo_req req = {};
  amdxdna_ccmd_create_bo_rsp rsp = {};

  req.hdr.cmd = AMDXDNA_CCMD_CREATE_BO;
  req.hdr.len = sizeof(req);
  req.hdr.rsp_off = 0;
  req.res_id = res_id;
  req.bo_type = type;
  req.size = size;
  req.map_align = align;
  vdev.host_call(&req, sizeof(req), &rsp, sizeof(rsp));
  return { rsp.handle, rsp.xdna_addr };
}

void
host_bo_free(const shim_xdna::pdev& dev, uint32_t host_hdl)
{
  const shim_xdna::pdev_virtio& vdev = static_cast<const shim_xdna::pdev_virtio&>(dev);
  amdxdna_ccmd_destroy_bo_req req = {};

  req.hdr.cmd = AMDXDNA_CCMD_DESTROY_BO;
  req.hdr.len = sizeof(req);
  req.hdr.rsp_off = 0;
  req.handle = host_hdl;
  vdev.host_call(&req, sizeof(req), nullptr, 0);
}

}

namespace shim_xdna {

bo_virtio::
bo_virtio(const pdev& pdev, xrt_core::hwctx_handle::slot_id ctx_id,
  size_t size, uint64_t flags)
  : bo_virtio(pdev, ctx_id, size, flags, flag_to_type(flags))
{
  if (m_type == AMDXDNA_BO_INVALID)
    shim_err(EINVAL, "Invalid BO flags: 0x%lx", flags);
}

bo_virtio::
bo_virtio(const pdev& pdev, size_t size, int type)
  : bo_virtio(pdev, AMDXDNA_INVALID_CTX_HANDLE, size, 0, type)
{
}

bo_virtio::
bo_virtio(const pdev& pdev, xrt_core::hwctx_handle::slot_id ctx_id,
  size_t size, uint64_t flags, int type)
  : bo(pdev, ctx_id, size, flags, type)
{
  alloc_bo();
  mmap_bo();

  // Newly allocated buffer may contain dirty pages. If used as output buffer,
  // the data in cacheline will be flushed onto memory and pollute the output
  // from device. We perform a cache flush right after the BO is allocated to
  // avoid this issue.
  if (m_type == AMDXDNA_BO_SHARE)
    sync(direction::host2device, size, 0);

  shim_debug("Allocated VIRTIO BO, %s, host=%d", describe().c_str(), m_host_handle);
}

bo_virtio::
~bo_virtio()
{
  shim_debug("Freeing VIRTIO BO, %s", describe().c_str());

  munmap_bo();
  try {
    // If BO is in use, we should block and wait in driver
    free_bo();
  } catch (const xrt_core::system_error& e) {
    shim_debug("Failed to free BO: %s", e.what());
  }
}

void
bo_virtio::
sync(direction dir, size_t size, size_t offset)
{
  if (offset + size > m_aligned_size)
    shim_err(EINVAL, "Invalid BO offset and size for sync'ing: %ld, %ld", offset, size);
  shim_xdna::clflush_data(m_aligned, offset, size); 
}

uint32_t
bo_virtio::
alloc_drm_bo(int type, size_t size)
{
  uint32_t boh = AMDXDNA_INVALID_BO_HANDLE;
  uint32_t resh = AMDXDNA_INVALID_BO_HANDLE;

  if (type != AMDXDNA_BO_DEV) {
    auto p = drm_bo_alloc(m_pdev, size);
    boh = p.first;
    resh = p.second;
  }
  auto p = host_bo_alloc(m_pdev, type, size, resh, m_alignment);
  m_host_handle = p.first;
  m_xdna_addr = p.second;

  return boh;
}

void
bo_virtio::
get_drm_bo_info(uint32_t boh, amdxdna_drm_get_bo_info* bo_info)
{
  const shim_xdna::pdev_virtio& vdev = static_cast<const shim_xdna::pdev_virtio&>(m_pdev);

  bo_info->handle = boh;
  bo_info->map_offset = drm_bo_get_map_offset(m_pdev, boh);
  bo_info->vaddr = m_type == AMDXDNA_BO_DEV ? vdev.get_dev_bo_vaddr(m_xdna_addr) : 0;
  bo_info->xdna_addr = m_xdna_addr;
}

void
bo_virtio::
free_drm_bo(uint32_t boh)
{
  host_bo_free(m_pdev, m_host_handle);
  drm_bo_free(m_pdev, boh);
}

uint32_t
bo_virtio::
get_host_bo_handle() const
{
  return m_host_handle;
}

} // namespace shim_xdna

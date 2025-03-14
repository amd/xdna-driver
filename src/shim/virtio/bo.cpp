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

std::tuple<uint32_t, uint32_t>
drm_bo_alloc(const shim_xdna::pdev& dev, size_t size)
{
  drm_virtgpu_resource_create_blob args = {
    .blob_mem   = VIRTGPU_BLOB_MEM_GUEST,
    .blob_flags = VIRTGPU_BLOB_FLAG_USE_MAPPABLE,
    .size       = size,
    .blob_id    = 0,
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
  drm_virtgpu_map args = {
    .handle = boh,
  };
  dev.ioctl(DRM_IOCTL_VIRTGPU_MAP, &args);
  return args.offset;
}

uint64_t
drm_bo_get_xdna_addr(const shim_xdna::pdev& dev, uint32_t resh, uint64_t align)
{
  const shim_xdna::pdev_virtio& vdev = static_cast<const shim_xdna::pdev_virtio&>(dev);
  amdxdna_ccmd_map_bo_req req = {};
  amdxdna_ccmd_map_bo_rsp rsp = {};

  req.hdr.cmd = AMDXDNA_CCMD_MAP_BO;
  req.hdr.len = sizeof(req);
  req.hdr.rsp_off = 0;
  req.res_id = resh;
  req.alignment = align;
  vdev.host_call(&req, sizeof(req), &rsp, sizeof(rsp));
  return rsp.iov_addr;
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

  shim_debug("Allocated VIRTIO BO, %s", describe().c_str());
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
  auto [ boh, resh ] = drm_bo_alloc(m_pdev, size);
  m_res_handle = resh;
  return boh;
}

void
bo_virtio::
get_drm_bo_info(uint32_t boh, amdxdna_drm_get_bo_info* bo_info)
{
  bo_info->handle = boh;
  bo_info->map_offset = drm_bo_get_map_offset(m_pdev, boh);
  bo_info->vaddr = 0;
  bo_info->xdna_addr = drm_bo_get_xdna_addr(m_pdev, m_res_handle, m_alignment);
}

void
bo_virtio::
free_drm_bo(uint32_t boh)
{
  drm_bo_free(m_pdev, boh);
}

} // namespace shim_xdna

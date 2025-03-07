// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2025, Advanced Micro Devices, Inc. All rights reserved.

#include "device.h"
#include "pcidev.h"

namespace {

const size_t shmem_size = 0x1000;

uint32_t
alloc_shmem(const shim_xdna::pdev& dev)
{
  drm_virtgpu_resource_create_blob args = {
    .blob_mem   = VIRTGPU_BLOB_MEM_HOST3D,
    .blob_flags = VIRTGPU_BLOB_FLAG_USE_MAPPABLE,
    .size       = shmem_size,
    .blob_id    = 0,
  };
  dev.ioctl(DRM_IOCTL_VIRTGPU_RESOURCE_CREATE_BLOB, &args);
  return args.bo_handle;
}

void
free_shmem(const shim_xdna::pdev& dev, uint32_t boh)
{
  drm_gem_close close_bo = {
    .handle = boh
  };
  dev.ioctl(DRM_IOCTL_GEM_CLOSE, &close_bo);
}

void *
map_shmem(const shim_xdna::pdev& dev, uint32_t boh)
{
  drm_virtgpu_map args = {
    .handle = boh,
  };
  dev.ioctl(DRM_IOCTL_VIRTGPU_MAP, &args);
  return dev.mmap(0, shmem_size, PROT_READ | PROT_WRITE, MAP_SHARED, args.offset);
}

void
unmap_shmem(const shim_xdna::pdev& dev, void *shmem)
{
  dev.munmap(shmem, shmem_size);
}

}

namespace shim_xdna {

pdev_virtio::
pdev_virtio(std::shared_ptr<const drv_virtio> driver, std::string sysfs_name)
  : pdev(driver, sysfs_name), m_shmem(nullptr)
{
  shim_debug("Created VIRTIO pcidev over %s", sysfs_name.c_str());
}

pdev_virtio::
~pdev_virtio()
{
  shim_debug("Destroying VIRTIO pcidev");
}

std::shared_ptr<xrt_core::device>
pdev_virtio::
create_device(xrt_core::device::handle_type handle, xrt_core::device::id_type id) const
{
  return std::make_shared<device_virtio>(*this, handle, id);
}

void
pdev_virtio::
on_first_open() const
{
  shim_debug("Setting up response shmem");
  m_shmem_bo_hdl = alloc_shmem(*this);
  m_shmem = reinterpret_cast<vdrm_shmem *>(map_shmem(*this, m_shmem_bo_hdl));
}

void
pdev_virtio::
on_last_close() const
{
  shim_debug("Tearing down response shmem");
  unmap_shmem(*this, m_shmem);
  free_shmem(*this, m_shmem_bo_hdl);
}

} // namespace shim_xdna


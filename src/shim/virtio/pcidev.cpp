// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2025, Advanced Micro Devices, Inc. All rights reserved.

#include "bo.h"
#include "device.h"
#include "pcidev.h"
#include "amdxdna_proto.h"
#include "core/common/config_reader.h"

#include <poll.h>
#include <drm/virtgpu_drm.h>

namespace {

const size_t resp_buf_size = 0x1000;
// Device memory heap needs to be multiple of 64MB page.
const size_t heap_page_size = (64 << 20);

unsigned int
get_heap_num_pages()
{
  static unsigned int num = 0;

  if (!num)
    num = xrt_core::config::detail::get_uint_value("Debug.num_heap_pages", 1);
  return num;
}

std::tuple<uint32_t, uint32_t>
alloc_resp_buf(const shim_xdna::pdev& dev)
{
  drm_virtgpu_resource_create_blob args = {
    .blob_mem   = VIRTGPU_BLOB_MEM_GUEST,
    .blob_flags = VIRTGPU_BLOB_FLAG_USE_MAPPABLE,
    .size       = resp_buf_size,
    .blob_id    = 0,
  };
  dev.ioctl(DRM_IOCTL_VIRTGPU_RESOURCE_CREATE_BLOB, &args);
  return {args.bo_handle, args.res_handle};
}

void
free_resp_buf(const shim_xdna::pdev& dev, uint32_t boh)
{
  if (boh == AMDXDNA_INVALID_BO_HANDLE)
    return;

  drm_gem_close close_bo = {
    .handle = boh
  };
  dev.ioctl(DRM_IOCTL_GEM_CLOSE, &close_bo);
}

void
hcall_no_resp(const shim_xdna::pdev& dev, void *in_buf, size_t in_size)
{
  drm_virtgpu_execbuffer exec = {};

  exec.command = reinterpret_cast<uintptr_t>(in_buf);
  exec.size = in_size;
  dev.ioctl(DRM_IOCTL_VIRTGPU_EXECBUFFER, &exec);
}

void
sync_wait(int fd, int timeout)
{
  struct timespec poll_start, poll_end;
  struct pollfd fds = {0};
  int ret;

  fds.fd = fd;
  fds.events = POLLIN;
  while (true) {
    clock_gettime(CLOCK_MONOTONIC, &poll_start);
    ret = poll(&fds, 1, timeout);
    clock_gettime(CLOCK_MONOTONIC, &poll_end);

    if (ret > 0) {
      if (fds.revents & (POLLERR | POLLNVAL))
        shim_err(-EINVAL, "failed to wait for host call response");
      break;
    }
    if (ret == 0)
      shim_err(-ETIME, "wait for host call response timeout");
    if (ret < 0 && errno != EINTR && errno != EAGAIN)
      shim_err(-errno, "failed to wait for host call response");

    timeout -= (poll_end.tv_sec - poll_start.tv_sec) * 1000 +
      (poll_end.tv_nsec - poll_end.tv_nsec) / 1000000;
  }
}

void
hcall(const shim_xdna::pdev& dev, void *in_buf, size_t in_size)
{
  drm_virtgpu_execbuffer exec = {};

  exec.flags = VIRTGPU_EXECBUF_FENCE_FD_OUT | VIRTGPU_EXECBUF_RING_IDX;
  exec.command = reinterpret_cast<uintptr_t>(in_buf);
  exec.size = in_size;
  exec.fence_fd = 0;
  exec.ring_idx = 1;
  dev.ioctl(DRM_IOCTL_VIRTGPU_EXECBUFFER, &exec);
  sync_wait(exec.fence_fd, -1);
  close(exec.fence_fd);
}

void
init_resp_buf(const shim_xdna::pdev& dev, uint32_t res_hdl)
{
  if (res_hdl == AMDXDNA_INVALID_BO_HANDLE)
    return;

  amdxdna_ccmd_init_req init_req = {};

  init_req.hdr.cmd = AMDXDNA_CCMD_INIT;
  init_req.hdr.len = sizeof(init_req);
  init_req.rsp_res_id = res_hdl;
  hcall_no_resp(dev, &init_req, sizeof(init_req));
}

void
fini_resp_buf(const shim_xdna::pdev& dev, uint32_t res_hdl)
{
  if (res_hdl == AMDXDNA_INVALID_BO_HANDLE)
    return;
}

void *
map_resp_buf(const shim_xdna::pdev& dev, uint32_t boh)
{
  drm_virtgpu_map args = {
    .handle = boh,
  };
  dev.ioctl(DRM_IOCTL_VIRTGPU_MAP, &args);
  return dev.mmap(0, resp_buf_size, PROT_READ | PROT_WRITE, MAP_SHARED, args.offset);
}

void
unmap_resp_buf(const shim_xdna::pdev& dev, void *resp_buf)
{
  if (!resp_buf)
    return;
  dev.munmap(resp_buf, resp_buf_size);
}

void
set_virtgpu_context(const shim_xdna::pdev& dev)
{
  struct drm_virtgpu_context_set_param params[] = {
    { VIRTGPU_CONTEXT_PARAM_CAPSET_ID, 6 /* VIRGL_RENDERER_CAPSET_DRM */ },
    { VIRTGPU_CONTEXT_PARAM_NUM_RINGS, 64 },
  };
  struct drm_virtgpu_context_init args = {
    .num_params = 2,
    .ctx_set_params = (uintptr_t)params,
  };

  dev.ioctl(DRM_IOCTL_VIRTGPU_CONTEXT_INIT, &args);
}

}

namespace shim_xdna {

pdev_virtio::
pdev_virtio(std::shared_ptr<const drv_virtio> driver, std::string sysfs_name)
  : pdev(driver, sysfs_name), m_resp_buf(nullptr)
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
  shim_debug("Setting up response buffer");

  set_virtgpu_context(*this);

  auto [m_resp_buf_bo_hdl, m_resp_buf_res_hdl] = alloc_resp_buf(*this);
  m_resp_buf = map_resp_buf(*this, m_resp_buf_bo_hdl);
  init_resp_buf(*this, m_resp_buf_res_hdl);

  // Allocating heap BO (require response buffer init'ed above) on first open
  auto heap_sz = heap_page_size * get_heap_num_pages();
  m_dev_heap_bo = std::make_unique<bo_virtio>(*this, heap_sz, AMDXDNA_BO_DEV_HEAP);
}

void
pdev_virtio::
on_last_close() const
{
  m_dev_heap_bo.reset();

  shim_debug("Tearing down response buffer");
  fini_resp_buf(*this, m_resp_buf_res_hdl);
  unmap_resp_buf(*this, m_resp_buf);
  free_resp_buf(*this, m_resp_buf_bo_hdl);
}

void
pdev_virtio::
host_call(void *in_buf, size_t in_size, void *out_buf, size_t out_size) const
{
  const std::lock_guard<std::mutex> lock(m_lock);
  auto sz = out_size;

  if (sz > resp_buf_size)
    sz = resp_buf_size;

  hcall(*this, in_buf, in_size);
  if (out_buf)
    memcpy(out_buf, m_resp_buf, sz);
}

uint32_t
pdev_virtio::
get_unique_id() const
{
  return ++m_id;
}

uint64_t
pdev_virtio::
get_dev_bo_vaddr(uint64_t dev_bo_xdna_addr) const
{
  uint64_t xdna_addr = m_dev_heap_bo->get_properties().paddr;
  uint64_t vaddr = reinterpret_cast<uint64_t>(m_dev_heap_bo->map(bo::map_type::write));
  return vaddr + (dev_bo_xdna_addr - xdna_addr);
}

} // namespace shim_xdna


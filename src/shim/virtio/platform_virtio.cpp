// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2025, Advanced Micro Devices, Inc. All rights reserved.

#include "../shim_debug.h"
#include "drm_local/amdxdna_accel.h"
#include "amdxdna_proto.h"
#include "platform_virtio.h"
#include "core/common/trace.h"
#include <poll.h>
#include <cstring>
#include <iostream>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <drm/virtgpu_drm.h>

namespace {

const size_t resp_buffer_size = 0x1000;

std::string
ioctl_cmd2name(unsigned long cmd)
{
  switch(cmd) {
  case DRM_IOCTL_VIRTGPU_RESOURCE_CREATE_BLOB:
    return "DRM_IOCTL_VIRTGPU_RESOURCE_CREATE_BLOB";
  case DRM_IOCTL_VIRTGPU_MAP:
    return "DRM_IOCTL_VIRTGPU_MAP";
  case DRM_IOCTL_VIRTGPU_EXECBUFFER:
    return "DRM_IOCTL_VIRTGPU_EXECBUFFER";
  case DRM_IOCTL_GEM_CLOSE:
    return "DRM_IOCTL_GEM_CLOSE";
  case DRM_IOCTL_PRIME_HANDLE_TO_FD:
    return "DRM_IOCTL_PRIME_HANDLE_TO_FD";
  case DRM_IOCTL_PRIME_FD_TO_HANDLE:
    return "DRM_IOCTL_PRIME_FD_TO_HANDLE";
  case DRM_IOCTL_SYNCOBJ_CREATE:
    return "DRM_IOCTL_SYNCOBJ_CREATE";
  case DRM_IOCTL_SYNCOBJ_DESTROY:
    return "DRM_IOCTL_SYNCOBJ_DESTROY";
  case DRM_IOCTL_SYNCOBJ_HANDLE_TO_FD:
    return "DRM_IOCTL_SYNCOBJ_HANDLE_TO_FD";
  case DRM_IOCTL_SYNCOBJ_FD_TO_HANDLE:
    return "DRM_IOCTL_SYNCOBJ_FD_TO_HANDLE";
  case DRM_IOCTL_SYNCOBJ_TIMELINE_SIGNAL:
    return "DRM_IOCTL_SYNCOBJ_TIMELINE_SIGNAL";
  case DRM_IOCTL_SYNCOBJ_TIMELINE_WAIT:
    return "DRM_IOCTL_SYNCOBJ_TIMELINE_WAIT";
  }

  return "UNKNOWN(" + std::to_string(cmd) + ")";
}

void
ioctl(int dev_fd, unsigned long cmd, void* arg)
{
  XRT_TRACE_POINT_SCOPE2(ioctl, cmd, arg);
  if (::ioctl(dev_fd, cmd, arg) == -1)
    shim_err(-errno, "%s IOCTL failed", ioctl_cmd2name(cmd).c_str());
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
        shim_err(EINVAL, "failed to wait for host call response");
      break;
    }
    if (ret == 0)
      shim_err(ETIME, "wait for host call response timeout");
    if (ret < 0 && errno != EINTR && errno != EAGAIN)
      shim_err(-errno, "failed to wait for host call response");

    timeout -= (poll_end.tv_sec - poll_start.tv_sec) * 1000 +
      (poll_end.tv_nsec - poll_end.tv_nsec) / 1000000;
  }
}

void
set_virtgpu_context(int dev_fd)
{
  struct drm_virtgpu_context_set_param params[] = {
    { VIRTGPU_CONTEXT_PARAM_CAPSET_ID, 6 /* VIRGL_RENDERER_CAPSET_DRM */ },
    { VIRTGPU_CONTEXT_PARAM_NUM_RINGS, 64 },
  };
  struct drm_virtgpu_context_init args = {
    .num_params = 2,
    .ctx_set_params = (uintptr_t)params,
  };

  ioctl(dev_fd, DRM_IOCTL_VIRTGPU_CONTEXT_INIT, &args);
}

void
hcall_no_resp(int dev_fd, void *in_buf, size_t in_size)
{
  drm_virtgpu_execbuffer exec = {};

  exec.command = reinterpret_cast<uintptr_t>(in_buf);
  exec.size = in_size;
  ioctl(dev_fd, DRM_IOCTL_VIRTGPU_EXECBUFFER, &exec);
}

// Notify host of response buffer
void
register_resp_buf(int dev_fd, uint32_t res_id)
{
  amdxdna_ccmd_init_req req = {};
  req.hdr.cmd = AMDXDNA_CCMD_INIT;
  req.hdr.len = sizeof(req);
  req.rsp_res_id = res_id;
  hcall_no_resp(dev_fd, &req, sizeof(req));
}

}

namespace shim_xdna {

void
platform_drv_virtio::
drv_ioctl(drv_ioctl_cmd cmd, void* cmd_arg) const
{
  switch (cmd) {
  default:
    shim_err(EINVAL, "Unknown drv_ioctl: %d", cmd);
    break;
  }
}

void
platform_drv_virtio::
drv_open(const std::string& sysfs_name) const
{
  // Call into parent to open the device node.
  platform_drv::drv_open(sysfs_name);

  auto fd = dev_fd();
  platform_drv::drv_open(sysfs_name);
  set_virtgpu_context(fd);
  m_resp_buf = std::make_unique<response_buffer>(fd);
  try {
    register_resp_buf(fd, m_resp_buf->res_id());
  } catch (const xrt_core::system_error& e) {
    std::cout << "Failed to notify host of response buffer: " << e.what() << std::endl;
    m_resp_buf.reset();
  }
}

void
platform_drv_virtio::
drv_close() const
{
  m_resp_buf.reset();
}

void
platform_drv_virtio::
hcall(int dev_fd, void *in_buf, size_t in_size, void *out_buf, size_t out_size) const
{
  drm_virtgpu_execbuffer exec = {};
  auto sz = out_size;

  if (sz > resp_buffer_size)
    sz = resp_buffer_size;

  exec.flags = VIRTGPU_EXECBUF_FENCE_FD_OUT | VIRTGPU_EXECBUF_RING_IDX;
  exec.command = reinterpret_cast<uintptr_t>(in_buf);
  exec.size = in_size;
  exec.fence_fd = 0;
  exec.ring_idx = 1;
  ioctl(dev_fd, DRM_IOCTL_VIRTGPU_EXECBUFFER, &exec);
  sync_wait(exec.fence_fd, -1);
  if (out_buf)
    memcpy(out_buf, m_resp_buf->get(), sz);
  close(exec.fence_fd);
}

platform_drv_virtio::response_buffer::
response_buffer(int dev_fd)
  : m_dev_fd(dev_fd)
{
  // Create response buffer
  drm_virtgpu_resource_create_blob cargs = {
    .blob_mem   = VIRTGPU_BLOB_MEM_GUEST,
    .blob_flags = VIRTGPU_BLOB_FLAG_USE_MAPPABLE,
    .size       = resp_buffer_size,
    .blob_id    = 0,
  };
  ioctl(m_dev_fd, DRM_IOCTL_VIRTGPU_RESOURCE_CREATE_BLOB, &cargs);
  m_bo = cargs.bo_handle;

  // Mmap response buffer
  drm_virtgpu_map margs = {
    .handle = m_bo,
  };
  try {
    ioctl(m_dev_fd, DRM_IOCTL_VIRTGPU_MAP, &margs);
  } catch (const xrt_core::system_error& e) {
    std::cout << "Failed to obtain mmap offset of response buffer: " << e.what() << std::endl;
    return;
  }
  m_ptr = mmap(nullptr, resp_buffer_size,
    PROT_READ | PROT_WRITE, MAP_SHARED, m_dev_fd, margs.offset);
  if (m_ptr == MAP_FAILED) {
    std::cout << "Failed to mmap response buffer" << std::endl;
    return;
  }

  shim_debug("Created response buffer, bo %d, res %d, ptr %p", m_bo, m_res, m_ptr);
}

platform_drv_virtio::response_buffer::
~response_buffer()
{
  if (m_bo == AMDXDNA_INVALID_BO_HANDLE)
    return;

  shim_debug("Destroying response buffer, bo %d, res %d, ptr %p", m_bo, m_res, m_ptr);

  munmap(m_ptr, resp_buffer_size);
  drm_gem_close close_bo = {
    .handle = m_bo
  };
  ioctl(m_dev_fd, DRM_IOCTL_GEM_CLOSE, &close_bo);
}

uint32_t
platform_drv_virtio::response_buffer::
res_id() const
{
  return m_res;
}

void *
platform_drv_virtio::response_buffer::
get() const
{
  return m_ptr;
}

}

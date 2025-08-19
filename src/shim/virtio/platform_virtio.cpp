// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2025, Advanced Micro Devices, Inc. All rights reserved.

// Disable debug print in this file.
#undef XDNA_SHIM_DEBUG

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

size_t
roundup_64bit(size_t size)
{
  return (size + sizeof(uint64_t) - 1) & ~(sizeof(uint64_t) - 1);
}

#ifndef VIRTGPU_DRM_CAPSET_DRM
#define VIRTGPU_DRM_CAPSET_DRM 6
#endif

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
  case DRM_IOCTL_VIRTGPU_GET_CAPS:
    return "DRM_IOCTL_VIRTGPU_GET_CAPS";

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

std::string
hcall_cmd2name(unsigned long cmd)
{
  switch(cmd) {
  case AMDXDNA_CCMD_NOP:
    return "AMDXDNA_CCMD_NOP";
  case AMDXDNA_CCMD_INIT:
    return "AMDXDNA_CCMD_INIT";
  case AMDXDNA_CCMD_CREATE_BO:
    return "AMDXDNA_CCMD_CREATE_BO";
  case AMDXDNA_CCMD_DESTROY_BO:
    return "AMDXDNA_CCMD_DESTROY_BO";
  case AMDXDNA_CCMD_CREATE_CTX:
    return "AMDXDNA_CCMD_CREATE_CTX";
  case AMDXDNA_CCMD_DESTROY_CTX:
    return "AMDXDNA_CCMD_DESTROY_CTX";
  case AMDXDNA_CCMD_CONFIG_CTX:
    return "AMDXDNA_CCMD_CONFIG_CTX";
  case AMDXDNA_CCMD_EXEC_CMD:
    return "AMDXDNA_CCMD_EXEC_CMD";
  case AMDXDNA_CCMD_WAIT_CMD:
    return "AMDXDNA_CCMD_WAIT_CMD";
  case AMDXDNA_CCMD_GET_INFO:
    return "AMDXDNA_CCMD_GET_INFO";
  case AMDXDNA_CCMD_READ_SYSFS:
    return "AMDXDNA_CCMD_READ_SYSFS";
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
  struct pollfd fds = {};
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
    { VIRTGPU_CONTEXT_PARAM_CAPSET_ID, VIRTGPU_DRM_CAPSET_DRM },
    { VIRTGPU_CONTEXT_PARAM_NUM_RINGS, AMDXDNA_MAX_RING_NUM },
  };
  struct drm_virtgpu_context_init args = {
    .num_params = 2,
    .ctx_set_params = reinterpret_cast<uintptr_t>(params),
  };

  ioctl(dev_fd, DRM_IOCTL_VIRTGPU_CONTEXT_INIT, &args);
}

void
hcall_no_wait(int dev_fd, void *buf, size_t size)
{
  drm_virtgpu_execbuffer exec = {
    .size = static_cast<uint32_t>(size),
    .command = reinterpret_cast<uintptr_t>(buf),
  };

  try {
    ioctl(dev_fd, DRM_IOCTL_VIRTGPU_EXECBUFFER, &exec);
  } catch (const xrt_core::system_error& e) {
    auto req = reinterpret_cast<vdrm_ccmd_req*>(buf);
    shim_err(e.get_code(), "%s HCALL failed: %s", hcall_cmd2name(req->cmd).c_str(), e.what());
  }
}

void
hcall_wait(int dev_fd, void *buf, size_t size)
{
  auto req = reinterpret_cast<vdrm_ccmd_req*>(buf);
  uint32_t ring_idx = 0;

  // For now, only AMDXDNA_CCMD_WAIT_CMD requires non-zero ring index
  if (req->cmd == AMDXDNA_CCMD_WAIT_CMD) {
    auto wcmd = reinterpret_cast<amdxdna_ccmd_wait_cmd_req*>(req);
    ring_idx = wcmd->ctx_handle;
  }

  drm_virtgpu_execbuffer exec = {
    .flags = VIRTGPU_EXECBUF_FENCE_FD_OUT | VIRTGPU_EXECBUF_RING_IDX,
    .size = static_cast<uint32_t>(size),
    .command = reinterpret_cast<uintptr_t>(buf),
    .ring_idx = ring_idx,
  };

  try {
    shim_debug("%s HCALL IOCTL started", hcall_cmd2name(req->cmd).c_str());
    ioctl(dev_fd, DRM_IOCTL_VIRTGPU_EXECBUFFER, &exec);
    shim_debug("%s HCALL IOCTL ended", hcall_cmd2name(req->cmd).c_str());
    sync_wait(exec.fence_fd, -1);
    shim_debug("%s HCALL IOCTL wait ended", hcall_cmd2name(req->cmd).c_str());
  } catch (const xrt_core::system_error& e) {
    shim_err(e.get_code(), "%s HCALL failed: %s", hcall_cmd2name(req->cmd).c_str(), e.what());
  }
  close(exec.fence_fd);
}

// Notify host of response buffer
void
register_resp_buf(int dev_fd, uint32_t res_id)
{
  amdxdna_ccmd_init_req req = {
    .hdr = { AMDXDNA_CCMD_INIT, sizeof(req) },
    .rsp_res_id = res_id,
  };
  hcall_no_wait(dev_fd, &req, sizeof(req));
}

uint32_t
get_capset(int dev_fd)
{
  virgl_renderer_capset_drm caps = {};
  drm_virtgpu_get_caps args = {
    .cap_set_id = VIRTGPU_DRM_CAPSET_DRM,
    .cap_set_ver = 0,
    .addr = (uintptr_t)&caps,
    .size = sizeof(caps),
  };
  ioctl(dev_fd, DRM_IOCTL_VIRTGPU_GET_CAPS, &args);
  return caps.context_type;
}

shim_xdna::bo_id
drm_bo_alloc(int fd, size_t size)
{
  drm_virtgpu_resource_create_blob args = {
    .blob_mem   = VIRTGPU_BLOB_MEM_GUEST,
    .blob_flags = VIRTGPU_BLOB_FLAG_USE_MAPPABLE,
    .size       = size,
  };
  ioctl(fd, DRM_IOCTL_VIRTGPU_RESOURCE_CREATE_BLOB, &args);
  return {args.res_handle, args.bo_handle};
}

void
drm_bo_free(int fd, uint32_t boh)
{
  if (boh == AMDXDNA_INVALID_BO_HANDLE)
    return;

  drm_gem_close close_bo = {
    .handle = boh
  };
  ioctl(fd, DRM_IOCTL_GEM_CLOSE, &close_bo);
}

off_t
drm_bo_get_map_offset(int fd, uint32_t boh)
{
  drm_virtgpu_map args = {
    .handle = boh,
  };
  ioctl(fd, DRM_IOCTL_VIRTGPU_MAP, &args);
  return args.offset;
}

std::pair<uint32_t, uint32_t>
drm_bo_get_info(int fd, uint32_t boh)
{
  drm_virtgpu_resource_info args = {
    .bo_handle = boh,
  };
  ioctl(fd, DRM_IOCTL_VIRTGPU_RESOURCE_INFO, &args);
  return {args.res_handle, args.size};
}

}

namespace shim_xdna {

//
//Implementation of response_buffer.
//

platform_drv_virtio::response_buffer::
response_buffer(int dev_fd)
  : response_buffer(dev_fd, resp_buffer_size)
{
}

platform_drv_virtio::response_buffer::
response_buffer(int dev_fd, size_t size)
  : m_dev_fd(dev_fd)
  , m_size(size)
{
  // Create response buffer
  m_id = drm_bo_alloc(m_dev_fd, m_size);

  // Mmap response buffer
  uint64_t mapoff;
  try {
    mapoff = drm_bo_get_map_offset(m_dev_fd, m_id.handle);
  } catch (const xrt_core::system_error& e) {
    drm_bo_free(m_dev_fd, m_id.handle);
    std::cout << "Failed to obtain mmap offset of response buffer: " << e.what() << std::endl;
    throw;
  }
  m_ptr = mmap(nullptr, m_size, PROT_READ | PROT_WRITE, MAP_SHARED, m_dev_fd, mapoff);
  if (m_ptr == MAP_FAILED) {
    drm_bo_free(m_dev_fd, m_id.handle);
    shim_err(-errno, "Failed to mmap response buffer");
  }

  shim_debug("Created response buffer, bo %d, res %d, ptr %p",
    m_id.handle, m_id.res_id, m_ptr);
}

platform_drv_virtio::response_buffer::
~response_buffer()
{
  shim_debug("Destroying response buffer, bo %d, res %d, ptr %p",
    m_id.handle, m_id.res_id, m_ptr);

  try {
    munmap(m_ptr, m_size);
    drm_bo_free(m_dev_fd, m_id.handle);
  } catch (const xrt_core::system_error& e) {
    std::cout << "Failed to free response buffer: " << e.what() << std::endl;
  }
}

uint32_t
platform_drv_virtio::response_buffer::
res_id() const
{
  return m_id.res_id;
}

void *
platform_drv_virtio::response_buffer::
get() const
{
  return m_ptr;
}

//
// Implementation of platform_drv_virtio.
//

void
platform_drv_virtio::
drv_open(const std::string& sysfs_name) const
{
  // Call into parent to open the device node.
  platform_drv::drv_open(sysfs_name);

  auto fd = dev_fd();
  if (get_capset(fd) != VIRTGPU_DRM_CONTEXT_AMDXDNA)
    shim_err(EINVAL, "%s is not NPU device", sysfs_name.c_str());

  set_virtgpu_context(fd);
  m_resp_buf = std::make_unique<response_buffer>(fd);
  try {
    register_resp_buf(fd, m_resp_buf->res_id());
  } catch (const xrt_core::system_error& e) {
    std::cout << "Failed to register response buffer with host: " << e.what() << std::endl;
    m_resp_buf.reset();
  }
}

void
platform_drv_virtio::
drv_close() const
{
  m_resp_buf.reset();

  // Call into parent to close the device node.
  platform_drv::drv_close();
}

void
platform_drv_virtio::
hcall(void *req) const
{
  // Assume the request buffer always starts with vdrm_ccmd_req!
  auto hdr = reinterpret_cast<vdrm_ccmd_req*>(req);
  auto fd = dev_fd();
  hcall_wait(fd, req, hdr->len);
}

void
platform_drv_virtio::
hcall(void *req, void *out_buf, size_t out_size) const
{
  // We have one response buffer, so can't really share across multiple requests.
  std::lock_guard<std::mutex> lg(m_lock);
  auto rsp_hdr = reinterpret_cast<amdxdna_ccmd_rsp*>(m_resp_buf->get());
  rsp_hdr->ret = 0;

  auto sz = out_size;
  if (sz > resp_buffer_size)
    sz = resp_buffer_size;

  hcall(req);
  if (rsp_hdr->ret) {
    auto r = reinterpret_cast<vdrm_ccmd_req*>(req);
    shim_err(rsp_hdr->ret, "%s HCALL received bad reponse", hcall_cmd2name(r->cmd).c_str());
  }
  std::memcpy(out_buf, m_resp_buf->get(), sz);
}

void
platform_drv_virtio::
create_ctx(create_ctx_arg& arg) const
{
  amdxdna_ccmd_create_ctx_req req = {
    .hdr = { AMDXDNA_CCMD_CREATE_CTX, sizeof(req) },
    .qos_info = arg.qos,
    .umq_blob_id = arg.umq_bo.handle,
    .log_buf_blob_id = arg.log_buf_bo.handle,
    .max_opc = arg.max_opc,
    .num_tiles = arg.num_tiles,
    .mem_size = arg.mem_size,
  };
  amdxdna_ccmd_create_ctx_rsp rsp = {};

  hcall(&req, &rsp, sizeof(rsp));
  arg.ctx_handle = rsp.handle;
  arg.syncobj_handle = AMDXDNA_INVALID_FENCE_HANDLE;
}

void
platform_drv_virtio::
destroy_ctx(destroy_ctx_arg& arg) const
{
  amdxdna_ccmd_destroy_ctx_req req = {
    .hdr = { AMDXDNA_CCMD_DESTROY_CTX, sizeof(req) },
    .handle = arg.ctx_handle,
  };
  hcall(&req);
}

std::pair<uint32_t, uint64_t>
platform_drv_virtio::
host_bo_alloc(uint32_t type, size_t size, uint32_t res_id, uint64_t align) const
{
  amdxdna_ccmd_create_bo_req req = {
    .hdr = { AMDXDNA_CCMD_CREATE_BO, sizeof(req) },
    .res_id = res_id,
    .bo_type = type,
    .size = size,
    .map_align = align,
  };
  amdxdna_ccmd_create_bo_rsp rsp = {};

  hcall(&req, &rsp, sizeof(rsp));
  return { rsp.handle, rsp.xdna_addr };
}

void
platform_drv_virtio::
host_bo_free(uint32_t host_hdl) const
{
  amdxdna_ccmd_destroy_bo_req req = {
    .hdr = { AMDXDNA_CCMD_DESTROY_BO, sizeof(req) },
    .handle = host_hdl,
  };
  hcall(&req);
}

void
platform_drv_virtio::
create_bo(create_bo_arg& arg) const
{
  bo_id id;
  auto fd = dev_fd();

  if (arg.type != AMDXDNA_BO_DEV) {
    id = drm_bo_alloc(fd, arg.size);
    arg.bo.res_id = id.handle;
    arg.map_offset = drm_bo_get_map_offset(fd, id.handle);
  } else {
    arg.bo.res_id = AMDXDNA_INVALID_BO_HANDLE;
    arg.map_offset = AMDXDNA_INVALID_ADDR;
  }

  try {
    std::tie(arg.bo.handle, arg.xdna_addr) =
      host_bo_alloc(arg.type, arg.size, id.res_id, arg.xdna_addr_align);
  } catch (...) {
    drm_bo_free(fd, arg.bo.res_id);
    throw;
  }
}

void
platform_drv_virtio::
destroy_bo(destroy_bo_arg& arg) const
{
  host_bo_free(arg.bo.handle);
  drm_bo_free(dev_fd(), arg.bo.res_id);
}

void
platform_drv_virtio::
get_info(amdxdna_drm_get_info& arg) const
{
  if (arg.param == DRM_AMDXDNA_QUERY_AIE_STATUS)
    shim_not_supported_err("get_info: DRM_AMDXDNA_QUERY_AIE_METADATA");
  if (arg.param == DRM_AMDXDNA_READ_AIE_MEM)
    shim_not_supported_err("get_info: DRM_AMDXDNA_READ_AIE_MEM");
  if (arg.param == DRM_AMDXDNA_READ_AIE_REG)
    shim_not_supported_err("get_info: DRM_AMDXDNA_READ_AIE_MEM");

  auto resp_buf = std::make_unique<response_buffer>(dev_fd(), arg.buffer_size);
  std::memcpy(resp_buf->get(), reinterpret_cast<char*>(arg.buffer), arg.buffer_size);
  amdxdna_ccmd_get_info_req req = {
    .hdr = { AMDXDNA_CCMD_GET_INFO, sizeof(req) },
    .param = arg.param,
    .size = arg.buffer_size,
    .info_res = resp_buf->res_id(),
  };
  amdxdna_ccmd_get_info_rsp rsp = {};
  hcall(&req, &rsp, sizeof(rsp));
  std::memcpy(reinterpret_cast<char*>(arg.buffer), resp_buf->get(), rsp.size);
  arg.buffer_size = rsp.size;
}

void
platform_drv_virtio::
get_info_array(amdxdna_drm_get_array& arg) const
{
  auto total_buf_size = arg.element_size * arg.num_element;
  auto resp_buf = std::make_unique<response_buffer>(dev_fd(), total_buf_size);
  std::memcpy(resp_buf->get(), reinterpret_cast<char*>(arg.buffer), total_buf_size);

  amdxdna_ccmd_get_info_req req = {
    .hdr = { AMDXDNA_CCMD_GET_INFO, sizeof(req) },
    .param = arg.param,
    .size = arg.element_size,
    .num_element = arg.num_element,
    .info_res = resp_buf->res_id(),
  };
  amdxdna_ccmd_get_info_rsp rsp = {};
  hcall(&req, &rsp, sizeof(rsp));
  std::memcpy(reinterpret_cast<char*>(arg.buffer), resp_buf->get(), total_buf_size);
  arg.element_size = rsp.size;
  arg.num_element = rsp.num_element;
}

void
platform_drv_virtio::
get_sysfs(get_sysfs_arg& arg) const
{
  const int name_size = 256; // Make sure size is multiple of 64 bits.
  const int response_size = 4096;
  if (arg.sysfs_node.size() >= name_size)
    shim_err(EINVAL, "sysfs node name is too long: %s", arg.sysfs_node.c_str());
  char req_data[sizeof(amdxdna_ccmd_read_sysfs_req) + name_size] = {};
  auto req = reinterpret_cast<amdxdna_ccmd_read_sysfs_req*>(req_data);
  char rsp_data[response_size] = {};
  auto rsp = reinterpret_cast<amdxdna_ccmd_read_sysfs_rsp*>(rsp_data);

  req->hdr.cmd = AMDXDNA_CCMD_READ_SYSFS;
  req->hdr.len = sizeof(req_data);
  std::strcpy(req->node_name, arg.sysfs_node.c_str());
  hcall(req, rsp, response_size);

  if (rsp->val_len > arg.data.size())
    shim_err(EINVAL, "sysfs content is too long: %dB", rsp->val_len);
  std::memcpy(arg.data.data(), rsp->val, rsp->val_len);
  arg.real_size = rsp->val_len;
}

void
platform_drv_virtio::
config_ctx_cu_config(config_ctx_cu_config_arg& arg) const
{
  std::vector<char> cu_conf_param_buf(sizeof(amdxdna_ccmd_config_ctx_req) + roundup_64bit(arg.conf_buf.size()));
  auto cu_conf_req = reinterpret_cast<amdxdna_ccmd_config_ctx_req *>(cu_conf_param_buf.data());
  auto cu_conf_param = reinterpret_cast<amdxdna_hwctx_param_config_cu *>(cu_conf_req->param_val);

  cu_conf_req->hdr.cmd = AMDXDNA_CCMD_CONFIG_CTX;
  cu_conf_req->hdr.len = cu_conf_param_buf.size();
  cu_conf_req->handle = arg.ctx_handle;
  cu_conf_req->param_type = DRM_AMDXDNA_HWCTX_CONFIG_CU;
  cu_conf_req->param_val_size = cu_conf_req->hdr.len - sizeof(amdxdna_ccmd_config_ctx_req);
  std::memcpy(cu_conf_param_buf.data() + sizeof(amdxdna_ccmd_config_ctx_req),
    arg.conf_buf.data(), arg.conf_buf.size());
  hcall(cu_conf_req);
}

void
platform_drv_virtio::
config_ctx_debug_bo(config_ctx_debug_bo_arg& arg) const
{
  amdxdna_ccmd_config_ctx_req req = {
    .hdr = { AMDXDNA_CCMD_CONFIG_CTX, sizeof(req) },
    .handle = arg.ctx_handle,
    .param_type = static_cast<uint32_t>(arg.is_detach ?
      DRM_AMDXDNA_HWCTX_REMOVE_DBG_BUF : DRM_AMDXDNA_HWCTX_ASSIGN_DBG_BUF),
    .inline_param = arg.bo.handle,
  };
  hcall(&req);
}

void
platform_drv_virtio::
submit_cmd(submit_cmd_arg& arg) const
{
  // Assuming 512 max args per cmd bo
  const size_t max_args = 512;
  const auto nargs = arg.arg_bos.size();
  if (nargs > max_args)
    shim_err(EINVAL, "Max arg %ld, received %ld", max_args, nargs);

  auto req_sz = sizeof(amdxdna_ccmd_exec_cmd_req);
  req_sz += sizeof(uint64_t); // One cmd handle
  req_sz += nargs * sizeof(uint32_t); // For args handle
  // Get a 64 bit aligned buffer for req
  auto req_sz_in_u64 = req_sz / sizeof(uint64_t) + 1;
  uint64_t req_buf[req_sz_in_u64] = {};
  auto req = reinterpret_cast<amdxdna_ccmd_exec_cmd_req*>(req_buf);
  amdxdna_ccmd_exec_cmd_rsp rsp = {};

  req->hdr.cmd = AMDXDNA_CCMD_EXEC_CMD;
  req->hdr.len = req_sz_in_u64 * sizeof(uint64_t);
  req->ctx_handle = arg.ctx_handle;
  req->type = AMDXDNA_CMD_SUBMIT_EXEC_BUF;
  req->cmd_count = 1;
  req->cmds_n_args[0] = arg.cmd_bo.handle;
  req->arg_count = nargs;
  req->arg_offset = 1;
  int i = req->arg_offset;
  for (auto& id : arg.arg_bos)
    req->cmds_n_args[i++] = id.handle;

  hcall(req, &rsp, sizeof(rsp));
  arg.seq = rsp.seq;
}

void
platform_drv_virtio::
wait_cmd_ioctl(wait_cmd_arg& arg) const
{
  amdxdna_ccmd_wait_cmd_req req = {
    .hdr = { AMDXDNA_CCMD_WAIT_CMD, sizeof(req) },
    .seq = arg.seq,
    .ctx_handle = arg.ctx_handle,
  };
  // TODO: needs to pass timeout to host
  hcall(&req);
}

void
platform_drv_virtio::
export_bo(export_bo_arg& bo_arg) const
{
  drm_prime_handle arg = {
    .handle = bo_arg.bo.res_id,
    .flags = DRM_RDWR | DRM_CLOEXEC,
    .fd = -1,
  };
  ioctl(dev_fd(), DRM_IOCTL_PRIME_HANDLE_TO_FD, &arg);
  bo_arg.fd = arg.fd;
}

void
platform_drv_virtio::
import_bo(import_bo_arg& bo_arg) const
{
  auto fd = dev_fd();
  drm_prime_handle carg = {
    .handle = AMDXDNA_INVALID_BO_HANDLE,
    .flags = 0,
    .fd = bo_arg.fd,
  };
  ioctl(fd, DRM_IOCTL_PRIME_FD_TO_HANDLE, &carg);
  auto gboh = carg.handle;

  auto [ resource, size ] = drm_bo_get_info(fd, gboh);

  uint32_t hboh = AMDXDNA_INVALID_BO_HANDLE;
  uint64_t xdna_addr = AMDXDNA_INVALID_ADDR;
  try {
    std::tie(hboh, xdna_addr) = host_bo_alloc(AMDXDNA_BO_SHARE, size, resource, 0);
  } catch (...) {
    drm_bo_free(fd, gboh);
    throw;
  }

  uint64_t map_offset = AMDXDNA_INVALID_ADDR;
  map_offset = drm_bo_get_map_offset(fd, gboh);

  bo_arg.bo.handle = hboh;
  bo_arg.bo.res_id = gboh;
  bo_arg.xdna_addr = xdna_addr;
  bo_arg.vaddr = nullptr;
  bo_arg.map_offset = map_offset;
  bo_arg.type = AMDXDNA_BO_SHARE;
  bo_arg.size = size;
}

}

// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2025, Advanced Micro Devices, Inc. All rights reserved.

#include "../shim_debug.h"
#include "platform_host.h"
#include "core/common/trace.h"
#include <fstream>
#include <fcntl.h>
#include <drm/drm.h>
#include <sys/ioctl.h>

namespace {

std::string
ioctl_cmd2name(unsigned long cmd)
{
  switch(cmd) {
  case DRM_IOCTL_AMDXDNA_CREATE_CTX:
    return "DRM_IOCTL_AMDXDNA_CREATE_CTX";
  case DRM_IOCTL_AMDXDNA_DESTROY_CTX:
    return "DRM_IOCTL_AMDXDNA_DESTROY_CTX";
  case DRM_IOCTL_AMDXDNA_CONFIG_CTX:
    return "DRM_IOCTL_AMDXDNA_CONFIG_CTX";
  case DRM_IOCTL_AMDXDNA_CREATE_BO:
    return "DRM_IOCTL_AMDXDNA_CREATE_BO";
  case DRM_IOCTL_AMDXDNA_GET_BO_INFO:
    return "DRM_IOCTL_AMDXDNA_GET_BO_INFO";
  case DRM_IOCTL_AMDXDNA_SYNC_BO:
    return "DRM_IOCTL_AMDXDNA_SYNC_BO";
  case DRM_IOCTL_AMDXDNA_EXEC_CMD:
    return "DRM_IOCTL_AMDXDNA_EXEC_CMD";
  case DRM_IOCTL_AMDXDNA_WAIT_CMD:
    return "DRM_IOCTL_AMDXDNA_WAIT_CMD";
  case DRM_IOCTL_AMDXDNA_GET_INFO:
    return "DRM_IOCTL_AMDXDNA_GET_INFO";
  case DRM_IOCTL_AMDXDNA_GET_INFO_ARRAY:
    return "DRM_IOCTL_AMDXDNA_GET_INFO_ARRAY";
  case DRM_IOCTL_AMDXDNA_SET_STATE:
    return "DRM_IOCTL_AMDXDNA_SET_STATE";

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

size_t
page_roundup(size_t size)
{
  static const uint64_t page_size = sysconf(_SC_PAGESIZE);
  return (size + page_size - 1) & ~(page_size - 1);
}

void
ioctl(int dev_fd, unsigned long cmd, void* arg)
{
  XRT_TRACE_POINT_SCOPE2(ioctl, cmd, arg);
  if (::ioctl(dev_fd, cmd, arg) == -1)
    shim_err(-errno, "%s IOCTL failed", ioctl_cmd2name(cmd).c_str());
}

void
wait_syncobj_available(int dev_fd, uint32_t sobj_hdl, uint64_t timepoint)
{
  drm_syncobj_timeline_wait wsobj = {
    .handles = reinterpret_cast<uintptr_t>(&sobj_hdl),
    .points = reinterpret_cast<uintptr_t>(&timepoint),
    .timeout_nsec = shim_xdna::platform_drv::timeout_ms2abs_ns(0), /* wait forever */
    .count_handles = 1,
    .flags = DRM_SYNCOBJ_WAIT_FLAGS_WAIT_ALL |
             DRM_SYNCOBJ_WAIT_FLAGS_WAIT_FOR_SUBMIT |
             DRM_SYNCOBJ_WAIT_FLAGS_WAIT_AVAILABLE,
  };
  ioctl(dev_fd, DRM_IOCTL_SYNCOBJ_TIMELINE_WAIT, &wsobj);
}

void *
to_ptr(uint64_t drv_ptr)
{
  return drv_ptr == AMDXDNA_INVALID_ADDR ? nullptr : reinterpret_cast<void*>(drv_ptr);
}

}

namespace shim_xdna {

void
platform_drv_host::
create_ctx(create_ctx_arg& ctx_arg) const
{
  amdxdna_drm_create_ctx arg = {};
  arg.qos_p = reinterpret_cast<uintptr_t>(&ctx_arg.qos);
  arg.umq_bo = ctx_arg.umq_bo.handle;
  arg.max_opc = ctx_arg.max_opc;
  arg.num_tiles = ctx_arg.num_tiles;
  arg.log_buf_bo = ctx_arg.log_buf_bo.handle;
  ioctl(dev_fd(), DRM_IOCTL_AMDXDNA_CREATE_CTX, &arg);
  
  ctx_arg.ctx_handle = arg.handle;
  ctx_arg.umq_doorbell = arg.umq_doorbell;
  ctx_arg.syncobj_handle = arg.syncobj_handle;
}

void
platform_drv_host::
destroy_ctx(destroy_ctx_arg& ctx_arg) const
{
  if (ctx_arg.syncobj_handle != AMDXDNA_INVALID_FENCE_HANDLE) {
    create_destroy_syncobj_arg sarg = {
      .handle = ctx_arg.syncobj_handle,
    };
    destroy_syncobj(sarg);
  }

  amdxdna_drm_destroy_ctx arg = {};
  arg.handle = ctx_arg.ctx_handle;
  ioctl(dev_fd(), DRM_IOCTL_AMDXDNA_DESTROY_CTX, &arg);
}

void
platform_drv_host::
config_ctx_cu_config(config_ctx_cu_config_arg& ctx_arg) const
{
  amdxdna_drm_config_ctx arg = {};
  arg.handle = ctx_arg.ctx_handle;
  arg.param_type = DRM_AMDXDNA_CTX_CONFIG_CU;
  arg.param_val = reinterpret_cast<uintptr_t>(ctx_arg.conf_buf.data());
  arg.param_val_size = ctx_arg.conf_buf.size();
  ioctl(dev_fd(), DRM_IOCTL_AMDXDNA_CONFIG_CTX, &arg);
}

void
platform_drv_host::
config_ctx_debug_bo(config_ctx_debug_bo_arg& ctx_arg) const
{
  amdxdna_drm_config_ctx arg = {};
  arg.handle = ctx_arg.ctx_handle;
  arg.param_type = ctx_arg.is_detach ?
    DRM_AMDXDNA_CTX_REMOVE_DBG_BUF : DRM_AMDXDNA_CTX_ASSIGN_DBG_BUF;
  arg.param_val = ctx_arg.bo.handle;
  ioctl(dev_fd(), DRM_IOCTL_AMDXDNA_CONFIG_CTX, &arg);
}

std::pair<uint64_t, uint64_t>
platform_drv_host::
get_bo_info(uint32_t boh) const
{
  amdxdna_drm_get_bo_info iarg = {};
  iarg.handle = boh;
  ioctl(dev_fd(), DRM_IOCTL_AMDXDNA_GET_BO_INFO, &iarg);
  return {iarg.xdna_addr, iarg.map_offset};
}

std::tuple<uint32_t, uint64_t, uint64_t>
platform_drv_host::
create_drm_bo(void *uva_tbl, size_t size, int type) const
{
  uint64_t xdna_addr, map_offset;

  amdxdna_drm_create_bo carg = {};
  carg.vaddr = reinterpret_cast<uintptr_t>(uva_tbl);
  carg.size = size;
  carg.type = type;
  ioctl(dev_fd(), DRM_IOCTL_AMDXDNA_CREATE_BO, &carg);

  try {
    std::tie(xdna_addr, map_offset) = get_bo_info(carg.handle);
  } catch (...) {
    destroy_bo_arg darg = { carg.handle };
    destroy_bo(darg);
    throw;
  }
  return { carg.handle, xdna_addr, map_offset };
}

void
platform_drv_host::
create_bo(create_bo_arg& bo_arg) const
{
  bo_arg.bo.res_id = AMDXDNA_INVALID_BO_HANDLE;
  std::tie(bo_arg.bo.handle, bo_arg.xdna_addr, bo_arg.map_offset) =
    create_drm_bo(nullptr, bo_arg.size, bo_arg.type);
}

void
platform_drv_host::
create_uptr_bo(create_uptr_bo_arg& bo_arg) const
{
  alignas(amdxdna_drm_va_tbl)
  char buf[sizeof(amdxdna_drm_va_tbl) + sizeof(amdxdna_drm_va_entry)];
  auto tbl = reinterpret_cast<amdxdna_drm_va_tbl*>(buf);
  tbl->udma_fd = -1;
  tbl->num_entries = 1;
  tbl->va_entries[0].vaddr = reinterpret_cast<uintptr_t>(bo_arg.buf);
  tbl->va_entries[0].len = page_roundup(bo_arg.size);

  bo_arg.bo.res_id = AMDXDNA_INVALID_BO_HANDLE;
  std::tie(bo_arg.bo.handle, bo_arg.xdna_addr, bo_arg.map_offset) =
    create_drm_bo(buf, 0, AMDXDNA_BO_SHARE);
}

void
platform_drv_host::
destroy_bo(destroy_bo_arg& bo_arg) const
{
  drm_gem_close arg = {};
  arg.handle = bo_arg.bo.handle;
  ioctl(dev_fd(), DRM_IOCTL_GEM_CLOSE, &arg);
}

void
platform_drv_host::
sync_bo(sync_bo_arg& bo_arg) const
{
  amdxdna_drm_sync_bo arg = {};
  arg.handle = bo_arg.bo.handle;
  arg.direction = bo_arg.direction == xrt_core::buffer_handle::direction::host2device ?
      SYNC_DIRECT_TO_DEVICE : SYNC_DIRECT_FROM_DEVICE;
  arg.offset = bo_arg.offset;
  arg.size = bo_arg.size;
  ioctl(dev_fd(), DRM_IOCTL_AMDXDNA_SYNC_BO, &arg);
}

void
platform_drv_host::
export_bo(export_bo_arg& bo_arg) const
{
  drm_prime_handle arg = {};
  arg.handle = bo_arg.bo.handle;
  arg.flags = DRM_RDWR | DRM_CLOEXEC;
  arg.fd = -1;
  ioctl(dev_fd(), DRM_IOCTL_PRIME_HANDLE_TO_FD, &arg);
  bo_arg.fd = arg.fd;
}

void
platform_drv_host::
import_bo(import_bo_arg& bo_arg) const
{
  drm_prime_handle carg = {};
  carg.handle = AMDXDNA_INVALID_BO_HANDLE;
  carg.flags = 0;
  carg.fd = bo_arg.fd;
  ioctl(dev_fd(), DRM_IOCTL_PRIME_FD_TO_HANDLE, &carg);

  amdxdna_drm_get_bo_info iarg = {};
  iarg.handle = carg.handle;
  ioctl(dev_fd(), DRM_IOCTL_AMDXDNA_GET_BO_INFO, &iarg);
  bo_arg.bo.handle = carg.handle;
  bo_arg.bo.res_id = AMDXDNA_INVALID_BO_HANDLE;
  bo_arg.xdna_addr = iarg.xdna_addr;
  bo_arg.vaddr = to_ptr(iarg.vaddr);
  bo_arg.map_offset = iarg.map_offset;
  bo_arg.type = AMDXDNA_BO_SHARE;
  bo_arg.size = lseek(bo_arg.fd, 0, SEEK_END);
  lseek(bo_arg.fd, 0, SEEK_SET);
}

void
platform_drv_host::
submit_cmd(submit_cmd_arg& cmd_arg) const
{
  // Assuming 512 max args per cmd bo
  const size_t max_args = 512;
  const auto nargs = cmd_arg.arg_bos.size();
  if (nargs > max_args)
    shim_err(EINVAL, "Max arg %ld, received %ld", max_args, nargs);

  uint32_t arg_bo_hdls[max_args] = {};
  int i = 0;
  for (auto& id : cmd_arg.arg_bos)
    arg_bo_hdls[i++] = id.handle;

  amdxdna_drm_exec_cmd arg = {};
  arg.ctx = cmd_arg.ctx_handle;
  arg.type = AMDXDNA_CMD_SUBMIT_EXEC_BUF;
  arg.cmd_handles = cmd_arg.cmd_bo.handle;
  arg.args = reinterpret_cast<uintptr_t>(arg_bo_hdls);
  arg.cmd_count = 1;
  arg.arg_count = nargs;
  ioctl(dev_fd(), DRM_IOCTL_AMDXDNA_EXEC_CMD, &arg);
  cmd_arg.seq = arg.seq;
}

void
platform_drv_host::
wait_cmd_ioctl(wait_cmd_arg& cmd_arg) const
{
  amdxdna_drm_wait_cmd wcmd = {
    .ctx = cmd_arg.ctx_handle,
    .timeout = cmd_arg.timeout_ms,
    .seq = cmd_arg.seq,
  };
  ioctl(dev_fd(), DRM_IOCTL_AMDXDNA_WAIT_CMD, &wcmd);
}

void
platform_drv_host::
wait_cmd_syncobj(wait_cmd_arg& cmd_arg) const
{
  wait_syncobj_arg wcmd = {
    .handle = cmd_arg.ctx_syncobj_handle,
    .timeout_ms = cmd_arg.timeout_ms,
    .timepoint = cmd_arg.seq,
  };
  wait_syncobj(wcmd);
}

void
platform_drv_host::
get_info(amdxdna_drm_get_info& info) const
{
  ioctl(dev_fd(), DRM_IOCTL_AMDXDNA_GET_INFO, &info);
}

void
platform_drv_host::
get_info_array(amdxdna_drm_get_info_array& info) const
{
  ioctl(dev_fd(), DRM_IOCTL_AMDXDNA_GET_INFO_ARRAY, &info);
}

void
platform_drv_host::
set_state(amdxdna_drm_set_state& state) const
{
  ioctl(dev_fd(), DRM_IOCTL_AMDXDNA_SET_STATE, &state);
}

void
platform_drv_host::
get_sysfs(get_sysfs_arg& arg) const
{
  std::string path = sysfs_root() + "/" + arg.sysfs_node;
  std::ifstream ifs(path, std::ios::binary);
  if (!ifs.is_open())
    shim_err(-errno, "Failed to open %s", path.c_str());

  ifs.read(arg.data.data(), arg.data.size());
  arg.real_size = ifs.gcount();

  ifs.close();
}

void
platform_drv_host::
put_sysfs(put_sysfs_arg& arg) const
{
  std::string path = sysfs_root() + "/" + arg.sysfs_node;
  std::ofstream ofs(path, std::ios::binary);
  if (!ofs.is_open())
    shim_err(-errno, "Failed to open %s", path.c_str());

  ofs.write(arg.data.data(), arg.data.size());
  if (!ofs.good())
    shim_err(-errno, "Failed to write %s", path.c_str());

  ofs.close();
}

}

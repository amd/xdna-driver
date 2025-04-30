// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2025, Advanced Micro Devices, Inc. All rights reserved.

#include "shim_debug.h"
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

void
ioctl(int dev_fd, unsigned long cmd, void* arg)
{
  XRT_TRACE_POINT_SCOPE2(ioctl, cmd, arg);
  if (::ioctl(dev_fd, cmd, arg) == -1)
    shim_err(-errno, "%s IOCTL failed", ioctl_cmd2name(cmd).c_str());
}

void
create_ctx(int dev_fd, shim_xdna::create_ctx_arg& ctx_arg)
{
  amdxdna_drm_create_ctx arg = {};
  arg.qos_p = reinterpret_cast<uintptr_t>(&ctx_arg.qos);
  arg.umq_bo = ctx_arg.umq_bo.handle;
  arg.max_opc = ctx_arg.max_opc;
  arg.num_tiles = ctx_arg.num_tiles;
  arg.log_buf_bo = ctx_arg.log_buf_bo.handle;
  ioctl(dev_fd, DRM_IOCTL_AMDXDNA_CREATE_CTX, &arg);
  
  ctx_arg.ctx_handle = arg.handle;
  ctx_arg.umq_doorbell = arg.umq_doorbell;
  ctx_arg.syncobj_handle = arg.syncobj_handle;
}

void
destroy_ctx(int dev_fd, shim_xdna::destroy_ctx_arg& ctx_arg)
{
  amdxdna_drm_destroy_ctx arg = {};
  arg.handle = ctx_arg.ctx_handle;
  ioctl(dev_fd, DRM_IOCTL_AMDXDNA_DESTROY_CTX, &arg);
}

void
config_ctx_cu_config(int dev_fd, shim_xdna::config_ctx_cu_config_arg& ctx_arg)
{
  amdxdna_drm_config_ctx arg = {};
  arg.handle = ctx_arg.ctx_handle;
  arg.param_type = DRM_AMDXDNA_CTX_CONFIG_CU;
  arg.param_val = reinterpret_cast<uintptr_t>(ctx_arg.conf_buf.data());
  arg.param_val_size = ctx_arg.conf_buf.size();
  ioctl(dev_fd, DRM_IOCTL_AMDXDNA_CONFIG_CTX, &arg);
}

void
config_ctx_debug_bo(int dev_fd, shim_xdna::config_ctx_debug_bo_arg& ctx_arg)
{
  amdxdna_drm_config_ctx arg = {};
  arg.handle = ctx_arg.ctx_handle;
  arg.param_type = ctx_arg.is_detach ?
    DRM_AMDXDNA_CTX_REMOVE_DBG_BUF : DRM_AMDXDNA_CTX_ASSIGN_DBG_BUF;
  arg.param_val = ctx_arg.bo.handle;
  ioctl(dev_fd, DRM_IOCTL_AMDXDNA_CONFIG_CTX, &arg);
}

void *
to_ptr(uint64_t drv_ptr)
{
  return drv_ptr == AMDXDNA_INVALID_ADDR ? nullptr : reinterpret_cast<void*>(drv_ptr);
}

void
create_bo(int dev_fd, shim_xdna::create_bo_arg& bo_arg)
{
  amdxdna_drm_create_bo carg = {};
  carg.size = bo_arg.size;
  carg.type = bo_arg.type;
  ioctl(dev_fd, DRM_IOCTL_AMDXDNA_CREATE_BO, &carg);

  amdxdna_drm_get_bo_info iarg = {};
  iarg.handle = carg.handle;
  ioctl(dev_fd, DRM_IOCTL_AMDXDNA_GET_BO_INFO, &iarg);

  bo_arg.bo.handle = carg.handle;
  bo_arg.bo.res_id = AMDXDNA_INVALID_BO_HANDLE;
  bo_arg.xdna_addr = iarg.xdna_addr;
  bo_arg.vaddr = to_ptr(iarg.vaddr);
  bo_arg.map_offset = iarg.map_offset;
}

void
destroy_bo(int dev_fd, shim_xdna::destroy_bo_arg& bo_arg)
{
  drm_gem_close arg = {};
  arg.handle = bo_arg.bo.handle;
  ioctl(dev_fd, DRM_IOCTL_GEM_CLOSE, &arg);
}

void
sync_bo(int dev_fd, shim_xdna::sync_bo_arg& bo_arg)
{
  amdxdna_drm_sync_bo arg = {};
  arg.handle = bo_arg.bo.handle;
  arg.direction = bo_arg.direction == xrt_core::buffer_handle::direction::host2device ?
      SYNC_DIRECT_TO_DEVICE : SYNC_DIRECT_FROM_DEVICE;
  arg.offset = bo_arg.offset;
  arg.size = bo_arg.size;
  ioctl(dev_fd, DRM_IOCTL_AMDXDNA_SYNC_BO, &arg);
}

void
export_bo(int dev_fd, shim_xdna::export_bo_arg& bo_arg)
{
  drm_prime_handle arg = {};
  arg.handle = bo_arg.bo.handle;
  arg.flags = DRM_RDWR | DRM_CLOEXEC;
  arg.fd = -1;
  ioctl(dev_fd, DRM_IOCTL_PRIME_HANDLE_TO_FD, &arg);
  bo_arg.fd = arg.fd;
}

void
import_bo(int dev_fd, shim_xdna::import_bo_arg& bo_arg)
{
  drm_prime_handle carg = {};
  carg.handle = AMDXDNA_INVALID_BO_HANDLE;
  carg.flags = 0;
  carg.fd = bo_arg.fd;
  ioctl(dev_fd, DRM_IOCTL_PRIME_FD_TO_HANDLE, &carg);

  amdxdna_drm_get_bo_info iarg = {};
  iarg.handle = carg.handle;
  ioctl(dev_fd, DRM_IOCTL_AMDXDNA_GET_BO_INFO, &iarg);
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
submit_cmd(int dev_fd, shim_xdna::submit_cmd_arg& cmd_arg)
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
  ioctl(dev_fd, DRM_IOCTL_AMDXDNA_EXEC_CMD, &arg);
  cmd_arg.seq = arg.seq;
}

int64_t timeout_ms2abs_ns(int64_t timeout_ms)
{
  if (!timeout_ms)
    return std::numeric_limits<int64_t>::max(); // 0 means wait forever

  auto now = std::chrono::high_resolution_clock::now();
  auto now_ns = std::chrono::time_point_cast<std::chrono::nanoseconds>(now);
  return timeout_ms * 1000000 + now_ns.time_since_epoch().count();
}

void
wait_syncobj_available(int dev_fd, const uint32_t* sobj_hdls,
  const uint64_t* timepoints, uint32_t num)
{
  drm_syncobj_timeline_wait wsobj = {
    .handles = reinterpret_cast<uintptr_t>(sobj_hdls),
    .points = reinterpret_cast<uintptr_t>(timepoints),
    .timeout_nsec = timeout_ms2abs_ns(0), /* wait forever */
    .count_handles = num,
    .flags = DRM_SYNCOBJ_WAIT_FLAGS_WAIT_ALL |
             DRM_SYNCOBJ_WAIT_FLAGS_WAIT_FOR_SUBMIT |
             DRM_SYNCOBJ_WAIT_FLAGS_WAIT_AVAILABLE,
  };
  ioctl(dev_fd, DRM_IOCTL_SYNCOBJ_TIMELINE_WAIT, &wsobj);
}

void
submit_dep(int dev_fd, shim_xdna::submit_dep_arg& cmd_arg)
{
  wait_syncobj_available(dev_fd, cmd_arg.sync_objs, cmd_arg.sync_points, cmd_arg.count);

  amdxdna_drm_exec_cmd arg = {};
  arg.ctx = cmd_arg.ctx_handle;
  arg.type = AMDXDNA_CMD_SUBMIT_DEPENDENCY;
  arg.cmd_handles = reinterpret_cast<uintptr_t>(cmd_arg.sync_objs);
  arg.args = reinterpret_cast<uintptr_t>(cmd_arg.sync_points);
  arg.cmd_count = cmd_arg.count;
  arg.arg_count = cmd_arg.count;
  ioctl(dev_fd, DRM_IOCTL_AMDXDNA_EXEC_CMD, &arg);
}

void
submit_sig(int dev_fd, shim_xdna::submit_sig_arg& cmd_arg)
{
  amdxdna_drm_exec_cmd arg = {};
  arg.ctx = cmd_arg.ctx_handle;
  arg.type = AMDXDNA_CMD_SUBMIT_SIGNAL;
  arg.cmd_handles = cmd_arg.sync_obj;
  arg.args = cmd_arg.timepoint;
  arg.cmd_count = 1;
  arg.arg_count = 1;
  ioctl(dev_fd, DRM_IOCTL_AMDXDNA_EXEC_CMD, &arg);
}

void
get_info(int dev_fd, amdxdna_drm_get_info& info)
{
  ioctl(dev_fd, DRM_IOCTL_AMDXDNA_GET_INFO, &info);
}

void
set_state(int dev_fd, amdxdna_drm_set_state& state)
{
  ioctl(dev_fd, DRM_IOCTL_AMDXDNA_SET_STATE, &state);
}

void
create_syncobj(int dev_fd, shim_xdna::create_destroy_syncobj_arg& sobj_arg)
{
  drm_syncobj_create arg = {};
  arg.handle = AMDXDNA_INVALID_FENCE_HANDLE;
  arg.flags = 0;
  ioctl(dev_fd, DRM_IOCTL_SYNCOBJ_CREATE, &arg);
  sobj_arg.handle = arg.handle;
}

void
destroy_syncobj(int dev_fd, shim_xdna::create_destroy_syncobj_arg& sobj_arg)
{
  drm_syncobj_destroy arg = {};
  arg.handle = sobj_arg.handle;
  ioctl(dev_fd, DRM_IOCTL_SYNCOBJ_DESTROY, &arg);
}

void
export_syncobj(int dev_fd, shim_xdna::export_import_syncobj_arg& sobj_arg)
{
  drm_syncobj_handle arg = {};
  arg.handle = sobj_arg.handle;
  arg.flags = 0;
  arg.fd = -1;
  ioctl(dev_fd, DRM_IOCTL_SYNCOBJ_HANDLE_TO_FD, &arg);
  sobj_arg.fd = arg.fd;
}

void
import_syncobj(int dev_fd, shim_xdna::export_import_syncobj_arg& sobj_arg)
{
  drm_syncobj_handle arg = {};
  arg.handle = AMDXDNA_INVALID_FENCE_HANDLE;
  arg.flags = 0;
  arg.fd = sobj_arg.fd;
  ioctl(dev_fd, DRM_IOCTL_SYNCOBJ_FD_TO_HANDLE, &arg);
  sobj_arg.handle = arg.handle;
}

void
wait_syncobj(int dev_fd, shim_xdna::wait_syncobj_arg& sobj_arg)
{
  drm_syncobj_timeline_wait arg = {};
  arg.handles = reinterpret_cast<uintptr_t>(&sobj_arg.handle);
  arg.points = reinterpret_cast<uintptr_t>(&sobj_arg.timepoint);
  arg.timeout_nsec = timeout_ms2abs_ns(sobj_arg.timeout_ms);
  arg.count_handles = 1;
  /* Keep waiting even if not submitted yet */
  arg.flags = DRM_SYNCOBJ_WAIT_FLAGS_WAIT_FOR_SUBMIT;
  ioctl(dev_fd, DRM_IOCTL_SYNCOBJ_TIMELINE_WAIT, &arg);
}

void
signal_syncobj(int dev_fd, shim_xdna::signal_syncobj_arg& sobj_arg)
{
  drm_syncobj_timeline_array arg = {};
  arg.handles = reinterpret_cast<uintptr_t>(&sobj_arg.handle);
  arg.points = reinterpret_cast<uintptr_t>(&sobj_arg.timepoint);
  arg.count_handles = 1;
  ioctl(dev_fd, DRM_IOCTL_SYNCOBJ_TIMELINE_SIGNAL, &arg);
}

}

namespace shim_xdna {

void
platform_drv_host::
drv_ioctl(drv_ioctl_cmd cmd, void* cmd_arg) const
{
  auto fd = dev_fd();

  switch (cmd) {
  case drv_ioctl_cmd::create_ctx:
    create_ctx(fd, *static_cast<create_ctx_arg*>(cmd_arg));
    break;
  case drv_ioctl_cmd::destroy_ctx:
    destroy_ctx(fd, *static_cast<destroy_ctx_arg*>(cmd_arg));
    break;
  case drv_ioctl_cmd::config_ctx_cu_config:
    config_ctx_cu_config(fd, *static_cast<config_ctx_cu_config_arg*>(cmd_arg));
    break;
  case drv_ioctl_cmd::config_ctx_debug_bo:
    config_ctx_debug_bo(fd, *static_cast<config_ctx_debug_bo_arg*>(cmd_arg));
    break;
  case drv_ioctl_cmd::create_bo:
    create_bo(fd, *static_cast<create_bo_arg*>(cmd_arg));
    break;
  case drv_ioctl_cmd::destroy_bo:
    destroy_bo(fd, *static_cast<destroy_bo_arg*>(cmd_arg));
    break;
  case drv_ioctl_cmd::sync_bo:
    sync_bo(fd, *static_cast<sync_bo_arg*>(cmd_arg));
    break;
  case drv_ioctl_cmd::export_bo:
    export_bo(fd, *static_cast<export_bo_arg*>(cmd_arg));
    break;
  case drv_ioctl_cmd::import_bo:
    import_bo(fd, *static_cast<import_bo_arg*>(cmd_arg));
    break;
  case drv_ioctl_cmd::submit_cmd:
    submit_cmd(fd, *static_cast<submit_cmd_arg*>(cmd_arg));
    break;
  case drv_ioctl_cmd::submit_dep:
    submit_dep(fd, *static_cast<submit_dep_arg*>(cmd_arg));
    break;
  case drv_ioctl_cmd::submit_sig:
    submit_sig(fd, *static_cast<submit_sig_arg*>(cmd_arg));
    break;
  case drv_ioctl_cmd::get_info:
    get_info(fd, *static_cast<amdxdna_drm_get_info*>(cmd_arg));
    break;
  case drv_ioctl_cmd::set_state:
    set_state(fd, *static_cast<amdxdna_drm_set_state*>(cmd_arg));
    break;
  case drv_ioctl_cmd::create_syncobj:
    create_syncobj(fd, *static_cast<create_destroy_syncobj_arg*>(cmd_arg));
    break;
  case drv_ioctl_cmd::destroy_syncobj:
    destroy_syncobj(fd, *static_cast<create_destroy_syncobj_arg*>(cmd_arg));
    break;
  case drv_ioctl_cmd::export_syncobj:
    export_syncobj(fd, *static_cast<export_import_syncobj_arg*>(cmd_arg));
    break;
  case drv_ioctl_cmd::import_syncobj:
    import_syncobj(fd, *static_cast<export_import_syncobj_arg*>(cmd_arg));
    break;
  case drv_ioctl_cmd::signal_syncobj:
    signal_syncobj(fd, *static_cast<signal_syncobj_arg*>(cmd_arg));
    break;
  case drv_ioctl_cmd::wait_syncobj:
    wait_syncobj(fd, *static_cast<wait_syncobj_arg*>(cmd_arg));
    break;
  default:
    shim_err(EINVAL, "Unknown drv_ioctl: %d", cmd);
    break;
  }
}

}

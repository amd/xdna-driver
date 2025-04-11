// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2025, Advanced Micro Devices, Inc. All rights reserved.

#include "hwctx.h"
#include "hwq.h"
#include "bo.h"
#include "pcidev.h"
#include "amdxdna_proto.h"

#include "core/common/config_reader.h"
#include "core/common/memalign.h"
#include "core/common/query_requests.h"

namespace {

// For debug only
void
print_cu_config(amdxdna_ctx_param_config_cu *config)
{
  auto n = config->num_cus;
  auto conf = config->cu_configs;

  for (uint16_t i = 0; i < n; i++)
    shim_debug("CU_CONF: bo %d func=%d", conf[i].cu_bo, conf[i].cu_func);
}

}

namespace shim_xdna {

hw_ctx_virtio::
hw_ctx_virtio(const device& device, const xrt::xclbin& xclbin, const xrt::hw_context::qos_type& qos)
  : hw_ctx(device, qos, std::make_unique<hw_q_virtio>(device), xclbin)
{
  create_ctx_on_device();

  auto cu_info = get_cu_info();
  std::vector<char> cu_conf_param_buf(sizeof(amdxdna_ccmd_config_ctx_req) +
    sizeof(amdxdna_ctx_param_config_cu) + cu_info.size() * sizeof(amdxdna_cu_config));
  auto cu_conf_req = reinterpret_cast<amdxdna_ccmd_config_ctx_req *>(cu_conf_param_buf.data());
  auto cu_conf_param = reinterpret_cast<amdxdna_ctx_param_config_cu *>(cu_conf_req->param_val);

  cu_conf_param->num_cus = cu_info.size();
  xcl_bo_flags f = {};
  f.flags = XRT_BO_FLAGS_CACHEABLE;
  for (int i = 0; i < cu_info.size(); i++) {
    auto& ci = cu_info[i];

    m_pdi_bos.push_back(alloc_bo(nullptr, ci.m_pdi.size(), f.all));
    auto& pdi_bo = m_pdi_bos[i];
    auto pdi_vaddr = reinterpret_cast<char *>(
      pdi_bo->map(xrt_core::buffer_handle::map_type::write));

    auto& cf = cu_conf_param->cu_configs[i];
    std::memcpy(pdi_vaddr, ci.m_pdi.data(), ci.m_pdi.size());
    pdi_bo->sync(xrt_core::buffer_handle::direction::host2device, pdi_bo->get_properties().size, 0);
    cf.cu_bo = static_cast<bo_virtio*>(pdi_bo.get())->get_host_bo_handle();
    cf.cu_func = ci.m_func;
  }

  print_cu_config(cu_conf_param);

  cu_conf_req->hdr.cmd = AMDXDNA_CCMD_CONFIG_CTX;
  cu_conf_req->hdr.len = cu_conf_param_buf.size();
  cu_conf_req->hdr.rsp_off = 0;
  cu_conf_req->handle = get_slotidx();
  cu_conf_req->param_type = DRM_AMDXDNA_CTX_CONFIG_CU;
  cu_conf_req->param_val_size = cu_conf_req->hdr.len - sizeof(amdxdna_ccmd_config_ctx_req);
  const pdev_virtio& vdev = static_cast<const shim_xdna::pdev_virtio&>(device.get_pdev());
  vdev.host_call(cu_conf_req, cu_conf_param_buf.size(), nullptr, 0);

  shim_debug("Created VIRTIO HW context (%d)", get_slotidx());
}

hw_ctx_virtio::
~hw_ctx_virtio()
{
  shim_debug("Destroying VIRTIO HW context (%d)...", get_slotidx());
  try {
    delete_ctx_on_device();
  } catch (const xrt_core::system_error& e) {
    shim_debug("Failed to delete context on device: %s", e.what());
  }
  set_slotidx(AMDXDNA_INVALID_CTX_HANDLE);
}

std::unique_ptr<xrt_core::buffer_handle>
hw_ctx_virtio::
alloc_bo(void* userptr, size_t size, uint64_t flags)
{
  // const_cast: alloc_bo() is not const yet in device class
  auto& dev = const_cast<device&>(get_device());

  // Debug buffer is specific to one context.
  if (xcl_bo_flags{flags}.use == XRT_BO_USE_DEBUG)
    return dev.alloc_bo(userptr, get_slotidx(), size, flags);
  // Other BOs are shared across all contexts.
  return dev.alloc_bo(userptr, AMDXDNA_INVALID_CTX_HANDLE, size, flags);
}

void
hw_ctx_virtio::
create_ctx_on_device()
{
  amdxdna_ccmd_create_ctx_rsp rsp = {};
  amdxdna_ccmd_create_ctx_req req = {};

  req.hdr.cmd = AMDXDNA_CCMD_CREATE_CTX;
  req.hdr.len = sizeof(req);
  req.hdr.rsp_off = 0;
  req.max_opc = m_ops_per_cycle;
  req.num_tiles = m_num_cols * /*xrt_core::device_query<xrt_core::query::aie_tiles_stats>(&get_device()).core_rows*/4;
  req.qos_info = m_qos;
  auto& pdev = get_device().get_pdev();
  auto& vdev = static_cast<const shim_xdna::pdev_virtio&>(pdev);
  vdev.host_call(&req, sizeof(req), &rsp, sizeof(rsp));

  set_slotidx(rsp.handle);
  m_q->bind_hwctx(this);
}

void
hw_ctx_virtio::
delete_ctx_on_device()
{
  m_q->unbind_hwctx();

  amdxdna_ccmd_destroy_ctx_req req = {};

  req.hdr.cmd = AMDXDNA_CCMD_DESTROY_CTX;
  req.hdr.len = sizeof(req);
  req.hdr.rsp_off = 0;
  req.handle = get_slotidx();
  auto& pdev = get_device().get_pdev();
  auto& vdev = static_cast<const shim_xdna::pdev_virtio&>(pdev);
  vdev.host_call(&req, sizeof(req), nullptr, 0);
}

} // shim_xdna

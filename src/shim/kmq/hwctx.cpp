// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2023-2025, Advanced Micro Devices, Inc. All rights reserved.

#include "hwctx.h"
#include "hwq.h"
#include "../bo.h"

#include "core/common/config_reader.h"
#include "core/common/memalign.h"

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

hw_ctx_kmq::
hw_ctx_kmq(const device& device, const xrt::xclbin& xclbin, const xrt::hw_context::qos_type& qos)
  : hw_ctx(device, qos, std::make_unique<hw_q_kmq>(device), xclbin)
{
  hw_ctx::create_ctx_on_device();

  auto cu_info = get_cu_info();
  std::vector<char> cu_conf_param_buf(
    sizeof(amdxdna_ctx_param_config_cu) + cu_info.size() * sizeof(amdxdna_cu_config));
  auto cu_conf_param = reinterpret_cast<amdxdna_ctx_param_config_cu *>(cu_conf_param_buf.data());

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
    cf.cu_bo = static_cast<bo*>(pdi_bo.get())->get_drm_bo_handle();
    cf.cu_func = ci.m_func;
  }

  print_cu_config(cu_conf_param);

  amdxdna_drm_config_ctx arg = {};
  arg.handle = get_slotidx();
  arg.param_type = DRM_AMDXDNA_CTX_CONFIG_CU;
  arg.param_val = reinterpret_cast<uintptr_t>(cu_conf_param);
  arg.param_val_size = cu_conf_param_buf.size();
  get_device().get_pdev().ioctl(DRM_IOCTL_AMDXDNA_CONFIG_CTX, &arg);

  shim_debug("Created KMQ HW context (%d)", get_slotidx());
}

hw_ctx_kmq::
~hw_ctx_kmq()
{
  shim_debug("Destroying KMQ HW context (%d)...", get_slotidx());
}

std::unique_ptr<xrt_core::buffer_handle>
hw_ctx_kmq::
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

} // shim_xdna

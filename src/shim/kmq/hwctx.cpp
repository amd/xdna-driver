// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2023-2025, Advanced Micro Devices, Inc. All rights reserved.

#include "hwq.h"
#include "hwctx.h"

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

hwctx_kmq::
hwctx_kmq(const device& device, const xrt::xclbin& xclbin, const qos_type& qos)
  : hwctx(device, qos, xclbin, std::make_unique<hwq_kmq>(device))
{
  xclbin_parser xp(xclbin);
  std::vector<char> cu_conf_param_buf(
    sizeof(amdxdna_ctx_param_config_cu) + xp.get_num_cus() * sizeof(amdxdna_cu_config));
  auto cu_conf_param = reinterpret_cast<amdxdna_ctx_param_config_cu *>(cu_conf_param_buf.data());

  cu_conf_param->num_cus = xp.get_num_cus();
  xcl_bo_flags f = {};
  f.flags = XRT_BO_FLAGS_CACHEABLE;
  for (int i = 0; i < cu_conf_param->num_cus; i++) {
    auto& pdi = xp.get_cu_pdi(i);
    auto bo = alloc_bo(pdi.size(), f.all);
    m_pdi_bos.emplace_back(dynamic_cast<buffer*>(bo.release()));

    auto& pdi_bo = m_pdi_bos[i];
    auto pdi_vaddr = reinterpret_cast<char *>(pdi_bo->vaddr());

    auto& cf = cu_conf_param->cu_configs[i];
    std::memcpy(pdi_vaddr, pdi.data(), pdi.size());
    pdi_bo->sync(xrt_core::buffer_handle::direction::host2device, pdi_bo->size(), 0);
    cf.cu_bo = pdi_bo->id().handle;
    cf.cu_func = xp.get_cu_func(i);
  }

  //print_cu_config(cu_conf_param);

  config_ctx_cu_config_arg arg = {
    .ctx_handle = get_slotidx(),
    .conf_buf = cu_conf_param_buf,
  };
  device.get_pdev().drv_ioctl(drv_ioctl_cmd::config_ctx_cu_config, &arg);

  shim_debug("Created KMQ HW context (%d)", get_slotidx());
}

hwctx_kmq::
hwctx_kmq(const device& device, uint32_t partition_size)
  : hwctx(device, partition_size, std::make_unique<hwq_kmq>(device))
{
  shim_debug("Created KMQ HW context (%d)", get_slotidx());
}

hwctx_kmq::
~hwctx_kmq()
{
  shim_debug("Destroying KMQ HW context (%d)...", get_slotidx());
}

}

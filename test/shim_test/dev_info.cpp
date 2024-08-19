// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2024, Advanced Micro Devices, Inc. All rights reserved.

#include "dev_info.h"

// Test program location, all workspace paths below are relative to it
extern std::string cur_path;
// Force to use xclbin pointed to by this path
extern std::string xclbin_path;

namespace {

xclbin_info xclbin_infos[] = {
  {
    .name = "1x4.xclbin",
    .device = npu1_device_id,
    .revision_id = npu1_revision_id,
    .ip_name2idx = {
      { "DPU_PDI_0:IPUV1CNN",         {0} },
      { "DPU_PDI_1:IPUV1CNN",         {1} },
      { "DPU_PDI_2:IPUV1CNN",         {2} },
      { "DPU_PDI_3:IPUV1CNN",         {3} },
      { "DPU_PDI_4:IPUV1CNN",         {4} },
      { "DPU_PDI_5:IPUV1CNN",         {5} },
      { "DPU_PDI_6:IPUV1CNN",         {6} },
      { "DPU_PDI_7:IPUV1CNN",         {7} },
    },
    .workspace = "npu1_workspace",
  },
  {
    .name = "1x4.xclbin",
    .device = npu2_device_id,
    .revision_id = npu2_revision_id,
    .ip_name2idx = {
      { "DPU_PDI_0:IPUV1CNN",         {0} },
      { "DPU_PDI_1:IPUV1CNN",         {1} },
      { "DPU_PDI_2:IPUV1CNN",         {2} },
      { "DPU_PDI_3:IPUV1CNN",         {3} },
      { "DPU_PDI_4:IPUV1CNN",         {4} },
      { "DPU_PDI_5:IPUV1CNN",         {5} },
      { "DPU_PDI_6:IPUV1CNN",         {6} },
      { "DPU_PDI_7:IPUV1CNN",         {7} },
    },
    .workspace = "npu2_workspace",
  },
  {
    .name = "vadd.xclbin",
    .device = npu3_device_id,
    .revision_id = npu_any_revision_id,
    .ip_name2idx = {
      { "dpu:vadd", {0} },
    },
    .workspace = "npu3_workspace",
  },
  {
    .name = "vadd.xclbin",
    .device = npu3_device_id1,
    .revision_id = npu_any_revision_id,
    .ip_name2idx = {
      { "dpu:vadd", {0} },
    },
    .workspace = "npu3_workspace",
  },
  {
    .name = "move_memtiles.xclbin",
    .device = npu3_device_id,
    .revision_id = npu_any_revision_id,
    .ip_name2idx = {
      { "dpu:vadd", {0} },
    },
    .workspace = "npu3_workspace",
  },
  {
    .name = "move_memtiles.xclbin",
    .device = npu3_device_id1,
    .revision_id = npu_any_revision_id,
    .ip_name2idx = {
      { "dpu:vadd", {0} },
    },
    .workspace = "npu3_workspace",
  },
  {
    .name = "ddr_memtile.xclbin",
    .device = npu3_device_id1,
    .revision_id = npu_any_revision_id,
    .ip_name2idx = {
      { "dpu:vadd", {0} },
    },
    .workspace = "npu3_workspace",
  },
  {
    .name = "remote_barrier.xclbin",
    .device = npu3_device_id1,
    .revision_id = npu_any_revision_id,
    .ip_name2idx = {
      { "dpu:vadd", {0} },
    },
    .workspace = "npu3_workspace",
  },
  {
    .name = "1x4.xclbin",
    .device = npu2_device_id,
    .revision_id = npu4_revision_id,
    .ip_name2idx = {
      { "DPU_PDI_0:IPUV1CNN",         {0} },
      { "DPU_PDI_1:IPUV1CNN",         {1} },
      { "DPU_PDI_2:IPUV1CNN",         {2} },
      { "DPU_PDI_3:IPUV1CNN",         {3} },
      { "DPU_PDI_4:IPUV1CNN",         {4} },
      { "DPU_PDI_5:IPUV1CNN",         {5} },
      { "DPU_PDI_6:IPUV1CNN",         {6} },
      { "DPU_PDI_7:IPUV1CNN",         {7} },
      { "DPU_PDI_8:IPUV1CNN",         {8} },
      { "DPU_PDI_9:IPUV1CNN",         {9} },
      { "DPU_PDI_10:IPUV1CNN",         {10} },
      { "DPU_PDI_11:IPUV1CNN",         {11} },
      { "DPU_PDI_12:IPUV1CNN",         {12} },
      { "DPU_PDI_13:IPUV1CNN",         {13} },
    },
    .workspace = "npu4_workspace",
  },
  {
    .name = "1x4.xclbin",
    .device = npu2_device_id,
    .revision_id = npu5_revision_id,
    .ip_name2idx = {
      { "DPU_PDI_0:IPUV1CNN",         {0} },
      { "DPU_PDI_1:IPUV1CNN",         {1} },
      { "DPU_PDI_2:IPUV1CNN",         {2} },
      { "DPU_PDI_3:IPUV1CNN",         {3} },
      { "DPU_PDI_4:IPUV1CNN",         {4} },
      { "DPU_PDI_5:IPUV1CNN",         {5} },
      { "DPU_PDI_6:IPUV1CNN",         {6} },
      { "DPU_PDI_7:IPUV1CNN",         {7} },
      { "DPU_PDI_8:IPUV1CNN",         {8} },
      { "DPU_PDI_9:IPUV1CNN",         {9} },
      { "DPU_PDI_10:IPUV1CNN",        {10} },
      { "DPU_PDI_11:IPUV1CNN",        {11} },
      { "DPU_PDI_12:IPUV1CNN",        {12} },
      { "DPU_PDI_13:IPUV1CNN",        {13} },
    },
    .workspace = "npu5_workspace",
  },
  {
    .name = "1x4.xclbin",
    .device = npu2_device_id,
    .revision_id = npu6_revision_id,
    .ip_name2idx = {
      { "DPU_PDI_0:IPUV1CNN",         {0} },
      { "DPU_PDI_1:IPUV1CNN",         {1} },
      { "DPU_PDI_2:IPUV1CNN",         {2} },
      { "DPU_PDI_3:IPUV1CNN",         {3} },
      { "DPU_PDI_4:IPUV1CNN",         {4} },
      { "DPU_PDI_5:IPUV1CNN",         {5} },
      { "DPU_PDI_6:IPUV1CNN",         {6} },
      { "DPU_PDI_7:IPUV1CNN",         {7} },
      { "DPU_PDI_8:IPUV1CNN",         {8} },
      { "DPU_PDI_9:IPUV1CNN",         {9} },
      { "DPU_PDI_10:IPUV1CNN",         {10} },
      { "DPU_PDI_11:IPUV1CNN",         {11} },
      { "DPU_PDI_12:IPUV1CNN",         {12} },
      { "DPU_PDI_13:IPUV1CNN",         {13} },
    },
    .workspace = "npu6_workspace",
  },
  {
    .name = "design.xclbin",
    .device = npu1_device_id,
    .revision_id = npu1_revision_id,
    .ip_name2idx = {
      { "DPU:IPUV1CNN", {0} },
    },
    .workspace = "local_shim_test_data/elf_txn_no_cp_npu1",
  },
  {
    .name = "design.xclbin",
    .device = npu2_device_id,
    .revision_id = npu_any_revision_id,
    .ip_name2idx = {
      { "DPU:IPUV1CNN", {0} },
    },
    .workspace = "local_shim_test_data/elf_txn_no_cp_npu2",
  },
};

}

const xclbin_info&
get_xclbin_info(device* dev, const char *xclbin_name)
{
  auto pci_dev_id = device_query<query::pcie_device>(dev);
  auto revision_id = device_query<query::pcie_id>(dev).revision_id;
  for (auto& xclbin : xclbin_infos) {
    if ((xclbin.device == pci_dev_id) &&
        ((xclbin.revision_id == revision_id) || (xclbin.revision_id == npu_any_revision_id)) &&
        (xclbin_name == nullptr || !strcmp(xclbin.name, xclbin_name)))
      return xclbin;
  }
  throw std::runtime_error("xclbin info not found");
}

std::string
get_xclbin_name(device* dev)
{
  return get_xclbin_info(dev).name;
}

std::string
get_xclbin_workspace(device* dev, const char *xclbin_name)
{
  return (cur_path + "/../" + get_xclbin_info(dev, xclbin_name).workspace);
}

std::string
get_xclbin_path(device* dev, const char *xclbin_name)
{
  if (!xclbin_path.empty())
    return xclbin_path;

  auto wrk = get_xclbin_workspace(dev, xclbin_name);
  if (!xclbin_name)
    return wrk + "/" + get_xclbin_name(dev);
  return wrk + "/" + std::string(xclbin_name);
}

const std::map<const char*, cuidx_type>&
get_xclbin_ip_name2index(device* dev, const char *xclbin_name)
{
  return get_xclbin_info(dev, xclbin_name).ip_name2idx;
}

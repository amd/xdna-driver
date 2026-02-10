// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2024-2026, Advanced Micro Devices, Inc. All rights reserved.

#include "dev_info.h"

// Test program location, all paths below are relative to it
extern std::string cur_path;
// Force to use xclbin pointed to by this path
extern std::string xclbin_path;

namespace {

static std::string
dirname_of(const std::string& path)
{
  auto pos = path.find_last_of('/');
  if (pos == std::string::npos)
    return ".";
  return path.substr(0, pos);
}

binary_info binary_infos[] = {
  {
    .tag = "good",
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
    .path = "npu1_workspace/1x4.xclbin",
    .data = "data",
    .flow = LEGACY,
  },
  {
    .tag = "good",
    .device = npu1_device_id1,
    .revision_id = npu1_revision_id1,
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
    .path = "npu1_workspace/1x4.xclbin",
    .data = "data",
    .flow = LEGACY,
  },
  {
    .tag = "good",
    .device = npu3_device_id,
    .revision_id = npu_any_revision_id,
    .ip_name2idx = {
      { "DPU:dpu", {0xffffffff} },
    },
    .path = "local_shim_test_data/npu3/vadd/vadd.elf",
    .flow = FULL_ELF,
  },
  {
    .tag = "bad",
    .device = npu3_device_id,
    .revision_id = npu_any_revision_id,
    .ip_name2idx = {
      { "DPU:dpu", {0xffffffff} },
    },
    .path = "local_shim_test_data/npu3/bad/bad_timeout.elf",
    .flow = FULL_ELF,
  },
  {
    .tag = "nop",
    .device = npu3_device_id,
    .revision_id = npu_any_revision_id,
    .ip_name2idx = {
      { "DPU:dpu", {0xffffffff} },
    },
    .path = "local_shim_test_data/npu3/nop/nop.elf",
    .flow = FULL_ELF,
  },
  {
    .tag = "good",
    .device = npu3_device_id1,
    .revision_id = npu_any_revision_id,
    .ip_name2idx = {
      { "DPU:dpu", {0xffffffff} },
    },
    .path = "local_shim_test_data/npu3a/vadd/vadd.elf",
    .flow = FULL_ELF,
  },
  {
    .tag = "bad",
    .device = npu3_device_id1,
    .revision_id = npu_any_revision_id,
    .ip_name2idx = {
      { "DPU:dpu", {0xffffffff} },
    },
    .path = "local_shim_test_data/npu3a/bad/bad_timeout.elf",
    .flow = FULL_ELF,
  },
  {
    .tag = "nop",
    .device = npu3_device_id1,
    .revision_id = npu_any_revision_id,
    .ip_name2idx = {
      { "DPU:dpu", {0xffffffff} },
    },
    .path = "local_shim_test_data/npu3a/nop/nop.elf",
    .flow = FULL_ELF,
  },
  {
    .tag = "good",
    .device = npu4_device_id,
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
      { "DPU_PDI_10:IPUV1CNN",        {10} },
      { "DPU_PDI_11:IPUV1CNN",        {11} },
      { "DPU_PDI_12:IPUV1CNN",        {12} },
      { "DPU_PDI_13:IPUV1CNN",        {13} },
    },
    .path = "npu4_workspace/1x4.xclbin",
    .data = "data",
    .flow = LEGACY,
  },
  {
    .tag = "good",
    .device = npu4_device_id,
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
    .path = "npu5_workspace/1x4.xclbin",
    .data = "data",
    .flow = LEGACY,
  },
  {
    .tag = "good",
    .device = npu4_device_id,
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
    .path = "npu6_workspace/1x4.xclbin",
    .data = "data",
    .flow = LEGACY,
  },
  {
    .tag = "good",
    .device = npu1_device_id,
    .revision_id = npu1_revision_id,
    .ip_name2idx = {
      { "DPU_ELF:IPUV1CNN", {9} },
    },
    .path = "local_shim_test_data/npu1/partial_elf/design.xclbin",
    .flow = PARTIAL_ELF,
  },
  {
    .tag = "good",
    .device = npu4_device_id,
    .revision_id = npu_any_revision_id,
    .ip_name2idx = {
      { "DPU:IPUV1CNN", {1} },
    },
    .path = "local_shim_test_data/npu4/partial_elf/design.xclbin",
    .flow = PARTIAL_ELF,
  },
  {
    .tag = "good",
    .device = npu4_device_id,
    .revision_id = npu_any_revision_id,
    .ip_name2idx = {
      { "DPU:IPUV1CNN", {1} },
    },
    .path = "local_shim_test_data/npu4/preempt_partial_elf/pm_reload.xclbin",
    .flow = PREEMPT_PARTIAL_ELF,
  },
  {
    .tag = "good",
    .device = npu4_device_id,
    .revision_id = npu_any_revision_id,
    .ip_name2idx = {
      { "DPU:dpu", {0xffffffff} }, // CU index is not needed for full ELF
    },
    .path = "local_shim_test_data/npu4/preempt_full_elf/yolo_fullelf_aximm.elf",
    .flow = PREEMPT_FULL_ELF,
  },
  {
    .tag = "bad",
    .device = npu4_device_id,
    .revision_id = npu_any_revision_id,
    .ip_name2idx = {
      { "DPU:IPUV1CNN", {0} },
    },
    .path = "local_shim_test_data/npu4/bad/bad_txn.xclbin",
    .flow = PARTIAL_ELF,
  },
  {
    .tag = "gemm",
    .device = npu4_device_id,
    .revision_id = npu_any_revision_id,
    .ip_name2idx = {
      { "DPU:IPUV1CNN", {0} },
    },
    .path = "local_shim_test_data/npu4/gemm/gemm.xclbin",
    .flow = PARTIAL_ELF,
  },
  {
    .tag = "nop",
    .device = npu4_device_id,
    .revision_id = npu_any_revision_id,
    .ip_name2idx = {
      { "DPU:IPUV1CNN", {1} },
    },
    .path = "local_shim_test_data/npu4/nop/nop.xclbin",
    .flow = PARTIAL_ELF,
  },
  {
    .tag = "nop",
    .device = npu1_device_id,
    .revision_id = npu1_revision_id,
    .ip_name2idx = {
      { "DPU:IPUV1CNN", {1} },
    },
    .path = "local_shim_test_data/npu1/nop/nop.xclbin",
    .flow = PARTIAL_ELF,
  },
  {
    .tag = "aie_debug",
    .device = npu4_device_id,
    .revision_id = npu_any_revision_id,
    .ip_name2idx = {
      { "DPU:IPUV1CNN", {0} },
    },
    .path = "local_shim_test_data/npu4/aie_debug/verify_4x4.xclbin",
    .flow = PARTIAL_ELF,
  },
};

}

const binary_info&
get_binary_info(device* dev, const char* tag, const flow_type* flow)
{
  auto pci_dev_id = device_query<query::pcie_device>(dev);
  auto revision_id = device_query<query::pcie_id>(dev).revision_id;
  bool match_tag = (tag == nullptr || tag[0] == '\0');
  bool match_flow = (flow == nullptr);
  for (auto& bin : binary_infos) {
    if ((bin.device == pci_dev_id) &&
        ((bin.revision_id == revision_id) || (bin.revision_id == npu_any_revision_id)) &&
        (match_tag || (bin.tag && !strcmp(bin.tag, tag))) &&
        (match_flow || (bin.flow == *flow)))
      return bin;
  }
  throw std::runtime_error("binary info not found");
}

std::string
get_binary_path(device* dev, const char* tag, const flow_type* flow)
{
  if (!xclbin_path.empty())
    return xclbin_path;
  return cur_path + "/../" + get_binary_info(dev, tag, flow).path;
}

std::string
get_kernel_name(device* dev, const char* tag, const flow_type* flow)
{
  return get_binary_info(dev, tag, flow).ip_name2idx.begin()->first;
}

flow_type
get_flow_type(device* dev, const char* tag, const flow_type* flow)
{
  return get_binary_info(dev, tag, flow).flow;
}

static std::string
get_binary_workspace_dir(device* dev, const char* tag, const flow_type* flow)
{
  const auto& info = get_binary_info(dev, tag, flow);
  return cur_path + "/../" + dirname_of(info.path) + "/";
}

std::string
get_binary_data(device* dev, const char* tag, const flow_type* flow)
{
  const auto& info = get_binary_info(dev, tag, flow);
  if (info.data.empty())
    return get_binary_workspace_dir(dev, tag, flow);
  return get_binary_workspace_dir(dev, tag, flow) + info.data + "/";
}

const std::map<const char*, cuidx_type>&
get_binary_ip_name2index(device* dev, const char* tag, const flow_type* flow)
{
  return get_binary_info(dev, tag, flow).ip_name2idx;
}

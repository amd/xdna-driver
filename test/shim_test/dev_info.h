// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2024-2025, Advanced Micro Devices, Inc. All rights reserved.

#ifndef _SHIMTEST_DEV_INFO_H_
#define _SHIMTEST_DEV_INFO_H_

#include "core/common/device.h"
#include "core/common/query_requests.h"

using namespace xrt_core;

enum kernel_type {
  KERNEL_TYPE_DPU_SEQ = 0,
  KERNEL_TYPE_TXN,
  KERNEL_TYPE_TXN_PREEMPT,
  KERNEL_TYPE_TXN_FULL_ELF_PREEMPT,
};

struct xclbin_info {
  const char* name;
  const uint16_t device;
  const uint16_t revision_id;
  const std::map<const char*, cuidx_type> ip_name2idx;
  const std::string workspace;
  const std::string data;
  const kernel_type type;
};

const uint16_t npu1_device_id = 0x1502;
const uint16_t npu1_device_id1 = 0x1050;
const uint16_t npu3_device_id = 0x17f1;
const uint16_t npu3_device_id1 = 0x17f3;
const uint16_t npu4_device_id = 0x17f0;
const uint16_t npu_any_revision_id = 0xffff;
const uint16_t npu1_revision_id = 0x0;
const uint16_t npu1_revision_id1 = 0x1;
const uint16_t npu2_revision_id = 0x0;
const uint16_t npu4_revision_id = 0x10;
const uint16_t npu5_revision_id = 0x11;
const uint16_t npu6_revision_id = 0x20;

const xclbin_info& get_xclbin_info(device* dev, const char *xclbin_name=nullptr);
std::string get_xclbin_name(device* dev); // Find default xclbin name for this device
std::string get_kernel_name(device* dev, const char*);
kernel_type get_kernel_type(device* dev, const char*);
std::string get_xclbin_data(device* dev, const char *xclbin_name=nullptr);
std::string get_xclbin_path(device* dev, const char *xclbin_name=nullptr);
const std::map<const char*, cuidx_type>& get_xclbin_ip_name2index(device* dev, const char *xclbin_name=nullptr);
std::string get_preemption_libs_path();

#endif // _SHIMTEST_DEV_INFO_H_

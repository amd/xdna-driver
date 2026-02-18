// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2024-2026, Advanced Micro Devices, Inc. All rights reserved.

#ifndef _SHIMTEST_DEV_INFO_H_
#define _SHIMTEST_DEV_INFO_H_

#include "core/common/device.h"
#include "core/common/query_requests.h"

using namespace xrt_core;

enum flow_type {
  LEGACY = 0,
  PARTIAL_ELF,
  PREEMPT_PARTIAL_ELF,
  FULL_ELF,
  PREEMPT_FULL_ELF,
};

struct binary_info {
  const char* tag;  /* tag for test lookup, e.g. "nop", "bad", "good" */
  const uint16_t device;
  const uint16_t revision_id;
  const std::map<const char*, cuidx_type> ip_name2idx;
  const std::string path;
  const std::string data;
  const flow_type flow;
};

const uint16_t npu1_device_id = 0x1502;
const uint16_t npu1_device_id1 = 0x1050;
const uint16_t npu3_device_id = 0x17f1;
const uint16_t npu3_device_id1 = 0x17f3;
const uint16_t npu4_device_id = 0x17f0;
const uint16_t npu_any_revision_id = 0xffff;
const uint16_t npu1_revision_id = 0x0;
const uint16_t npu1_revision_id1 = 0x1;
const uint16_t npu4_revision_id = 0x10;
const uint16_t npu5_revision_id = 0x11;
const uint16_t npu6_revision_id = 0x20;

const binary_info& get_binary_info(device* dev, const char* tag = nullptr, const flow_type* flow = nullptr);
std::string get_binary_path(device* dev, const char* tag = nullptr, const flow_type* flow = nullptr);
std::string get_kernel_name(device* dev, const char* tag, const flow_type* flow = nullptr);
flow_type get_flow_type(device* dev, const char* tag, const flow_type* flow = nullptr);
std::string get_binary_data(device* dev, const char* tag = nullptr, const flow_type* flow = nullptr);
const std::map<const char*, cuidx_type>& get_binary_ip_name2index(device* dev, const char* tag = nullptr, const flow_type* flow = nullptr);

#endif // _SHIMTEST_DEV_INFO_H_

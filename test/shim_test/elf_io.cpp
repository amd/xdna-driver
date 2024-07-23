// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2024, Advanced Micro Devices, Inc. All rights reserved.


#include "bo.h"
#include "hwctx.h"
#include "dev_info.h"
#include "exec_buf.h"

#include "core/common/device.h"
#include <fstream>

namespace {

using namespace xrt_core;

size_t
get_bin_size(const std::string& filename)
{
  std::ifstream ifs(filename, std::ifstream::ate | std::ifstream::binary);
  if (!ifs.is_open())
    throw std::runtime_error("Failure opening file " + filename + "!!");
  return ifs.tellg();
}

void
read_from_bin(const std::string& filename, char *buf, size_t size)
{
  std::ifstream ifs(filename, std::ios::in | std::ios::binary);
  if (!ifs.is_open())
    throw std::runtime_error("Failure opening file " + filename + " for reading!!");
  ifs.read(buf, size);
}

bo
create_bo_from_bin(device* dev, const std::string& filename)
{
  size_t sz = get_bin_size(filename);
  bo ret_bo{dev, sz};
  read_from_bin(filename, reinterpret_cast<char*>(ret_bo.map()), sz);
  ret_bo.get()->sync(buffer_handle::direction::host2device, sz, 0);
  std::cout << "Created BO from " << filename << std::endl;
  return ret_bo;
}

void
prepare_cmd_npu1(bo& execbuf, std::string elf, bo& ctrl, bo& ifm, bo& wts, bo& ofm)
{
  exec_buf ebuf(execbuf, ERT_START_NPU);

  ebuf.add_ctrl_bo(ctrl);
  ebuf.add_arg_32(3);
  ebuf.add_arg_64(0);
  ebuf.add_arg_64(0);
  ebuf.add_arg_bo(wts);
  ebuf.add_arg_bo(ifm);
  ebuf.add_arg_bo(ofm);
  ebuf.add_arg_64(0);
  ebuf.add_arg_64(0);
  ebuf.patch_ctrl_code(ctrl, elf);
  //ebuf.dump();
 
  std::cout << "NPU1: init'ed exec_buf, patched control code from " << elf << std::endl;
}

void
prepare_cmd_npu2(bo& execbuf, std::string elf, bo& ctrl, bo& ifm, bo& wts, bo& ofm)
{
  exec_buf ebuf(execbuf, ERT_START_NPU);

  ebuf.add_ctrl_bo(ctrl);
  ebuf.add_arg_32(3);
  ebuf.add_arg_64(0);
  ebuf.add_arg_64(0);
  ebuf.add_arg_bo(ifm);
  ebuf.add_arg_bo(wts);
  ebuf.add_arg_bo(ofm);
  ebuf.add_arg_64(0);
  ebuf.add_arg_64(0);
  ebuf.patch_ctrl_code(ctrl, elf);
  //ebuf.dump();
 
  std::cout << "NPU2: init'ed exec_buf, patched control code from " << elf << std::endl;
}

void
check_result(bo& bo_ofm, bo& bo_ofm_golden)
{
  bo_ofm.get()->sync(buffer_handle::direction::device2host, bo_ofm.size(), 0);

  auto ofm_p = reinterpret_cast<uint8_t*>(bo_ofm.map());
  auto ofm_golden_p = reinterpret_cast<uint8_t*>(bo_ofm_golden.map());
  size_t count = 0;
  for (size_t i = 0; i < bo_ofm.size(); i++) {
    if (ofm_p[i] != ofm_golden_p[i])
      count++;
  }
  if (count)
    throw std::runtime_error(std::to_string(count) + " bytes result mismatch!!!");
}

} // namespace

void
TEST_txn_elf_flow(device::id_type id, std::shared_ptr<device> sdev, const std::vector<uint64_t>& arg)
{
  const char* xclbin_nm = "design.xclbin";

  auto dev = sdev.get();
  auto wrk = get_xclbin_workspace(dev, xclbin_nm);
  auto bo_ifm = create_bo_from_bin(dev, wrk + "/ifm.bin");
  auto bo_wts = create_bo_from_bin(dev, wrk + "/wts.bin");
  auto bo_ofm_golden = create_bo_from_bin(dev, wrk + "/ofm.bin");
  bo bo_ofm{dev, bo_ofm_golden.size()};

  auto elf = wrk + "/no-ctrl-packet.elf";
  auto instr_size = exec_buf::get_ctrl_code_size(elf);
  bo bo_ctrl_code{dev, instr_size, XCL_BO_FLAGS_CACHEABLE};
  bo bo_exec_buf{dev, 0x1000ul, XCL_BO_FLAGS_EXECBUF};
  auto dev_id = device_query<query::pcie_device>(dev);
  if (dev_id == npu1_device_id)
    prepare_cmd_npu1(bo_exec_buf, elf, bo_ctrl_code, bo_ifm, bo_wts, bo_ofm);
  else if (dev_id == npu2_device_id)
    prepare_cmd_npu2(bo_exec_buf, elf, bo_ctrl_code, bo_ifm, bo_wts, bo_ofm);
  else
    throw std::runtime_error("Device ID not supported: " + std::to_string(dev_id));

  hw_ctx hwctx{dev, xclbin_nm};
  auto hwq = hwctx.get()->get_hw_queue();
  auto cu_idx = hwctx.get()->open_cu_context("DPU:IPUV1CNN");
  exec_buf::set_cu_idx(bo_exec_buf, cu_idx);

  hwq->submit_command(bo_exec_buf.get());
  hwq->wait_command(bo_exec_buf.get(), 0);

  check_result(bo_ofm, bo_ofm_golden);
}

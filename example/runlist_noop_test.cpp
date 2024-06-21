// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2022-2023, Advanced Micro Devices, Inc. All rights reserved.

#include <iostream>
#include <cstring>
#include <string>
#include <chrono>

/*
 * This is an example of xrt::runlist NO-OP throughput test on NPU device.
 * The application is build with Xilinx Runtime(XRT) APIs.
 * XRT is open source and it is a submodule of amd-aie repository.
 * The XRT API document: https://xilinx.github.io/XRT/master/html/index.html
 */

// Include XRT headers
#include "xrt/xrt_device.h"
#include "xrt/xrt_kernel.h"
#include "xrt/xrt_bo.h"
#include "experimental/xrt_kernel.h" /* For xrt::runlist */

const int total_run = 32000; /* Total times of run obj execution */
const int total_runobj = 512; /* Total number of run obj to be allocated */
const int dummy_buffer_size = 4096; /* in bytes */
const int noop_instrction_size = 128; /* in bytes */

void run_test(xrt::device& device, xrt::hw_context& context, xrt::kernel kernel,
    int total_runlist_submit, int num_runlist, int run_per_list)
{
  /* In this example, use vectors to hold all allocated bo, run, and runlist objects */
  std::vector<xrt::bo> instrs;
  std::vector<xrt::bo> ifms;
  std::vector<xrt::bo> params;
  std::vector<xrt::bo> ofms;
  std::vector<xrt::bo> inters;
  std::vector<xrt::bo> mcs;
  std::vector<xrt::run> runs;
  std::vector<xrt::runlist> runlists;

  for (int i = 0; i < num_runlist * run_per_list; i++) {
    auto bo_instr = xrt::bo(device, noop_instrction_size, XCL_BO_FLAGS_CACHEABLE, kernel.group_id(5));
    auto bo_ifm   = xrt::bo(device, dummy_buffer_size, XRT_BO_FLAGS_HOST_ONLY, kernel.group_id(1));
    auto bo_param = xrt::bo(device, dummy_buffer_size, XRT_BO_FLAGS_HOST_ONLY, kernel.group_id(2));
    auto bo_ofm   = xrt::bo(device, dummy_buffer_size, XRT_BO_FLAGS_HOST_ONLY, kernel.group_id(3));
    auto bo_inter = xrt::bo(device, dummy_buffer_size, XRT_BO_FLAGS_HOST_ONLY, kernel.group_id(4));
    auto bo_mc    = xrt::bo(device, dummy_buffer_size, XRT_BO_FLAGS_HOST_ONLY, kernel.group_id(7));

    // Fill no-op instrctions
    std::memset(bo_instr.map<char*>(), 0, noop_instrction_size);

    bo_instr.sync(XCL_BO_SYNC_BO_TO_DEVICE);
    // It is okay to sync below BOs, noop instrction do nothing.
    // You will need to sync below input BOs in your real application.
    bo_ifm.sync(XCL_BO_SYNC_BO_TO_DEVICE);
    bo_param.sync(XCL_BO_SYNC_BO_TO_DEVICE);
    bo_mc.sync(XCL_BO_SYNC_BO_TO_DEVICE);

    // Prepare run object
    uint64_t opcode = 1;
    auto run = xrt::run(kernel);
    run.set_arg(0, opcode);
    run.set_arg(1, std::move(bo_ifm));
    run.set_arg(2, std::move(bo_param));
    run.set_arg(3, std::move(bo_ofm));
    run.set_arg(4, std::move(bo_inter));
    run.set_arg(5, std::move(bo_instr));
    run.set_arg(6, noop_instrction_size/sizeof(uint32_t));
    run.set_arg(7, std::move(bo_mc));

    // Save created objects
    ifms.push_back(std::move(bo_ifm));
    params.push_back(std::move(bo_param));
    ofms.push_back(std::move(bo_ofm));
    inters.push_back(std::move(bo_inter));
    instrs.push_back(std::move(bo_instr));
    mcs.push_back(std::move(bo_mc));

    runs.push_back(std::move(run));
  }

  // Finally, create xrt::runlist and runlist vector for throughput test
  for (int i = 0; i < num_runlist; i++) {
    runlists.emplace_back(context);
    for (int j = 0; j < run_per_list; j++) {
      runlists[i].add(runs[i * run_per_list + j]);
    }
  }

  int issued = 0;
  int completed = 0;
  int wait_idx = 0;
  std::chrono::milliseconds timeout(10000);

  auto start = std::chrono::high_resolution_clock::now();
  // Submit all of the runlists we have
  for (auto& runlist : runlists) {
      runlist.execute();
      if (++issued == total_runlist_submit)
          break;
  }

  // Wait till total_runlist_submit completed
  while (completed < total_runlist_submit) {
      runlists[wait_idx].wait(timeout);
      completed++;
      // Re-submit till total_runlist_submit exceeded
      if (issued < total_runlist_submit) {
          runlists[wait_idx].execute();
          issued++;
      }

      if (++wait_idx == runlists.size())
          wait_idx = 0;
  }
  auto end = std::chrono::high_resolution_clock::now();

  auto duration_us = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
  auto run_per_sec = (total_runlist_submit * run_per_list * 1000000.0) / duration_us;
  auto latency_us = 1000000.0 / run_per_sec;
  std::cout << total_runlist_submit * run_per_list << " runs finished in "
            << duration_us << " us, " << run_per_list << " run per list, "
            << run_per_sec << " run/sec, "
            << "Average latency " << latency_us << " us" << std::endl;
}

int main(int argc, char **argv)
{
  if (argc != 2) {
    std::cout << "Usage: " << argv[0] << " <path-to-xclbin>" << std::endl;
    exit(1);
  }

  std::string xclbin_file(argv[1]);

  try {
    std::cout << "Host test code start..." << std::endl;

    std::cout << "Host test code is creating device object..." << std::endl;
    // On Phoenix, there is only one NPU device, thus the device index will be 0
    unsigned int device_index = 0;
    auto device = xrt::device(device_index);

    std::cout << "Host test code is loading xclbin object..." << std::endl;
    auto xclbin = xrt::xclbin(xclbin_file);

    std::cout << "Host test code is creating kernel object..." << std::endl;
    auto xkernel = xclbin.get_kernel("DPU_PDI_0");
    auto kernelName = xkernel.get_name();
    std::cout << "Host test code kernel name: " << kernelName << std::endl;

    std::cout << "Host code is registering xclbin to the device..." << std::endl;
    device.register_xclbin(xclbin);

    std::cout << "Host code is creating hw_context..." << std::endl;
    xrt::hw_context context(device, xclbin.get_uuid());

    std::cout << "Host test code is creating kernel object..." << std::endl;
    auto kernel = xrt::kernel(context, kernelName);

    std::cout << "==== Throughput test start ====" << std::endl;
    for (int run_per_list = 1; run_per_list <= 128; run_per_list *=2) {
      int num_runlist = total_runobj / run_per_list;
      int total_runlist_submit = total_run / run_per_list;

      std::cout << "Total " << num_runlist << " runlist, "
                << run_per_list << " runobj/list, "
                << "submit " << total_runlist_submit << " runlist(s)"
                << std::endl;
      run_test(device, context, kernel, total_runlist_submit, num_runlist, run_per_list);
    }
    std::cout << "==== Throughput test completed ====" << std::endl;
  }
  catch (const std::exception& ex) {
    std::cout << "ERROR: Caught exception: " << ex.what() << '\n';
    std::cout << "TEST FAILED!" << std::endl;
    return EXIT_FAILURE;
  }

  std::cout << "TEST PASSED!" << std::endl;

  return EXIT_SUCCESS;
}

// vim: ts=2 sw=2

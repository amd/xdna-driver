// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2022-2023, Advanced Micro Devices, Inc. All rights reserved.

#include <iostream>
#include <cstring>
#include <string>
#include <chrono>

/*
 * This is an example NO-OP test on IPU device.
 * The application is build with Xilinx Runtime(XRT) APIs.
 * XRT is open source and it is a submodule of amd-aie repository.
 * The XRT API document: https://xilinx.github.io/XRT/master/html/index.html
 */

// Include XRT headers
#include "xrt/xrt_device.h"
#include "xrt/xrt_kernel.h"
#include "xrt/xrt_bo.h"

const int iteration = 70000;
const int dummy_buffer_size = 4096; /* in bytes */
const int noop_instrction_size = 128; /* in bytes */

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
    // On Phoenix, there is only one IPU device, thus the device index will be 0
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

    std::cout << "Host test code allocate buffer objects..." << std::endl;
    auto bo_instr = xrt::bo(device, noop_instrction_size, XCL_BO_FLAGS_CACHEABLE, kernel.group_id(5));
    auto bo_ifm   = xrt::bo(device, dummy_buffer_size, XRT_BO_FLAGS_HOST_ONLY, kernel.group_id(1));
    auto bo_param = xrt::bo(device, dummy_buffer_size, XRT_BO_FLAGS_HOST_ONLY, kernel.group_id(2));
    auto bo_ofm   = xrt::bo(device, dummy_buffer_size, XRT_BO_FLAGS_HOST_ONLY, kernel.group_id(3));
    auto bo_inter = xrt::bo(device, dummy_buffer_size, XRT_BO_FLAGS_HOST_ONLY, kernel.group_id(4));
    auto bo_mc    = xrt::bo(device, dummy_buffer_size, XRT_BO_FLAGS_HOST_ONLY, kernel.group_id(7));

    // Fill no-op instrctions
    std::memset(bo_instr.map<char*>(), 0, noop_instrction_size);

    // Sync Input BOs
    std::cout << "Host test code sync buffer objects to device..." << std::endl;
    bo_instr.sync(XCL_BO_SYNC_BO_TO_DEVICE);
    bo_ifm.sync(XCL_BO_SYNC_BO_TO_DEVICE);
    bo_param.sync(XCL_BO_SYNC_BO_TO_DEVICE);
    bo_mc.sync(XCL_BO_SYNC_BO_TO_DEVICE);

    std::cout << "Host test code iterations (~10 seconds): " << iteration << std::endl;
    uint64_t opcode = 1;
    auto start = std::chrono::high_resolution_clock::now();

    // Set kernel argument and trigger it to run. A run object will be returned.
    auto run = kernel(opcode, bo_ifm, bo_param, bo_ofm, bo_inter, bo_instr, noop_instrction_size/sizeof(uint32_t), bo_mc);
    // Wait on the run object
    run.wait2();

    for (int i = 1; i < iteration; i++) {
      // Re-start the same run object with same arguments
      run.start();
      run.wait2();
    }
    auto end = std::chrono::high_resolution_clock::now();

    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
    std::cout << "Host test microseconds: " << duration.count() << std::endl;
    std::cout << "Host test average latency: " <<  duration.count() / iteration << " us/iter" << std::endl;
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

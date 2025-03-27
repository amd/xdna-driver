# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2023-2024, Advanced Micro Devices, Inc. All rights reserved.

# Bring in XRT git submodule and exclude parts of XRT we don't need
set(XRT_EXCLUDE_SUB_DIRECTORY
  src/runtime_src/core/pcie/emulation
  src/runtime_src/core/pcie/windows
  src/runtime_src/core/pcie/driver
  src/runtime_src/core/pcie/tools
  src/runtime_src/core/pcie/noop

  src/runtime_src/core/tools
  src/runtime_src/core/edge

  src/runtime_src/tools
  src/runtime_src/xocl
  src/runtime_src/ert
  src/runtime_src/xrt

  tests/validate
  src/xma
  )

# Instruct XRT to build the npu component
set(XRT_NPU 1)
# To be removed when controlled by XDP with XRT_NPU
set(XDP_CLIENT_BUILD_CMAKE "yes")

set(XRT_EXCLUDE_INCLUDE_FILE
  src/CMake/nativeTests.cmake
  )

set(XDP_CLIENT_BUILD_CMAKE "yes")

set(XDNA_XRT_DIR xrt)
set(XRT_SOURCE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/${XDNA_XRT_DIR}")
set(XRT_BINARY_DIR "${CMAKE_CURRENT_BINARY_DIR}/${XDNA_XRT_DIR}")
add_subdirectory(${XDNA_XRT_DIR} EXCLUDE_FROM_ALL)

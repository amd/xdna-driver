# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2023-2024, Advanced Micro Devices, Inc. All rights reserved.

# Bring in XRT git submodule and exclude parts of XRT we don't need
set(XRT_EXCLUDE_SUB_DIRECTORY
  src/runtime_src/core/pcie/driver
# Hard dependencies for xrt cmake target are introduced in master. Can't exclude below directories any more
# src/runtime_src/core/pcie/emulation
# src/runtime_src/xocl
  src/runtime_src/core/pcie/tools
  src/runtime_src/core/pcie/windows
  src/runtime_src/core/tools
  src/runtime_src/ert
  src/runtime_src/xrt
  src/xma
  tests/validate
  )

set(XRT_EXCLUDE_INCLUDE_FILE
  src/CMake/nativeTests.cmake
  )

set(XDP_MINIMAL_BUILD "yes")

set(XDNA_XRT_DIR xrt)
set(XRT_SOURCE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/${XDNA_XRT_DIR}")
set(XRT_BINARY_DIR "${CMAKE_CURRENT_BINARY_DIR}/${XDNA_XRT_DIR}")
add_subdirectory(${XDNA_XRT_DIR} EXCLUDE_FROM_ALL)

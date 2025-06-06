# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2023, Advanced Micro Devices, Inc. All rights reserved.

# Bring in XRT git submodule and exclude parts of XRT we don't need

set(XRT_EXCLUDE_SUB_DIRECTORY
  src/runtime_src/core/edge/ps_kernels
  src/runtime_src/core/edge/skd
  src/runtime_src/core/edge/test
  src/runtime_src/ert
  src/xma
  tests/validate
  )

set(XRT_EXCLUDE_INCLUDE_FILE
  src/CMake/nativeTests.cmake
  )

set(XDP_MINIMAL_BUILD "yes")

set(XRT_AIE_BUILD "true")
#set(XDP_VE2_BUILD_CMAKE "yes")

add_compile_options(-DXRT_ENABLE_AIE -DOPENCL_ICD_LOADER)

# EDGE_VE2_XDNA flag is used in XRT submodule to indicate
# build is for combined shims
set(EDGE_VE2 "true")
add_compile_definitions(XRT_BUILD EDGE_VE2_XDNA XDNA_VE2)
include_directories(${PROJECT_SOURCE_DIR}/src/)

set(AIE_XRT_DIR xrt)
set(XRT_SOURCE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/${AIE_XRT_DIR}")

set(XRT_BINARY_DIR "${CMAKE_CURRENT_BINARY_DIR}/${AIE_XRT_DIR}")


include_directories(
        ${CMAKE_CURRENT_SOURCE_DIR}/src/include/uapi/
        )
add_subdirectory(${AIE_XRT_DIR})

include_directories(
        ${XRT_SOURCE_DIR}/src/runtime_src
        ${XRT_SOURCE_DIR}/src/runtime_src/core/include
        ${XRT_BINARY_DIR}/src/gen
        )

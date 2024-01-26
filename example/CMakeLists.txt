# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2022-2024, Advanced Micro Devices, Inc. All rights reserved.

cmake_minimum_required(VERSION 3.19.0)
project("amdxdna-example") 

# This required by XRT
set(CMAKE_CXX_STANDARD 17)
find_package(XRT REQUIRED)

set(XDNA_EXAMPLE example_noop_test)

add_executable(${XDNA_EXAMPLE} example_noop_test.cpp)

target_link_libraries(${XDNA_EXAMPLE} PRIVATE
  XRT::xrt_coreutil
  dl
  )

target_include_directories(${XDNA_EXAMPLE} PRIVATE
  ${XRT_INCLUDE_DIRS}
  )

target_compile_options(${XDNA_EXAMPLE} PRIVATE -O3)

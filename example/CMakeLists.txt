# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2022-2024, Advanced Micro Devices, Inc. All rights reserved.

cmake_minimum_required(VERSION 3.19.0)
project("amdxdna-example") 

# This required by XRT
set(CMAKE_CXX_STANDARD 17)
find_package(XRT REQUIRED)

function(create_example_exec_target name file)
add_executable(${name} ${file})

target_link_libraries(${name} PRIVATE
  XRT::xrt_coreutil
  dl
  )

target_include_directories(${name} PRIVATE
  ${XRT_INCLUDE_DIRS}
  )

target_compile_options(${name} PRIVATE -O3)
endfunction()

create_example_exec_target(example_noop_test example_noop_test.cpp)
create_example_exec_target(runlist_noop_test runlist_noop_test.cpp)

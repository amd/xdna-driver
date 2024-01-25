# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2022-2023, Advanced Micro Devices, Inc. All rights reserved.

cmake_minimum_required(VERSION 3.19.0)
project("amd-xdna")
set(PROJECT_DESCRIPTION "AMD XDNA driver and SHIM for Linux")

# Set install component that will be packaged
set(XDNA_COMPONENT "amdxdna" CACHE STRING "XDNA component name")

# Bring in xrt git submodule before include any local directories
include(${CMAKE_CURRENT_SOURCE_DIR}/CMake/xrt.cmake)

# For saving all built artifacts for quick testing purpose
# Should be redirected/prefixed by DESTDIR in make command line
# Can only be used with cmake install() command
set(XDNA_BIN_DIR /bins)

add_subdirectory(src)

# By default, build/build.sh downloads binaries to build/amdxdna_bins/
set(AMDXDNA_BINS_DIR ${CMAKE_BINARY_DIR}/../amdxdna_bins)

set(XRT_SUBMOD_SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/xrt)
set(XRT_SUBMOD_BINARY_DIR ${CMAKE_CURRENT_BINARY_DIR}/xrt)

include(${CMAKE_CURRENT_SOURCE_DIR}/CMake/version.cmake)
include(${CMAKE_CURRENT_SOURCE_DIR}/CMake/pkg.cmake)

add_subdirectory(test)

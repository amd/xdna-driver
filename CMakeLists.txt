# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2022-2024, Advanced Micro Devices, Inc. All rights reserved.

cmake_minimum_required(VERSION 3.19.0)
project("amd-xdna")
set(PROJECT_DESCRIPTION "AMD XDNA driver and SHIM for Linux")

if (DEFINED ENV{XRT_PLUGIN_VERSION_PATCH})
  SET(XRT_PLUGIN_VERSION_PATCH $ENV{XRT_PLUGIN_VERSION_PATCH})
else(DEFINED $ENV{XRT_PLUGIN_VERSION_PATCH})
  SET(XRT_PLUGIN_VERSION_PATCH 0)
endif(DEFINED ENV{XRT_PLUGIN_VERSION_PATCH})

message("-- XRT_INSTALL_PREFIX is set ${XRT_INSTALL_PREFIX}")
# Set install component that will be packaged
set(XDNA_COMPONENT "amdxdna" CACHE STRING "XDNA component name")

# Bring in xrt git submodule before include any local directories
include(${CMAKE_CURRENT_SOURCE_DIR}/CMake/xrt.cmake)
# version.cmake create XRT_PLUGIN_VERSION_STRING
include(${CMAKE_CURRENT_SOURCE_DIR}/CMake/version.cmake)

# For saving all built artifacts for quick testing purpose
# Should be redirected/prefixed by DESTDIR in make command line
# Can only be used with cmake install() command
set(XDNA_BIN_DIR /bins)

add_subdirectory(src)

# By default, build/build.sh downloads binaries to build/amdxdna_bins/
set(AMDXDNA_BINS_DIR ${CMAKE_BINARY_DIR}/../amdxdna_bins)

set(XRT_SUBMOD_SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/xrt)
set(XRT_SUBMOD_BINARY_DIR ${CMAKE_CURRENT_BINARY_DIR}/xrt)

include(${CMAKE_CURRENT_SOURCE_DIR}/CMake/pkg.cmake)

add_subdirectory(test)

set(amdxdna_tools
  ${CMAKE_CURRENT_SOURCE_DIR}/tools/io_page_fault_flags
  )
install(FILES ${amdxdna_tools}
  PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE
  DESTINATION xrt/${XDNA_COMPONENT}
  COMPONENT ${XDNA_COMPONENT}
  )

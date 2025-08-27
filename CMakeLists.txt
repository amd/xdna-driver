# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2022-2025, Advanced Micro Devices, Inc. All rights reserved.

cmake_minimum_required(VERSION 3.19.0)
project("amd-xdna")
set(PROJECT_DESCRIPTION "AMD XDNA driver and SHIM for Linux")
option(SKIP_KMOD "Building and packaging SHIM without driver and firmware" 1)

if (DEFINED ENV{XRT_PLUGIN_VERSION_PATCH})
  SET(XRT_PLUGIN_VERSION_PATCH $ENV{XRT_PLUGIN_VERSION_PATCH})
else()
  SET(XRT_PLUGIN_VERSION_PATCH 0)
endif()

# Set install component that will be packaged
# Default install compoment will install to shim test area
set(XDNA_COMPONENT "amdxdna")

# Set destination paths in install command
# Relocatable by ${CMAKE_INSTALL_PREFIX}
include (GNUInstallDirs)
set(XDNA_PKG_DIR      .)
set(XDNA_PKG_LIB_DIR  ${XDNA_PKG_DIR}/${CMAKE_INSTALL_LIBDIR})
set(XDNA_PKG_DATA_DIR ${XDNA_PKG_DIR}/${CMAKE_INSTALL_DATADIR}/${XDNA_COMPONENT})
# Non-relocatable by ${CMAKE_INSTALL_PREFIX}
set(XDNA_PKG_FW_DIR   /usr/lib/firmware/amdnpu)
set(XDNA_BIN_DIR      /bins) # For saving all built artifacts for quick testing
message("-- XDNA_PKG_LIB_DIR=${XDNA_PKG_LIB_DIR}")
message("-- XDNA_PKG_DATA_DIR=${XDNA_PKG_DATA_DIR}")
message("-- XDNA_PKG_FW_DIR=${XDNA_PKG_FW_DIR}")
message("-- XDNA_BIN_DIR=${XDNA_BIN_DIR}")

# By default, build/build.sh downloads binaries to build/amdxdna_bins/
# Absolute path, cannot be used in install command as destination.
set(AMDXDNA_BINS_DIR ${CMAKE_BINARY_DIR}/../amdxdna_bins)

if(XDNA_VE2)

include(${CMAKE_CURRENT_SOURCE_DIR}/CMake/xrt_ve2.cmake)
add_subdirectory(src)

else(XDNA_VE2)

# Bring in xrt git submodule before include any local directories
include(${CMAKE_CURRENT_SOURCE_DIR}/CMake/xrt.cmake)
set(XRT_SUBMOD_SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/xrt)
set(XRT_SUBMOD_BINARY_DIR ${CMAKE_CURRENT_BINARY_DIR}/xrt)

# Upstreaming pkg will not have access to .git which is required for version.cmake
if(NOT SKIP_KMOD)
  include(${CMAKE_CURRENT_SOURCE_DIR}/CMake/version.cmake)
endif()

include(${CMAKE_CURRENT_SOURCE_DIR}/CMake/pkg.cmake)

add_subdirectory(src)

if(NOT SKIP_KMOD)
  add_subdirectory(test)
endif()

endif(XDNA_VE2)

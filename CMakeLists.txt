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

if (XRT_UPSTREAM)
  include(CMake/upstream.cmake)
else()
  include(CMake/native.cmake)
endif()

# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2025-2026, Advanced Micro Devices, Inc. All rights reserved.

# For native xdna-driver builds, XRT headers and link library
# comes from xdna-driver's XRT submodule.

# User can choose to package either legacy driver or upstream driver source.
# By default the upstream (staging) driver is packaged as the primary
# amdxdna.ko, and the out-of-tree/legacy driver is packaged alongside it
# as amdxdna_legacy.ko.
option(PACKAGE_LEGACY_DRIVER "Package legacy driver source" OFF)

# The VE2 shim test (test/shim_test) is not part of the normal VE2 runtime
# build. It is opt-in (e.g. built on demand by a dedicated packaging recipe)
# so the default xrt/amdxdna build does not compile or install test artifacts.
option(XDNA_BUILD_SHIM_TEST "Build test/shim_test for the VE2 edge build" OFF)

# By default, build/build.sh downloads binaries to build/amdxdna_bins/
# Absolute path, cannot be used in install command as destination.
set(AMDXDNA_BINS_DIR ${CMAKE_BINARY_DIR}/../amdxdna_bins)

if(XDNA_VE2)

include(${CMAKE_CURRENT_SOURCE_DIR}/CMake/xrt_ve2.cmake)
add_subdirectory(src)

# Build the shim tests (test/shim_test) only when explicitly requested. The
# shim_test include dirs reference XRT_SUBMOD_SOURCE_DIR/BINARY_DIR, which are
# only set on the non-VE2 path above; point them at the same xrt submodule the
# VE2 build uses so the test target resolves its headers/generated sources.
if(XDNA_BUILD_SHIM_TEST)
  set(XRT_SUBMOD_SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/xrt)
  set(XRT_SUBMOD_BINARY_DIR ${CMAKE_CURRENT_BINARY_DIR}/xrt)
  add_subdirectory(test)
endif()

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
  add_subdirectory(drivers)
  add_subdirectory(test)
endif()

endif(XDNA_VE2)

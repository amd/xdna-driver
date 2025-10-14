# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2025, Advanced Micro Devices, Inc. All rights reserved.

# For native xdna-driver builds, XRT headers and link library
# comes from xdna-driver's XRT submodule.

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

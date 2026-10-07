# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2022-2026, Advanced Micro Devices, Inc. All rights reserved.

# VE2 and the other devices share src/shim. The VE2 path does not run
# pkg.cmake, which is what normally sets this version string.
if(NOT XRT_PLUGIN_VERSION_STRING)
  set(XRT_PLUGIN_VERSION_STRING "${XRT_VERSION_STRING}")
endif()

add_subdirectory(shim)

if(NOT XDNA_VE2)
  # Optionally build vxdna library
  option(BUILD_VXDNA "Build vxdna library" OFF)
  if(BUILD_VXDNA)
    add_subdirectory(vxdna)
  endif()
endif()

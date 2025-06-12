# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2025, Advanced Micro Devices, Inc. All rights reserved.

include_directories(
  ${DRM_INCLUDE_DIRS}
  ${CMAKE_BINARY_DIR} # include gen/version.h
  )

file(GLOB XRT_EDGE_USER_FILES "*.cpp")

set(XDNA_VE2_TARGET xrt_driver_xdna)

aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR} MAIN_SOURCES)

set(CMAKE_CXX_FLAGS "-DXCLHAL_MAJOR_VER=2 ${CMAKE_CXX_FLAGS}")
set(CMAKE_CXX_FLAGS "-DXCLHAL_MINOR_VER=1 ${CMAKE_CXX_FLAGS}")

# Bypass binary targets if clangtidy is enabled,
# same targets are defined for DC
if (${XRT_CLANGTIDY_REVIEW})
  return()
endif()

add_library(${XDNA_VE2_TARGET} SHARED ${MAIN_SOURCES})

set_target_properties(${XDNA_VE2_TARGET} PROPERTIES VERSION ${XRT_VERSION_STRING}
  SOVERSION ${XRT_SOVERSION})

target_link_libraries(${XDNA_VE2_TARGET} PRIVATE
  xrt_core
  xrt_coreutil
  )

install (TARGETS ${XDNA_VE2_TARGET} 
  EXPORT xrt-targets 
  LIBRARY DESTINATION ${XRT_INSTALL_LIB_DIR}
)
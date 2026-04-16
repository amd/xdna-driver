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

# VTD pin: https://github.com/Xilinx/VTD/tree/4517a16b2aa1ecb8de235b11e9ba7666553bfc34/archive/ve2
set(vtd_ve2_rev "4517a16b2aa1ecb8de235b11e9ba7666553bfc34")
set(vtd_ve2_base "https://github.com/Xilinx/VTD/raw/${vtd_ve2_rev}/archive/ve2")

set(vtd_file "${CMAKE_CURRENT_BINARY_DIR}/xrt_smi_ve2.ar")
file(DOWNLOAD "${vtd_ve2_base}/xrt_smi_ve2.a" "${vtd_file}")

# Same layout as VTD: .../amdxdna/bins/xrt_smi_ve2.ar and .../amdxdna/bins/aie_ddr_connections/*
set(vtd_aie_ddr_dir "${CMAKE_CURRENT_BINARY_DIR}/aie_ddr_connections")
file(MAKE_DIRECTORY "${vtd_aie_ddr_dir}")
set(vtd_aie_ddr_files
  nop.elf
  runner.json
  recipe_latency.json
  validate.xclbin
  profile_start0.json
  profile_start4.json
  profile_start8.json
  profile_start12.json
  profile_start16.json
  profile_start20.json
  profile_start24.json
  profile_start32.json
  )
foreach(_f IN LISTS vtd_aie_ddr_files)
  file(DOWNLOAD "${vtd_ve2_base}/aie_ddr_connections/${_f}" "${vtd_aie_ddr_dir}/${_f}")
endforeach()

install(FILES "${vtd_file}"
  DESTINATION ${CMAKE_INSTALL_DATADIR}/amdxdna/bins/
  )
install(DIRECTORY "${vtd_aie_ddr_dir}/"
  DESTINATION ${CMAKE_INSTALL_DATADIR}/amdxdna/bins/aie_ddr_connections
  )

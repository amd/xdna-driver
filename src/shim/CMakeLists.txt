# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2022-2024, Advanced Micro Devices, Inc. All rights reserved.

set(XDNA_TARGET xrt_driver_xdna)

aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR} MAIN_SOURCES)
aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR}/npu NPU_SOURCES)
add_library(${XDNA_TARGET} SHARED
  ${MAIN_SOURCES}
  ${NPU_SOURCES}
  )

set_target_properties(${XDNA_TARGET} PROPERTIES
  VERSION ${XRT_VERSION_STRING}
  SOVERSION ${XRT_SOVERSION}
  )

target_compile_definitions(${XDNA_TARGET} PRIVATE
  # below macros is required so that i/f defined in ishim.h is
  # consistent with native xrt implementation
  XRT_ENABLE_AIE
  XRT_AIE_BUILD
  )

if(${CMAKE_BUILD_TYPE} STREQUAL "Debug")
  add_definitions(-DXDNA_SHIM_DEBUG)
endif()

target_compile_options(${XDNA_TARGET} PRIVATE
  "-fPIC"
  )

target_include_directories(${XDNA_TARGET} PRIVATE
  ${XRT_SOURCE_DIR}/src/runtime_src
  ${XRT_SOURCE_DIR}/src/runtime_src/core/include
  ${XRT_BINARY_DIR}/src/gen
  ${CMAKE_CURRENT_SOURCE_DIR}/../include/uapi
  )

# driver plugin will be loaded while xrt_core is still being
# dlopen'ed, symbols against libxrt_core.so can't be solved
# at that time, so need to be fully solved here.
target_link_libraries(${XDNA_TARGET} PRIVATE
  xrt_core
  xrt_coreutil
  )

target_link_options(${XDNA_TARGET} PRIVATE
  "-Wl,-z,defs"
  )

# install components for packaging
install(TARGETS ${XDNA_TARGET} DESTINATION xrt/lib COMPONENT ${XDNA_COMPONENT})

# install components for testing
install(TARGETS xrt_core DESTINATION ${XDNA_BIN_DIR}/lib)
install(TARGETS xrt_coreutil DESTINATION ${XDNA_BIN_DIR}/lib)
install(TARGETS xrt_driver_xdna DESTINATION ${XDNA_BIN_DIR}/lib)

# TODO update when dpu sequence location is decided
install(FILES ${CMAKE_CURRENT_SOURCE_DIR}/dpu/df_bw.txt DESTINATION xrt/test/DPU_Sequence COMPONENT ${XDNA_COMPONENT})

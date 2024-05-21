# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2022-2024, Advanced Micro Devices, Inc. All rights reserved.

set(XDNA_TARGET xrt_driver_xdna)
set(XRT_CORE_TARGET xrt_core)
set(XRT_COREUTIL_TARGET xrt_coreutil)

aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR} MAIN_SOURCES)
aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR}/kmq KMQ_SOURCES)
aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR}/umq UMQ_SOURCES)
add_library(${XDNA_TARGET} SHARED
  ${MAIN_SOURCES}
  ${KMQ_SOURCES}
  ${UMQ_SOURCES}
  )

set_target_properties(${XDNA_TARGET} PROPERTIES
  VERSION ${XRT_PLUGIN_VERSION_STRING}
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
  ${XRT_SOURCE_DIR}/src/runtime_src/core/common/gsl/include
  ${XRT_BINARY_DIR}/src/gen
  ${CMAKE_CURRENT_SOURCE_DIR}/../include/uapi
  )

# driver plugin will be loaded while xrt_core is still being
# dlopen'ed, symbols against libxrt_core.so can't be solved
# at that time, so need to be fully solved here.
target_link_libraries(${XDNA_TARGET} PRIVATE
  xrt_core
  ${XRT_CORE_TARGET}
  ${XRT_COREUTIL_TARGET}
  )

target_link_options(${XDNA_TARGET} PRIVATE
  "-Wl,-z,defs"
  )

# install components for packaging
install(TARGETS ${XDNA_TARGET} DESTINATION xrt/lib COMPONENT ${XDNA_COMPONENT})

# install components for testing
install(TARGETS ${XRT_CORE_TARGET} DESTINATION ${XDNA_BIN_DIR}/lib)
install(TARGETS ${XRT_COREUTIL_TARGET} DESTINATION ${XDNA_BIN_DIR}/lib)
install(TARGETS ${XDNA_TARGET} DESTINATION ${XDNA_BIN_DIR}/lib)

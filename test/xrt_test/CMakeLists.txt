# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2024, Advanced Micro Devices, Inc. All rights reserved.

set(XDNA_XRT_TEST xrt_test.elf)

add_executable(${XDNA_XRT_TEST}
  xrt_test.cpp
  )

target_compile_definitions(${XDNA_XRT_TEST} PRIVATE
  # below macros is required so that i/f defined in ishim.h is
  # consistent with native xrt implementation
  XRT_ENABLE_AIE
  XRT_BUILD
  )

target_link_libraries(${XDNA_XRT_TEST} PRIVATE
  xrt_coreutil
  dl
  )

set_target_properties(${XDNA_XRT_TEST} PROPERTIES
  BUILD_WITH_INSTALL_RPATH FALSE
  LINK_FLAGS "-Wl,-rpath,$ORIGIN/../lib"
  )

target_include_directories(${XDNA_XRT_TEST} PRIVATE
  ${XRT_SUBMOD_SOURCE_DIR}/src/runtime_src/core/include
  ${XRT_SUBMOD_BINARY_DIR}/src/gen
  )

target_compile_options(${XDNA_XRT_TEST} PRIVATE -O3)

configure_file(
  xrt_test.in
  xrt_test
  @ONLY
  )

install(TARGETS ${XDNA_XRT_TEST} DESTINATION ${XDNA_BIN_DIR}/bin)
install(PROGRAMS ${CMAKE_CURRENT_BINARY_DIR}/xrt_test DESTINATION ${XDNA_BIN_DIR}/bin)

install(CODE "execute_process( \
  COMMAND ${CMAKE_COMMAND} -E create_symlink \
  ${AMDXDNA_BINS_DIR}/workspaces/NPU3_1x4_TESTCASES \
  ${CMAKE_BINARY_DIR}/${XDNA_BIN_DIR}/npu3_workspace \
  )"
  )

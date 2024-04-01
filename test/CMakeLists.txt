# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2022-2024, Advanced Micro Devices, Inc. All rights reserved.

set(XDNA_SHIM_TEST shim_test.elf)

add_executable(${XDNA_SHIM_TEST}
  shim_test.cpp
  )

target_compile_definitions(${XDNA_SHIM_TEST} PRIVATE
  # below macros is required so that i/f defined in ishim.h is
  # consistent with native xrt implementation
  XRT_ENABLE_AIE
  XRT_XDNA_BUILD
  )

target_link_libraries(${XDNA_SHIM_TEST} PRIVATE
  xrt_coreutil
  dl
  elf
  )

set_target_properties(${XDNA_SHIM_TEST} PROPERTIES
  BUILD_WITH_INSTALL_RPATH FALSE
  LINK_FLAGS "-Wl,-rpath,$ORIGIN/../lib"
  )

target_include_directories(${XDNA_SHIM_TEST} PRIVATE
  ${XRT_SUBMOD_SOURCE_DIR}/src/runtime_src
  ${XRT_SUBMOD_SOURCE_DIR}/src/runtime_src/core/include
  ${XRT_SUBMOD_BINARY_DIR}/src/gen
  )

target_compile_options(${XDNA_SHIM_TEST} PRIVATE -O3)

configure_file(
  shim_test.in
  shim_test
  @ONLY
  )

install(TARGETS ${XDNA_SHIM_TEST} DESTINATION ${XDNA_BIN_DIR}/bin)
install(PROGRAMS ${CMAKE_CURRENT_BINARY_DIR}/shim_test DESTINATION ${XDNA_BIN_DIR}/bin)

install(CODE "execute_process( \
  COMMAND ${CMAKE_COMMAND} -E create_symlink \
  ${AMDXDNA_BINS_DIR}/workspaces/NPU1_1x4_TESTCASES \
  ${CMAKE_BINARY_DIR}/${XDNA_BIN_DIR}/npu1_workspace \
  )"
  )

install(CODE "execute_process( \
  COMMAND ${CMAKE_COMMAND} -E create_symlink \
  ${AMDXDNA_BINS_DIR}/workspaces/NPU2_1x4_TESTCASES \
  ${CMAKE_BINARY_DIR}/${XDNA_BIN_DIR}/npu2_workspace \
  )"
  )

 install(CODE "execute_process( \
  COMMAND ${CMAKE_COMMAND} -E create_symlink \
  ${AMDXDNA_BINS_DIR}/workspaces/NPU4_1x4_TESTCASES \
  ${CMAKE_BINARY_DIR}/${XDNA_BIN_DIR}/npu4_workspace \
  )"
  )

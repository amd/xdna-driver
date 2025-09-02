# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2023-2025 Advanced Micro Devices, Inc. All rights reserved.

if (NOT DEFINED BUILD_REPO_ROOT)
  set(BUILD_REPO_ROOT ${CMAKE_CURRENT_SOURCE_DIR})
endif()
message("-- BUILD_REPO_ROOT: ${BUILD_REPO_ROOT}")

# Get the branch
execute_process(
  COMMAND git rev-parse --abbrev-ref HEAD
  WORKING_DIRECTORY ${BUILD_REPO_ROOT}
  OUTPUT_VARIABLE XDNA_BRANCH
  OUTPUT_STRIP_TRAILING_WHITESPACE
)

# Get the latest abbreviated commit hash of the working branch
execute_process(
  COMMAND git rev-parse --verify HEAD
  WORKING_DIRECTORY ${BUILD_REPO_ROOT}
  OUTPUT_VARIABLE XDNA_HASH
  OUTPUT_STRIP_TRAILING_WHITESPACE
)

# Get the latest abbreviated commit hash date of the working branch
execute_process(
  COMMAND git log -1 --pretty=format:%cD
  WORKING_DIRECTORY ${BUILD_REPO_ROOT}
  OUTPUT_VARIABLE XDNA_HASH_DATE
  OUTPUT_STRIP_TRAILING_WHITESPACE
)

# Get the build date in "YYYYMMDD"
execute_process(
  COMMAND date +%Y%m%d
  WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
  OUTPUT_VARIABLE XDNA_DATE
  OUTPUT_STRIP_TRAILING_WHITESPACE
)

# Get the XRT gitsubmodule branch
execute_process(
  COMMAND git rev-parse --abbrev-ref HEAD
  WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/xrt
  OUTPUT_VARIABLE XDNA_XRT_BRANCH
  OUTPUT_STRIP_TRAILING_WHITESPACE
)

# Get the latest XRT gitsubmodule abbreviated commit hash of the working branch
execute_process(
  COMMAND git rev-parse --verify HEAD
  WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/xrt
  OUTPUT_VARIABLE XDNA_XRT_HASH
  OUTPUT_STRIP_TRAILING_WHITESPACE
)

# Get the latest XRT gitsubmodule abbreviated commit hash date of the working branch
execute_process(
  COMMAND git log -1 --pretty=format:%cD
  WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/xrt
  OUTPUT_VARIABLE XDNA_XRT_HASH_DATE
  OUTPUT_STRIP_TRAILING_WHITESPACE
)

set(XDNA_VERSION_JSON_FILE ${CMAKE_CURRENT_BINARY_DIR}/version.json)
configure_file(
  ${CMAKE_CURRENT_SOURCE_DIR}/CMake/config/version.json.in
  ${XDNA_VERSION_JSON_FILE}
)

if(NOT XDNA_VE2)
  install(FILES ${XDNA_VERSION_JSON_FILE} DESTINATION ${XDNA_PKG_DATA_DIR} COMPONENT ${XDNA_COMPONENT})
endif()

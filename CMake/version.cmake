# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2023-2024 Advanced Micro Devices, Inc. All rights reserved.

# Get the branch
execute_process(
  COMMAND git rev-parse --abbrev-ref HEAD
  WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
  OUTPUT_VARIABLE XDNA_BRANCH
  OUTPUT_STRIP_TRAILING_WHITESPACE
)

# Get the latest abbreviated commit hash of the working branch
execute_process(
  COMMAND git rev-parse --verify HEAD
  WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
  OUTPUT_VARIABLE XDNA_HASH
  OUTPUT_STRIP_TRAILING_WHITESPACE
)

# Get the latest abbreviated commit hash date of the working branch
execute_process(
  COMMAND git log -1 --pretty=format:%cD
  WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
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

install(FILES ${XDNA_VERSION_JSON_FILE} DESTINATION xrt/${XDNA_COMPONENT} COMPONENT ${XDNA_COMPONENT})

# Substitute driver version in the source code
set(XDNA_TAR_GZ amdxdna.tar.gz)
set(AMDXDNA_DRV_FILE driver/amdxdna/amdxdna_drv.c)
add_custom_command(
  OUTPUT ${CMAKE_BINARY_DIR}/driver/${XDNA_TAR_GZ}
  COMMENT "Substitute amdxdna module version and re-tar"
  DEPENDS driver_tarball
  WORKING_DIRECTORY ${CMAKE_BINARY_DIR}/driver
  COMMAND $(CMAKE_COMMAND) -E make_directory tmp
  COMMAND tar xf ${CMAKE_BINARY_DIR}/driver/amdxdna.tar -C tmp
  COMMAND find tmp -name amdxdna_drv.c -exec sed -i 's/MODULE_VERSION\(\".*\"\)/MODULE_VERSION\(\"${XRT_VERSION_STRING}_${XDNA_DATE},${XDNA_HASH}\"\)/' {} \\\;
  COMMAND tar zcf ${CMAKE_BINARY_DIR}/driver/${XDNA_TAR_GZ} -C tmp .
  COMMAND $(CMAKE_COMMAND) -E rm -r tmp
  )
add_custom_target(driver_ver_tarball ALL DEPENDS ${CMAKE_BINARY_DIR}/driver/${XDNA_TAR_GZ})
install(FILES ${CMAKE_BINARY_DIR}/driver/${XDNA_TAR_GZ}
  DESTINATION xrt/${XDNA_COMPONENT}
  COMPONENT ${XDNA_COMPONENT}
  )

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

# Resolve the drm-firmware WHENCE ref and commit that the firmware tree will be
# synced from, using a lightweight, download-free method so version.json records
# them at configure time without fetching any firmware. Firmware downloads are a
# packaging step (see build/build.sh), not part of the compile.
#
#   * A committed tools/WHENCE snapshot (release branches) pins the commit in a
#     "# whence-commit:" line, so read it directly.
#   * Otherwise (main/link) resolve the amd-ipu-staging tip via git ls-remote,
#     which is metadata only and downloads no firmware.
#
# Resolution is best-effort: an offline or unresolvable remote leaves the hash
# empty and never fails the configure.
set(XDNA_FW_WHENCE_REF "amd-ipu-staging")
set(XDNA_FW_WHENCE_COMMIT "")
set(XDNA_WHENCE_SNAPSHOT ${CMAKE_SOURCE_DIR}/tools/WHENCE)
if(EXISTS ${XDNA_WHENCE_SNAPSHOT})
  file(STRINGS ${XDNA_WHENCE_SNAPSHOT} XDNA_FW_WHENCE_REF_LINES
       REGEX "^# whence-ref:")
  if(XDNA_FW_WHENCE_REF_LINES)
    list(GET XDNA_FW_WHENCE_REF_LINES 0 XDNA_FW_WHENCE_REF_LINE)
    string(REGEX REPLACE "^# whence-ref:[ \t]*" "" XDNA_FW_WHENCE_REF
           "${XDNA_FW_WHENCE_REF_LINE}")
    string(STRIP "${XDNA_FW_WHENCE_REF}" XDNA_FW_WHENCE_REF)
  endif()
  file(STRINGS ${XDNA_WHENCE_SNAPSHOT} XDNA_FW_WHENCE_PIN_LINES
       REGEX "^# whence-commit:")
  if(XDNA_FW_WHENCE_PIN_LINES)
    list(GET XDNA_FW_WHENCE_PIN_LINES 0 XDNA_FW_WHENCE_PIN)
    string(REGEX REPLACE "^# whence-commit:[ \t]*" "" XDNA_FW_WHENCE_COMMIT
           "${XDNA_FW_WHENCE_PIN}")
    string(STRIP "${XDNA_FW_WHENCE_COMMIT}" XDNA_FW_WHENCE_COMMIT)
  endif()
endif()
if(XDNA_FW_WHENCE_COMMIT STREQUAL "")
  execute_process(
    COMMAND git ls-remote https://gitlab.com/kernel-firmware/drm-firmware.git ${XDNA_FW_WHENCE_REF}
    OUTPUT_VARIABLE XDNA_FW_LS_REMOTE
    RESULT_VARIABLE XDNA_FW_LS_RESULT
    ERROR_QUIET
    OUTPUT_STRIP_TRAILING_WHITESPACE
    TIMEOUT 60
  )
  if(XDNA_FW_LS_RESULT EQUAL 0 AND NOT XDNA_FW_LS_REMOTE STREQUAL "")
    string(REGEX MATCH "^[0-9a-fA-F]+" XDNA_FW_WHENCE_COMMIT
           "${XDNA_FW_LS_REMOTE}")
  endif()
endif()

# Resolve the Xilinx/VTD commit that the VTD archives will be fetched from,
# using the same lightweight, download-free approach as the firmware above so
# version.json records it at configure time without downloading any archive.
#
#   * A committed tools/WHENCE snapshot pins the commit in a "# vtd-commit:"
#     line (release branches), so read it directly.
#   * Otherwise (main/link) resolve the Xilinx/VTD HEAD via git ls-remote, which
#     is metadata only and downloads no archive.
#
# Resolution is best-effort and never fails the configure when offline.
set(XDNA_VTD_COMMIT "")
if(EXISTS ${XDNA_WHENCE_SNAPSHOT})
  file(STRINGS ${XDNA_WHENCE_SNAPSHOT} XDNA_VTD_PIN_LINES
       REGEX "^# vtd-commit:")
  if(XDNA_VTD_PIN_LINES)
    list(GET XDNA_VTD_PIN_LINES 0 XDNA_VTD_PIN)
    string(REGEX REPLACE "^# vtd-commit:[ \t]*" "" XDNA_VTD_COMMIT
           "${XDNA_VTD_PIN}")
    string(STRIP "${XDNA_VTD_COMMIT}" XDNA_VTD_COMMIT)
  endif()
endif()
if(XDNA_VTD_COMMIT STREQUAL "")
  execute_process(
    COMMAND git ls-remote https://github.com/Xilinx/VTD.git HEAD
    OUTPUT_VARIABLE XDNA_VTD_LS_REMOTE
    RESULT_VARIABLE XDNA_VTD_LS_RESULT
    ERROR_QUIET
    OUTPUT_STRIP_TRAILING_WHITESPACE
    TIMEOUT 60
  )
  if(XDNA_VTD_LS_RESULT EQUAL 0 AND NOT XDNA_VTD_LS_REMOTE STREQUAL "")
    string(REGEX MATCH "^[0-9a-fA-F]+" XDNA_VTD_COMMIT "${XDNA_VTD_LS_REMOTE}")
  endif()
endif()

set(XDNA_VERSION_JSON_FILE ${CMAKE_CURRENT_BINARY_DIR}/version.json)
configure_file(
  ${CMAKE_CURRENT_SOURCE_DIR}/CMake/config/version.json.in
  ${XDNA_VERSION_JSON_FILE}
)

if(NOT XDNA_VE2)
  install(FILES ${XDNA_VERSION_JSON_FILE} DESTINATION ${XDNA_PKG_DATA_DIR} COMPONENT ${XDNA_COMPONENT})
endif()

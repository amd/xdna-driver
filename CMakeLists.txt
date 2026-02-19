# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2022-2025, Advanced Micro Devices, Inc. All rights reserved.

cmake_minimum_required(VERSION 3.19.0)
project("amd-xdna")
set(PROJECT_DESCRIPTION "AMD XDNA driver and SHIM for Linux")
option(SKIP_KMOD "Building and packaging SHIM without driver and firmware" 1)

if (DEFINED ENV{XRT_PLUGIN_VERSION_PATCH})
  SET(XRT_PLUGIN_VERSION_PATCH $ENV{XRT_PLUGIN_VERSION_PATCH})
else()
  SET(XRT_PLUGIN_VERSION_PATCH 0)
endif()

# Set install component that will be packaged
# Default install compoment will install to shim test area
set(XDNA_COMPONENT "amdxdna")

# Set destination paths in install command
# Relocatable by ${CMAKE_INSTALL_PREFIX}
include (GNUInstallDirs)
set(XDNA_PKG_DIR      .)
set(XDNA_PKG_LIB_DIR  ${XDNA_PKG_DIR}/${CMAKE_INSTALL_LIBDIR})
set(XDNA_PKG_DATA_DIR ${XDNA_PKG_DIR}/${CMAKE_INSTALL_DATADIR}/${XDNA_COMPONENT})
set(XDNA_PKG_INCLUDE_DIR ${XDNA_PKG_DIR}/${CMAKE_INSTALL_INCLUDEDIR})
# Non-relocatable by ${CMAKE_INSTALL_PREFIX}
set(XDNA_PKG_FW_DIR   /usr/lib/firmware/amdnpu)
set(XDNA_BIN_DIR      /bins) # For saving all built artifacts for quick testing
message("-- XDNA_PKG_LIB_DIR=${XDNA_PKG_LIB_DIR}")
message("-- XDNA_PKG_DATA_DIR=${XDNA_PKG_DATA_DIR}")
message("-- XDNA_PKG_FW_DIR=${XDNA_PKG_FW_DIR}")
message("-- XDNA_BIN_DIR=${XDNA_BIN_DIR}")

if (XRT_UPSTREAM)
  include(CMake/upstream.cmake)
else()
  include(CMake/native.cmake)
endif()

# Include version info after native.cmake/upstream.cmake to get XRT_PLUGIN_VERSION_STRING
include(CMake/version.cmake)

# ============================================================================
# DKMS Source Package Generation Targets
# ============================================================================



# Configure debian/ files with version information for source packages
set(DEBIAN_TEMPLATE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/CMake/debian)
set(DEBIAN_BUILD_DIR ${CMAKE_CURRENT_BINARY_DIR}/debian_build)
set(DEBIAN_CHANGELOG_TEMPLATE ${DEBIAN_TEMPLATE_DIR}/changelog.in)
set(DEBIAN_CHANGELOG_FILE ${DEBIAN_BUILD_DIR}/changelog)

# Create output directory for configured debian files
file(MAKE_DIRECTORY ${DEBIAN_BUILD_DIR})

# Set DEBIAN_PKG_VERSION for template substitution
set(DEBIAN_PKG_VERSION "${XRT_PLUGIN_VERSION_STRING}~${XDNA_DATE}")
message(STATUS "DEBIAN_PKG_VERSION: ${DEBIAN_PKG_VERSION}")

# Generate debian/changelog with proper version substitution
configure_file(
  ${DEBIAN_CHANGELOG_TEMPLATE}
  ${DEBIAN_CHANGELOG_FILE}
  @ONLY
)

# Generate debian/rules, postinst, prerm with version substitution
configure_file(
  ${DEBIAN_TEMPLATE_DIR}/rules.in
  ${DEBIAN_BUILD_DIR}/rules
  @ONLY
)

configure_file(
  ${DEBIAN_TEMPLATE_DIR}/postinst.in
  ${DEBIAN_BUILD_DIR}/postinst
  @ONLY
)

configure_file(
  ${DEBIAN_TEMPLATE_DIR}/prerm.in
  ${DEBIAN_BUILD_DIR}/prerm
  @ONLY
)

# Generate dkms.conf with version substitution (for in-tree builds)
configure_file(
  ${CMAKE_SOURCE_DIR}/CMake/debian/dkms.conf
  ${DEBIAN_BUILD_DIR}/dkms.conf
  @ONLY
)

# Generate separate dkms-source specific files
set(DKMS_SOURCE_BUILD_DIR ${CMAKE_CURRENT_BINARY_DIR}/dkms_source_build)
file(MAKE_DIRECTORY ${DKMS_SOURCE_BUILD_DIR})

configure_file(
  ${CMAKE_SOURCE_DIR}/CMake/debian/dkms.conf.dkms-source
  ${DKMS_SOURCE_BUILD_DIR}/dkms.conf
  @ONLY
)

configure_file(
  ${CMAKE_SOURCE_DIR}/CMake/debian/postinst.in.dkms-source
  ${DKMS_SOURCE_BUILD_DIR}/postinst
  @ONLY
)

configure_file(
  ${CMAKE_SOURCE_DIR}/CMake/debian/rules.in.dkms-source
  ${DKMS_SOURCE_BUILD_DIR}/rules
  @ONLY
)

# Create a custom target to generate DKMS source packages
add_custom_target(dkms-source
  COMMENT "Generating DKMS source package for PPA upload"
  COMMAND ${CMAKE_COMMAND} -E echo "Preparing minimal DKMS source tree..."
  COMMAND ${CMAKE_COMMAND} -E make_directory dkms-src/debian/source
  # Copy only actual kernel driver source, not entire build system
  COMMAND ${CMAKE_COMMAND} -E copy_directory ${CMAKE_SOURCE_DIR}/src/driver/amdxdna dkms-src/amdxdna
  COMMAND ${CMAKE_COMMAND} -E copy_directory ${CMAKE_SOURCE_DIR}/src/include dkms-src/include
  COMMAND ${CMAKE_COMMAND} -E copy_directory ${CMAKE_SOURCE_DIR}/src/driver/tools dkms-src/tools
  # Copy configure_kernel.sh and run_prebuild.sh to root for PRE_BUILD hook
  COMMAND ${CMAKE_COMMAND} -E copy ${CMAKE_SOURCE_DIR}/src/driver/tools/configure_kernel.sh dkms-src/configure_kernel.sh
  COMMAND ${CMAKE_COMMAND} -E copy ${CMAKE_SOURCE_DIR}/src/driver/tools/run_prebuild.sh dkms-src/run_prebuild.sh
  COMMAND ${CMAKE_COMMAND} -E copy ${CMAKE_SOURCE_DIR}/LICENSE.amdnpu dkms-src/LICENSE.amdnpu
  COMMAND ${CMAKE_COMMAND} -E copy ${CMAKE_SOURCE_DIR}/README.md dkms-src/README.md
  # Copy firmware if available
  COMMAND ${CMAKE_SOURCE_DIR}/CMake/scripts/copy_firmware.sh ${CMAKE_CURRENT_BINARY_DIR}/../amdxdna_bins/firmware dkms-src/firmware
  # Copy debian packaging files (using dkms-source specific versions)
  COMMAND ${CMAKE_COMMAND} -E copy ${DEBIAN_CHANGELOG_FILE} dkms-src/debian/changelog
  COMMAND ${CMAKE_COMMAND} -E copy ${DKMS_SOURCE_BUILD_DIR}/rules dkms-src/debian/rules
  COMMAND ${CMAKE_COMMAND} -E copy ${DKMS_SOURCE_BUILD_DIR}/postinst dkms-src/debian/postinst
  COMMAND ${CMAKE_COMMAND} -E copy ${DEBIAN_BUILD_DIR}/prerm dkms-src/debian/prerm
  COMMAND ${CMAKE_COMMAND} -E copy ${DEBIAN_TEMPLATE_DIR}/control dkms-src/debian/control
  COMMAND ${CMAKE_COMMAND} -E copy ${DEBIAN_TEMPLATE_DIR}/copyright dkms-src/debian/copyright
  COMMAND ${CMAKE_COMMAND} -E copy ${DEBIAN_TEMPLATE_DIR}/source-format dkms-src/debian/source/format
  COMMAND ${CMAKE_COMMAND} -E copy ${DKMS_SOURCE_BUILD_DIR}/dkms.conf dkms-src/dkms.conf
  COMMAND chmod 755 dkms-src/debian/rules dkms-src/debian/postinst dkms-src/debian/prerm dkms-src/configure_kernel.sh dkms-src/run_prebuild.sh
  COMMAND ${CMAKE_COMMAND} -E echo "Building source package..."
  COMMAND cd dkms-src && dpkg-buildpackage -S -d -us -uc
  COMMAND ${CMAKE_COMMAND} -E echo "Cleaning up temporary source tree..."
  COMMAND ${CMAKE_COMMAND} -E remove_directory dkms-src
  WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
)

# Helper function to check for required tools
function(check_required_tool tool_name package_name)
  find_program(TOOL_PATH ${tool_name})
  if(NOT TOOL_PATH)
    message(WARNING "${tool_name} not found. Install with: sudo apt-get install ${package_name}")
  else()
    message(STATUS "${tool_name} found at ${TOOL_PATH}")
  endif()
endfunction()

# Check for required Debian packaging tools on Ubuntu systems
if(EXISTS /etc/os-release)
  file(STRINGS /etc/os-release OS_ID REGEX "^ID=")
  if(OS_ID MATCHES "ubuntu")
    check_required_tool(dpkg-buildpackage dpkg-dev)
    check_required_tool(debsign devscripts)
    check_required_tool(dput dput)
  endif()
endif()

message(STATUS "DEBIAN_PKG_VERSION for source packaging: ${DEBIAN_PKG_VERSION}")
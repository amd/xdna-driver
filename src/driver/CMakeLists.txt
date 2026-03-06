# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2022-2026, Advanced Micro Devices, Inc. All rights reserved.

set(XDNA_DRV amdxdna)

set(XDNA_DRV_DIR amdxdna)
set(XDNA_DRV_TGT ${XDNA_DRV}.ko)
set(XDNA_DRV_PATH ${CMAKE_BINARY_DIR}/driver/${XDNA_DRV_TGT})
set(XDNA_DRV_BLD_DIR driver/${XDNA_DRV_DIR})
set(XDNA_DRV_BLD_SRC ${CMAKE_CURRENT_BINARY_DIR}/${XDNA_DRV_BLD_DIR})
set(XDNA_DRV_BLD_TGT ${CMAKE_CURRENT_BINARY_DIR}/${XDNA_DRV_DIR})
set(XDNA_DRV_CONFIG_KERNEL_HEADER config_kernel.h)
set(XDNA_DRV_CONFIG_KERNEL_SCRIPT configure_kernel.sh)

if (XDNA_DRV_INT_NAME)
  set(XDNA_DRV_INT ${XDNA_DRV_INT_NAME})

  set(XDNA_DRV_INT_DIR ${XDNA_DRV_INT_NAME})
  set(XDNA_DRV_INT_TGT ${XDNA_DRV_INT}.ko)
  set(XDNA_DRV_INT_PATH ${CMAKE_BINARY_DIR}/driver/${XDNA_DRV_INT_TGT})
  set(XDNA_DRV_INT_BLD_DIR driver/${XDNA_DRV_INT_DIR})
  set(XDNA_DRV_INT_BLD_SRC ${CMAKE_CURRENT_BINARY_DIR}/${XDNA_DRV_INT_BLD_DIR})
  set(XDNA_DRV_INT_BLD_TGT ${CMAKE_CURRENT_BINARY_DIR}/${XDNA_DRV_INT_DIR})
endif(XDNA_DRV_INT_NAME)

# Common flags used for both building driver and configuring dkms
if (DEFINED ENV{XDNA_DRV_BLD_FLAGS})
  set(XDNA_DRV_BLD_FLAGS_DKMS $ENV{XDNA_DRV_BLD_FLAGS})
  set(XDNA_DRV_BLD_FLAGS_MAKE $ENV{XDNA_DRV_BLD_FLAGS})
  separate_arguments(XDNA_DRV_BLD_FLAGS_MAKE)
endif(DEFINED ENV{XDNA_DRV_BLD_FLAGS})

message("-- Extra driver source dir: ${XDNA_EXTRA_DRV_DIR}")
message("-- Extra driver tar exclude rules: ${XDNA_EXTRA_DRV_EXCLUDES}")

add_custom_command(
  OUTPUT all_driver_source
  COMMENT "Collect all driver source code"
  WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
  COMMAND ${CMAKE_COMMAND} -E make_directory ${XDNA_DRV_BLD_DIR}
  COMMAND cp -rf ${CMAKE_CURRENT_SOURCE_DIR}/${XDNA_DRV_DIR}/* ${XDNA_EXTRA_DRV_DIR} ${XDNA_DRV_BLD_DIR}
  COMMAND cp -r ${CMAKE_CURRENT_SOURCE_DIR}/../include .
  COMMAND cp -r ${CMAKE_CURRENT_SOURCE_DIR}/tools/${XDNA_DRV_CONFIG_KERNEL_SCRIPT} .
  )

# Generate XDNA_DRV_CONFIG_KERNEL_HEADER before doing build
add_custom_command(
  OUTPUT ${XDNA_DRV_BLD_SRC}/${XDNA_DRV_CONFIG_KERNEL_HEADER}
  COMMENT "Configuring kernel compatibility header"
  WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
  COMMAND ${CMAKE_COMMAND} -E env bash ./${XDNA_DRV_CONFIG_KERNEL_SCRIPT}
  DEPENDS all_driver_source
)

# Because ${XDNA_DRV_TGT} is generated in ${XDNA_DRV_BLD_TGT}. So this custom command will always run.
add_custom_command(
  OUTPUT ${XDNA_DRV_TGT}
  COMMENT "Build ${XDNA_DRV_TGT}"
  COMMAND $(MAKE) -f ${XDNA_DRV_BLD_SRC}/Makefile BUILD_ROOT_DIR=${XDNA_DRV_BLD_TGT} ${KERNEL_VER} UMQ_HELLO_TEST=${UMQ_HELLO_TEST} ${XDNA_DRV_BLD_FLAGS_MAKE} XDNA_BUS_TYPE=pci
  COMMAND $(MAKE) -f ${XDNA_DRV_BLD_SRC}/Makefile BUILD_ROOT_DIR=${XDNA_DRV_BLD_TGT} copy_ko
  COMMAND ${CMAKE_COMMAND} -E copy ${XDNA_DRV_BLD_TGT}/${XDNA_DRV_TGT} ${XDNA_DRV_PATH}
  DEPENDS ${XDNA_DRV_BLD_SRC}/${XDNA_DRV_CONFIG_KERNEL_HEADER}
  )

if (XDNA_DRV_INT_NAME)
  add_custom_command(
    OUTPUT int_driver_source
    COMMENT "Collect internal driver source code"
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
    COMMAND ${CMAKE_COMMAND} -E make_directory ${XDNA_DRV_INT_BLD_DIR}
    COMMAND cp -rf ${XDNA_DRV_INT_SRC_DIR} ${XDNA_DRV_INT_BLD_DIR}
    #temporary workaround to grab common code for int driver
    COMMAND cp ${XDNA_DRV_BLD_DIR}/amdxdna_mailbox.* ${XDNA_DRV_BLD_DIR}/amdxdna_trace.h ${XDNA_DRV_INT_BLD_DIR}
    DEPENDS all_driver_source
  )

  # Build internal driver
  add_custom_command(
    OUTPUT ${XDNA_DRV_INT_TGT}
    COMMENT "Build ${XDNA_DRV_INT_TGT}"
    COMMAND $(MAKE) -f ${XDNA_DRV_INT_BLD_SRC}/Makefile BUILD_ROOT_DIR=${XDNA_DRV_INT_BLD_TGT} ${KERNEL_VER} XDNA_BUS_TYPE=pci
    COMMAND $(MAKE) -f ${XDNA_DRV_INT_BLD_SRC}/Makefile BUILD_ROOT_DIR=${XDNA_DRV_INT_BLD_TGT} copy_ko
    COMMAND ${CMAKE_COMMAND} -E copy ${XDNA_DRV_INT_BLD_TGT}/${XDNA_DRV_INT_TGT} ${XDNA_DRV_INT_PATH}
    DEPENDS ${XDNA_DRV_BLD_SRC}/${XDNA_DRV_CONFIG_KERNEL_HEADER} int_driver_source
  )
endif(XDNA_DRV_INT_NAME)

if(XDNA_DRV_INT_SRC_DIR)
add_custom_target(legacy_driver ALL DEPENDS ${XDNA_DRV_TGT} ${XDNA_DRV_INT_TGT})
else()
add_custom_target(legacy_driver ALL DEPENDS ${XDNA_DRV_TGT})
endif()

# Tar and install driver source code for packaging
if(PACKAGE_LEGACY_DRIVER)
  message("-- Packaging legacy driver source")
  set(XDNA_DRV_SRC_DIR
    driver
    include
    )
  set(TAR_DRV_SOURCE_TGT legacy_driver)
  include(${CMAKE_SOURCE_DIR}/CMake/pkg_driver_source.cmake)
endif()

# install .ko for testing as amdxdna_legacy.ko - will include extra paths if defined
set(TEST_KO_NAME amdxdna_legacy.ko)
if(PACKAGE_LEGACY_DRIVER)
  # When this driver is packaged, we become the default ko for CI test
  set(TEST_KO_NAME amdxdna.ko)
endif()

if(DEFINED XDNA_DRV_INT_TGT)
  install(FILES ${XDNA_DRV_PATH} DESTINATION ${XDNA_BIN_DIR}/driver RENAME ${TEST_KO_NAME})
  install(FILES ${XDNA_DRV_INT_PATH} DESTINATION ${XDNA_BIN_DIR}/driver)
else()
  install(FILES ${XDNA_DRV_PATH} DESTINATION ${XDNA_BIN_DIR}/driver RENAME ${TEST_KO_NAME})
endif()

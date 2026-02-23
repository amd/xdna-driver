# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2022-2026, Advanced Micro Devices, Inc. All rights reserved.

set(XDNA_DRV amdxdna)

set(XDNA_DRV_DIR amdxdna)
set(XDNA_DRV_TGT ${XDNA_DRV}.ko)
set(XDNA_DRV_PATH ${CMAKE_BINARY_DIR}/drivers/accel/${XDNA_DRV_TGT})
set(XDNA_DRV_BLD_DIR driver/${XDNA_DRV_DIR})
set(XDNA_DRV_BLD_SRC ${CMAKE_CURRENT_BINARY_DIR}/${XDNA_DRV_BLD_DIR})
set(XDNA_DRV_BLD_TGT ${CMAKE_CURRENT_BINARY_DIR}/${XDNA_DRV_DIR})
set(XDNA_DRV_CONFIG_KERNEL_HEADER config_kernel.h)
set(XDNA_DRV_CONFIG_KERNEL_SCRIPT configure_kernel.sh)

if (DEFINED ENV{XDNA_DRV_BLD_FLAGS})
  set(XDNA_DRV_BLD_FLAGS_MAKE $ENV{XDNA_DRV_BLD_FLAGS})
  separate_arguments(XDNA_DRV_BLD_FLAGS_MAKE)
endif(DEFINED ENV{XDNA_DRV_BLD_FLAGS})

add_custom_command(
  OUTPUT all_driver_source
  COMMENT "Collect all driver source code"
  WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
  COMMAND ${CMAKE_COMMAND} -E make_directory ${XDNA_DRV_BLD_DIR}
  COMMAND cp -rf ${CMAKE_CURRENT_SOURCE_DIR}/../../drivers/accel/${XDNA_DRV_DIR}/* ${XDNA_DRV_BLD_DIR}
  COMMAND cp -r ${CMAKE_CURRENT_SOURCE_DIR}/../../include .
  COMMAND cp -r ${CMAKE_CURRENT_SOURCE_DIR}/../../drivers/tools/${XDNA_DRV_CONFIG_KERNEL_SCRIPT} .
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

message(STATUS "Build accel amdxdna driver in ${XDNA_DRV_PATH}")

add_custom_target(accel_driver ALL DEPENDS ${XDNA_DRV_TGT})

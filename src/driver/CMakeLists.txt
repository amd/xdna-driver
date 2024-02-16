# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2022-2023, Advanced Micro Devices, Inc. All rights reserved.

set(XDNA_DRV amdxdna)

set(XDNA_DRV_DIR amdxdna)
set(XDNA_DRV_TGT ${XDNA_DRV}.ko)
set(XDNA_DRV_BLD_SRC ${CMAKE_CURRENT_SOURCE_DIR}/${XDNA_DRV_DIR})
set(XDNA_DRV_BLD_TGT ${CMAKE_CURRENT_BINARY_DIR}/${XDNA_DRV_DIR})
add_custom_command(
  OUTPUT ${XDNA_DRV_TGT}
  COMMENT "Build ${XDNA_DRV_TGT}"
  COMMAND $(MAKE) -f ${XDNA_DRV_BLD_SRC}/Makefile BUILD_DIR=${XDNA_DRV_BLD_TGT} SRC_DIR=${XDNA_DRV_BLD_SRC} ${KERNEL_VER}
  COMMAND $(CMAKE_COMMAND) -E copy ${XDNA_DRV_BLD_TGT}/${XDNA_DRV_TGT} ${CMAKE_BINARY_DIR}/driver/${XDNA_DRV_TGT}
  )
add_custom_target(driver DEPENDS ${XDNA_DRV_TGT})

# Tar and install driver source code for packaging
set(XDNA_DRV_SRC_DIR
  driver
  include
  )
set(XDNA_DRV_EXCLUDES
  --exclude=CMake*
  --exclude=tools
  --exclude=doc
  )
aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR}/${XDNA_DRV_DIR}
  XDNA_DRV_SRC_MAIN
  )
aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR}/../include
  XDNA_DRV_SRC_INCLUDE
  )
set(XDNA_DRV_SRC_TGT ${XDNA_DRV}.tar)
add_custom_command(
  OUTPUT ${XDNA_DRV_SRC_TGT}
  COMMENT "Tar ${XDNA_DRV} driver source code"
  WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
  COMMAND tar ${XDNA_DRV_EXCLUDES} -cf ${CMAKE_CURRENT_BINARY_DIR}/${XDNA_DRV_SRC_TGT} -C .. ${XDNA_DRV_SRC_DIR}
  COMMAND $(CMAKE_COMMAND) -E copy ${CMAKE_CURRENT_BINARY_DIR}/${XDNA_DRV_SRC_TGT} ${CMAKE_BINARY_DIR}/driver/${XDNA_DRV_SRC_TGT}
  DEPENDS ${XDNA_DRV_SRC_MAIN} ${XDNA_DRV_SRC_INCLUDE}
  )
add_custom_target(driver_tarball DEPENDS ${XDNA_DRV_SRC_TGT})

# Install config file and driver related scripts for packaging
set(XDNA_DKMS_PKG_NAME xrt-${XDNA_DRV})
configure_file(
  ${CMAKE_CURRENT_SOURCE_DIR}/CMake/config/dkms.conf.in
  ${CMAKE_CURRENT_BINARY_DIR}/dkms.conf
  @ONLY
  )
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/dkms.conf
  DESTINATION xrt/${XDNA_COMPONENT}
  COMPONENT ${XDNA_COMPONENT}
  )

set(amdxdna_drv_tools
  ${CMAKE_CURRENT_SOURCE_DIR}/tools/dkms_driver.sh
  ${CMAKE_CURRENT_SOURCE_DIR}/tools/setup_xclbin_firmware.sh
  )
install(FILES ${amdxdna_drv_tools}
  PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE
  DESTINATION xrt/${XDNA_COMPONENT}
  COMPONENT ${XDNA_COMPONENT}
  )

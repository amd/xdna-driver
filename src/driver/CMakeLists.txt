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
add_custom_target(driver ALL DEPENDS ${XDNA_DRV_TGT} ${XDNA_DRV_INT_TGT})
else()
add_custom_target(driver ALL DEPENDS ${XDNA_DRV_TGT})
endif()

# Tar and install driver source code for packaging
set(XDNA_DRV_SRC_DIR
  driver
  include
  )
set(XDNA_DRV_EXCLUDES
  --exclude=CMake*
  --exclude=tools
  --exclude=doc
  --exclude=${XDNA_DRV_CONFIG_KERNEL_HEADER}
  ${XDNA_EXTRA_DRV_EXCLUDES}
  )
file(GLOB_RECURSE ALL_DRV_FILES
  ${XDNA_DRV_BLD_SRC}/Makefile
  ${XDNA_DRV_BLD_SRC}/*.c
  ${XDNA_DRV_BLD_SRC}/*.h
  ${CMAKE_CURRENT_BINARY_DIR}/include/*.h
  )
set(XDNA_DRV_SRC_TGT ${XDNA_DRV}.tar)
add_custom_command(
  OUTPUT ${CMAKE_BINARY_DIR}/driver/${XDNA_DRV_SRC_TGT}
  COMMENT "Tar ${XDNA_DRV} driver source code"
  WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
  COMMAND tar ${XDNA_DRV_EXCLUDES} -cf ${CMAKE_CURRENT_BINARY_DIR}/${XDNA_DRV_SRC_TGT} ${XDNA_DRV_SRC_DIR}
  COMMAND ${CMAKE_COMMAND} -E copy ${CMAKE_CURRENT_BINARY_DIR}/${XDNA_DRV_SRC_TGT} ${CMAKE_BINARY_DIR}/driver/${XDNA_DRV_SRC_TGT}
  DEPENDS ${ALL_DRV_FILES}
  )

# Substitute driver version in the source code
set(XDNA_TAR_GZ ${XDNA_DRV}.tar.gz)
add_custom_command(
  OUTPUT ${CMAKE_BINARY_DIR}/driver/${XDNA_TAR_GZ}
  COMMENT "Substitute amdxdna module version and re-tar"
  WORKING_DIRECTORY ${CMAKE_BINARY_DIR}/driver
  COMMAND ${CMAKE_COMMAND} -E make_directory tmp
  COMMAND tar xf ${CMAKE_BINARY_DIR}/driver/${XDNA_DRV_SRC_TGT} -C tmp
  COMMAND find tmp -name amdxdna_pci_drv.c -exec sed -i 's/MODULE_VERSION\(\".*\"\)/MODULE_VERSION\(\"${XRT_PLUGIN_VERSION_STRING}_${XDNA_DATE},${XDNA_HASH}\"\)/' {} \\\;
  COMMAND tar zcf ${CMAKE_BINARY_DIR}/driver/${XDNA_TAR_GZ} -C tmp .
  COMMAND ${CMAKE_COMMAND} -E rm -r tmp
  DEPENDS ${CMAKE_BINARY_DIR}/driver/${XDNA_DRV_SRC_TGT}
  )
add_custom_target(driver_ver_tarball ALL DEPENDS ${CMAKE_BINARY_DIR}/driver/${XDNA_TAR_GZ} driver)
install(FILES ${CMAKE_BINARY_DIR}/driver/${XDNA_TAR_GZ}
  DESTINATION ${XDNA_PKG_DATA_DIR}
  COMPONENT ${XDNA_COMPONENT}
  )

set(MAKE_DRV "make -C driver/${XDNA_DRV_DIR} ${XDNA_DRV_BLD_FLAGS_DKMS} KERNEL_SRC=\${kernel_source_dir}")
set(CLEAN_DRV "make -C driver/${XDNA_DRV_DIR} clean KERNEL_SRC=\${kernel_source_dir}")
set(MODULE_DRV "BUILT_MODULE_NAME[0]=${XDNA_DRV}
BUILT_MODULE_LOCATION[0]=\"driver/${XDNA_DRV_DIR}/build/driver/amdxdna\"
DEST_MODULE_LOCATION[0]=\"/kernel/extras\"")

if(XDNA_DRV_INT_SRC_DIR)
  set(MAKE_DRV "${MAKE_DRV}; cd driver/${XDNA_DRV_INT_DIR}; make KERNEL_SRC=\${kernel_source_dir}")
  set(CLEAN_DRV "${CLEAN_DRV}; cd driver/${XDNA_DRV_INT_DIR}; make clean KERNEL_SRC=\${kernel_source_dir}")
  set(MODULE_DRV "${MODULE_DRV}
BUILT_MODULE_NAME[1]=${XDNA_DRV_INT}
BUILT_MODULE_LOCATION[1]=\"driver/${XDNA_DRV_INT_DIR}/build/driver/${XDNA_DRV_INT_DIR}\"
DEST_MODULE_LOCATION[1]=\"/kernel/extras\"")
endif(XDNA_DRV_INT_SRC_DIR)

# Install config file and driver related scripts for packaging
set(XDNA_DKMS_PKG_NAME xrt-${XDNA_DRV})
configure_file(
  ${CMAKE_CURRENT_SOURCE_DIR}/CMake/config/dkms.conf.in
  ${CMAKE_CURRENT_BINARY_DIR}/dkms.conf
  @ONLY
  )
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/dkms.conf
  DESTINATION ${XDNA_PKG_DATA_DIR}
  COMPONENT ${XDNA_COMPONENT}
  )

# install .ko for testing - will include extra paths if defined
if(DEFINED XDNA_DRV_INT_TGT)
  install(FILES ${XDNA_DRV_PATH} ${XDNA_DRV_INT_PATH} DESTINATION ${XDNA_BIN_DIR}/driver)
else()
  install(FILES ${XDNA_DRV_PATH} DESTINATION ${XDNA_BIN_DIR}/driver)
endif()

set(amdxdna_drv_tools
  ${CMAKE_CURRENT_SOURCE_DIR}/tools/${XDNA_DRV_CONFIG_KERNEL_SCRIPT}
  ${CMAKE_CURRENT_SOURCE_DIR}/tools/dkms_driver.sh
  ${CMAKE_CURRENT_SOURCE_DIR}/tools/npu_perf_trace.sh
  ${CMAKE_CURRENT_SOURCE_DIR}/tools/npu_perf_analyze.sh
  ${CMAKE_CURRENT_SOURCE_DIR}/tools/io_page_fault_flags
  )
install(FILES ${amdxdna_drv_tools}
  PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE
  DESTINATION ${XDNA_PKG_DATA_DIR}
  COMPONENT ${XDNA_COMPONENT}
  )


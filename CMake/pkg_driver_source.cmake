set(XDNA_DRV_EXCLUDES
  --exclude=CMake*
  --exclude=tools
  --exclude=doc
  --exclude=${XDNA_DRV_CONFIG_KERNEL_HEADER}
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
# Defines phony target which always run (ALL) to trigger above custom command after "driver".
add_custom_target(driver_ver_tarball ALL DEPENDS ${CMAKE_BINARY_DIR}/driver/${XDNA_TAR_GZ} ${TAR_DRV_SOURCE_TGT})
install(FILES ${CMAKE_BINARY_DIR}/driver/${XDNA_TAR_GZ}
  DESTINATION ${XDNA_PKG_DATA_DIR}
  COMPONENT ${XDNA_COMPONENT}
  )

#Prepare and install dkms.conf
set(MAKE_DRV "make -C ${XDNA_DRV_BLD_DIR} ${XDNA_DRV_BLD_FLAGS_DKMS} KERNEL_SRC=\${kernel_source_dir}")
set(CLEAN_DRV "make -C ${XDNA_DRV_BLD_DIR} clean KERNEL_SRC=\${kernel_source_dir}")
set(MODULE_DRV "BUILT_MODULE_NAME[0]=${XDNA_DRV}
BUILT_MODULE_LOCATION[0]=\"${XDNA_DRV_BLD_DIR}/build/${XDNA_DRV_BLD_DIR}\"
DEST_MODULE_LOCATION[0]=\"/kernel/extras\"")
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

# Install extra driver tools and scripts
set(amdxdna_drv_tools
  ${CMAKE_CURRENT_SOURCE_DIR}/tools/${XDNA_DRV_CONFIG_KERNEL_SCRIPT}
  ${CMAKE_CURRENT_SOURCE_DIR}/tools/dkms_driver.sh
  )
install(FILES ${amdxdna_drv_tools}
  PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE
  DESTINATION ${XDNA_PKG_DATA_DIR}
  COMPONENT ${XDNA_COMPONENT}
  )

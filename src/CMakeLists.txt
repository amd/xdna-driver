# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2022-2023, Advanced Micro Devices, Inc. All rights reserved.

add_subdirectory(driver)
add_subdirectory(shim)

set(amdxdna_xrt_smi_config
  ${CMAKE_CURRENT_SOURCE_DIR}/tools/xrt_smi_config.json
  )
install(FILES ${amdxdna_xrt_smi_config}
  PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE
  DESTINATION xrt/${XDNA_COMPONENT}
  COMPONENT ${XDNA_COMPONENT}
  )
  
# SPDX-License-Identifier: MIT
# Copyright (C) 2025, Advanced Micro Devices, Inc. All rights reserved.

include(${CMAKE_CURRENT_LIST_DIR}/check_linux_config.cmake)


# Library version
set(VXDNA_VERSION_MAJOR 1)
set(VXDNA_VERSION_MINOR 0)
set(VXDNA_VERSION_PATCH 0)
set(VXDNA_VERSION "${VXDNA_VERSION_MAJOR}.${VXDNA_VERSION_MINOR}.${VXDNA_VERSION_PATCH}")

# Source files
set(VXDNA_SOURCES
    src/vaccel_manager.cpp
    src/vaccel_amdxdna.cpp
    util/os_file.cpp
    util/vxdna_debug.cpp
)

# Create shared library
add_library(vxdna SHARED ${VXDNA_SOURCES})

# Set library version and C++ standard
set_target_properties(vxdna PROPERTIES
    VERSION ${VXDNA_VERSION}
    SOVERSION ${VXDNA_VERSION_MAJOR}
    OUTPUT_NAME "vxdna"
    CXX_STANDARD 17
    CXX_STANDARD_REQUIRED ON
    CXX_EXTENSIONS OFF
)

# Include directories
target_include_directories(vxdna PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
    PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${CMAKE_CURRENT_SOURCE_DIR}/util
    ${CMAKE_CURRENT_SOURCE_DIR}/../include/uapi
)

# Compiler flags
target_compile_options(vxdna PRIVATE
    -fPIC
    -Wall
    -Wextra
)

# Compile definitions
if(HAVE_DRM_SET_CLIENT_NAME)
    target_compile_definitions(vxdna PRIVATE HAVE_DRM_SET_CLIENT_NAME=1)
endif()

if(HAVE_STRUCT_IOVEC)
    target_compile_definitions(vxdna PRIVATE HAVE_STRUCT_IOVEC=1)
endif()

# Link libraries
target_link_libraries(vxdna PRIVATE
    pthread
)

# Install library
install(TARGETS vxdna
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    COMPONENT ${XDNA_COMPONENT}
)

# Install headers
install(FILES
    include/vaccel.h
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
    COMPONENT ${XDNA_COMPONENT}
)


# SPDX-License-Identifier: MIT
# Copyright (C) 2025, Advanced Micro Devices, Inc. All rights reserved.

# Unit tests for vaccel APIs

cmake_minimum_required(VERSION 3.10)

# Find GTest package
find_package(GTest REQUIRED)
include(GoogleTest)

# Test executable sources
set(TEST_SOURCES
    test_vaccel.cpp
    test_helper.cpp
)

# Create test executable
add_executable(vaccel_tests ${TEST_SOURCES})

# Set C++ standard
set_target_properties(vaccel_tests PROPERTIES
    CXX_STANDARD 17
    CXX_STANDARD_REQUIRED ON
    CXX_EXTENSIONS OFF
)

# Include directories
target_include_directories(vaccel_tests PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/../include
    ${CMAKE_CURRENT_SOURCE_DIR}/../src
    ${CMAKE_CURRENT_SOURCE_DIR}/../util
    ${CMAKE_CURRENT_SOURCE_DIR}/../../shim/virtio
    ${CMAKE_CURRENT_SOURCE_DIR}/../../include/uapi
    ${GTEST_INCLUDE_DIRS}
)

# Link libraries
target_link_libraries(vaccel_tests
    vxdna
    GTest::GTest
    GTest::Main
    pthread
)

# Compiler flags
target_compile_options(vaccel_tests PRIVATE
    -Wall
    -Wextra
    -Wno-unused-parameter
)

# Register tests with CTest
gtest_discover_tests(vaccel_tests)

# Custom target to run tests
add_custom_target(run_tests
    COMMAND ${CMAKE_CURRENT_BINARY_DIR}/vaccel_tests
    DEPENDS vaccel_tests
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
    COMMENT "Running vaccel unit tests"
)


#!/bin/bash
# SPDX-License-Identifier: MIT
# Copyright (C) 2025, Advanced Micro Devices, Inc. All rights reserved.

# Script to build and run vaccel unit tests

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="${SCRIPT_DIR}/build"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo "========================================"
echo "vaccel Unit Tests Build Script"
echo "========================================"
echo ""

# Check for DRM devices
echo "Checking for DRM devices..."
if [ ! -d "/dev/dri" ]; then
    echo -e "${YELLOW}WARNING: /dev/dri directory not found${NC}"
    echo "Tests will be skipped if no DRM devices are available"
else
    echo "DRM devices found:"
    ls -la /dev/dri/ 2>/dev/null || echo "  (unable to list)"
fi
echo ""

# Check if Google Test is installed
echo "Checking for Google Test..."
if ! pkg-config --exists gtest 2>/dev/null; then
    echo -e "${YELLOW}WARNING: Google Test not found via pkg-config${NC}"
    echo "Attempting to continue anyway (CMake may find it)"
else
    echo "Google Test found: $(pkg-config --modversion gtest)"
fi
echo ""

# Create build directory
echo "Creating build directory: ${BUILD_DIR}"
mkdir -p "${BUILD_DIR}"
cd "${BUILD_DIR}"

# Run CMake
echo ""
echo "Running CMake..."
cmake .. || {
    echo -e "${RED}ERROR: CMake configuration failed${NC}"
    echo "Make sure Google Test is installed:"
    echo "  Ubuntu/Debian: sudo apt-get install libgtest-dev"
    echo "  Fedora/RHEL:   sudo dnf install gtest-devel"
    exit 1
}

# Build
echo ""
echo "Building tests..."
make -j$(nproc) || {
    echo -e "${RED}ERROR: Build failed${NC}"
    exit 1
}

echo ""
echo -e "${GREEN}Build successful!${NC}"
echo ""

# Check if user wants to run tests
if [ "$1" == "--no-run" ]; then
    echo "Skipping test execution (--no-run specified)"
    echo "To run tests manually:"
    echo "  ${BUILD_DIR}/vaccel_tests"
    exit 0
fi

# Run tests
echo "========================================"
echo "Running Tests"
echo "========================================"
echo ""

./vaccel_tests "$@" || {
    RESULT=$?
    echo ""
    echo -e "${RED}Some tests failed${NC}"
    exit $RESULT
}

echo ""
echo -e "${GREEN}All tests passed!${NC}"


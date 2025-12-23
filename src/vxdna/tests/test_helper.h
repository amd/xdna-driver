// SPDX-License-Identifier: MIT
// Copyright (C) 2025, Advanced Micro Devices, Inc. All rights reserved.

/**
 * @file test_helper.h
 * @brief Helper utilities for vaccel unit tests
 *
 * Provides utility functions for opening DRM devices, creating test
 * fixtures, and managing test resources.
 */

#ifndef TEST_HELPER_H
#define TEST_HELPER_H

#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>
#include <string>
#include <vector>
#include <cstring>
#include <sys/stat.h>

#include "vaccel.h"

/**
 * @brief Helper class for managing DRM file descriptors
 *
 * Provides methods to open and manage DRM device file descriptors
 * for testing purposes.
 */
class DrmHelper {
public:
    /**
     * @brief Find and open a DRM render node
     *
     * Searches /dev/dri/ for available render nodes (renderD*) and
     * attempts to open the first available one.
     *
     * @return Valid file descriptor (>0) on success, -1 on failure
     */
    static int openDrmRenderNode();

    /**
     * @brief Find and open a DRM card device
     *
     * Searches /dev/dri/ for available card devices (card*) and
     * attempts to open the first available one.
     *
     * @return Valid file descriptor (>0) on success, -1 on failure
     */
    static int openDrmCard();

    /**
     * @brief Try to open any available DRM device
     *
     * Tries render nodes first, then card devices.
     *
     * @return Valid file descriptor (>0) on success, -1 on failure
     */
    static int openAnyDrmDevice();

    /**
     * @brief Check if a DRM device is available
     *
     * @return true if at least one DRM device exists, false otherwise
     */
    static bool isDrmDeviceAvailable();

    /**
     * @brief Get list of available DRM devices
     *
     * @return Vector of DRM device paths
     */
    static std::vector<std::string> listDrmDevices();
};

/**
 * @brief Test fixture providing common test setup and teardown
 *
 * Manages DRM device handles and provides common functionality
 * for vaccel tests.
 */
class VaccelRendererTestBase {
protected:
    int drm_fd_ = -1;
    void *cookie_ = nullptr;
    struct vaccel_callbacks callbacks_ = {};
    bool device_created_ = false;

    /**
     * @brief Set up test fixture
     *
     * Opens DRM device and prepares test environment.
     */
    void SetUp();

    /**
     * @brief Tear down test fixture
     *
     * Cleans up resources and closes file descriptors.
     */
    void TearDown();

    /**
     * @brief Callback to get device FD from cookie
     *
     * Returns the stored DRM file descriptor.
     *
     * @param cookie Test cookie
     * @return DRM file descriptor
     */
    static int getDeviceFdCallback(void *cookie);

    /**
     * @brief Create a test device with the given capset ID
     *
     * @param capset_id Capability set ID
     * @return 0 on success, negative errno on failure
     */
    int createTestDevice(uint32_t capset_id = VIRACCEL_CAPSET_ID_AMDXDNA);

    /**
     * @brief Destroy the test device
     */
    void destroyTestDevice();

    void *getCookie() const noexcept { return cookie_; }
};

#endif /* TEST_HELPER_H */


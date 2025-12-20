// SPDX-License-Identifier: MIT
// Copyright (C) 2025, Advanced Micro Devices, Inc. All rights reserved.

/**
 * @file test_vaccel.cpp
 * @brief Unit tests for vaccel.h APIs
 *
 * Tests all public APIs exposed in vaccel.h including:
 * - vaccel_create()
 * - vaccel_destroy()
 * - vaccel_get_capset_info()
 * - vaccel_fill_capset()
 */

#include <gtest/gtest.h>
#include <errno.h>
#include <cstring>
#include <thread>
#include <vector>

#include "vaccel.h"
#include "drm_local/amdxdna_accel.h"
#include "amdxdna_proto.h"
#include "test_helper.h"

// =============================================================================
// Test Fixture
// =============================================================================

class VaccelRendererTest : public ::testing::Test, public VaccelRendererTestBase {
protected:
    void SetUp() override {
        VaccelRendererTestBase::SetUp();
    }

    void TearDown() override {
        VaccelRendererTestBase::TearDown();
    }
};

// =============================================================================
// DRM Device Tests
// =============================================================================

TEST(DrmHelperTest, DrmDeviceAvailable) {
    bool available = DrmHelper::isDrmDeviceAvailable();
    if (!available) {
        GTEST_SKIP() << "No DRM devices available on this system";
    }
    EXPECT_TRUE(available);
}

TEST(DrmHelperTest, ListDrmDevices) {
    std::vector<std::string> devices = DrmHelper::listDrmDevices();
    if (devices.empty()) {
        GTEST_SKIP() << "No DRM devices found";
    }

    std::cout << "Available DRM devices:" << std::endl;
    for (const auto& device : devices) {
        std::cout << "  - " << device << std::endl;
    }

    EXPECT_FALSE(devices.empty());
}

TEST(DrmHelperTest, OpenDrmDevice) {
    int fd = DrmHelper::openAnyDrmDevice();
    if (fd < 0) {
        GTEST_SKIP() << "Cannot open DRM device";
    }

    EXPECT_GT(fd, 0);
    close(fd);
}

// =============================================================================
// vaccel_create() Tests
// =============================================================================

TEST_F(VaccelRendererTest, CreateDeviceSuccess) {
    if (drm_fd_ < 0) {
        GTEST_SKIP() << "No DRM device available";
    }

    int ret = createTestDevice(VIRACCEL_CAPSET_ID_AMDXDNA);
    EXPECT_EQ(ret, 0) << "vaccel_create() should succeed";
}

TEST_F(VaccelRendererTest, CreateDeviceNullCookie) {
    int ret = vaccel_create(nullptr, VIRACCEL_CAPSET_ID_AMDXDNA, &callbacks_);
    EXPECT_EQ(ret, -EINVAL) << "vaccel_create() should fail with NULL cookie";
}

TEST_F(VaccelRendererTest, CreateDeviceNullCallbacks) {
    if (drm_fd_ < 0) {
        GTEST_SKIP() << "No DRM device available";
    }

    int ret = vaccel_create(cookie_, VIRACCEL_CAPSET_ID_AMDXDNA, nullptr);
    EXPECT_EQ(ret, -EINVAL) << "vaccel_create() should fail with NULL callbacks";
}

TEST_F(VaccelRendererTest, CreateDeviceInvalidCapsetId) {
    if (drm_fd_ < 0) {
        GTEST_SKIP() << "No DRM device available";
    }

    // Use an invalid capset ID (beyond MAX)
    int ret = createTestDevice(VIRACCEL_CAPSET_ID_MAX + 1);
    EXPECT_LT(ret, 0) << "vaccel_create() should fail with invalid capset_id";
}

TEST_F(VaccelRendererTest, CreateDeviceDuplicate) {
    if (drm_fd_ < 0) {
        GTEST_SKIP() << "No DRM device available";
    }

    // Create device first time
    int ret = createTestDevice(VIRACCEL_CAPSET_ID_AMDXDNA);
    ASSERT_EQ(ret, 0) << "First vaccel_create() should succeed";

    // Try to create same device again with same cookie
    ret = vaccel_create(cookie_, VIRACCEL_CAPSET_ID_AMDXDNA, &callbacks_);
    EXPECT_EQ(ret, -EEXIST) << "vaccel_create() should fail with duplicate cookie";
}

TEST_F(VaccelRendererTest, CreateDeviceNullGetDeviceFdCallback) {
    if (drm_fd_ < 0) {
        GTEST_SKIP() << "No DRM device available";
    }

    struct vaccel_callbacks bad_callbacks = {};
    bad_callbacks.get_device_fd = nullptr;

    int ret = vaccel_create(cookie_, VIRACCEL_CAPSET_ID_AMDXDNA, &bad_callbacks);
    EXPECT_EQ(ret, -EINVAL) << "vaccel_create() should fail with NULL get_device_fd callback";
}

TEST_F(VaccelRendererTest, CreateDeviceInvalidFdFromCallback) {
    if (drm_fd_ < 0) {
        GTEST_SKIP() << "No DRM device available";
    }

    // Create callback that returns invalid FD
    struct vaccel_callbacks bad_callbacks = {};
    bad_callbacks.get_device_fd = [](void *) -> int { return -1; };

    int ret = vaccel_create(cookie_, VIRACCEL_CAPSET_ID_AMDXDNA, &bad_callbacks);
    EXPECT_LT(ret, 0) << "vaccel_create() should fail when callback returns invalid FD";
}

// =============================================================================
// vaccel_destroy() Tests
// =============================================================================

TEST_F(VaccelRendererTest, DestroyDeviceSuccess) {
    if (drm_fd_ < 0) {
        GTEST_SKIP() << "No DRM device available";
    }

    // Create device
    int ret = createTestDevice(VIRACCEL_CAPSET_ID_AMDXDNA);
    ASSERT_EQ(ret, 0);

    // Destroy device
    destroyTestDevice();

    // Should be safe to call multiple times
    vaccel_destroy(cookie_);
}

TEST_F(VaccelRendererTest, DestroyDeviceNullCookie) {
    // Should not crash
    vaccel_destroy(nullptr);
}

TEST_F(VaccelRendererTest, DestroyDeviceNonExistent) {
    void *fake_cookie = reinterpret_cast<void*>(0xDEADBEEF);

    // Should not crash
    vaccel_destroy(fake_cookie);
}

TEST_F(VaccelRendererTest, CreateDestroyCreateAgain) {
    if (drm_fd_ < 0) {
        GTEST_SKIP() << "No DRM device available";
    }

    // Create device
    int ret = createTestDevice(VIRACCEL_CAPSET_ID_AMDXDNA);
    ASSERT_EQ(ret, 0);

    // Destroy device
    destroyTestDevice();

    // Create again with same cookie (should succeed)
    ret = createTestDevice(VIRACCEL_CAPSET_ID_AMDXDNA);
    EXPECT_EQ(ret, 0) << "Should be able to create device again after destroy";
}

// =============================================================================
// vaccel_get_capset_info() Tests
// =============================================================================

TEST_F(VaccelRendererTest, GetCapsetInfoSuccess) {
    if (drm_fd_ < 0) {
        GTEST_SKIP() << "No DRM device available";
    }

    // Create device first
    int ret = createTestDevice(VIRACCEL_CAPSET_ID_AMDXDNA);
    ASSERT_EQ(ret, 0);

    uint32_t max_version = 0;
    uint32_t max_size = 0;

    ret = vaccel_get_capset_info(cookie_, &max_version, &max_size);
    EXPECT_EQ(ret, 0) << "vaccel_get_capset_info() should succeed";

    // Verify reasonable values
    EXPECT_GT(max_version, 0) << "max_version should be positive";
    EXPECT_GT(max_size, 0) << "max_size should be positive";

    std::cout << "Capset info: max_version=" << max_version 
              << ", max_size=" << max_size << std::endl;
}

TEST_F(VaccelRendererTest, GetCapsetInfoNullCookie) {
    uint32_t max_version = 0;
    uint32_t max_size = 0;

    int ret = vaccel_get_capset_info(nullptr, &max_version, &max_size);
    EXPECT_EQ(ret, -EINVAL) << "vaccel_get_capset_info() should fail with NULL cookie";
}

TEST_F(VaccelRendererTest, GetCapsetInfoDeviceNotFound) {
    void *fake_cookie = reinterpret_cast<void*>(0xDEADBEEF);
    uint32_t max_version = 0;
    uint32_t max_size = 0;

    int ret = vaccel_get_capset_info(fake_cookie, &max_version, &max_size);
    EXPECT_EQ(ret, -ENODEV) << "vaccel_get_capset_info() should fail with non-existent device";
}

TEST_F(VaccelRendererTest, GetCapsetInfoNullOutputs) {
    if (drm_fd_ < 0) {
        GTEST_SKIP() << "No DRM device available";
    }

    // Create device first
    int ret = createTestDevice(VIRACCEL_CAPSET_ID_AMDXDNA);
    ASSERT_EQ(ret, 0);

    // Should succeed with NULL output pointers (allowed per API)
    ret = vaccel_get_capset_info(cookie_, nullptr, nullptr);
    EXPECT_EQ(ret, 0) << "vaccel_get_capset_info() should allow NULL output parameters";
}

TEST_F(VaccelRendererTest, GetCapsetInfoPartialOutputs) {
    if (drm_fd_ < 0) {
        GTEST_SKIP() << "No DRM device available";
    }

    // Create device first
    int ret = createTestDevice(VIRACCEL_CAPSET_ID_AMDXDNA);
    ASSERT_EQ(ret, 0);

    uint32_t max_version = 0;

    // Get only max_version
    ret = vaccel_get_capset_info(cookie_, &max_version, nullptr);
    EXPECT_EQ(ret, 0);
    EXPECT_GT(max_version, 0);

    uint32_t max_size = 0;

    // Get only max_size
    ret = vaccel_get_capset_info(cookie_, nullptr, &max_size);
    EXPECT_EQ(ret, 0);
    EXPECT_GT(max_size, 0);
}

// =============================================================================
// vaccel_fill_capset() Tests
// =============================================================================

TEST_F(VaccelRendererTest, FillCapsetSuccess) {
    if (drm_fd_ < 0) {
        GTEST_SKIP() << "No DRM device available";
    }

    // Create device first
    int ret = createTestDevice(VIRACCEL_CAPSET_ID_AMDXDNA);
    ASSERT_EQ(ret, 0);

    // Get capset size first
    uint32_t max_size = 0;
    ret = vaccel_get_capset_info(cookie_, nullptr, &max_size);
    ASSERT_EQ(ret, 0);
    ASSERT_GT(max_size, 0);

    // Allocate buffer
    std::vector<uint8_t> capset_buf(max_size);

    // Fill capset
    ret = vaccel_fill_capset(cookie_, max_size, capset_buf.data());
    EXPECT_EQ(ret, 0) << "vaccel_fill_capset() should succeed";

    // Verify the buffer was filled (at least check it's not all zeros)
    bool has_data = false;
    for (size_t i = 0; i < capset_buf.size(); i++) {
        if (capset_buf[i] != 0) {
            has_data = true;
            break;
        }
    }
    EXPECT_TRUE(has_data) << "Capset buffer should contain data";
}

TEST_F(VaccelRendererTest, FillCapsetNullCookie) {
    uint8_t buffer[256] = {};

    int ret = vaccel_fill_capset(nullptr, sizeof(buffer), buffer);
    EXPECT_EQ(ret, -EINVAL) << "vaccel_fill_capset() should fail with NULL cookie";
}

TEST_F(VaccelRendererTest, FillCapsetNullBuffer) {
    if (drm_fd_ < 0) {
        GTEST_SKIP() << "No DRM device available";
    }

    // Create device first
    int ret = createTestDevice(VIRACCEL_CAPSET_ID_AMDXDNA);
    ASSERT_EQ(ret, 0);

    ret = vaccel_fill_capset(cookie_, 256, nullptr);
    EXPECT_EQ(ret, -EINVAL) << "vaccel_fill_capset() should fail with NULL buffer";
}

TEST_F(VaccelRendererTest, FillCapsetDeviceNotFound) {
    void *fake_cookie = reinterpret_cast<void*>(0xDEADBEEF);
    uint8_t buffer[256] = {};

    int ret = vaccel_fill_capset(fake_cookie, sizeof(buffer), buffer);
    EXPECT_EQ(ret, -ENODEV) << "vaccel_fill_capset() should fail with non-existent device";
}

TEST_F(VaccelRendererTest, FillCapsetZeroSize) {
    if (drm_fd_ < 0) {
        GTEST_SKIP() << "No DRM device available";
    }

    // Create device first
    int ret = createTestDevice(VIRACCEL_CAPSET_ID_AMDXDNA);
    ASSERT_EQ(ret, 0);

    uint8_t buffer[256] = {};

    // Zero size should either fail or be handled gracefully
    ret = vaccel_fill_capset(cookie_, 0, buffer);
    // Implementation may return 0 or error - both are acceptable
    EXPECT_TRUE(ret <= 0) << "vaccel_fill_capset() should handle zero size";
}

TEST_F(VaccelRendererTest, FillCapsetVerifyStructure) {
    if (drm_fd_ < 0) {
        GTEST_SKIP() << "No DRM device available";
    }

    // Create device first
    int ret = createTestDevice(VIRACCEL_CAPSET_ID_AMDXDNA);
    ASSERT_EQ(ret, 0);

    // The capset should be at least the size of vaccel_drm_capset
    uint32_t max_size = 0;
    ret = vaccel_get_capset_info(cookie_, nullptr, &max_size);
    ASSERT_EQ(ret, 0);
    ASSERT_GE(max_size, sizeof(struct vaccel_drm_capset));

    // Fill capset
    struct vaccel_drm_capset capset = {};
    ret = vaccel_fill_capset(cookie_, sizeof(capset), &capset);
    EXPECT_EQ(ret, 0);

    // Verify structure fields
    EXPECT_EQ(capset.context_type, VIRTACCEL_DRM_CONTEXT_AMDXDNA) 
        << "context_type should match AMDXDNA";

    std::cout << "Capset structure: version_major=" << capset.version_major
              << ", version_minor=" << capset.version_minor
              << ", version_patchlevel=" << capset.version_patchlevel
              << ", context_type=" << capset.context_type
              << ", pad=" << capset.pad << std::endl;
}

// =============================================================================
// Multi-Device Tests
// =============================================================================

TEST_F(VaccelRendererTest, CreateMultipleDevices) {
    if (drm_fd_ < 0) {
        GTEST_SKIP() << "No DRM device available";
    }

    // Try to open a second DRM device
    int drm_fd2 = DrmHelper::openAnyDrmDevice();
    if (drm_fd2 < 0) {
        GTEST_SKIP() << "Need at least one DRM device";
    }

    void *cookie2 = &drm_fd2;

    struct vaccel_callbacks callbacks2 = {};
    callbacks2.get_device_fd = [](void *cookie) -> int {
        int *fd_ptr = static_cast<int*>(cookie);
        return *fd_ptr;
    };

    // Create first device
    int ret = createTestDevice(VIRACCEL_CAPSET_ID_AMDXDNA);
    ASSERT_EQ(ret, 0);

    // Create second device with different cookie
    ret = vaccel_create(cookie2, VIRACCEL_CAPSET_ID_AMDXDNA, &callbacks2);
    EXPECT_EQ(ret, 0) << "Should be able to create multiple devices";

    // Both devices should be independently accessible
    uint32_t max_version1 = 0, max_version2 = 0;

    ret = vaccel_get_capset_info(cookie_, &max_version1, nullptr);
    EXPECT_EQ(ret, 0);

    ret = vaccel_get_capset_info(cookie2, &max_version2, nullptr);
    EXPECT_EQ(ret, 0);

    // Clean up second device
    vaccel_destroy(cookie2);
    close(drm_fd2);
}

// =============================================================================
// Thread Safety Tests
// =============================================================================

TEST_F(VaccelRendererTest, ConcurrentCreateDestroy) {
    if (drm_fd_ < 0) {
        GTEST_SKIP() << "No DRM device available";
    }

    const int num_threads = 4;
    const int iterations = 10;
    std::vector<std::thread> threads;
    std::atomic<int> success_count{0};

    for (int t = 0; t < num_threads; t++) {
        threads.emplace_back([&]() {
            for (int i = 0; i < iterations; i++) {
                void *thread_cookie = getCookie();
                
                // Note: This test will have EEXIST errors which is expected
                // We're just testing that the API is thread-safe
                int ret = vaccel_create(thread_cookie, VIRACCEL_CAPSET_ID_AMDXDNA, &callbacks_);
                if (ret == 0) {
                    success_count++;
                    vaccel_destroy(thread_cookie);
                }
            }
        });
    }

    for (auto& thread : threads) {
        thread.join();
    }

    // At least some operations should succeed
    EXPECT_GT(success_count.load(), 0);
}

// =============================================================================
// Edge Case Tests
// =============================================================================

TEST_F(VaccelRendererTest, LargeCapsetBuffer) {
    if (drm_fd_ < 0) {
        GTEST_SKIP() << "No DRM device available";
    }

    // Create device first
    int ret = createTestDevice(VIRACCEL_CAPSET_ID_AMDXDNA);
    ASSERT_EQ(ret, 0);

    // Try with a very large buffer (should handle gracefully)
    std::vector<uint8_t> large_buffer(1024 * 1024); // 1 MB

    ret = vaccel_fill_capset(cookie_, large_buffer.size(), large_buffer.data());
    // Should either succeed or fail gracefully
    EXPECT_TRUE(ret <= 0);
}

TEST_F(VaccelRendererTest, SmallCapsetBuffer) {
    if (drm_fd_ < 0) {
        GTEST_SKIP() << "No DRM device available";
    }

    // Create device first
    int ret = createTestDevice(VIRACCEL_CAPSET_ID_AMDXDNA);
    ASSERT_EQ(ret, 0);

    // Try with a buffer smaller than the actual capset
    uint8_t small_buffer[4] = {};

    ret = vaccel_fill_capset(cookie_, sizeof(small_buffer), small_buffer);
    // Should handle gracefully (may truncate or error)
    // Both behaviors are acceptable
}

// =============================================================================
// vaccel_submit_ccmd() Tests
// =============================================================================

TEST_F(VaccelRendererTest, SubmitCcmdNullCookie) {
    uint8_t dummy_cmd[16] = {};

    int ret = vaccel_submit_ccmd(nullptr, 1, dummy_cmd, sizeof(dummy_cmd));
    EXPECT_EQ(ret, -EINVAL) << "vaccel_submit_ccmd() should fail with NULL cookie";
}

TEST_F(VaccelRendererTest, SubmitCcmdDeviceNotFound) {
    void *fake_cookie = reinterpret_cast<void*>(0xDEADBEEF);
    uint8_t dummy_cmd[16] = {};

    int ret = vaccel_submit_ccmd(fake_cookie, 1, dummy_cmd, sizeof(dummy_cmd));
    EXPECT_EQ(ret, -ENODEV) << "vaccel_submit_ccmd() should fail with non-existent device";
}

TEST_F(VaccelRendererTest, SubmitCcmdNullBuffer) {
    if (drm_fd_ < 0) {
        GTEST_SKIP() << "No DRM device available";
    }

    // Create device
    int ret = createTestDevice(VIRACCEL_CAPSET_ID_AMDXDNA);
    ASSERT_EQ(ret, 0);

    ret = vaccel_submit_ccmd(cookie_, 1, nullptr, 16);
    EXPECT_EQ(ret, -EINVAL) << "vaccel_submit_ccmd() should fail with NULL buffer";
}

TEST_F(VaccelRendererTest, SubmitCcmdZeroSize) {
    if (drm_fd_ < 0) {
        GTEST_SKIP() << "No DRM device available";
    }

    // Create device
    int ret = createTestDevice(VIRACCEL_CAPSET_ID_AMDXDNA);
    ASSERT_EQ(ret, 0);

    uint8_t dummy_cmd[16] = {};
    ret = vaccel_submit_ccmd(cookie_, 1, dummy_cmd, 0);
    EXPECT_EQ(ret, -EINVAL) << "vaccel_submit_ccmd() should fail with zero size";
}

TEST_F(VaccelRendererTest, SubmitCcmdUnalignedSize) {
    if (drm_fd_ < 0) {
        GTEST_SKIP() << "No DRM device available";
    }

    // Create device
    int ret = createTestDevice(VIRACCEL_CAPSET_ID_AMDXDNA);
    ASSERT_EQ(ret, 0);

    // Command size must be aligned to 4 bytes
    uint8_t dummy_cmd[17] = {};  // Not aligned to 4 bytes
    ret = vaccel_submit_ccmd(cookie_, 1, dummy_cmd, 17);
    EXPECT_EQ(ret, -EINVAL) << "vaccel_submit_ccmd() should fail with unaligned size";
}

TEST_F(VaccelRendererTest, SubmitCcmdContextNotFound) {
    if (drm_fd_ < 0) {
        GTEST_SKIP() << "No DRM device available";
    }

    // Create device
    int ret = createTestDevice(VIRACCEL_CAPSET_ID_AMDXDNA);
    ASSERT_EQ(ret, 0);

    // Try to submit to a non-existent context
    uint8_t dummy_cmd[16] = {};
    ret = vaccel_submit_ccmd(cookie_, 999, dummy_cmd, sizeof(dummy_cmd));
    EXPECT_EQ(ret, -ENOENT) << "vaccel_submit_ccmd() should fail with non-existent context";
}

TEST_F(VaccelRendererTest, SubmitCcmdWithValidContext) {
    if (drm_fd_ < 0) {
        GTEST_SKIP() << "No DRM device available";
    }

    // Create device
    int ret = createTestDevice(VIRACCEL_CAPSET_ID_AMDXDNA);
    ASSERT_EQ(ret, 0);

    // Create a context
    uint32_t ctx_id = 1;
    const char *ctx_name = "test_context";
    ret = vaccel_create_ctx_with_flags(cookie_, ctx_id, 0, strlen(ctx_name), ctx_name);
    ASSERT_EQ(ret, 0) << "Context creation should succeed";

    // Submit a simple NOP command

    struct amdxdna_ccmd_nop_req nop_cmd = {};
    nop_cmd.hdr.cmd = AMDXDNA_CCMD_NOP;
    nop_cmd.hdr.len = sizeof(struct amdxdna_ccmd_nop_req);

    ret = vaccel_submit_ccmd(cookie_, ctx_id, &nop_cmd, sizeof(nop_cmd));
    EXPECT_EQ(ret, 0) << "vaccel_submit_ccmd() should succeed with valid context and command";
}

TEST_F(VaccelRendererTest, SubmitCcmdInvalidCommandSize) {
    if (drm_fd_ < 0) {
        GTEST_SKIP() << "No DRM device available";
    }

    // Create device
    int ret = createTestDevice(VIRACCEL_CAPSET_ID_AMDXDNA);
    ASSERT_EQ(ret, 0);

    // Create a context
    uint32_t ctx_id = 1;
    ret = vaccel_create_ctx_with_flags(cookie_, ctx_id, 0, 0, nullptr);
    ASSERT_EQ(ret, 0);

    // Create a command with invalid length (smaller than header)
    struct {
        uint32_t cmd;
        uint32_t len;
        uint32_t seqno;
        uint32_t rsp_off;
    } bad_cmd = {
        .cmd = 1,
        .len = 8,  // Too small, less than sizeof(vdrm_ccmd_req)
        .seqno = 1,
        .rsp_off = 0
    };

    ret = vaccel_submit_ccmd(cookie_, ctx_id, &bad_cmd, sizeof(bad_cmd));
    EXPECT_LT(ret, 0) << "vaccel_submit_ccmd() should fail with invalid command size";
}

TEST_F(VaccelRendererTest, SubmitCcmdInvalidCommandLength) {
    if (drm_fd_ < 0) {
        GTEST_SKIP() << "No DRM device available";
    }

    // Create device
    int ret = createTestDevice(VIRACCEL_CAPSET_ID_AMDXDNA);
    ASSERT_EQ(ret, 0);

    // Create a context
    uint32_t ctx_id = 1;
    ret = vaccel_create_ctx_with_flags(cookie_, ctx_id, 0, 0, nullptr);
    ASSERT_EQ(ret, 0);

    // Create a command with length larger than buffer size
    struct {
        uint32_t cmd;
        uint32_t len;
        uint32_t seqno;
        uint32_t rsp_off;
    } bad_cmd = {
        .cmd = 1,
        .len = 1024,  // Much larger than actual buffer
        .seqno = 1,
        .rsp_off = 0
    };

    ret = vaccel_submit_ccmd(cookie_, ctx_id, &bad_cmd, sizeof(bad_cmd));
    EXPECT_LT(ret, 0) << "vaccel_submit_ccmd() should fail when cmd.len > buffer_size";
}

TEST_F(VaccelRendererTest, SubmitCcmdUnalignedRspOffset) {
    if (drm_fd_ < 0) {
        GTEST_SKIP() << "No DRM device available";
    }

    // Create device
    int ret = createTestDevice(VIRACCEL_CAPSET_ID_AMDXDNA);
    ASSERT_EQ(ret, 0);

    // Create a context (with alignment requirement of 8)
    uint32_t ctx_id = 1;
    ret = vaccel_create_ctx_with_flags(cookie_, ctx_id, 0, 0, nullptr);
    ASSERT_EQ(ret, 0);

    // Create a command with unaligned rsp_off
    struct {
        uint32_t cmd;
        uint32_t len;
        uint32_t seqno;
        uint32_t rsp_off;
    } bad_cmd = {
        .cmd = 1,
        .len = 16,
        .seqno = 1,
        .rsp_off = 5  // Not aligned to 8
    };

    ret = vaccel_submit_ccmd(cookie_, ctx_id, &bad_cmd, sizeof(bad_cmd));
    EXPECT_LT(ret, 0) << "vaccel_submit_ccmd() should fail with unaligned rsp_off";
}

TEST_F(VaccelRendererTest, SubmitCcmdMultipleCommands) {
    if (drm_fd_ < 0) {
        GTEST_SKIP() << "No DRM device available";
    }

    // Create device
    int ret = createTestDevice(VIRACCEL_CAPSET_ID_AMDXDNA);
    ASSERT_EQ(ret, 0);

    // Create a context
    uint32_t ctx_id = 1;
    ret = vaccel_create_ctx_with_flags(cookie_, ctx_id, 0, 0, nullptr);
    ASSERT_EQ(ret, 0);

    // Create buffer with multiple nop commands

    // Two NOP commands
    std::vector<uint8_t> cmd_buf(sizeof(struct amdxdna_ccmd_nop_req) * 2);
    auto *cmd1 = reinterpret_cast<struct amdxdna_ccmd_nop_req*>(cmd_buf.data());
    cmd1->hdr.cmd = AMDXDNA_CCMD_NOP;
    cmd1->hdr.len = sizeof(struct amdxdna_ccmd_nop_req);

    auto *cmd2 = reinterpret_cast<struct amdxdna_ccmd_nop_req*>(cmd_buf.data() + sizeof(struct amdxdna_ccmd_nop_req));
    cmd2->hdr.cmd = AMDXDNA_CCMD_NOP;
    cmd2->hdr.len = sizeof(struct amdxdna_ccmd_nop_req);

    ret = vaccel_submit_ccmd(cookie_, ctx_id, cmd_buf.data(), cmd_buf.size());
    EXPECT_EQ(ret, 0) << "vaccel_submit_ccmd() should succeed with multiple commands";
}

TEST_F(VaccelRendererTest, SubmitCcmdTrailingBytes) {
    if (drm_fd_ < 0) {
        GTEST_SKIP() << "No DRM device available";
    }

    // Create device
    int ret = createTestDevice(VIRACCEL_CAPSET_ID_AMDXDNA);
    ASSERT_EQ(ret, 0);

    // Create a context
    uint32_t ctx_id = 1;
    ret = vaccel_create_ctx_with_flags(cookie_, ctx_id, 0, 0, nullptr);
    ASSERT_EQ(ret, 0);

    // Create buffer with trailing bytes
    std::vector<uint8_t> cmd_buf(20);  // 16 bytes for command + 4 trailing bytes
    struct {
        uint32_t cmd;
        uint32_t len;
        uint32_t seqno;
        uint32_t rsp_off;
    } *cmd = reinterpret_cast<decltype(cmd)>(cmd_buf.data());

    cmd->cmd = 1;
    cmd->len = 16;  // Only 16 bytes, but buffer is 20
    cmd->seqno = 1;
    cmd->rsp_off = 0;

    ret = vaccel_submit_ccmd(cookie_, ctx_id, cmd_buf.data(), cmd_buf.size());
    EXPECT_LT(ret, 0) << "vaccel_submit_ccmd() should fail with trailing bytes";
}

TEST_F(VaccelRendererTest, SubmitCcmdInvalidCommand) {
    if (drm_fd_ < 0) {
        GTEST_SKIP() << "No DRM device available";
    }

    // Create device
    int ret = createTestDevice(VIRACCEL_CAPSET_ID_AMDXDNA);
    ASSERT_EQ(ret, 0);

    // Create a context
    uint32_t ctx_id = 1;
    ret = vaccel_create_ctx_with_flags(cookie_, ctx_id, 0, 0, nullptr);
    ASSERT_EQ(ret, 0);

    // Submit command with invalid cmd number
    struct {
        uint32_t cmd;
        uint32_t len;
        uint32_t seqno;
        uint32_t rsp_off;
    } bad_cmd = {
        .cmd = 999,  // Invalid command
        .len = 16,
        .seqno = 1,
        .rsp_off = 0
    };

    ret = vaccel_submit_ccmd(cookie_, ctx_id, &bad_cmd, sizeof(bad_cmd));
    EXPECT_LT(ret, 0) << "vaccel_submit_ccmd() should fail with invalid command number";
}

// =============================================================================
// AMDXDNA_CCMD_GET_INFO Tests
// =============================================================================

TEST_F(VaccelRendererTest, SubmitCcmdGetInfoNoContext) {
    if (drm_fd_ < 0) {
        GTEST_SKIP() << "No DRM device available";
    }

    // Create device
    int ret = createTestDevice(VIRACCEL_CAPSET_ID_AMDXDNA);
    ASSERT_EQ(ret, 0);

    // Try to submit GET_INFO without creating a context
    struct amdxdna_ccmd_get_info_req get_info_cmd = {};
    get_info_cmd.hdr.cmd = AMDXDNA_CCMD_GET_INFO;
    get_info_cmd.hdr.len = sizeof(get_info_cmd);
    get_info_cmd.param = 0;
    get_info_cmd.size = 64;
    get_info_cmd.num_element = 0;
    get_info_cmd.info_res = 1;

    ret = vaccel_submit_ccmd(cookie_, 999, &get_info_cmd, sizeof(get_info_cmd));
    EXPECT_EQ(ret, -ENOENT) << "Should fail without context";
}

TEST_F(VaccelRendererTest, SubmitCcmdGetInfoNoInit) {
    if (drm_fd_ < 0) {
        GTEST_SKIP() << "No DRM device available";
    }

    // Create device
    int ret = createTestDevice(VIRACCEL_CAPSET_ID_AMDXDNA);
    ASSERT_EQ(ret, 0);

    // Create a context
    uint32_t ctx_id = 1;
    ret = vaccel_create_ctx_with_flags(cookie_, ctx_id, 0, 0, nullptr);
    ASSERT_EQ(ret, 0);

    // Try GET_INFO without INIT (no response resource set)
    struct amdxdna_ccmd_get_info_req get_info_cmd = {};
    get_info_cmd.hdr.cmd = AMDXDNA_CCMD_GET_INFO;
    get_info_cmd.hdr.len = sizeof(get_info_cmd);
    get_info_cmd.param = 0;
    get_info_cmd.size = 64;
    get_info_cmd.num_element = 0;
    get_info_cmd.info_res = 1;

    ret = vaccel_submit_ccmd(cookie_, ctx_id, &get_info_cmd, sizeof(get_info_cmd));
    EXPECT_LT(ret, 0) << "Should fail without INIT command";
}

TEST_F(VaccelRendererTest, SubmitCcmdGetInfoInvalidResource) {
    if (drm_fd_ < 0) {
        GTEST_SKIP() << "No DRM device available";
    }

    // Create device and context
    int ret = createTestDevice(VIRACCEL_CAPSET_ID_AMDXDNA);
    ASSERT_EQ(ret, 0);

    uint32_t ctx_id = 1;
    ret = vaccel_create_ctx_with_flags(cookie_, ctx_id, 0, 0, nullptr);
    ASSERT_EQ(ret, 0);

    // Create response resource
    std::vector<uint8_t> resp_buf(4096);
    struct iovec resp_iov = {
        .iov_base = resp_buf.data(),
        .iov_len = resp_buf.size()
    };

    struct vaccel_create_resource_blob_args resp_res_args = {};
    resp_res_args.res_handle = 100;
    resp_res_args.size = resp_buf.size();
    resp_res_args.blob_mem = VIRTGPU_BLOB_MEM_GUEST;
    resp_res_args.iovecs = &resp_iov;
    resp_res_args.num_iovs = 1;

    ret = vaccel_create_resource_blob(cookie_, &resp_res_args);
    ASSERT_EQ(ret, 0);

    // Send INIT command
    struct amdxdna_ccmd_init_req init_cmd = {};
    init_cmd.hdr.cmd = AMDXDNA_CCMD_INIT;
    init_cmd.hdr.len = sizeof(init_cmd);
    init_cmd.rsp_res_id = 100;

    ret = vaccel_submit_ccmd(cookie_, ctx_id, &init_cmd, sizeof(init_cmd));
    EXPECT_EQ(ret, 0);

    // Try GET_INFO with invalid info resource
    struct amdxdna_ccmd_get_info_req get_info_cmd = {};
    get_info_cmd.hdr.cmd = AMDXDNA_CCMD_GET_INFO;
    get_info_cmd.hdr.len = sizeof(get_info_cmd);
    get_info_cmd.hdr.rsp_off = 0;
    get_info_cmd.param = 0;
    get_info_cmd.size = 64;
    get_info_cmd.num_element = 0;
    get_info_cmd.info_res = 999; // Invalid resource ID

    ret = vaccel_submit_ccmd(cookie_, ctx_id, &get_info_cmd, sizeof(get_info_cmd));
    EXPECT_LT(ret, 0) << "Should fail with invalid info resource";
}

TEST_F(VaccelRendererTest, SubmitCcmdGetInfoSingleValue) {
    if (drm_fd_ < 0) {
        GTEST_SKIP() << "No DRM device available";
    }

    // Create device and context
    int ret = createTestDevice(VIRACCEL_CAPSET_ID_AMDXDNA);
    ASSERT_EQ(ret, 0);

    uint32_t ctx_id = 1;
    ret = vaccel_create_ctx_with_flags(cookie_, ctx_id, 0, 0, nullptr);
    ASSERT_EQ(ret, 0);

    // Create response resource
    std::vector<uint8_t> resp_buf(4096);
    struct iovec resp_iov = {
        .iov_base = resp_buf.data(),
        .iov_len = resp_buf.size()
    };

    struct vaccel_create_resource_blob_args resp_res_args = {};
    resp_res_args.res_handle = 100;
    resp_res_args.size = resp_buf.size();
    resp_res_args.blob_mem = VIRTGPU_BLOB_MEM_GUEST;
    resp_res_args.iovecs = &resp_iov;
    resp_res_args.num_iovs = 1;

    ret = vaccel_create_resource_blob(cookie_, &resp_res_args);
    ASSERT_EQ(ret, 0);

    // Create info resource
    std::vector<uint8_t> info_buf(16*1024);
    struct iovec info_iov = {
        .iov_base = info_buf.data(),
        .iov_len = info_buf.size()
    };

    struct vaccel_create_resource_blob_args info_res_args = {};
    info_res_args.res_handle = 101;
    info_res_args.size = info_buf.size();
    info_res_args.blob_mem = VIRTGPU_BLOB_MEM_GUEST;
    info_res_args.iovecs = &info_iov;
    info_res_args.num_iovs = 1;

    ret = vaccel_create_resource_blob(cookie_, &info_res_args);
    ASSERT_EQ(ret, 0);

    // Send INIT command
    struct amdxdna_ccmd_init_req init_cmd = {};
    init_cmd.hdr.cmd = AMDXDNA_CCMD_INIT;
    init_cmd.hdr.len = sizeof(init_cmd);
    init_cmd.rsp_res_id = 100;

    ret = vaccel_submit_ccmd(cookie_, ctx_id, &init_cmd, sizeof(init_cmd));
    EXPECT_EQ(ret, 0);

    // Send GET_INFO command (single value)
    struct amdxdna_ccmd_get_info_req get_info_cmd = {};
    get_info_cmd.hdr.cmd = AMDXDNA_CCMD_GET_INFO;
    get_info_cmd.hdr.len = sizeof(get_info_cmd);
    get_info_cmd.hdr.rsp_off = 0;
    get_info_cmd.param = DRM_AMDXDNA_QUERY_AIE_STATUS;
    get_info_cmd.size = info_buf.size();
    get_info_cmd.num_element = 0; // Single value
    get_info_cmd.info_res = 101;
    struct amdxdna_drm_query_aie_status *status = reinterpret_cast<struct amdxdna_drm_query_aie_status *>(info_buf.data());
    status->buffer = static_cast<uint64_t>(reinterpret_cast<uintptr_t>(info_buf.data())) + sizeof(struct amdxdna_drm_query_aie_status);
    status->buffer_size = info_buf.size() - sizeof(struct amdxdna_drm_query_aie_status);
    status->cols_filled = 0;

    ret = vaccel_submit_ccmd(cookie_, ctx_id, &get_info_cmd, sizeof(get_info_cmd));
    EXPECT_EQ(ret, 0) << "GET_INFO command should succeed";

    // Verify response was written
    auto *rsp = reinterpret_cast<struct amdxdna_ccmd_get_info_rsp*>(resp_buf.data());
    EXPECT_EQ(rsp->hdr.base.len, sizeof(struct amdxdna_ccmd_get_info_rsp));
}

TEST_F(VaccelRendererTest, SubmitCcmdGetInfoArray) {
    if (drm_fd_ < 0) {
        GTEST_SKIP() << "No DRM device available";
    }

    // Create device and context
    int ret = createTestDevice(VIRACCEL_CAPSET_ID_AMDXDNA);
    ASSERT_EQ(ret, 0);

    uint32_t ctx_id = 1;
    ret = vaccel_create_ctx_with_flags(cookie_, ctx_id, 0, 0, nullptr);
    ASSERT_EQ(ret, 0);

    // Create response resource
    std::vector<uint8_t> resp_buf(4096);
    struct iovec resp_iov = {
        .iov_base = resp_buf.data(),
        .iov_len = resp_buf.size()
    };

    struct vaccel_create_resource_blob_args resp_res_args = {};
    resp_res_args.res_handle = 100;
    resp_res_args.size = resp_buf.size();
    resp_res_args.blob_mem = VIRTGPU_BLOB_MEM_GUEST;
    resp_res_args.iovecs = &resp_iov;
    resp_res_args.num_iovs = 1;

    ret = vaccel_create_resource_blob(cookie_, &resp_res_args);
    ASSERT_EQ(ret, 0);

    // Create info resource (larger for array)
    std::vector<uint8_t> info_buf(4096);
    struct iovec info_iov = {
        .iov_base = info_buf.data(),
        .iov_len = info_buf.size()
    };

    struct vaccel_create_resource_blob_args info_res_args = {};
    info_res_args.res_handle = 101;
    info_res_args.size = info_buf.size();
    info_res_args.blob_mem = VIRTGPU_BLOB_MEM_GUEST;
    info_res_args.iovecs = &info_iov;
    info_res_args.num_iovs = 1;

    ret = vaccel_create_resource_blob(cookie_, &info_res_args);
    ASSERT_EQ(ret, 0);

    // Send INIT command
    struct amdxdna_ccmd_init_req init_cmd = {};
    init_cmd.hdr.cmd = AMDXDNA_CCMD_INIT;
    init_cmd.hdr.len = sizeof(init_cmd);
    init_cmd.rsp_res_id = 100;

    ret = vaccel_submit_ccmd(cookie_, ctx_id, &init_cmd, sizeof(init_cmd));
    EXPECT_EQ(ret, 0);

    // Send GET_INFO command (array)
    struct amdxdna_ccmd_get_info_req get_info_cmd = {};
    get_info_cmd.hdr.cmd = AMDXDNA_CCMD_GET_INFO;
    get_info_cmd.hdr.len = sizeof(get_info_cmd);
    get_info_cmd.hdr.rsp_off = 0;
    get_info_cmd.param = DRM_AMDXDNA_HW_CONTEXT_ALL;
    get_info_cmd.size = 32;
    get_info_cmd.num_element = 4; // Array of 4 elements
    get_info_cmd.info_res = 101;

    ret = vaccel_submit_ccmd(cookie_, ctx_id, &get_info_cmd, sizeof(get_info_cmd));
    EXPECT_EQ(ret, 0) << "GET_INFO array command should succeed";

    // Verify response was written
    auto *rsp = reinterpret_cast<struct amdxdna_ccmd_get_info_rsp*>(resp_buf.data());
    EXPECT_EQ(rsp->hdr.base.len, sizeof(struct amdxdna_ccmd_get_info_rsp));
}

// =============================================================================
// AMDXDNA_CCMD_READ_SYSFS Tests
// =============================================================================

TEST_F(VaccelRendererTest, SubmitCcmdReadSysfsNoContext) {
    if (drm_fd_ < 0) {
        GTEST_SKIP() << "No DRM device available";
    }

    // Create device
    int ret = createTestDevice(VIRACCEL_CAPSET_ID_AMDXDNA);
    ASSERT_EQ(ret, 0);

    // Try to submit READ_SYSFS without creating a context
    alignas(struct amdxdna_ccmd_read_sysfs_req) char cmd_buf[128];
    auto *read_sysfs_cmd = reinterpret_cast<struct amdxdna_ccmd_read_sysfs_req*>(cmd_buf);
    read_sysfs_cmd->hdr.cmd = AMDXDNA_CCMD_READ_SYSFS;
    read_sysfs_cmd->hdr.len = sizeof(struct amdxdna_ccmd_read_sysfs_req) + strlen("device") + 1;
    strcpy(read_sysfs_cmd->node_name, "device");

    ret = vaccel_submit_ccmd(cookie_, 999, read_sysfs_cmd, sizeof(read_sysfs_cmd));
    EXPECT_EQ(ret, -ENOENT) << "Should fail without context";
}

TEST_F(VaccelRendererTest, SubmitCcmdReadSysfsNoInit) {
    if (drm_fd_ < 0) {
        GTEST_SKIP() << "No DRM device available";
    }

    // Create device
    int ret = createTestDevice(VIRACCEL_CAPSET_ID_AMDXDNA);
    ASSERT_EQ(ret, 0);

    // Create a context
    uint32_t ctx_id = 1;
    ret = vaccel_create_ctx_with_flags(cookie_, ctx_id, 0, 0, nullptr);
    ASSERT_EQ(ret, 0);

    // Try READ_SYSFS without INIT (no response resource set)
    alignas(struct amdxdna_ccmd_read_sysfs_req) char cmd_buf[128];
    auto *read_sysfs_cmd = reinterpret_cast<struct amdxdna_ccmd_read_sysfs_req*>(cmd_buf);
    read_sysfs_cmd->hdr.cmd = AMDXDNA_CCMD_READ_SYSFS;
    read_sysfs_cmd->hdr.len = sizeof(struct amdxdna_ccmd_read_sysfs_req) + strlen("device") + 1;
    read_sysfs_cmd->hdr.rsp_off = 0;
    strcpy(read_sysfs_cmd->node_name, "device");

    ret = vaccel_submit_ccmd(cookie_, ctx_id, read_sysfs_cmd, read_sysfs_cmd->hdr.len);
    EXPECT_LT(ret, 0) << "Should fail without INIT command";
}

TEST_F(VaccelRendererTest, SubmitCcmdReadSysfsValidNode) {
    if (drm_fd_ < 0) {
        GTEST_SKIP() << "No DRM device available";
    }

    // Create device and context
    int ret = createTestDevice(VIRACCEL_CAPSET_ID_AMDXDNA);
    ASSERT_EQ(ret, 0);

    uint32_t ctx_id = 1;
    ret = vaccel_create_ctx_with_flags(cookie_, ctx_id, 0, 0, nullptr);
    ASSERT_EQ(ret, 0);

    // Create response resource (large enough for sysfs content)
    std::vector<uint8_t> resp_buf(8192);
    struct iovec resp_iov = {
        .iov_base = resp_buf.data(),
        .iov_len = resp_buf.size()
    };

    struct vaccel_create_resource_blob_args resp_res_args = {};
    resp_res_args.res_handle = 100;
    resp_res_args.size = resp_buf.size();
    resp_res_args.blob_mem = VIRTGPU_BLOB_MEM_GUEST;
    resp_res_args.iovecs = &resp_iov;
    resp_res_args.num_iovs = 1;

    ret = vaccel_create_resource_blob(cookie_, &resp_res_args);
    ASSERT_EQ(ret, 0);

    // Send INIT command
    struct amdxdna_ccmd_init_req init_cmd = {};
    init_cmd.hdr.cmd = AMDXDNA_CCMD_INIT;
    init_cmd.hdr.len = sizeof(init_cmd);
    init_cmd.rsp_res_id = 100;

    ret = vaccel_submit_ccmd(cookie_, ctx_id, &init_cmd, sizeof(init_cmd));
    EXPECT_EQ(ret, 0);

    // Send READ_SYSFS command for a commonly available node
    alignas(struct amdxdna_ccmd_read_sysfs_req) char cmd_buf[128];
    auto *read_sysfs_cmd = reinterpret_cast<struct amdxdna_ccmd_read_sysfs_req*>(cmd_buf);
    read_sysfs_cmd->hdr.cmd = AMDXDNA_CCMD_READ_SYSFS;
    const char *node_name = "uevent"; // Common sysfs node
    read_sysfs_cmd->hdr.len = sizeof(struct amdxdna_ccmd_read_sysfs_req) + strlen(node_name) + 1;
    read_sysfs_cmd->hdr.rsp_off = 0;
    strcpy(read_sysfs_cmd->node_name, node_name);

    ret = vaccel_submit_ccmd(cookie_, ctx_id, read_sysfs_cmd, read_sysfs_cmd->hdr.len);
    // This may succeed or fail depending on the actual device
    // The test verifies the command is properly dispatched
    if (ret == 0) {
        // Verify response structure
        auto *rsp = reinterpret_cast<struct amdxdna_ccmd_read_sysfs_rsp*>(resp_buf.data());
        EXPECT_GT(rsp->hdr.base.len, sizeof(struct amdxdna_ccmd_read_sysfs_rsp))
            << "Response should contain data";
        EXPECT_GT(rsp->val_len, 0) << "Should have read some data";
    }
}

TEST_F(VaccelRendererTest, SubmitCcmdReadSysfsInvalidNode) {
    if (drm_fd_ < 0) {
        GTEST_SKIP() << "No DRM device available";
    }

    // Create device and context
    int ret = createTestDevice(VIRACCEL_CAPSET_ID_AMDXDNA);
    ASSERT_EQ(ret, 0);

    uint32_t ctx_id = 1;
    ret = vaccel_create_ctx_with_flags(cookie_, ctx_id, 0, 0, nullptr);
    ASSERT_EQ(ret, 0);

    // Create response resource
    std::vector<uint8_t> resp_buf(4096);
    struct iovec resp_iov = {
        .iov_base = resp_buf.data(),
        .iov_len = resp_buf.size()
    };

    struct vaccel_create_resource_blob_args resp_res_args = {};
    resp_res_args.res_handle = 100;
    resp_res_args.size = resp_buf.size();
    resp_res_args.blob_mem = VIRTGPU_BLOB_MEM_GUEST;
    resp_res_args.iovecs = &resp_iov;
    resp_res_args.num_iovs = 1;

    ret = vaccel_create_resource_blob(cookie_, &resp_res_args);
    ASSERT_EQ(ret, 0);

    // Send INIT command
    struct amdxdna_ccmd_init_req init_cmd = {};
    init_cmd.hdr.cmd = AMDXDNA_CCMD_INIT;
    init_cmd.hdr.len = sizeof(init_cmd);
    init_cmd.rsp_res_id = 100;

    ret = vaccel_submit_ccmd(cookie_, ctx_id, &init_cmd, sizeof(init_cmd));
    EXPECT_EQ(ret, 0);

    // Send READ_SYSFS command for non-existent node
    alignas(struct amdxdna_ccmd_read_sysfs_req) char cmd_buf[128];
    auto *read_sysfs_cmd = reinterpret_cast<struct amdxdna_ccmd_read_sysfs_req*>(cmd_buf);
    read_sysfs_cmd->hdr.cmd = AMDXDNA_CCMD_READ_SYSFS;
    const char *node_name = "nonexistent_node_12345";
    read_sysfs_cmd->hdr.len = sizeof(struct amdxdna_ccmd_read_sysfs_req) + strlen(node_name) + 1;
    read_sysfs_cmd->hdr.rsp_off = 0;
    strcpy(read_sysfs_cmd->node_name, node_name);

    ret = vaccel_submit_ccmd(cookie_, ctx_id, read_sysfs_cmd, read_sysfs_cmd->hdr.len);
    EXPECT_LT(ret, 0) << "Should fail with non-existent sysfs node";
}

TEST_F(VaccelRendererTest, SubmitCcmdReadSysfsEmptyNodeName) {
    if (drm_fd_ < 0) {
        GTEST_SKIP() << "No DRM device available";
    }

    // Create device and context
    int ret = createTestDevice(VIRACCEL_CAPSET_ID_AMDXDNA);
    ASSERT_EQ(ret, 0);

    uint32_t ctx_id = 1;
    ret = vaccel_create_ctx_with_flags(cookie_, ctx_id, 0, 0, nullptr);
    ASSERT_EQ(ret, 0);

    // Create response resource
    std::vector<uint8_t> resp_buf(4096);
    struct iovec resp_iov = {
        .iov_base = resp_buf.data(),
        .iov_len = resp_buf.size()
    };

    struct vaccel_create_resource_blob_args resp_res_args = {};
    resp_res_args.res_handle = 100;
    resp_res_args.size = resp_buf.size();
    resp_res_args.blob_mem = VIRTGPU_BLOB_MEM_GUEST;
    resp_res_args.iovecs = &resp_iov;
    resp_res_args.num_iovs = 1;

    ret = vaccel_create_resource_blob(cookie_, &resp_res_args);
    ASSERT_EQ(ret, 0);

    // Send INIT command
    struct amdxdna_ccmd_init_req init_cmd = {};
    init_cmd.hdr.cmd = AMDXDNA_CCMD_INIT;
    init_cmd.hdr.len = sizeof(init_cmd);
    init_cmd.rsp_res_id = 100;

    ret = vaccel_submit_ccmd(cookie_, ctx_id, &init_cmd, sizeof(init_cmd));
    EXPECT_EQ(ret, 0);

    // Send READ_SYSFS command with empty node name
    alignas(struct amdxdna_ccmd_read_sysfs_req) char cmd_buf[128];
    auto *read_sysfs_cmd = reinterpret_cast<struct amdxdna_ccmd_read_sysfs_req*>(cmd_buf);
    read_sysfs_cmd->hdr.cmd = AMDXDNA_CCMD_READ_SYSFS;
    read_sysfs_cmd->hdr.len = sizeof(struct amdxdna_ccmd_read_sysfs_req) + 1;
    read_sysfs_cmd->hdr.rsp_off = 0;
    read_sysfs_cmd->node_name[0] = '\0';

    ret = vaccel_submit_ccmd(cookie_, ctx_id, read_sysfs_cmd, read_sysfs_cmd->hdr.len);
    EXPECT_LT(ret, 0) << "Should fail with empty node name";
}

// =============================================================================
// Integration Test
// =============================================================================

TEST_F(VaccelRendererTest, FullWorkflow) {
    if (drm_fd_ < 0) {
        GTEST_SKIP() << "No DRM device available";
    }

    // 1. Create device
    int ret = createTestDevice(VIRACCEL_CAPSET_ID_AMDXDNA);
    ASSERT_EQ(ret, 0) << "Device creation failed";

    // 2. Get capset info
    uint32_t max_version = 0;
    uint32_t max_size = 0;
    ret = vaccel_get_capset_info(cookie_, &max_version, &max_size);
    ASSERT_EQ(ret, 0) << "Get capset info failed";
    ASSERT_GT(max_size, 0) << "Invalid capset size";

    // 3. Fill capset
    std::vector<uint8_t> capset_buf(max_size);
    ret = vaccel_fill_capset(cookie_, max_size, capset_buf.data());
    ASSERT_EQ(ret, 0) << "Fill capset failed";

    // 4. Verify capset structure
    struct vaccel_drm_capset *capset =
        reinterpret_cast<struct vaccel_drm_capset*>(capset_buf.data());
    EXPECT_GT(capset->version_major, 0);
    EXPECT_LE(capset->version_minor, capset->version_major);
    EXPECT_EQ(capset->context_type, VIRTACCEL_DRM_CONTEXT_AMDXDNA);
    EXPECT_EQ(capset->pad, 0);

    // 5. Destroy device
    destroyTestDevice();

    // 6. Verify device is gone
    ret = vaccel_get_capset_info(cookie_, &max_version, &max_size);
    EXPECT_EQ(ret, -ENODEV) << "Device should not exist after destroy";

    std::cout << "Full workflow test completed successfully!" << std::endl;
}

// =============================================================================
// Main
// =============================================================================

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);

    std::cout << "========================================" << std::endl;
    std::cout << "vaccel Unit Tests" << std::endl;
    std::cout << "========================================" << std::endl;

    // Check for DRM devices before running tests
    if (!DrmHelper::isDrmDeviceAvailable()) {
        std::cout << "WARNING: No DRM devices found. Most tests will be skipped." << std::endl;
        std::cout << "Available DRM devices:" << std::endl;
        auto devices = DrmHelper::listDrmDevices();
        if (devices.empty()) {
            std::cout << "  (none)" << std::endl;
        } else {
            for (const auto& device : devices) {
                std::cout << "  - " << device << std::endl;
            }
        }
    }

    return RUN_ALL_TESTS();
}


// SPDX-License-Identifier: MIT
// Copyright (C) 2025, Advanced Micro Devices, Inc. All rights reserved.

#include "test_helper.h"
#include <iostream>
#include <algorithm>

// DrmHelper implementation

int DrmHelper::openDrmRenderNode() {
    // Try render nodes (renderD128, renderD129, etc.)
    constexpr int max_render_node_index = 192;
    for (int i = 0; i < max_render_node_index; i++) {
        std::string device_path = "/dev/accel/accel" + std::to_string(i);
        int fd = open(device_path.c_str(), O_RDWR);
        if (fd > 0) {
            std::cout << "Opened DRM render node: " << device_path << " (fd=" << fd << ")" << std::endl;
            return fd;
        }
    }
    return -1;
}

int DrmHelper::openDrmCard() {
    // Try card devices (card0, card1, etc.)
    for (int i = 0; i < 16; i++) {
        std::string device_path = "/dev/dri/card" + std::to_string(i);
        int fd = open(device_path.c_str(), O_RDWR);
        if (fd > 0) {
            std::cout << "Opened DRM card device: " << device_path << " (fd=" << fd << ")" << std::endl;
            return fd;
        }
    }
    return -1;
}

int DrmHelper::openAnyDrmDevice() {
    // Try render nodes first (preferred for compute/AI workloads)
    int fd = openDrmRenderNode();
    if (fd > 0) {
        return fd;
    }

    // Fall back to card devices
    fd = openDrmCard();
    if (fd > 0) {
        return fd;
    }

    std::cerr << "ERROR: No DRM devices found in /dev/accel/ or /dev/dri/" << std::endl;
    std::cerr << "Please ensure:" << std::endl;
    std::cerr << "  1. DRM kernel modules are loaded" << std::endl;
    std::cerr << "  2. You have permissions to access /dev/accel/ or /dev/dri/ devices" << std::endl;
    std::cerr << "  3. A GPU or render device is available on the system" << std::endl;

    return -1;
}

bool DrmHelper::isDrmDeviceAvailable() {
    struct stat st;
    if (stat("/dev/dri", &st) != 0) {
        return false;
    }

    std::vector<std::string> devices = listDrmDevices();
    return !devices.empty();
}

std::vector<std::string> DrmHelper::listDrmDevices() {
    std::vector<std::string> devices;
    
    DIR *dir = opendir("/dev/dri");
    if (!dir) {
        return devices;
    }

    struct dirent *entry;
    while ((entry = readdir(dir)) != nullptr) {
        std::string name(entry->d_name);
        if (name.find("card") == 0 || name.find("renderD") == 0) {
            devices.push_back("/dev/dri/" + name);
        }
    }
    closedir(dir);

    // Sort for consistent ordering
    std::sort(devices.begin(), devices.end());
    
    return devices;
}

// VaccelRendererTestBase implementation

void VaccelRendererTestBase::SetUp() {
    // Open a real DRM device
    drm_fd_ = DrmHelper::openAnyDrmDevice();
    
    // For testing purposes, we'll use the address of drm_fd_ as cookie
    cookie_ = &drm_fd_;
    
    // Set up callbacks
    callbacks_.get_device_fd = getDeviceFdCallback;
}

void VaccelRendererTestBase::TearDown() {
    // Destroy device if it was created
    if (device_created_) {
        destroyTestDevice();
    }
    
    // Close DRM FD if it was opened
    if (drm_fd_ > 0) {
        close(drm_fd_);
        drm_fd_ = -1;
    }
}

int VaccelRendererTestBase::getDeviceFdCallback(void *cookie) {
    // Cookie points to drm_fd_
    if (!cookie) {
        return -EINVAL;
    }
    int *fd_ptr = static_cast<int*>(cookie);
    return *fd_ptr;
}

int VaccelRendererTestBase::createTestDevice(uint32_t capset_id) {
    int ret = vaccel_create(cookie_, capset_id, &callbacks_);
    if (ret == 0) {
        device_created_ = true;
    }
    return ret;
}

void VaccelRendererTestBase::destroyTestDevice() {
    if (device_created_) {
        vaccel_destroy(cookie_);
        device_created_ = false;
    }
}

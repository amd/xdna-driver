// SPDX-License-Identifier: MIT
// Copyright (C) 2025, Advanced Micro Devices, Inc. All rights reserved.

/*
 * Device Manager
 * Manages per-device instances with cookie-based lookup
 * C++ implementation using std::unordered_map
 */

#include "vaccel_internal.h"
#include "../util/vxdna_debug.h"

#include <unordered_map>
#include <cerrno>
#include <cstring>

#ifdef __unix__
#include <unistd.h>
#endif

#include "vaccel_amdxdna.h"

void *
vaccel_resource::
mmap(int fd)
{
    if (m_map_addr)
        VACCEL_THROW_MSG(-EINVAL, "Resource already mapped");
    vxdna_dbg("vaccel_resource::mmap: res_id=%u, fd=%d, ctx_id=%u, size=%zu", m_res_id, fd, m_ctx_id, m_size);
    m_map_addr = ::mmap(NULL, m_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (m_map_addr == MAP_FAILED)
        VACCEL_THROW_MSG(-errno, "Failed to mmap resource: errno %d, %s", errno, strerror(errno));
    m_map_info = 1; // TODO:Used by linux kernel virtio-gpu driver vram, to set pgprot for mapping
                  // 1 is for CACHED
    return m_map_addr;
}

/* Global device table: cookie -> shared_ptr<vaccel> */
static vaccel_map<void*, std::shared_ptr<vxdna>> device_table;

/**
 * @brief Add a device to the global device table
 *
 * @param device Shared pointer to device (moved into table)
 * @return 0 on success, negative errno on failure
 */
static void
vaccel_add(std::shared_ptr<vxdna>&& device)
{
    void *cookie = device->get_cookie();
    device_table.insert(cookie, std::move(device));
}

/**
 * @brief Remove a device from the global device table
 *
 * @param cookie Device cookie
 */
static void
vaccel_remove(void *cookie)
{
    device_table.erase(cookie);
}

/**
 * @brief Look up a device by its cookie
 *
 * @param cookie Device cookie
 * @return Shared pointer to device if found, nullptr otherwise
 */
static std::shared_ptr<vxdna>
vaccel_lookup(void *cookie)
{
    return device_table.lookup(cookie);
}

/**
 * @brief Calculate the total size of an array of iovecs
 *
 * @param iovecs Pointer to array of struct iovec
 * @param num_iovs Number of elements in the iovecs array
 * @return Total number of bytes in all iovecs
 */
static size_t
_vaccel_get_iovec_size(const struct iovec *iovecs, uint32_t num_iovs)
{
    size_t total = 0;
    if (!iovecs || num_iovs == 0)
        return 0;
    for (uint32_t i = 0; i < num_iovs; ++i) {
        total += iovecs[i].iov_len;
    }
    return total;
}

static void
_vaccel_create_resource_blob(void *cookie, const struct vaccel_create_resource_blob_args *args)
{
    if (!cookie)
        VACCEL_THROW_MSG(-EINVAL, "Cookie is nullptr");

    auto device = vaccel_lookup(cookie);
    if (!device)
        VACCEL_THROW_MSG(-ENODEV, "Device not found for cookie %p", cookie);

    /* user resource id must be greater than 0 */
    if (args->res_handle == 0)
        VACCEL_THROW_MSG(-EINVAL, "Resource handle must be greater than 0");
    /* user resource id must be unique */
    if (device->get_resource(args->res_handle))
        VACCEL_THROW_MSG(-EINVAL, "Resource handle must be unique, %u already exists", args->res_handle);

    if (args->size == 0)
        VACCEL_THROW_MSG(-EINVAL, "Resource blob size must be greater than 0, size=%zu", args->size);

    if (args->blob_mem == VIRTGPU_BLOB_MEM_GUEST) {
        const size_t iov_size = _vaccel_get_iovec_size(args->iovecs, args->num_iovs);
        if (iov_size < args->size)
            VACCEL_THROW_MSG(-EINVAL, "IO vector size is less than the blob size");
    
        device->create_resource(args);
    } else if (args->blob_mem == VIRTGPU_BLOB_MEM_HOST3D) {
        device->create_resource_from_blob(args);
    } else {
        VACCEL_THROW_MSG(-EINVAL, "Unsupported blob memory type: %u", args->blob_mem);
    }
}

static void
_vaccel_resource_map(void *cookie, uint32_t res_id, void** data, size_t* size)
{
    vxdna_dbg("resource map: res_id=%u, cookie=%p", res_id, cookie);
    if (!cookie)
        VACCEL_THROW_MSG(-EINVAL, "Cookie is nullptr");
    auto device = vaccel_lookup(cookie);
    if (!device)
        VACCEL_THROW_MSG(-ENODEV, "Device not found for cookie %p", cookie);
    auto fd = device->export_resource_fd(res_id);
    if (fd < 0)
        VACCEL_THROW_MSG(-EINVAL, "Export resource fd failed ret %d, errno %d, %s", fd, errno, strerror(errno));
    auto res = device->get_resource(res_id);
    if (!res) {
        close(fd);
        VACCEL_THROW_MSG(-ENOENT, "Resource handle %u not found", res_id);
    }
    *data = res->mmap(fd);
    *size = res->get_size();
    close(fd);
}

static void
_vaccel_resource_unmap(void *cookie, uint32_t res_id)
{
    if (!cookie)
        VACCEL_THROW_MSG(-EINVAL, "Cookie is nullptr");
    auto device = vaccel_lookup(cookie);
    if (!device)
        VACCEL_THROW_MSG(-ENODEV, "Device not found for cookie %p", cookie);
    auto res = device->get_resource(res_id);
    if (!res)
        VACCEL_THROW_MSG(-ENOENT, "Resource handle %u not found", res_id);
    res->munmap();
}

static void
_vaccel_resource_get_map_info(void *cookie, uint32_t res_id, uint32_t *map_info)
{
    if (!map_info)
        VACCEL_THROW_MSG(-EINVAL, "Map info is nullptr");
    if (!cookie)
        VACCEL_THROW_MSG(-EINVAL, "Cookie is nullptr");
    auto device = vaccel_lookup(cookie);
    if (!device)
        VACCEL_THROW_MSG(-ENODEV, "Device not found for cookie %p", cookie);
    auto res = device->get_resource(res_id);
    if (!res)
        VACCEL_THROW_MSG(-ENOENT, "Resource handle %u not found", res_id);
    *map_info = res->get_map_info();
}

static void
_vaccel_detach_resource_blob(void *cookie, uint32_t res_handle,
                             struct iovec **iovecs_out, uint32_t *num_iovs_out)
{
    if (!cookie)
        VACCEL_THROW_MSG(-EINVAL, "Cookie is nullptr");

    // Lookup the device
    auto device = vaccel_lookup(cookie);
    if (!device)
        VACCEL_THROW_MSG(-ENODEV, "Device not found for cookie %p", cookie);

    // Lookup the resource.
    auto resource = device->get_resource(res_handle);
    if (!resource)
        VACCEL_THROW_MSG(-ENOENT, "Resource handle %u not found", res_handle);

    const struct iovec *iovecs;
    auto num_iovs = resource->get_iovecs(&iovecs);
    *iovecs_out = const_cast<struct iovec *>(iovecs);
    *num_iovs_out = num_iovs;
}

static void
_vaccel_destroy_resource_blob(void *cookie, uint32_t res_handle)
{
    if (!cookie)
        VACCEL_THROW_MSG(-EINVAL, "Cookie is nullptr");
    auto device = vaccel_lookup(cookie);
    if (!device)
        VACCEL_THROW_MSG(-ENODEV, "Device not found for cookie %p", cookie);
    device->destroy_resource(res_handle);
}

static void
_vaccel_submit_fence(void *cookie, uint32_t ctx_id, uint32_t flags,
                     uint32_t ring_idx, uint64_t fence_id)
{
    if (!cookie)
        VACCEL_THROW_MSG(-EINVAL, "Cookie is nullptr");
    auto device = vaccel_lookup(cookie);
    if (!device)
        VACCEL_THROW_MSG(-ENODEV, "Device not found for cookie %p", cookie);
    device->submit_fence(ctx_id, flags, ring_idx, fence_id);
}

static void
_vaccel_submit_ccmd(void *cookie, uint32_t ctx_id, const void *ccmd, uint32_t ccmd_size)
{
    if (!ccmd_size)
        VACCEL_THROW_MSG(-EINVAL, "Command buffer size is 0");
    if (!ccmd)
        VACCEL_THROW_MSG(-EINVAL, "Command buffer is nullptr");
    if (!cookie)
        VACCEL_THROW_MSG(-EINVAL, "Cookie is nullptr");
    if (ccmd_size & 3)
        VACCEL_THROW_MSG(-EINVAL, "Command buffer size is not aligned to 4 bytes");
    auto device = vaccel_lookup(cookie);
    if (!device)
        VACCEL_THROW_MSG(-ENODEV, "Device not found for cookie %p", cookie);
    auto ctx = device->get_ctx(ctx_id);
    if (!ctx)
        VACCEL_THROW_MSG(-ENOENT, "Context not found: ctx_id=%u", ctx_id);

    const uint8_t *buf = static_cast<const uint8_t *>(ccmd);
    uint32_t alignment = ctx->get_ccmd_align();

    vxdna_dbg("Submitting command buffer: ctx_id=%u, size=%u", ctx->get_id(), ccmd_size);

    while (ccmd_size >= sizeof(struct vdrm_ccmd_req)) {
        const struct vdrm_ccmd_req *hdr = reinterpret_cast<const struct vdrm_ccmd_req *>(buf);

        /* Sanity check first: */
        if ((hdr->len > ccmd_size) || (hdr->len < sizeof(*hdr)) || (hdr->len & (alignment - 1)))
            VACCEL_THROW_MSG(-EINVAL, "bad size, %u vs %u (cmd %u, min alignment %u)",
                             hdr->len, ccmd_size, hdr->cmd, alignment);

        if (hdr->rsp_off & (alignment - 1))
            VACCEL_THROW_MSG(-EINVAL, "bad rsp_off, %u, min alignment %u",
                            hdr->rsp_off, alignment);

        device->dispatch_ccmd(ctx, hdr);

        buf += hdr->len;
        ccmd_size -= hdr->len;
    }

    if (ccmd_size > 0)
        VACCEL_THROW_MSG(-EINVAL, "bad size, %u trailing bytes", ccmd_size);
}

static void
_vaccel_get_capset_info(void *cookie, uint32_t *max_version, uint32_t *max_size)
{
    vxdna_dbg("Getting capset info for cookie=%p", cookie);

    if (!cookie)
        VACCEL_THROW_MSG(-EINVAL, "Cookie is nullptr");

    /* Lookup device by cookie */
    auto device = vaccel_lookup(cookie);
    if (!device)
        VACCEL_THROW_MSG(-ENODEV, "Device not found for cookie %p", cookie);

    /* Validate capset ID */
    auto capset_id = device->get_capset_id();
    if (capset_id != VIRACCEL_CAPSET_ID_AMDXDNA)
        VACCEL_THROW_MSG(-ENOTSUP, "Unsupported capset ID: %u (expected %u)",
                         capset_id, VIRACCEL_CAPSET_ID_AMDXDNA);

    /* Return max version if requested */
    device->get_capset_info(max_version, max_size);

    vxdna_info("Capset info retrieved successfully for capset_id=%u", capset_id);
}

static void
_vaccel_fill_capset(void *cookie, uint32_t capset_size, void *capset_buf)
{
    vxdna_dbg("Filling capset for cookie=%p, capset_size=%u", cookie, capset_size);

    if (!cookie)
        VACCEL_THROW_MSG(-EINVAL, "Cookie is nullptr");
        
    if (!capset_buf)
        VACCEL_THROW_MSG(-EINVAL, "Capset buffer is nullptr");

    /* Lookup device by cookie */
    auto device = vaccel_lookup(cookie);
    if (!device)
        VACCEL_THROW_MSG(-ENODEV, "Device not found for cookie %p", cookie);

    device->fill_capset(capset_size, capset_buf);
}

static void
_vaccel_create_ctx_with_flags(void *cookie, uint32_t ctx_id, uint32_t ctx_flags,
                              uint32_t nlen, const char *name)
{
    vxdna_dbg("Creating execution ctx: cookie=%p, ctx_id=%u, flags=0x%x, nlen=%u, name=%s",
              cookie, ctx_id, ctx_flags, nlen, name ? name : "(null)");

    if (!cookie)
        VACCEL_THROW_MSG(-EINVAL, "Cookie is nullptr");

    // Lookup device
    auto device = vaccel_lookup(cookie);
    if (!device)
        VACCEL_THROW_MSG(-ENODEV, "Device not found for cookie %p", cookie);

    // Delegate to device method to create context
    device->create_ctx(ctx_id, ctx_flags, nlen, name);

    vxdna_dbg("Execution context created successfully: ctx_id=%u (device %p)", ctx_id, cookie);
}

static void
_vaccel_destroy_ctx(void *cookie, uint32_t ctx_id)
{
    vxdna_dbg("Destroying execution ctx: cookie=%p, ctx_id=%u", cookie, ctx_id);
    if (!cookie)
        VACCEL_THROW_MSG(-EINVAL, "Cookie is nullptr");
    auto device = vaccel_lookup(cookie);
    if (!device)
        VACCEL_THROW_MSG(-ENODEV, "Device not found for cookie %p", cookie);
    device->destroy_ctx(ctx_id);
}

static void
_vaccel_device_create(void *cookie, uint32_t capset_id,
                      const struct vaccel_callbacks *callbacks)
{
    if (!cookie)
        VACCEL_THROW_MSG(-EINVAL, "Cookie is nullptr");

    if (capset_id != VIRACCEL_CAPSET_ID_AMDXDNA)
        VACCEL_THROW_MSG(-EINVAL, "Unsupported capset ID: %u", capset_id);

    /* Check if device already exists */
    if (vaccel_lookup(cookie))
        VACCEL_THROW_MSG(-EEXIST, "Device already exists for cookie %p", cookie);

    if (!callbacks)
        VACCEL_THROW_MSG(-EINVAL, "Callbacks are nullptr");

    /* Create device as shared_ptr */
    auto device = std::make_shared<vxdna>(cookie, capset_id, callbacks);

    if (!callbacks->get_device_fd)
        VACCEL_THROW_MSG(-EINVAL, "get_device_fd callback is nullptr");

    int drm_fd = callbacks->get_device_fd(cookie);
    if (drm_fd <= 0)
        VACCEL_THROW_MSG(drm_fd, "Invalid device file descriptor");

    device->set_drm_fd(drm_fd);
    /* Add to global table (moves shared_ptr into map) */
    vaccel_add(std::move(device));

    vxdna_info("Device created successfully: cookie=%p, capset_id=%u",
               cookie, capset_id);
}

static void
_vaccel_device_destroy(void *cookie)
{
    if (!vaccel_lookup(cookie))
        return;

    /* Remove from global table (automatically calls destructor) */
    vaccel_remove(cookie);
}

/**
 * @defgroup vaccel_device_mgmt External Device Management API
 * @brief External APIs for vaccel device management.
 *
 * This group provides interface functions to query device capability set information,
 * create a vaccel device instance, and destroy a vaccel device instance.
 * @{
 */

int
vaccel_create_resource_blob(void *cookie, const struct vaccel_create_resource_blob_args *args)
{
    return vaccel_error_wrap("vaccel_create_resource_blob", [&]() {
        _vaccel_create_resource_blob(cookie, args);
    });
}

int vaccel_resource_map(void *cookie, uint32_t res_id, void** data, size_t* size)
{
    return vaccel_error_wrap("vaccel_resource_map", [&]()-> void {
        _vaccel_resource_map(cookie, res_id, data, size);
    });
}

int vaccel_resource_unmap(void *cookie, uint32_t res_id)
{
    return vaccel_error_wrap("vaccel_resource_unmap", [&]() -> void {
        _vaccel_resource_unmap(cookie, res_id);
    });
}   

int vaccel_resource_get_map_info(void *cookie, uint32_t res_id, uint32_t *map_info)
{
    return vaccel_error_wrap("vaccel_resource_get_map_info", [&]() {
        _vaccel_resource_get_map_info(cookie, res_id, map_info);
    });
}

int
vaccel_detach_resource_blob(void *cookie, uint32_t res_handle,
                            struct iovec **iovecs_out, uint32_t *num_iovs_out)
{
    return vaccel_error_wrap("vaccel_detach_resource_blob", [&]() {
        _vaccel_detach_resource_blob(cookie, res_handle, iovecs_out, num_iovs_out);
    });
}

int
vaccel_destroy_resource_blob(void *cookie, uint32_t res_handle)
{
    return vaccel_error_wrap("vaccel_destroy_resource_blob", [&]() {
        _vaccel_destroy_resource_blob(cookie, res_handle);
    });
}

int vaccel_detach_destroy_resource_blob(void *cookie, uint32_t res_handle,
                                        struct iovec **iovecs_out, uint32_t *num_iovs_out)
{
    return vaccel_error_wrap("vaccel_detach_destroy_resource_blob", [&]() {
        _vaccel_detach_resource_blob(cookie, res_handle, iovecs_out, num_iovs_out);
        _vaccel_destroy_resource_blob(cookie, res_handle);
    });
}

int vaccel_submit_fence(void *cookie, uint32_t ctx_id, uint32_t flags,
                        uint32_t ring_idx, uint64_t fence_id)
{
    return vaccel_error_wrap("vaccel_submit_fence", [&]() {
        _vaccel_submit_fence(cookie, ctx_id, flags, ring_idx, fence_id);
    });
}

int vaccel_submit_ccmd(void *cookie, uint32_t ctx_id, const void *ccmd, uint32_t ccmd_size)
{
    return vaccel_error_wrap("vaccel_submit_ccmd", [&]() {
        _vaccel_submit_ccmd(cookie, ctx_id, ccmd, ccmd_size);
    });
}

int
vaccel_get_capset_info(void *cookie,
                       uint32_t *max_version, uint32_t *max_size)
{
    return vaccel_error_wrap("vaccel_get_capset_info", [&]() {
        return _vaccel_get_capset_info(cookie, max_version, max_size);
    });
}

int vaccel_fill_capset(void *cookie, uint32_t capset_size, void *capset_buf)
{
    return vaccel_error_wrap("vaccel_fill_capset", [&]() {
        return _vaccel_fill_capset(cookie, capset_size, capset_buf);
    });
}

int vaccel_create_ctx_with_flags(void *cookie, uint32_t ctx_id, uint32_t ctx_flags,
                                 uint32_t nlen, const char *name)
{
    return vaccel_error_wrap("vaccel_create_ctx_with_flags", [&]() {
        _vaccel_create_ctx_with_flags(cookie, ctx_id, ctx_flags, nlen, name);
    });
}

void vaccel_destroy_ctx(void *cookie, uint32_t ctx_id)
{
    (void)vaccel_error_wrap("vaccel_destroy_ctx", [&]() {
        _vaccel_destroy_ctx(cookie, ctx_id);
    });
}

int
vaccel_create(void *cookie, uint32_t capset_id, const struct vaccel_callbacks *callbacks)
{
    return vaccel_error_wrap("vaccel_create", [&]() {
        _vaccel_device_create(cookie, capset_id, callbacks);
    });
}

void
vaccel_destroy(void *cookie)
{
    (void)vaccel_error_wrap("vaccel_destroy", [&]() {
        _vaccel_device_destroy(cookie);
    });
}

/** @} */ /* end of vaccel_device_mgmt */

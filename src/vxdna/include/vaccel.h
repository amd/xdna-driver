// SPDX-License-Identifier: MIT
// Copyright (C) 2025, Advanced Micro Devices, Inc. All rights reserved.

/**
 * @file vaccelh
 * @brief virtual accelerator host backend library public API
 *
 * Multi-device with cookie-based device management, per-device
 * lookup tables for resources, contexts, and fences.
 */

#ifndef VACCEL_H
#define VACCEL_H

#include <stdint.h>
#include <stddef.h>
#include <drm/virtgpu_drm.h>

#ifdef __cplusplus
extern "C" {
#endif

struct iovec; // from Linux, iovec is defined in <linux/fs.h>

struct vaccel_create_resource_blob_args
{
    uint32_t res_handle; /**< Resource handle */
    uint32_t ctx_id; /**< Context ID */
    uint32_t blob_mem; /**< Blob memory type */
    uint32_t blob_flags; /**< Blob flags */
    uint64_t blob_id; /**< Blob ID */
    uint64_t size; /**< Blob size */
    const struct iovec *iovecs; /**< IO vectors */
    uint32_t num_iovs; /**< Number of IO vectors */
};

/**
 * @brief Virtio vaccel capset identifiers enumeration
 */
enum viraccel_capset_id {
    VIRACCEL_CAPSET_ID_AMDXDNA = 0, /**< AMD XDNA virtio capset identifier */
    VIRACCEL_CAPSET_ID_MAX = 1,    /**< Maximum supported capset identifier */
};

/**
 * @brief Virtio vaccel context type enumeration
 */
enum virtaccel_context_type {
    VIRTACCEL_DRM_CONTEXT_MSM = 1,
    VIRTACCEL_DRM_CONTEXT_AMDGPU = 2,
    VIRTACCEL_DRM_CONTEXT_AMDXDNA = 3,
};

/**
 * @brief Callback functions structure
 *
 * User-provided callback functions for vaccel operations.
 * This allows customization of device access and other operations.
 */
struct vaccel_callbacks {
    /**
     * @brief Get device file descriptor from cookie
     *
     * Called to retrieve a device file descriptor associated with a given cookie.
     * This callback is invoked:
     * - Once during device creation (stored as device FD)
     * - Once per context creation (stored as context FD)
     *
     * **IMPORTANT: FD Ownership Semantics**
     *
     * The callback MUST return a newly dup()'d file descriptor on each call.
     * The vaccel library takes ownership of the returned FD and will close() it:
     * - Device FD: closed in ~vaccel() destructor
     * - Context FD: closed in context destructor
     *
     * If the same FD is returned multiple times, the first close() will
     * invalidate the FD for all other contexts, causing undefined behavior.
     *
     * Example implementation:
     * @code
     * int my_get_device_fd(void *cookie) {
     *     int original_fd = get_original_fd(cookie);
     *     return dup(original_fd);  // MUST return dup'd FD
     * }
     * @endcode
     *
     * @param cookie Device cookie
     * @return Newly dup()'d file descriptor on success, negative errno on failure
     */
    int (*get_device_fd)(void *cookie);
    /**
     * @brief Write context fence to device, referring to virglrenderer fence write function
     *
     * Per-context fences signal in creation order only within a context.
     * Two per-context fences in two contexts might signal in any order.
     *
     * When a per-context fence is created, a fence cookie can be specified. The
     * cookie will be passed to write_context_fence callback. This replaces
     * fence_id that is used in ctx0 fencing.
     *
     * write_context_fence is called on each fence unless the fence has
     * VACCEL_FENCE_FLAG_MERGEABLE set. When the bit is set,
     * write_context_fence might be skipped.
     *
     * @param cookie Device cookie
     * @param ctx_id Context ID to write the fence to
     * @param ring_idx Hardware/software ring index to associate the fence with
     * @param fence_id Fence ID to write
     */
    void (*write_context_fence)(void *cookie, uint32_t ctx_id, uint32_t ring_idx, uint64_t fence_id);
};

/**
 * @brief Create a device with a given cookie
 *
 * Creates a new device instance identified by a unique cookie.
 * The cookie is typically a DRM file descriptor or device handle.
 *
 * @param cookie Unique device identifier (e.g., DRM FD, device handle)
 * @param capset_id Capability set ID (e.g., VIRACCEL_CAPSET_ID_AMDXDNA)
 * @param callbacks Optional callbacks structure (can be NULL for default behavior)
 * @return 0 on success, negative errno on failure
 * @retval 0 Success
 * @retval -EINVAL Invalid arguments or device not initialized
 * @retval -EEXIST Device with this cookie already exists
 * @retval -ENOMEM Out of memory
 */
int vaccel_create(void *cookie, uint32_t capset_id, const struct vaccel_callbacks *callbacks);

/**
 * @brief Destroy a device
 *
 * Destroys a device and all associated resources, contexts, and fences.
 *
 * @param cookie Device cookie
 */
void vaccel_destroy(void *cookie);

/**
 * @brief Get virtio vaccel capset information
 *
 * Retrieves capability set information for the specified capset ID.
 * This includes the maximum supported version and maximum size of the capset.
 *
 * @param cookie Device cookie
 * @param[out] max_version Maximum supported capset version (can be NULL)
 * @param[out] max_size Maximum capset size in bytes (can be NULL)
 * @return 0 on success, negative errno on failure
 */
int vaccel_get_capset_info(void *cookie, uint32_t *max_version, uint32_t *max_size);

/**
 * @brief Fill capset structure with capability set data
 *
 * Copies the full capability set structure into the provided buffer.
 * The buffer must be large enough to hold the complete capset data.
 *
 * @param cookie Device cookie
 * @param capset_size Size of the provided buffer in bytes
 * @param[out] capset_buf Buffer to receive capset data
 * @return 0 on success, negative errno on failure
 */
int vaccel_fill_capset(void *cookie, uint32_t capset_size, void *capset_buf);

/**
 * @brief Create a new execution ctx
 *
 * Creates a new ctx associated with the given device cookie, with specified
 * ctx ID, flags, and optional debug name for tracing or debugging purposes.
 *
 * @param cookie Device cookie
 * @param ctx_id 32-bit ctx identifier (unique per ctx)
 * @param ctx_flags 32-bit flags (behavioral/ctx creation options)
 * @param nlen Optional, length of debug name in bytes (can be 0 if not provided)
 * @param name Optional, pointer to C-style string used as a debug name (can be NULL)
 * @return 0 on success, negative errno on failure
 */
int vaccel_create_ctx_with_flags(void *cookie, uint32_t ctx_id, uint32_t ctx_flags,
                                 uint32_t nlen, const char *name);

/**
 * @brief Destroy a context
 *
 * Destroys a context and all associated resources, fences, and other resources.
 *
 * @param cookie Device cookie
 * @param ctx_id Context ID to destroy
 */
void vaccel_destroy_ctx(void *cookie, uint32_t ctx_id);

/**
 * @brief Create a resource blob
 *
 * Allocates a new resource (buffer object/blob) associated with the given device.
 * The resource is uniquely identified by a resource handle, and must be created
 * with a valid handle and size. The contents and location are specified by IOVs,
 * which must collectively be at least as large as the requested blob size.
 *
 * @param cookie Device cookie
 * @param args Pointer to vaccel_create_resource_blob_args structure describing
 *             the resource to be created. Must include handle, size, flags,
 *             and IO vector array.
 * @return 0 on success, negative errno on failure
 */
int vaccel_create_resource_blob(void *cookie, const struct vaccel_create_resource_blob_args *args);

/**
 * @brief Detach a resource from the device and return its IO vector table
 *
 * Removes the resource associated with the specified resource handle from the device,
 * and provides the caller with the base pointer to the resource's IO vector table,
 * along with the number of IO vectors.
 *
 * The caller must manage/lifetime of the returned IO vector table as appropriate.
 * On success, *iovecs_out will point to the resource's IO vector array and
 * *num_iovs_out will contain its count.
 *
 * @param cookie Device cookie
 * @param res_handle Resource handle to detach
 * @param[out] iovecs_out Pointer to receive IO vector array base pointer
 * @param[out] num_iovs_out Pointer to receive number of IO vectors
 * @return 0 on success, negative errno on failure
 */
int vaccel_detach_resource_blob(void *cookie, uint32_t res_handle,
                                struct iovec **iovecs_out, uint32_t *num_iovs_out);

/**
 * @brief Destroy a resource blob
 *
 * Frees the resource associated with the specified resource handle,
 * and releases the associated IO vector table.
 *
 * @param cookie Device cookie
 * @param res_handle Resource handle to destroy
 * @return 0 on success, negative errno on failure
 */
int vaccel_destroy_resource_blob(void *cookie, uint32_t res_handle);

/**
 * @brief Detach and destroy a resource blob
 *
 * Removes the resource associated with the specified resource handle from the device,
 * and provides the caller with the base pointer to the resource's IO vector table,
 * along with the number of IO vectors.
 *
 * @param cookie Device cookie
 * @param res_handle Resource handle to detach and destroy
 * @param[out] iovecs_out Pointer to receive IO vector array base pointer
 * @param[out] num_iovs_out Pointer to receive number of IO vectors
 * @return 0 on success, negative errno on failure
 */
int vaccel_detach_destroy_resource_blob(void *cookie, uint32_t res_handle,
                                        struct iovec **iovecs_out, uint32_t *num_iovs_out);

/**
 * @brief submit a fence for GPU command synchronization
 *
 * Creates a fence object associated with the specified context on the device.
 *
 * @param cookie Device cookie
 * @param ctx_id Context ID on which to create the fence
 * @param flags Fence creation flags (implementation-specific)
 * @param ring_idx Hardware/software ring index to associate the fence with
 * @param fence_id Pointer to receive the created fence ID
 * @return 0 on success, negative errno on failure
 */
 int vaccel_submit_fence(void *cookie, uint32_t ctx_id, uint32_t flags,
                         uint32_t ring_idx, uint64_t fence_id);

/**
 * @brief Submit a virtio GPU context command (ccmd)
 *
 * Submits a GPU context command buffer to the device associated with the provided cookie and context ID.
 *
 * @param cookie Device cookie
 * @param ctx_id Context ID to submit the command to
 * @param ccmd Pointer to the command buffer
 * @param ccmd_size Size of the command buffer, in bytes
 * @return 0 on success, negative errno on failure
 */
int vaccel_submit_ccmd(void *cookie, uint32_t ctx_id, const void *ccmd, uint32_t ccmd_size);

/**
 * @brief Map a resource blob to host memory
 *
 * Maps a resource blob to host memory.
 *
 * @param cookie Device cookie
 * @param res_id Resource handle to map
 * @param[out] data Pointer to receive the mapped memory address
 * @param[out] size Pointer to receive the mapped memory size
 * @return 0 on success, negative errno on failure
 */
int vaccel_resource_map(void *cookie, uint32_t res_id, void** data, size_t* size);

/**
 * @brief Unmap a resource blob from host memory
 *
 * Unmaps a resource blob from host memory.
 *
 * @param cookie Device cookie
 * @param res_id Resource handle to unmap
 * @return 0 on success, negative errno on failure
 */
int vaccel_resource_unmap(void *cookie, uint32_t res_id);

/**
 * @brief Get map information for a resource blob
 *
 * Gets map information for a resource blob.
 *
 * @param cookie Device cookie
 * @param res_id Resource handle to get map information for
 * @param[out] map_info Pointer to receive the map information
 * @return 0 on success, negative errno on failure
 */
int vaccel_resource_get_map_info(void *cookie, uint32_t res_id, uint32_t *map_info);

#ifdef __cplusplus
}
#endif

#endif /* VACCEL_H */

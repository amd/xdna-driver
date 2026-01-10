// SPDX-License-Identifier: MIT
// Copyright (C) 2025, Advanced Micro Devices, Inc. All rights reserved.

/**
 * @file vaccel_internal.h
 * @brief Internal API and data structures for vaccel
 *
 * This header defines the internal structures and APIs used by the
 * vaccel implementation. Not part of the public API.
 */

#ifndef VACCEL_INTERNAL_H
#define VACCEL_INTERNAL_H

#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <cstddef>
#include <cstring>
#include <functional>
#include <unordered_map>
#include <memory>
#include <mutex>
#include <sys/mman.h>
#ifdef HAVE_STRUCT_IOVEC
#include <sys/uio.h>
#endif
#include <thread>
#ifdef __unix__
#include <unistd.h>
#endif
#include <vector>

#include "vaccel_error.h"
#include "../include/vaccel.h"

#ifndef HAVE_STRUCT_IOVEC
// Define iovec if it is not defined
struct iovec {
    void *iov_base;
    size_t iov_len;
};
#endif

/**
 * @brief Thread-safe wrapper around std::unordered_map
 *
 * Provides synchronized access to an unordered_map using std::mutex.
 * All operations are protected by a mutex lock, making it safe for
 * concurrent access from multiple threads.
 *
 * Typical usage with shared_ptr values:
 * @code
 * vaccel_map<uint32_t, std::shared_ptr<MyObject>> table;
 * table.insert(id, std::make_shared<MyObject>());
 * auto obj = table.lookup(id);  // Returns shared_ptr (copy)
 * table.erase(id);              // Removes from table
 * @endcode
 *
 * @tparam Key Key type (must be hashable)
 * @tparam Value Value type (typically std::shared_ptr<T>)
 *
 * @note Non-copyable to prevent accidental copies of mutex.
 * @note O(1) average time complexity for all operations.
 */
template<typename Key, typename Value>
class vaccel_map {
public:
    vaccel_map() = default;

    // Non-copyable (contains mutex)
    vaccel_map(const vaccel_map&) = delete;
    vaccel_map& operator=(const vaccel_map&) = delete;

    /**
     * @brief Look up value by key
     *
     * @param key Key to search for
     * @return Copy of value if found, default-constructed Value otherwise
     * @note Returns copy, not reference, for thread safety
     */
    Value lookup(const Key& key) const {
        std::lock_guard<std::mutex> lock(m_mtx);
        auto it = m_map.find(key);
        if (it != m_map.end())
            return it->second;
        return Value();
    }

    /**
     * @brief Insert value by const reference
     *
     * @param key Key to insert
     * @param value Value to copy into map
     * @return true if inserted, false if key already exists
     */
    bool insert(const Key& key, const Value& value) {
        std::lock_guard<std::mutex> lock(m_mtx);
        return m_map.emplace(key, value).second;
    }

    /**
     * @brief Insert value by rvalue reference (move)
     *
     * @param key Key to insert
     * @param value Value to move into map
     * @return true if inserted, false if key already exists
     */
    bool insert(const Key& key, Value&& value) {
        std::lock_guard<std::mutex> lock(m_mtx);
        return m_map.emplace(key, std::move(value)).second;
    }

    /**
     * @brief Insert with rvalue key and value
     *
     * @param key Key to move into map
     * @param value Value to move into map
     * @return true if inserted, false if key already exists
     */
    bool insert(Key&& key, Value&& value) {
        std::lock_guard<std::mutex> lock(m_mtx);
        return m_map.emplace(std::move(key), std::move(value)).second;
    }

    /**
     * @brief Remove element by key
     *
     * @param key Key to remove
     * @return true if element was removed, false if not found
     */
    bool erase(const Key& key) {
        std::lock_guard<std::mutex> lock(m_mtx);
        return m_map.erase(key) > 0;
    }

    /**
     * @brief Remove all elements
     */
    void clear() {
        std::lock_guard<std::mutex> lock(m_mtx);
        m_map.clear();
    }

    /**
     * @brief Check if key exists
     *
     * @param key Key to check
     * @return true if key exists, false otherwise
     */
    bool contains(const Key& key) const {
        std::lock_guard<std::mutex> lock(m_mtx);
        return m_map.find(key) != m_map.end();
    }

    /**
     * @brief Get number of elements
     * @return Current size of map
     */
    size_t size() const {
        std::lock_guard<std::mutex> lock(m_mtx);
        return m_map.size();
    }

private:
    std::unordered_map<Key, Value> m_map;  /**< Underlying hash map */
    mutable std::mutex m_mtx;               /**< Mutex for thread safety */
};

/**
 * @brief GPU resource (buffer object) abstraction
 *
 * Represents a buffer that can be shared between host and guest.
 * Resources can be backed by:
 * - Guest memory (via IO vectors from virtio-gpu)
 * - Host memory (via DRM GEM objects, identified by opaque_handle)
 *
 * Provides scatter-gather I/O through IO vectors, allowing efficient
 * access to non-contiguous guest memory regions.
 *
 * Two construction modes:
 * - Guest memory: Created with iovecs pointing to guest memory
 * - Host memory: Created with opaque_handle to DRM GEM object
 *
 * @note Destructor automatically unmaps memory if mapped.
 */
class vaccel_resource {
public:
    /**
     * @brief Construct resource backed by guest memory
     *
     * @param res_id_in Unique resource identifier
     * @param size_in Total size in bytes
     * @param flags_in Creation flags (blob_flags)
     * @param iovecs_in Array of IO vectors pointing to guest memory
     * @param num_iovecs_in Number of IO vectors
     * @param ctx_id_in Owning context ID
     */
    vaccel_resource(uint32_t res_id_in, uint64_t size_in, uint32_t flags_in,
        const struct iovec *iovecs_in, uint32_t num_iovecs_in, uint32_t ctx_id_in)
        : m_res_id(res_id_in)
        , m_size(size_in)
        , m_flags(flags_in)
        , m_map_addr(nullptr)
        , m_map_info(0)
        , m_iovecs(iovecs_in)
        , m_num_iovecs(num_iovecs_in)
        , m_ctx_id(ctx_id_in)
        , m_opaque_handle(0)
    {}

    /**
     * @brief Construct resource backed by host memory (DRM GEM)
     *
     * @param res_id_in Unique resource identifier
     * @param size_in Total size in bytes
     * @param opaque_handle_in DRM GEM handle
     * @param ctx_id_in Owning context ID
     */
    vaccel_resource(uint32_t res_id_in, uint64_t size_in, int opaque_handle_in, uint32_t ctx_id_in)
        : m_res_id(res_id_in)
        , m_size(size_in)
        , m_flags(0)
        , m_map_addr(nullptr)
        , m_map_info(0)
        , m_iovecs(nullptr)
        , m_num_iovecs(0)
        , m_ctx_id(ctx_id_in)
        , m_opaque_handle(opaque_handle_in)
    {}

    /**
     * @brief Destructor - unmaps memory if mapped
     */
    ~vaccel_resource() noexcept
    {
        munmap();
    }

    /** @name Accessors
     * @{
     */

    /** @brief Get resource ID */
    uint32_t get_res_id() const noexcept { return m_res_id; }

    /** @brief Get resource size in bytes */
    uint64_t get_size() const noexcept { return m_size; }

    /** @brief Get creation flags */
    uint32_t get_flags() const noexcept { return m_flags; }

    /** @brief Get mapped address (nullptr if not mapped) */
    void * get_map_addr() const noexcept { return m_map_addr; }

    /** @brief Get owning context ID */
    uint32_t get_ctx_id() const noexcept { return m_ctx_id; }

    /** @brief Get opaque handle (DRM GEM handle for host memory) */
    int get_opaque_handle() const noexcept { return m_opaque_handle; }

    /** @brief Get map info for virtio-gpu driver */
    uint32_t get_map_info() const noexcept { return m_map_info; }

    /**
     * @brief Get IO vectors
     *
     * @param[out] iovecs_out Receives pointer to iovec array
     * @return Number of IO vectors
     */
    uint32_t get_iovecs(const struct iovec **iovecs_out) const noexcept
    {
        *iovecs_out = m_iovecs;
        return m_num_iovecs;
    }

    /** @} */

    /** @name I/O Operations
     * @{
     */

    /**
     * @brief Write data to resource via scatter-gather
     *
     * Copies data from buffer to resource's IO vectors, handling
     * scatter across multiple iovecs.
     *
     * @param offset Byte offset within resource
     * @param buf Source buffer
     * @param len Number of bytes to write
     * @return Number of bytes written
     * @throws vaccel_error if write exceeds resource size
     */
    uint32_t write(uint32_t offset, const void *buf, uint32_t len)
    {
        uint32_t bytes_written = 0;

        for (uint32_t i = 0; i < m_num_iovecs; i++) {
            if (offset >= m_iovecs[i].iov_len) {
                offset -= m_iovecs[i].iov_len;
                continue;
            }

            uint32_t chunk = len;
            if (chunk > m_iovecs[i].iov_len - offset)
                 chunk = m_iovecs[i].iov_len - offset;
            void *dst = static_cast<void *>(static_cast<uint8_t *>(m_iovecs[i].iov_base) + offset);
            std::memcpy(dst, buf, chunk);

            buf = static_cast<const void *>(static_cast<const uint8_t *>(buf) + chunk);
            len -= chunk;
            bytes_written += chunk;
            offset = 0;
        }

        if (len > 0)
            VACCEL_THROW_MSG(-EINVAL, "buffer to res is too big, %u bytes remaining, %u bytes written",
                             len, bytes_written);

        return bytes_written;
    }

    /**
     * @brief Read data from resource via scatter-gather
     *
     * Copies data from resource's IO vectors to buffer, handling
     * gather from multiple iovecs.
     *
     * @param offset Byte offset within resource
     * @param buf Destination buffer
     * @param len Number of bytes to read
     * @return Number of bytes read
     * @throws vaccel_error if read exceeds resource size
     */
    uint32_t read(uint32_t offset, void *buf, uint32_t len)
    {
        uint32_t bytes_read = 0;
        for (uint32_t i = 0; i < m_num_iovecs; i++) {
            if (offset >= m_iovecs[i].iov_len) {
                offset -= m_iovecs[i].iov_len;
                continue;
            }
            uint32_t chunk = len;
            if (chunk > m_iovecs[i].iov_len - offset)
                 chunk = m_iovecs[i].iov_len - offset;
            void *src = static_cast<void *>(static_cast<uint8_t *>(m_iovecs[i].iov_base) + offset);
            std::memcpy(buf, src, chunk);

            buf = static_cast<void *>(static_cast<uint8_t *>(buf) + chunk);
            len -= chunk;
            bytes_read += chunk;
            offset = 0;
        }

        if (len > 0)
            VACCEL_THROW_MSG(-EINVAL, "buffer from res is too big, %u bytes remaining, %u bytes read",
                             len, bytes_read);

        return bytes_read;
    }

    /** @} */

    /** @name Memory Mapping
     * @{
     */

    /**
     * @brief Map resource to host address space
     *
     * Maps the underlying DRM buffer to a virtual address.
     * Used for host memory resources (HOST3D blobs).
     *
     * @param fd File descriptor for mmap
     * @return Mapped address
     * @throws vaccel_error on mmap failure
     */
    void * mmap(int fd);

    /**
     * @brief Unmap resource from host address space
     */
    void munmap()
    {
        vxdna_dbg("vaccel_resource::munmap: line %d, ctx_id=%u, res_id=%u, opaque_handle=%d, map_addr=%p",
                  __LINE__, m_ctx_id, m_res_id, m_opaque_handle, m_map_addr);
        if (m_map_addr != nullptr)
            ::munmap(m_map_addr, m_size);
        m_map_addr = nullptr;
    }

    /** @} */

private:
    uint32_t m_res_id;            /**< Resource ID (unique per device) */
    uint64_t m_size;              /**< Resource size in bytes */
    uint32_t m_flags;             /**< Resource creation flags */
    void *m_map_addr;             /**< Mapped address (nullptr if not mapped) */
    uint32_t m_map_info;          /**< Map info for virtio-gpu (1=cached) */
    const struct iovec *m_iovecs; /**< IO vectors for guest memory */
    uint32_t m_num_iovecs;        /**< Number of IO vectors */
    uint32_t m_ctx_id;            /**< Owning context ID */
    int m_opaque_handle;          /**< DRM GEM handle for host memory */
};

/**
 * @brief Base class for rendering contexts (CRTP template)
 *
 * Provides common functionality for execution contexts using the
 * Curiously Recurring Template Pattern (CRTP) for compile-time
 * polymorphism, avoiding virtual function overhead.
 *
 * Each context represents an independent command stream with:
 * - Its own file descriptor (typically duplicated from device)
 * - Access to parent device for resource lookup
 * - Command buffer alignment requirements
 *
 * CRTP Requirements:
 * The Derived class must implement:
 * @code
 * int get_blob_impl(const struct vaccel_create_resource_blob_args *args);
 * @endcode
 *
 * Usage:
 * @code
 * class my_context : public vaccel_context<my_context, my_device> {
 * public:
 *     int get_blob_impl(const struct vaccel_create_resource_blob_args *args) {
 *         // Implementation
 *     }
 * };
 * @endcode
 *
 * @tparam Derived The derived context class (for CRTP dispatch)
 * @tparam DeviceType The device class type (for accessing device methods)
 *
 * @note Non-copyable and non-movable (contains reference).
 */
template <typename Derived, typename DeviceType>
class vaccel_context {
public:
    /**
     * @brief Construct context
     *
     * @param ctx_id_in Unique context identifier
     * @param ccmd_align_in Command buffer alignment requirement
     * @param device Reference to parent device
     */
    vaccel_context(uint32_t ctx_id_in, uint32_t ccmd_align_in, DeviceType& device)
        : m_ctx_id(ctx_id_in)
        , m_fd(device.get_drm_fd())
        , m_ccmd_align(ccmd_align_in)
        , m_device(device)
    {}

    // Non-copyable, non-movable (contains reference)
    vaccel_context(const vaccel_context&) = delete;
    vaccel_context& operator=(const vaccel_context&) = delete;
    vaccel_context(vaccel_context&&) = delete;
    vaccel_context& operator=(vaccel_context&&) = delete;

    /** @name Accessors
     * @{
     */

    /** @brief Get context file descriptor */
    int get_fd() const noexcept { return m_fd; }

    /** @brief Get context ID */
    uint32_t get_id() const noexcept { return m_ctx_id; }

    /** @brief Get command buffer alignment requirement */
    uint32_t get_ccmd_align() const noexcept { return m_ccmd_align; }

    /**
     * @brief Get device cookie (forwarded from device)
     * @return Opaque device identifier
     */
    void* get_cookie() const noexcept
    {
        return m_device.get_cookie();
    }

    /**
     * @brief Get callbacks structure (forwarded from device)
     * @return Pointer to callbacks
     */
    const struct vaccel_callbacks* get_callbacks() const noexcept
    {
        return m_device.get_callbacks();
    }

    /**
     * @brief Get mutable reference to parent device
     * @return Reference to device
     */
    DeviceType& get_device() noexcept { return m_device; }

    /**
     * @brief Get const reference to parent device
     * @return Const reference to device
     */
    const DeviceType& get_device() const noexcept { return m_device; }

    /** @} */

    /**
     * @brief Create host memory blob (CRTP dispatch)
     *
     * Dispatches to derived class implementation via static_cast.
     * This avoids virtual function overhead.
     *
     * @param args Blob creation arguments
     * @return Handle on success, or throws on failure
     */
    int get_blob(const struct vaccel_create_resource_blob_args *args)
    {
        return static_cast<Derived*>(this)->get_blob_impl(args);
    }

protected:
    uint32_t m_ctx_id;           /**< Context ID (unique per device) */
    int m_fd;                    /**< Context file descriptor, every context has its own */
    uint32_t m_ccmd_align;       /**< Command buffer alignment (bytes) */
    DeviceType& m_device;        /**< Reference to parent device */
};

/**
 * @brief Fence synchronization primitive
 *
 * Represents a synchronization point in the GPU timeline, used to
 * track command completion and signal the guest when operations finish.
 *
 * Each fence contains:
 * - Guest-provided fence ID for callback identification
 * - Sync point (sequence number) to wait for
 * - DRM syncobj handle for kernel-level synchronization
 * - Ring index (hardware context handle)
 * - Timeout for wait operations
 *
 * Lifecycle:
 * 1. Created when submit_fence is called with pending sync point
 * 2. Added to hardware context's pending fence queue
 * 3. Polling thread waits on syncobj timeline
 * 4. On signal/timeout, callback invoked with fence ID
 *
 * @note Immutable after construction.
 */
class vaccel_fence {
public:
    /**
     * @brief Construct fence with all parameters
     *
     * @param id_in Guest-provided fence ID for callback
     * @param sync_point_in Sequence number to wait for
     * @param syncobj_handle_in DRM syncobj handle
     * @param ring_idx_in Hardware context handle (ring index)
     * @param timeout_nsec_in Wait timeout in nanoseconds
     */
    vaccel_fence(uint64_t id_in, uint64_t sync_point_in,
                 uint32_t syncobj_handle_in, uint32_t ring_idx_in,
                 int64_t timeout_nsec_in)
        : m_id(id_in)
        , m_sync_point(sync_point_in)
        , m_syncobj_handle(syncobj_handle_in)
        , m_ring_idx(ring_idx_in)
        , m_timeout_nsec(timeout_nsec_in)
    {}

    /** @name Accessors
     * @{
     */

    /** @brief Get sync point (sequence number) */
    uint64_t get_sync_point() const noexcept { return m_sync_point; }

    /** @brief Get DRM syncobj handle */
    uint32_t get_syncobj_handle() const noexcept { return m_syncobj_handle; }

    /** @brief Get ring index (hardware context handle) */
    uint32_t get_ring_idx() const noexcept { return m_ring_idx; }

    /** @brief Get guest fence ID */
    uint64_t get_id() const noexcept { return m_id; }

    /** @brief Get wait timeout in nanoseconds */
    int64_t get_timeout_nsec() const noexcept { return m_timeout_nsec; }

    /** @} */

private:
    uint64_t m_id;               /**< Guest fence ID for callback */
    uint64_t m_sync_point;       /**< Sequence number to wait for */
    uint32_t m_syncobj_handle;   /**< DRM syncobj handle */
    uint32_t m_ring_idx;         /**< Hardware context handle */
    int64_t m_timeout_nsec;      /**< Wait timeout (nanoseconds) */
};

/**
 * @brief Base class for device instances (CRTP template)
 *
 * Represents a single accelerator device instance with its own lookup
 * tables for resources, contexts, and fences. Multiple devices can
 * coexist independently, each identified by a unique cookie.
 *
 * Uses CRTP for compile-time polymorphism. Derived class must implement:
 * - get_capset_info(uint32_t *max_version, uint32_t *max_size)
 * - fill_capset(uint32_t capset_size, void *capset_buf)
 * - create_ctx(uint32_t ctx_id, uint32_t ctx_flags, uint32_t nlen, const char *name)
 * - destroy_ctx(uint32_t ctx_id)
 * - create_resource_from_blob(const vaccel_create_resource_blob_args *args)
 * - destroy_resource(const std::shared_ptr<vaccel_resource> &res)
 * - submit_fence(uint32_t ctx_id, uint32_t flags, uint32_t ring_idx, uint64_t fence_id)
 * - dispatch_ccmd(std::shared_ptr<ContextType> &ctx, const vdrm_ccmd_req *hdr)
 *
 * @tparam T Derived device class (for CRTP dispatch)
 * @tparam ContextType Context class used by this device
 *
 * @note Non-copyable and non-movable.
 */
template <typename T, typename ContextType>
class vaccel {
public:
    /**
     * @brief Construct device instance
     *
     * @param cookie Opaque device identifier (e.g., from virtio-gpu)
     * @param capset_id Capability set ID for this device type
     * @param callbacks User-provided callbacks for FD access and fences
     */
    vaccel(void *cookie, uint32_t capset_id, const struct vaccel_callbacks *callbacks)
        : m_cookie(cookie)
        , m_drm_fd(-1)
        , m_capset_id(capset_id)
        , m_callbacks(callbacks)
    {}

    /**
     * @brief Destructor - closes DRM FD if owned
     */
    ~vaccel()
    {
        if (m_drm_fd >= 0) {
            close(m_drm_fd);
        }
    }

    // Non-copyable, non-movable
    vaccel(const vaccel&) = delete;
    vaccel& operator=(const vaccel&) = delete;
    vaccel(vaccel&&) = delete;
    vaccel& operator=(vaccel&&) = delete;

    /** @name Capability Set Interface
     * CRTP dispatch to derived class implementation.
     * @{
     */

    /** @brief Get capset version and size (CRTP dispatch) */
    void get_capset_info(uint32_t *max_version, uint32_t *max_size)
    {
        static_cast<T*>(this)->get_capset_info(max_version, max_size);
    }

    /** @brief Fill capset buffer (CRTP dispatch) */
    void fill_capset(uint32_t capset_size, void *capset_buf)
    {
        static_cast<T*>(this)->fill_capset(capset_size, capset_buf);
    }

    /** @} */

    /** @name Context Management
     * @{
     */

    /**
     * @brief Look up context by ID
     * @param ctx_id Context ID
     * @return Shared pointer to context, or nullptr if not found
     */
    std::shared_ptr<ContextType> get_ctx(uint32_t ctx_id)
    {
        return m_context_table.lookup(ctx_id);
    }

    /**
     * @brief Add context to table
     * @param ctx_id Context ID
     * @param ctx Context to add (moved into table)
     */
    void add_ctx(uint32_t ctx_id, std::shared_ptr<ContextType> &&ctx)
    {
       m_context_table.insert(ctx_id, std::move(ctx));
    }

    /**
     * @brief Remove context from table
     * @param ctx_id Context ID to remove
     */
    void remove_ctx(uint32_t ctx_id)
    {
        m_context_table.erase(ctx_id);
    }

    /**
     * @brief Create new context (validates then dispatches to derived)
     *
     * @param ctx_id Unique context ID
     * @param ctx_flags Creation flags
     * @param nlen Length of debug name
     * @param name Debug name string
     * @throws vaccel_error if context already exists
     */
    void create_ctx(uint32_t ctx_id, uint32_t ctx_flags, uint32_t nlen, const char *name)
    {
        auto ctx = get_ctx(ctx_id);
        if (ctx)
            VACCEL_THROW_MSG(-EEXIST, "Context already exists: ctx_id=%u", ctx_id);
        static_cast<T*>(this)->create_ctx(ctx_id, ctx_flags, nlen, name);
    }

    /**
     * @brief Destroy context (validates then dispatches to derived)
     *
     * @param ctx_id Context ID to destroy
     * @throws vaccel_error if context not found
     */
    void destroy_ctx(uint32_t ctx_id)
    {
        auto ctx = get_ctx(ctx_id);
        if (!ctx)
            VACCEL_THROW_MSG(-ENOENT, "Context not found: ctx_id=%u", ctx_id);
        static_cast<T*>(this)->destroy_ctx(ctx_id);
    }

    /** @} */

    /** @name Resource Management
     * @{
     */

    /**
     * @brief Look up resource by ID
     * @param res_id Resource ID
     * @return Shared pointer to resource, or nullptr if not found
     */
    std::shared_ptr<vaccel_resource> get_resource(uint32_t res_id) const
    {
        return m_resource_table.lookup(res_id);
    }

    /**
     * @brief Add resource to table
     * @param res_id Resource ID
     * @param res Resource to add (moved into table)
     */
    void add_resource(uint32_t res_id, std::shared_ptr<vaccel_resource> &&res)
    {
        m_resource_table.insert(res_id, std::move(res));
    }

    /**
     * @brief Create resource from guest memory blob
     *
     * Creates a vaccel_resource backed by the provided IO vectors.
     *
     * @param args Blob creation arguments with iovecs
     */
    void create_resource(const struct vaccel_create_resource_blob_args *args)
    {
        auto res = std::make_shared<vaccel_resource>(args->res_handle, args->size,
                                                     args->blob_flags, args->iovecs,
                                                     args->num_iovs, args->ctx_id);
        add_resource(args->res_handle, std::move(res));
    }

    /**
     * @brief Create resource from host memory blob (CRTP dispatch)
     * @param args Blob creation arguments
     */
    void create_resource_from_blob(const struct vaccel_create_resource_blob_args *args)
    {
        static_cast<T*>(this)->create_resource_from_blob(args);
    }

    /**
     * @brief Destroy resource
     *
     * Validates resource exists, dispatches to derived for cleanup,
     * then removes from table.
     *
     * @param res_id Resource ID to destroy
     * @throws vaccel_error if resource not found
     */
    void destroy_resource(uint32_t res_id)
    {
        auto res = get_resource(res_id);
        if (!res)
            VACCEL_THROW_MSG(-ENOENT, "Resource not found: res_id=%u", res_id);
        static_cast<T*>(this)->destroy_resource(res);
        m_resource_table.erase(res_id);
    }

    /**
     * @brief Export resource as DMA-BUF file descriptor
     *
     * For host memory resources, exports via DRM PRIME.
     *
     * @param res_id Resource ID to export
     * @return File descriptor on success
     * @throws vaccel_error on failure
     */
    [[nodiscard]] int export_resource_fd(uint32_t res_id)
    {
        auto res = get_resource(res_id);
        if (!res)
            VACCEL_THROW_MSG(-ENOENT, "Resource not found: res_id=%u", res_id);
        if (res->get_opaque_handle() <= 0)
            VACCEL_THROW_MSG(-EINVAL, "Resource is not opaque");
        auto ctx_id = res->get_ctx_id();
        auto ctx = get_ctx(ctx_id);
        if (!ctx)
            VACCEL_THROW_MSG(-ENOENT, "Context not found: ctx_id=%u", ctx_id);
        return static_cast<ContextType*>(ctx.get())->export_resource_fd(res);
    }

    /** @} */

    /** @name Device Accessors
     * @{
     */

    /**
     * @brief Get DRM file descriptor
     *
     * Calls the user-provided get_device_fd callback.
     *
     * @return DRM file descriptor
     */
    int get_drm_fd() const noexcept
    {
        return m_callbacks->get_device_fd(get_cookie());
    }

    /**
     * @brief Set owned DRM file descriptor
     * @param fd File descriptor to store
     */
    void set_drm_fd(int fd) noexcept { m_drm_fd = fd; }

    /** @brief Get capability set ID */
    uint32_t get_capset_id() const noexcept { return m_capset_id; }

    /** @brief Get device cookie */
    void * get_cookie() const noexcept { return m_cookie; }

    /** @brief Get callbacks structure */
    const struct vaccel_callbacks * get_callbacks() const noexcept { return m_callbacks; }

    /** @} */

    /** @name Fence Management
     * @{
     */

    /**
     * @brief Look up fence by ID
     * @param fence_id Fence ID
     * @return Shared pointer to fence, or nullptr if not found
     */
    std::shared_ptr<vaccel_fence> get_fence(uint32_t fence_id)
    {
        return m_fence_table.lookup(fence_id);
    }

    /**
     * @brief Add fence to table
     * @param fence_id Fence ID
     * @param fence Fence to add (moved into table)
     */
    void add_fence(uint32_t fence_id, std::shared_ptr<vaccel_fence> &&fence)
    {
        m_fence_table.insert(fence_id, std::move(fence));
    }

    /**
     * @brief Remove fence from table
     * @param fence_id Fence ID to remove
     */
    void remove_fence(uint32_t fence_id)
    {
        m_fence_table.erase(fence_id);
    }

    /**
     * @brief Submit fence (CRTP dispatch)
     *
     * @param ctx_id Context ID
     * @param flags Fence flags
     * @param ring_idx Hardware context handle
     * @param fence_id Guest fence ID
     */
    void submit_fence(uint32_t ctx_id, uint32_t flags, uint32_t ring_idx, uint64_t fence_id)
    {
        static_cast<T*>(this)->submit_fence(ctx_id, flags, ring_idx, fence_id); 
    }

    /**
     * @brief Destroy fence (CRTP dispatch)
     * @param fence_id Fence ID to destroy
     */
    void destroy_fence(uint32_t fence_id)
    {
        static_cast<T*>(this)->destroy_fence(fence_id);
    }

    /** @} */

    /**
     * @brief Dispatch command to handler (CRTP dispatch)
     *
     * @param ctx Target context
     * @param hdr Command header
     */
    void dispatch_ccmd(std::shared_ptr<ContextType> &ctx, const struct vdrm_ccmd_req *hdr)
    {
        static_cast<T*>(this)->dispatch_ccmd(ctx, hdr);
    }

private:
    void *m_cookie;              /**< Opaque device identifier */
    int m_drm_fd;                /**< Owned DRM file descriptor (-1 if not owned) */
    uint32_t m_capset_id;        /**< Capability set ID */
    const struct vaccel_callbacks *m_callbacks; /**< User callbacks */

    /** @name Lookup Tables
     * Thread-safe maps for device resources.
     * Use shared_ptr for automatic reference counting.
     * @{
     */
    vaccel_map<uint32_t, std::shared_ptr<vaccel_resource>> m_resource_table; /**< Resources */
    vaccel_map<uint32_t, std::shared_ptr<ContextType>> m_context_table;      /**< Contexts */
    vaccel_map<uint64_t, std::shared_ptr<vaccel_fence>> m_fence_table;       /**< Fences */
    /** @} */
};

#endif /* VACCEL_INTERNAL_H */

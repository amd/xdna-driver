// SPDX-License-Identifier: MIT
// Copyright (C) 2025, Advanced Micro Devices, Inc. All rights reserved.

/**
 * @file vaccel_amdxdna.h
 * @brief Internal API for AMDXDNA device management
 *
 * This header defines the internal AMDXDNA-specific functions used by
 * the vaccel implementation. Not part of the public API.
 */

#ifndef VACCEL_AMDXDNA_H
#define VACCEL_AMDXDNA_H

#include <cstdint>
#include <stddef.h>
#include <stdexcept>
#include <memory>

#include "drm_hw.h" // from xdna shim virtio

#include "drm_local/amdxdna_accel.h"
#include "amdxdna_proto.h"
#include "vaccel.h"
#include "vaccel_internal.h"

/**
 * @brief AMDXDNA Buffer Object wrapper
 *
 * Manages DRM GEM buffer objects for AMDXDNA devices. Handles creation,
 * memory mapping, and cleanup of buffers used for data transfer between
 * host and NPU.
 *
 * Supports two creation modes:
 * - With resource: Creates BO backed by guest memory (via IO vectors)
 * - Without resource: Creates device-local BO (AMDXDNA_BO_DEV)
 *
 * @note Non-copyable and non-movable to ensure unique ownership of DRM handles.
 */
class vxdna_bo {
public:
    /**
     * @brief Construct BO backed by guest resource
     *
     * Creates a buffer object using memory from a vaccel_resource.
     * The resource's IO vectors provide the backing memory.
     *
     * @param res Shared pointer to the backing resource
     * @param ctx_fd_in Context file descriptor for DRM ioctls
     * @param req BO creation request with type, size, and alignment
     * @throws vaccel_error on DRM ioctl failure
     */
    vxdna_bo(const std::shared_ptr<vaccel_resource> &res, int ctx_fd_in, const struct amdxdna_ccmd_create_bo_req *req);

    /**
     * @brief Construct device-local BO
     *
     * Creates a buffer object in device memory (AMDXDNA_BO_DEV type).
     * No backing resource is needed; memory is allocated on the NPU.
     *
     * @param ctx_fd_in Context file descriptor for DRM ioctls
     * @param req BO creation request with type and size
     * @throws vaccel_error on DRM ioctl failure
     */
    vxdna_bo(int ctx_fd_in, const struct amdxdna_ccmd_create_bo_req *req);

    /**
     * @brief Destructor - unmaps memory and closes GEM handle
     */
    ~vxdna_bo() noexcept;

    // Non-copyable, non-movable
    vxdna_bo(const vxdna_bo&) = delete;
    vxdna_bo& operator=(const vxdna_bo&) = delete;
    vxdna_bo(vxdna_bo&&) = delete;
    vxdna_bo& operator=(vxdna_bo&&) = delete;

    /**
     * @brief Get the address to use for NPU commands
     *
     * Returns the device address (xdna_addr) if valid, otherwise
     * returns the virtual address (vaddr). The returned address
     * can be used in command buffers sent to the NPU.
     *
     * @return NPU-accessible address of the buffer
     */
    uint64_t get_addr() const noexcept
    {
        if (m_xdna_addr != AMDXDNA_INVALID_ADDR)
            return m_xdna_addr;
        return m_vaddr;
    }

    /**
     * @brief Get the DRM GEM handle
     * @return GEM handle for use in DRM ioctls
     */
    uint32_t get_handle() const noexcept
    {
        return m_bo_handle;
    }

private:
    uint64_t m_size = 0;          /**< Buffer size in bytes */
    uint64_t m_vaddr = 0;         /**< Virtual address (after mmap) */
    uint64_t m_map_offset = 0;    /**< Offset for mmap() from DRM */
    uint64_t m_xdna_addr = 0;     /**< NPU device address */
    uint64_t m_map_size = 0;      /**< Size of mapped region */
    uint32_t m_bo_handle = 0;     /**< DRM GEM handle */
    uint32_t m_bo_type = 0;       /**< BO type (DEV, SHMEM, CMD) */
    int m_opaque_handle = -1;     /**< Opaque handle from resource */
    int m_ctx_fd = -1;            /**< Context file descriptor */
};


// Forward declaration
class vxdna;

/**
 * @brief AMDXDNA execution context
 *
 * Represents an independent command stream for AMDXDNA device operations.
 * Each context has its own DRM file descriptor, buffer object table, and
 * hardware context table.
 *
 * Uses CRTP (Curiously Recurring Template Pattern) to inherit from
 * vaccel_context with compile-time polymorphism, avoiding virtual function
 * overhead.
 *
 * Key responsibilities:
 * - Buffer object lifecycle management
 * - Hardware context creation and configuration
 * - Command execution and response handling
 * - Fence submission for async completion
 *
 * @note Each context gets a duplicated DRM FD for isolation.
 * @note Non-copyable and non-movable.
 */
class vxdna_context : public vaccel_context<vxdna_context, vxdna> {
public:
    using base_type = vaccel_context<vxdna_context, vxdna>;

    /**
     * @brief Construct a new context
     *
     * @param ctx_id Unique context identifier
     * @param ccmd_align Command buffer alignment requirement
     * @param device Reference to parent vxdna device
     */
    vxdna_context(uint32_t ctx_id, uint32_t ccmd_align, vxdna& device)
        : base_type(ctx_id, ccmd_align, device)
    { vxdna_dbg("Context created: ctx_id=%u, fd=%d", get_id(), get_fd()); }

    /**
     * @brief Destructor - closes FD and cleans up resources
     */
    ~vxdna_context() {
        vxdna_dbg("Context destroying: ctx_id=%u, fd=%d", get_id(), get_fd());
        close(get_fd());
    }

    /**
     * @brief Set the response resource for ccmd responses
     *
     * The response resource is a shared buffer where command responses
     * are written. Set during the init ccmd.
     *
     * @param res Response resource (moved into context)
     */
    void set_resp_res(std::shared_ptr<vaccel_resource> &&res)
    {
        m_resp_res = std::move(res);
    }

    /**
     * @brief Get the response resource
     * @return Shared pointer to response resource, or nullptr if not set
     */
    std::shared_ptr<vaccel_resource> get_resp_res() const noexcept
    {
        return m_resp_res;
    }

    /**
     * @brief Export resource as DMA-BUF file descriptor
     *
     * @param res Resource to export
     * @return File descriptor on success
     * @throws vaccel_error on failure
     */
    [[nodiscard]] int export_resource_fd(const std::shared_ptr<vaccel_resource> &res);

    /** @name Buffer Object Management
     * @{
     */

    /**
     * @brief Create a buffer object from ccmd request
     *
     * Handles both device-local (AMDXDNA_BO_DEV) and shared memory
     * (AMDXDNA_BO_SHMEM, AMDXDNA_BO_CMD) buffer types.
     *
     * @param req BO creation request from guest
     * @throws vaccel_error on creation failure
     */
    void create_bo(const struct amdxdna_ccmd_create_bo_req *req);

    /**
     * @brief Add a pre-created BO to the context's table
     * @param bo Buffer object to add (moved into table)
     */
    void add_bo(std::shared_ptr<vxdna_bo> &&bo);

    /**
     * @brief Remove and destroy a BO by handle
     * @param handle GEM handle of BO to remove
     */
    void remove_bo(uint32_t handle);

    /** @} */

    /** @name Response Handling
     * @{
     */

    /**
     * @brief Write error response to response buffer
     * @param err Error code (negative errno)
     */
    void write_err_rsp(int err);

    /**
     * @brief Write response data to response buffer
     *
     * @param rsp Response data pointer
     * @param rsp_size Size of response in bytes
     * @param rsp_off Offset within response buffer
     */
    void write_rsp(const void *rsp, size_t rsp_size, uint32_t rsp_off);

    /** @} */

    /** @name Hardware Context Management
     * @{
     */

    /**
     * @brief Create a hardware execution context
     *
     * Creates an NPU hardware context with specified QoS parameters.
     * Starts a polling thread for async fence completion.
     *
     * @param req HW context creation request
     * @throws vaccel_error on creation failure
     */
    void create_hwctx(const struct amdxdna_ccmd_create_ctx_req *req);

    /**
     * @brief Remove and destroy a hardware context
     * @param handle HW context handle to remove
     */
    void remove_hwctx(uint32_t handle);

    /**
     * @brief Configure hardware context parameters
     * @param req Configuration request
     * @throws vaccel_error on configuration failure
     */
    void config_hwctx(const struct amdxdna_ccmd_config_ctx_req *req);

    /** @} */

    /** @name Command Execution
     * @{
     */

    /**
     * @brief Execute a command on a hardware context
     *
     * Submits command buffer(s) to the NPU for execution.
     * Returns sequence number for tracking completion.
     *
     * @param req Execution request with command handles
     * @throws vaccel_error on submission failure
     */
    void exec_cmd(const struct amdxdna_ccmd_exec_cmd_req *req);

    /**
     * @brief Wait for command completion with timeout
     *
     * Sets sync point for the next fence submission.
     *
     * @param req Wait request with sequence number and timeout
     * @throws vaccel_error on wait failure
     */
    void wait_cmd(const struct amdxdna_ccmd_wait_cmd_req *req);

    /** @} */

    /** @name Device Information
     * @{
     */

    /**
     * @brief Query device/driver information
     *
     * Retrieves information via DRM_IOCTL_AMDXDNA_GET_INFO.
     *
     * @param req Info request with parameter type
     * @throws vaccel_error on query failure
     */
    void get_info(const struct amdxdna_ccmd_get_info_req *req);

    /**
     * @brief Read sysfs attribute
     *
     * Reads device sysfs file and returns contents.
     *
     * @param req Sysfs read request with node name
     * @throws vaccel_error on read failure
     */
    void read_sysfs(const struct amdxdna_ccmd_read_sysfs_req *req);

    /** @} */

    /**
     * @brief Submit fence for async completion notification
     *
     * Associates a fence ID with the last executed command.
     * When the command completes, the fence callback is invoked.
     *
     * @param ring_idx Hardware context handle (ring index)
     * @param fence_id Guest fence ID for callback
     */
    void submit_fence(uint32_t ring_idx, uint64_t fence_id);

    /**
     * @brief Create a host memory blob (CRTP implementation)
     *
     * Called by base class via CRTP dispatch to create a
     * HOST3D blob backed by DRM GEM object.
     *
     * @param args Blob creation arguments
     * @return GEM handle on success
     * @throws vaccel_error on creation failure
     */
    [[nodiscard]] int get_blob_impl(const struct vaccel_create_resource_blob_args *args);
private:
    /**
     * @brief Hardware execution context for NPU command submission
     *
     * Manages a single NPU hardware context with its associated DRM handles,
     * fence timeline, and async completion polling thread.
     *
     * Architecture:
     * - Each hwctx has a unique DRM hardware context handle
     * - Uses DRM syncobj for timeline-based fence tracking
     * - Runs a dedicated polling thread to wait on pending fences
     * - Signals completion via write_context_fence callback
     *
     * Fence flow:
     * 1. exec_cmd() returns sequence number
     * 2. wait_cmd() sets sync_point and timeout via set_sync_point()
     * 3. submit_fence() creates vaccel_fence and adds to pending queue
     * 4. Polling thread waits on syncobj timeline
     * 5. On completion, invokes write_fence_callback to notify guest
     *
     * @note Non-copyable and non-movable.
     * @note Destructor joins polling thread before cleanup.
     */
    class vxdna_hwctx {
    public:
        vxdna_hwctx() = delete;
        vxdna_hwctx(const vxdna_hwctx&) = delete;
        vxdna_hwctx& operator=(const vxdna_hwctx&) = delete;
        vxdna_hwctx(vxdna_hwctx&&) = delete;
        vxdna_hwctx& operator=(vxdna_hwctx&&) = delete;

        /**
         * @brief Construct hardware context
         *
         * Creates DRM hardware context via DRM_IOCTL_AMDXDNA_CREATE_HWCTX
         * and starts the fence polling thread.
         *
         * @param ctx Parent context (provides cookie, callbacks, FD)
         * @param req Creation request with QoS parameters
         * @throws vaccel_error on DRM ioctl failure
         */
        vxdna_hwctx(const vxdna_context &ctx,
                    const struct amdxdna_ccmd_create_ctx_req *req);

        /**
         * @brief Destructor - stops polling thread and destroys DRM handles
         */
        ~vxdna_hwctx() noexcept;

        /**
         * @brief Configure hardware context parameters
         * @param req Configuration request
         * @throws vaccel_error on failure
         */
        void config(const struct amdxdna_ccmd_config_ctx_req *req);

        /**
         * @brief Execute command on this hardware context
         *
         * @param req Execution request with command handles
         * @return Sequence number for tracking completion
         * @throws vaccel_error on failure
         */
        uint64_t exec_cmd(const struct amdxdna_ccmd_exec_cmd_req *req);

        /**
         * @brief Set sync point for next fence submission
         *
         * Called by wait_cmd to associate a sequence number and timeout
         * with the next fence that will be submitted.
         *
         * @param sync_point_in Sequence number to wait for
         * @param timeout_nsec_in Timeout in nanoseconds
         */
        void set_sync_point(uint64_t sync_point_in, int64_t timeout_nsec_in) noexcept
        {
            std::lock_guard<std::mutex> lock(m_fences_lock);
            m_sync_point = sync_point_in;
            m_timeout_nsec = timeout_nsec_in;
            m_has_sync_point = true;
        }

        /**
         * @brief Get the DRM hardware context handle
         * @return Handle (also used as ring_idx)
         */
        uint32_t get_handle() const noexcept
        {
            return m_hwctx_handle;
        }

        /**
         * @brief Submit fence for async completion
         *
         * If sync point is set, creates a fence and adds to pending queue.
         * If no sync point, immediately invokes callback (command already done).
         *
         * @param fence_id Guest fence ID for callback
         */
        void submit_fence(uint64_t fence_id);

    private:
        /**
         * @brief Poll and retire pending fences
         *
         * Waits on DRM syncobj timeline for each pending fence.
         * Invokes callback when fence signals or times out.
         *
         * @param copy_pending_fences Fences to process (moved from queue)
         */
        void poll_and_retire_pending(std::vector<std::shared_ptr<vaccel_fence>> &&copy_pending_fences);

        /** @name Context Information
         * Copied from parent context for use in async polling thread.
         * @{
         */
        void *m_cookie = nullptr;                   /**< Device cookie */
        void (*m_write_fence_callback)(void *cookie, uint32_t ctx_id, 
                                       uint32_t ring_idx, uint64_t fence_id) = nullptr;
        uint32_t m_ctx_fd = 0;                      /**< Context file descriptor */
        uint32_t m_ctx_id = 0;                      /**< Context ID */
        /** @} */

        /** @name Fence Synchronization
         * @{
         */
        mutable std::mutex m_fences_lock;           /**< Protects fence state */
        uint64_t m_sync_point = 0;                  /**< Current sync point */
        int64_t m_timeout_nsec = 0;                 /**< Timeout for current sync */
        bool m_has_sync_point = false;              /**< Whether sync point is set */
        std::condition_variable m_cv;               /**< Wakes polling thread */
        std::vector<std::shared_ptr<vaccel_fence>> m_pending_fences; /**< Queue */
        std::thread m_polling_thread;               /**< Async polling thread */
        std::atomic<bool> m_stop_polling{false};    /**< Stop signal for thread */
        /** @} */

        /** @name DRM Handles
         * @{
         */
        uint32_t m_hwctx_handle = AMDXDNA_INVALID_CTX_HANDLE;   /**< HW ctx handle */
        uint32_t m_syncobj_handle = AMDXDNA_INVALID_FENCE_HANDLE; /**< Syncobj handle */
        /** @} */
    };

    // Context-owned resources (cookie/callbacks accessed via base_type::get_device())
    std::shared_ptr<vaccel_resource> m_resp_res;
    vaccel_map<uint32_t, std::shared_ptr<vxdna_bo>> m_bo_table;
    vaccel_map<uint32_t, std::shared_ptr<vxdna_hwctx>> m_hwctx_table;
};

/**
 * @brief AMDXDNA device implementation
 *
 * Concrete device class for AMD XDNA (NPU) accelerators, inheriting from
 * the vaccel<T, ContextType> template. Implements all required virtual
 * dispatch points using CRTP.
 *
 * Responsibilities:
 * - Capability set negotiation with guest
 * - Context lifecycle management
 * - Resource blob creation (guest and host memory)
 * - Command dispatch to appropriate handlers
 * - Fence submission for async completion
 *
 * Each vxdna instance represents a single device identified by a cookie.
 * Multiple instances can coexist for multi-device scenarios.
 *
 * @note Non-copyable and non-movable.
 */
class vxdna : public vaccel<vxdna, vxdna_context>
{
public:
    /**
     * @brief Construct AMDXDNA device
     *
     * @param cookie Opaque device identifier from host
     * @param capset_id Capability set ID (VIRACCEL_CAPSET_ID_AMDXDNA)
     * @param callbacks User-provided callbacks for FD access and fences
     */
    vxdna(void *cookie, uint32_t capset_id, const struct vaccel_callbacks *callbacks)
        : vaccel<vxdna, vxdna_context>(cookie, capset_id, callbacks)
    {}

    ~vxdna() = default;

    // Non-copyable, non-movable
    vxdna(const vxdna&) = delete;
    vxdna& operator=(const vxdna&) = delete;
    vxdna(vxdna&&) = delete;
    vxdna& operator=(vxdna&&) = delete;

    // Bring base class method into scope
    using vaccel<vxdna, vxdna_context>::destroy_resource;

    /** @name Capability Set Interface
     * @{
     */

    /**
     * @brief Get capability set version and size
     *
     * @param[out] max_version Maximum supported version (optional)
     * @param[out] max_size Size of capset structure in bytes (optional)
     */
    void get_capset_info(uint32_t *max_version, uint32_t *max_size);

    /**
     * @brief Fill capability set buffer
     *
     * Copies the static capset structure to the provided buffer.
     *
     * @param capset_size Size of provided buffer
     * @param[out] capset_buf Buffer to receive capset data
     * @throws vaccel_error if buffer too small
     */
    void fill_capset(uint32_t capset_size, void *capset_buf);

    /** @} */

    /** @name Context Management
     * @{
     */

    /**
     * @brief Create a new execution context
     *
     * Duplicates the DRM FD and creates a vxdna_context.
     * Optionally sets client name for debugging.
     *
     * @param ctx_id Unique context identifier
     * @param ctx_flags Context creation flags (currently unused)
     * @param nlen Length of debug name (0 if none)
     * @param name Debug name string (nullptr if none)
     * @throws vaccel_error on failure
     */
    void create_ctx(uint32_t ctx_id, uint32_t ctx_flags, uint32_t nlen, const char *name);

    /**
     * @brief Destroy an execution context
     * @param ctx_id Context ID to destroy
     */
    void destroy_ctx(uint32_t ctx_id);

    /** @} */

    /** @name Resource Management
     * @{
     */

    /**
     * @brief Create resource from HOST3D blob
     *
     * Creates a DRM GEM-backed resource for host memory blobs.
     *
     * @param args Blob creation arguments
     * @throws vaccel_error on failure
     */
    void create_resource_from_blob(const struct vaccel_create_resource_blob_args *args);

    /**
     * @brief Destroy a resource (implementation hook)
     *
     * Called by base class during resource destruction.
     * Currently a no-op as cleanup is handled by BO destruction.
     *
     * @param res Resource to destroy
     */
    void destroy_resource(const std::shared_ptr<vaccel_resource> &res);

    /** @} */

    /** @name Command Processing
     * @{
     */

    /**
     * @brief Submit command buffer to context
     *
     * @param ctx Target context
     * @param ccmd Command buffer data
     * @param ccmd_size Size in bytes
     */
    void context_submit_ccmd(const std::shared_ptr<vxdna_context> &ctx, const void *ccmd, uint32_t ccmd_size);

    /**
     * @brief Submit fence for async completion
     *
     * Routes fence to the appropriate hardware context.
     *
     * @param ctx_id Context ID
     * @param flags Fence flags (currently unused)
     * @param ring_idx Hardware context handle
     * @param fence_id Guest fence ID
     * @throws vaccel_error if context not found
     */
    void submit_fence(uint32_t ctx_id, uint32_t flags, uint32_t ring_idx, uint64_t fence_id);

    /**
     * @brief Dispatch a single ccmd to its handler
     *
     * Looks up handler in dispatch table and invokes it.
     *
     * @param ctx Target context
     * @param hdr Command header with type and length
     * @throws vaccel_error on invalid command
     */
    void dispatch_ccmd(std::shared_ptr<vxdna_context> &ctx, const struct vdrm_ccmd_req *hdr);

    /** @} */

private:
    /**
     * @brief Static capability set for AMDXDNA devices
     */
    inline static constexpr struct vaccel_drm_capset capset = {
        .wire_format_version = 1,   /**< Protocol wire format version */
        .version_major = 1,         /**< Major version */
        .version_minor = 0,         /**< Minor version */
        .version_patchlevel = 0,    /**< Patch level */
        .context_type = VIRTACCEL_DRM_CONTEXT_AMDXDNA, /**< Context type ID */
        .pad = 0,                   /**< Padding for alignment */
    };
};


/**
 * @brief Get device context from cookie
 *
 * Helper function to retrieve the AMDXDNA device context for a given
 * device cookie.
 *
 * @param cookie Device cookie
 * @return Device context pointer (vxdna_device_ctx), or NULL if not found
 */
void *vxdna_device_get_ctx(void *cookie);

/**
 * @defgroup amdxdna_ccmd Command Processing
 * @brief Functions for processing virtio GPU command buffers
 * @{
 */

/**
 * @brief Process virtio GPU command buffer
 *
 * Processes a command buffer using the registered virtio_gpu_ccmd_process
 * callback. This function validates the device state and dispatches the
 * command to the appropriate handler.
 *
 * @param cookie Device cookie
 * @param cmd_buf Readonly command buffer
 * @param buf_size Size of command buffer in bytes
 * @return 0 on success, negative errno on failure
 * @retval -EINVAL Invalid command buffer or size
 * @retval -ENODEV Device not found
 * @retval -ENOTSUP Command callback not registered
 *
 * @note The command buffer must remain valid for the duration of this call.
 *       The function does not take ownership of the buffer.
 */
int vxdna_device_process_ccmd(void *cookie, const void *cmd_buf, size_t buf_size);

/**
 * @brief Exception wrapper for ccmd handlers
 *
 * Wraps a ccmd handler function to catch exceptions and write
 * appropriate error responses to the context's response buffer
 * before re-throwing.
 *
 * Usage:
 * @code
 * vxdna_ccmd_error_wrap(ctx, [&]() {
 *     ctx->create_bo(req);
 * });
 * @endcode
 *
 * Error handling:
 * - vaccel_error: Writes e.code() to response, re-throws
 * - std::exception: Writes -EIO to response, re-throws
 * - Unknown: Writes -EIO to response, throws std::runtime_error
 *
 * @tparam ContextType Context type (must have write_err_rsp method)
 * @tparam F Callable type (lambda, function, etc.)
 * @param ctx Context to write error response to
 * @param f Handler function to execute
 * @throws Re-throws caught exceptions after writing response
 */
template<typename ContextType, typename F> void
vxdna_ccmd_error_wrap(const std::shared_ptr<ContextType> &ctx, F &&f)
{
    try {
        f();
    } catch (const vaccel_error& e) {
        ctx->write_err_rsp(e.code());
        throw e;
    } catch (const std::exception& e) {
        ctx->write_err_rsp(-EIO);
        throw e;
    } catch (...) {
        ctx->write_err_rsp(-EIO);
        throw std::runtime_error("Unknown exception");
    }
}

/** @} */ /* end of amdxdna_ccmd */


#endif /* VACCEL_AMDXDNA_H */


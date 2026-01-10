// SPDX-License-Identifier: MIT
// Copyright (C) 2025, Advanced Micro Devices, Inc. All rights reserved.

/*
 * AMDXDNA Device Management
 * Provides device initialization, buffer object management, context handling,
 * command execution, and command dispatching for the AMDXDNA capset.
 */

#include <algorithm>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <filesystem>
#include <fstream>
#include <climits>
#include <sstream>
#include <sys/stat.h>
#include <thread>
#include <vector>

#include <drm/drm.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#ifdef __linux__
#include <sys/sysmacros.h>
#else
#error "non-Linux platform not supported"
#endif

#include "drm_local/amdxdna_accel.h"
#include "amdxdna_proto.h"

#include "vaccel_error.h"
#include "vaccel_amdxdna.h"
#include "../util/vxdna_debug.h"

/**
 * @brief Helper to close a DRM GEM handle (used for cleanup on exception)
 */
static void
close_gem_handle(int fd, uint32_t handle)
{
    if (handle != AMDXDNA_INVALID_BO_HANDLE) {
        struct drm_gem_close arg = {};
        arg.handle = handle;
        ioctl(fd, DRM_IOCTL_GEM_CLOSE, &arg);
    }
}

vxdna_bo::
vxdna_bo(int ctx_fd_in, const struct amdxdna_ccmd_create_bo_req *req)
         : m_opaque_handle(AMDXDNA_INVALID_BO_HANDLE)
{
    struct amdxdna_drm_get_bo_info bo_info = {};
    struct amdxdna_drm_create_bo args = {};
    int ret;

    m_ctx_fd = ctx_fd_in;
    m_bo_type = req->bo_type;
    m_size = req->size;
    m_map_size = 0;
    m_map_offset = 0;
    m_vaddr = AMDXDNA_INVALID_ADDR;
    m_xdna_addr = AMDXDNA_INVALID_ADDR;
    args.size = m_size;
    args.type = m_bo_type;
    vxdna_dbg("Create bo: ctx_fd=%d, type=%d, size=%lu", m_ctx_fd, m_bo_type, m_size);
    ret = ioctl(m_ctx_fd, DRM_IOCTL_AMDXDNA_CREATE_BO, &args);
    if (ret)
        VACCEL_THROW_MSG(-errno, "Create bo failed ret %d", ret);

    m_bo_handle = args.handle;
    bo_info.handle = m_bo_handle;
    ret = ioctl(m_ctx_fd, DRM_IOCTL_AMDXDNA_GET_BO_INFO, &bo_info);
    if (ret) {
        // Clean up the handle we just created before throwing
        close_gem_handle(m_ctx_fd, m_bo_handle);
        VACCEL_THROW_MSG(-errno, "Get bo info failed ret %d", ret);
    }

    m_map_offset = bo_info.map_offset;
    m_xdna_addr = bo_info.xdna_addr;
    m_vaddr = bo_info.vaddr;
    vxdna_dbg("Created bo: ctx_fd=%d, handle=%u, xdna_addr=%lu", m_ctx_fd, m_bo_handle, m_xdna_addr);
}

vxdna_bo::
vxdna_bo(const std::shared_ptr<vaccel_resource> &res, int ctx_fd_in,
         const struct amdxdna_ccmd_create_bo_req *req)
         : m_opaque_handle(res->get_opaque_handle())
{
    struct amdxdna_drm_get_bo_info bo_info = {};
    int ret;

    m_ctx_fd = ctx_fd_in;
    m_bo_type = req->bo_type;
    m_size = req->size;
    m_map_size = 0;
    const struct iovec *iovecs;
    auto num_iovs = res->get_iovecs(&iovecs);

    // Use vector to avoid VLA and potential stack overflow
    if (num_iovs > ((UINT32_MAX - sizeof(amdxdna_drm_va_tbl)) / sizeof(amdxdna_drm_va_entry)))
        VACCEL_THROW_MSG(-EINVAL, "Too many iovecs: %u", num_iovs);
    size_t buf_size = sizeof(amdxdna_drm_va_tbl) + sizeof(amdxdna_drm_va_entry) * num_iovs;
    std::vector<uint8_t> buf_vec(buf_size);
    auto tbl = reinterpret_cast<amdxdna_drm_va_tbl*>(buf_vec.data());
    tbl->udma_fd = -1;
    tbl->num_entries = num_iovs;
    for (uint32_t i = 0; i < num_iovs; i++) {
        tbl->va_entries[i].vaddr = static_cast<uint64_t>(reinterpret_cast<uintptr_t>(iovecs[i].iov_base));
        tbl->va_entries[i].len = static_cast<uint64_t>(iovecs[i].iov_len);
        m_map_size += tbl->va_entries[i].len;
    }

    // Track whether we created the BO (for cleanup on exception)
    bool has_created_bo = false;
    if (m_opaque_handle == AMDXDNA_INVALID_BO_HANDLE) {
        struct amdxdna_drm_create_bo args = {};
        args.vaddr = static_cast<uint64_t>(reinterpret_cast<uintptr_t>(buf_vec.data()));
        args.size = m_size;
        args.type = m_bo_type;
        ret = ioctl(m_ctx_fd, DRM_IOCTL_AMDXDNA_CREATE_BO, &args);
        if (ret)
            VACCEL_THROW_MSG(-errno, "Create bo failed ret %d, errno %d, %s", ret, -errno, strerror(errno));
        m_bo_handle = args.handle;
        has_created_bo = true;
    } else {
        m_bo_handle = m_opaque_handle;
    }

    bo_info.handle = m_bo_handle;
    ret = ioctl(m_ctx_fd, DRM_IOCTL_AMDXDNA_GET_BO_INFO, &bo_info);
    if (ret) {
        // Clean up the handle we created before throwing (only if we created it)
        if (has_created_bo) {
            close_gem_handle(m_ctx_fd, m_bo_handle);
        }
        VACCEL_THROW_MSG(-errno, "Get bo info failed ret %d", ret);
    }

    m_map_offset = bo_info.map_offset;
    m_xdna_addr = bo_info.xdna_addr;
    m_vaddr = bo_info.vaddr;

    if (m_map_offset == AMDXDNA_INVALID_ADDR) {
        // TODO: In case of HOST memory, there is no iovecs; however, the current amdxdna driver
        // requires BOs to be backed by a user pointer. As a result, we still need to mmap the BO
        // here to provide a user pointer to the driver. See the AMDXDNA BO creation ABI
        // (struct amdxdna_drm_create_bo and DRM_IOCTL_AMDXDNA_CREATE_BO) in
        // drm_local/amdxdna_accel.h. Once the driver supports HOST BOs without a user pointer,
        // this mmap requirement and the associated workaround can be removed.
        if (m_bo_type != AMDXDNA_BO_DEV) {
            // Clean up if we created the BO
            if (has_created_bo) {
                close_gem_handle(m_ctx_fd, m_bo_handle);
            }
            VACCEL_THROW_MSG(-EINVAL, "Non-DEV BO without map offset! handle=%u, type=%u", m_bo_handle, m_bo_type);
        }
        vxdna_dbg("No need to mmap for memory type, no map offset: handle=%u, xdna_addr=%lx, vaddr=%lx",
                  m_bo_handle, m_xdna_addr, m_vaddr);
        return;
    }

    if (!m_map_size)
        m_map_size = m_size;

    vxdna_dbg("mmap is required for handle: res_id=%u, handle=%u, opaque_handle=%d, vaddr=%lx, xdna_addr=%lx",
              res->get_res_id(), m_bo_handle, res->get_opaque_handle(), m_vaddr, m_xdna_addr);
    // mmap is required for non-dev BOs
    uint64_t resv_vaddr = 0, resv_size = 0, va_to_map = 0;
    void *resv_va = nullptr;
    int flags = MAP_SHARED | MAP_LOCKED;
    if (req->map_align) {
        resv_va = ::mmap(0, m_map_size + req->map_align, PROT_READ | PROT_WRITE,
                         MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (resv_va == MAP_FAILED) {
            // Clean up if we created the BO
            if (has_created_bo) {
                close_gem_handle(m_ctx_fd, m_bo_handle);
            }
            VACCEL_THROW_MSG(-ENOMEM, "Reserve vaddr range failed, map_align=%zu", req->map_align);
        }

        resv_size = m_map_size + req->map_align;
        resv_vaddr = reinterpret_cast<uint64_t>(resv_va);
        va_to_map = (resv_vaddr + req->map_align - 1) & ~(req->map_align - 1);
        flags |= MAP_FIXED;
    }
    void *va = ::mmap(reinterpret_cast<void *>(va_to_map), m_map_size, PROT_READ | PROT_WRITE,
                           flags, m_ctx_fd, m_map_offset);

    if (va == MAP_FAILED) {
        int saved_errno = errno;
        if (resv_va && resv_va != MAP_FAILED)
            ::munmap(resv_va, resv_size);
        // Clean up if we created the BO
        if (has_created_bo) {
            close_gem_handle(m_ctx_fd, m_bo_handle);
        }
        VACCEL_THROW_MSG(-saved_errno,
                         "Map bo failed, errno %d, %s, to map startaddr 0x%lx, map_offset 0x%lx, map_size 0x%lx",
                         saved_errno, strerror(saved_errno), va_to_map, m_map_offset, m_map_size);
    }
    m_vaddr = reinterpret_cast<uint64_t>(va);

    if (req->map_align && m_vaddr > resv_vaddr)
        ::munmap(resv_va, static_cast<size_t>(m_vaddr - resv_vaddr));
    if (resv_vaddr + resv_size > m_vaddr + m_map_size)
        munmap(reinterpret_cast<void *>(m_vaddr + m_map_size),
               static_cast<size_t>(resv_vaddr + resv_size - m_vaddr - m_map_size));
    vxdna_dbg("Created BO with resource: type=%u, res_id=%u", req->bo_type, req->res_id);
}

vxdna_bo::
~vxdna_bo() noexcept
{
    vxdna_dbg("vxdna Destroying bo: ctx_fd=%d, handle=%u, vaddr=%lx, map_size=%lu",
               m_ctx_fd, m_bo_handle, m_vaddr, m_map_size);
    if (m_vaddr != AMDXDNA_INVALID_ADDR)
        munmap(reinterpret_cast<void *>(m_vaddr), static_cast<size_t>(m_map_size));
    if (m_bo_handle != AMDXDNA_INVALID_BO_HANDLE) {
        struct drm_gem_close arg = {};
        arg.handle = m_bo_handle;
        vxdna_dbg("vxdna Close bo: ctx_fd=%d, handle=%u", m_ctx_fd, m_bo_handle);
        auto ret = ioctl(m_ctx_fd, DRM_IOCTL_GEM_CLOSE, &arg);
        if (ret)
            vxdna_err("Close vxdna bo failed ret %d", ret);
    }
}

void
vxdna_context::vxdna_hwctx::
poll_and_retire_pending(std::vector<std::shared_ptr<vaccel_fence>> &&copy_pending_fences)
{
    for (auto &fence : copy_pending_fences) {
        // Check stop flag before processing each fence
        if (m_stop_polling.load(std::memory_order_relaxed))
            break;

        uint64_t fence_sync_point = fence->get_sync_point();
        drm_syncobj_timeline_wait arg = {};
        arg.handles = reinterpret_cast<uintptr_t>(&m_syncobj_handle);
        arg.points = reinterpret_cast<uintptr_t>(&fence_sync_point);
        arg.timeout_nsec = fence->get_timeout_nsec();
        arg.count_handles = 1;
        /* Keep waiting even if not submitted yet */
        arg.flags = DRM_SYNCOBJ_WAIT_FLAGS_WAIT_FOR_SUBMIT;
        auto ret = ioctl(m_ctx_fd, DRM_IOCTL_SYNCOBJ_TIMELINE_WAIT, &arg);
        if (ret)
            vxdna_err("vxdna_hwctx::poll_and_retire_pending: Wait for fence failed ret %d, errno %d, %s, expect timeout: %ld",
                      ret, errno, strerror(errno), fence->get_timeout_nsec());
        // Fence is retired, write fence callback
        m_write_fence_callback(m_cookie, m_ctx_id, m_hwctx_handle, fence->get_id());
    }
}

vxdna_context::vxdna_hwctx::
vxdna_hwctx(const vxdna_context &ctx,
     const struct amdxdna_ccmd_create_ctx_req *req)
    : m_cookie(ctx.get_cookie())
    , m_write_fence_callback(ctx.get_callbacks()->write_context_fence)
    , m_ctx_fd(ctx.get_fd())
    , m_ctx_id(ctx.get_id())
{
    // Validate callback FIRST, before any resource allocation
    if (!m_write_fence_callback)
        VACCEL_THROW_MSG(-EINVAL, "Write fence callback not found");

    // Request XDNA driver to create a hardware context
    struct amdxdna_drm_create_hwctx args = {};
    args.max_opc = req->max_opc;
    args.num_tiles = req->num_tiles;
    args.mem_size = req->mem_size;
    args.qos_p = reinterpret_cast<uint64_t>(&req->qos_info);
    int ret = ioctl(m_ctx_fd, DRM_IOCTL_AMDXDNA_CREATE_HWCTX, &args);
    if (ret)
        VACCEL_THROW_MSG(-errno, "Create hw context failed ret %d, errno %d, %s", ret, errno, strerror(errno));

    if (args.handle == AMDXDNA_INVALID_CTX_HANDLE)
        VACCEL_THROW_MSG(-EINVAL, "Create hw context failed, returns invalid hwctx handle");

    m_hwctx_handle = args.handle;
    m_syncobj_handle = args.syncobj_handle;

    vxdna_dbg("Create hw context: ctx_fd=%d, max_opc=%u, num_tiles=%u, mem_size=%u",
              m_ctx_fd, req->max_opc, req->num_tiles, req->mem_size);

    // Start polling thread to retire fences
    m_stop_polling.store(false, std::memory_order_relaxed);
    try {
        m_polling_thread = std::thread([this]() {
            while (!m_stop_polling.load(std::memory_order_relaxed)) {
                std::vector<std::shared_ptr<vaccel_fence>> tmp_pending_fences;
                {
                    std::unique_lock<std::mutex> lock(m_fences_lock);
                    m_cv.wait(lock, [this] {
                        return m_stop_polling.load(std::memory_order_relaxed) || !m_pending_fences.empty();
                    });
                    if (m_stop_polling.load(std::memory_order_relaxed))
                        break;
                    tmp_pending_fences.swap(m_pending_fences);
                }
                poll_and_retire_pending(std::move(tmp_pending_fences));
            }
        });
    } catch (...) {
        vxdna_err("vxdna_hwctx ctor: failed to start polling thread.");
        // Clean up hwctx and syncobj
        struct drm_syncobj_destroy sync_arg = {};
        sync_arg.handle = m_syncobj_handle;
        ioctl(m_ctx_fd, DRM_IOCTL_SYNCOBJ_DESTROY, &sync_arg);

        struct amdxdna_drm_destroy_hwctx hwctx_arg = {};
        hwctx_arg.handle = m_hwctx_handle;
        ioctl(m_ctx_fd, DRM_IOCTL_AMDXDNA_DESTROY_HWCTX, &hwctx_arg);
        throw;
    }
}

vxdna_context::vxdna_hwctx::
~vxdna_hwctx() noexcept
{
    vxdna_dbg("HW context finishing: ctx_id=%u, hwctx_handle=%u", m_ctx_id, m_hwctx_handle);
    // Signal polling thread to stop
    m_stop_polling.store(true, std::memory_order_relaxed);
    m_cv.notify_all();

    // Wait for polling thread to finish
    if (m_polling_thread.joinable()) {
        m_polling_thread.join();
    }

    // Destroy sync object and hardware context
    if (m_syncobj_handle != AMDXDNA_INVALID_FENCE_HANDLE) {
        struct drm_syncobj_destroy arg = {};
        arg.handle = m_syncobj_handle;
        auto ret = ioctl(m_ctx_fd, DRM_IOCTL_SYNCOBJ_DESTROY, &arg);
        if (ret)
            vxdna_err("Destroy sync object failed ret %d", ret);
        m_syncobj_handle = AMDXDNA_INVALID_FENCE_HANDLE;
    }
    // Destroy hardware context
    if (m_hwctx_handle != AMDXDNA_INVALID_CTX_HANDLE) {
        struct amdxdna_drm_destroy_hwctx arg = {};
        arg.handle = m_hwctx_handle;
        auto ret = ioctl(m_ctx_fd, DRM_IOCTL_AMDXDNA_DESTROY_HWCTX, &arg);
        if (ret)
            vxdna_err("Close hw context failed ret %d", ret);
        m_hwctx_handle = AMDXDNA_INVALID_CTX_HANDLE;
    }
}

void
vxdna_context::vxdna_hwctx::
config(const struct amdxdna_ccmd_config_ctx_req *req)
{
    struct amdxdna_drm_config_hwctx args = {};
    args.handle = m_hwctx_handle;
    args.param_type = req->param_type;
    args.param_val_size = req->param_val_size;
    if (req->param_val_size)
        args.param_val = reinterpret_cast<uint64_t>(req->param_val);
    else
        args.param_val = req->inline_param;
    auto ret = ioctl(m_ctx_fd, DRM_IOCTL_AMDXDNA_CONFIG_HWCTX, &args);
    if (ret)
        VACCEL_THROW_MSG(-errno, "Config hw context failed ret %d, errno %d, %s", ret, errno, strerror(errno));
}

uint64_t
vxdna_context::vxdna_hwctx::
exec_cmd(const struct amdxdna_ccmd_exec_cmd_req *req)
{
    struct amdxdna_drm_exec_cmd args = {};
    args.hwctx = m_hwctx_handle;
    args.type = req->type;
    args.cmd_count = req->cmd_count;
    if (req->cmd_count > 1)
        args.cmd_handles = reinterpret_cast<uint64_t>(req->cmds_n_args);
    else
        args.cmd_handles = req->cmds_n_args[0];

    args.arg_count = req->arg_count;
    args.args = reinterpret_cast<uint64_t>(req->cmds_n_args + req->arg_offset);
    auto ret = ioctl(m_ctx_fd, DRM_IOCTL_AMDXDNA_EXEC_CMD, &args);
    if (ret)
        VACCEL_THROW_MSG(-errno, "Exec cmd failed ret %d", ret);
    return args.seq;
}

void
vxdna_context::vxdna_hwctx::
submit_fence(uint64_t fence_id)
{
    bool immediate_callback = false;
    {
        std::lock_guard<std::mutex> lock(m_fences_lock);
        if (!m_has_sync_point) {
            // Fence is not submitted yet, invoke callback outside lock
            immediate_callback = true;
        } else {
            auto fence = std::make_shared<vaccel_fence>(fence_id, m_sync_point, m_syncobj_handle, m_hwctx_handle, m_timeout_nsec);
            m_pending_fences.push_back(std::move(fence));
            m_has_sync_point = false;
            m_cv.notify_one();
        }
    }
    // Invoke callback outside lock to avoid deadlock
    if (immediate_callback) {
        m_write_fence_callback(m_cookie, m_ctx_id, m_hwctx_handle, fence_id);
    }
}

void
vxdna_context::
create_bo(const struct amdxdna_ccmd_create_bo_req *req)
{
    std::shared_ptr<vxdna_bo> xdna_bo;
    if (req->bo_type != AMDXDNA_BO_DEV) {
        auto res = get_device().get_resource(req->res_id);
        if (!res)
            VACCEL_THROW_MSG(-EINVAL, "Res: %u not found", req->res_id);
        xdna_bo = std::make_shared<vxdna_bo>(res, get_fd(), req);
    } else {
        xdna_bo = std::make_shared<vxdna_bo>(get_fd(), req);
    }

    struct amdxdna_ccmd_create_bo_rsp rsp = {};
    rsp.xdna_addr = xdna_bo->get_addr();
    rsp.handle = xdna_bo->get_handle();

    rsp.hdr.base.len = sizeof(rsp);
    auto resp_res = get_resp_res();
    if (!resp_res)
        VACCEL_THROW_MSG(-EINVAL, "Resp resource not found for context %u", get_id());
    (void)resp_res->write(req->hdr.rsp_off, &rsp, sizeof(rsp));
    add_bo(std::move(xdna_bo));
    vxdna_dbg("Created bo: handle=%u, xdna_addr=%lu", rsp.handle, rsp.xdna_addr);
}

void
vxdna_context::
add_bo(std::shared_ptr<vxdna_bo> &&bo)
{
    m_bo_table.insert(bo->get_handle(), std::move(bo));
}

void
vxdna_context::
remove_bo(uint32_t handle)
{
    vxdna_dbg("Removing bo: handle=%u", handle);
    m_bo_table.erase(handle);
}

int
vxdna_context::
export_resource_fd(const std::shared_ptr<vaccel_resource> &res)
{
    if (res->get_opaque_handle() < AMDXDNA_INVALID_BO_HANDLE)
        VACCEL_THROW_MSG(-EINVAL, "Resource is not opaque");
    struct drm_prime_handle args = {};
    args.handle = static_cast<uint32_t>(res->get_opaque_handle());
    args.flags = DRM_RDWR | DRM_CLOEXEC;
    args.fd = -1;
    auto ret = ioctl(get_fd(), DRM_IOCTL_PRIME_HANDLE_TO_FD, &args);
    if (ret)
        VACCEL_THROW_MSG(-errno, "Export resource fd failed ret %d, errno %d, %s", ret, errno, strerror(errno));
    return args.fd;
}

void
vxdna_context::
create_hwctx(const struct amdxdna_ccmd_create_ctx_req *req)
{
    struct amdxdna_ccmd_create_ctx_rsp rsp = {};
    auto hwctx = std::make_shared<vxdna_hwctx>(*this, req);
    rsp.hdr.base.len = sizeof(rsp);
    rsp.handle = hwctx->get_handle();
    m_hwctx_table.insert(hwctx->get_handle(), std::move(hwctx));
    write_rsp(&rsp, sizeof(rsp), req->hdr.rsp_off);
}

void
vxdna_context::
remove_hwctx(uint32_t handle)
{
    m_hwctx_table.erase(handle);
}

void
vxdna_context::
config_hwctx(const struct amdxdna_ccmd_config_ctx_req *req)
{
    auto hwctx = m_hwctx_table.lookup(req->handle);
    if (!hwctx)
        VACCEL_THROW_MSG(-EINVAL, "HW context not found handle %u", req->handle);
    hwctx->config(req);
}

void
vxdna_context::
submit_fence(uint32_t ring_idx, uint64_t fence_id)
{
    if (ring_idx == AMDXDNA_INVALID_CTX_HANDLE) {
        // there is fence for commands doesn't belong to any hardware context
        // in this case, just write the fence callback directly
        // TODO: in future, if there are async commands not related to any hardware
        // context, we can add a default hardware context per device context for it.
        get_callbacks()->write_context_fence(get_cookie(), get_id(), ring_idx, fence_id);
        return;
    }
    auto hwctx = m_hwctx_table.lookup(ring_idx);
    if (!hwctx)
        VACCEL_THROW_MSG(-EINVAL, "HW context not found ring_idx %u", ring_idx);
    hwctx->submit_fence(fence_id);
}

void
vxdna_context::
exec_cmd(const struct amdxdna_ccmd_exec_cmd_req *req)
{
    auto hwctx = m_hwctx_table.lookup(req->ctx_handle);
    if (!hwctx)
        VACCEL_THROW_MSG(-EINVAL, "HW context not found handle %u", req->ctx_handle);
    struct amdxdna_ccmd_exec_cmd_rsp rsp = {};
    rsp.seq = hwctx->exec_cmd(req);
    rsp.hdr.base.len = sizeof(rsp); 
    write_rsp(&rsp, sizeof(rsp), req->hdr.rsp_off);
}

void
vxdna_context::
wait_cmd(const struct amdxdna_ccmd_wait_cmd_req *req)
{
    auto hwctx = m_hwctx_table.lookup(req->ctx_handle);
    if (!hwctx)
        VACCEL_THROW_MSG(-EINVAL, "HW context not found handle %u", req->ctx_handle);
    hwctx->set_sync_point(req->seq, req->timeout_nsec);
    write_err_rsp(0); // Success
}

void
vxdna_context::
get_info(const struct amdxdna_ccmd_get_info_req *req)
{
    auto res = get_device().get_resource(req->info_res);
    if (!res)
        VACCEL_THROW_MSG(-EINVAL, "%s, Did not find info resource, res_id %u", __func__, req->info_res);

    struct amdxdna_drm_get_array array_args = {};
    struct amdxdna_ccmd_get_info_rsp rsp = {};
    struct amdxdna_drm_get_info args = {};
    uint32_t info_size;
    unsigned long cmd;
    void *pargs;
    int ret;

    if (req->num_element) {
        // Check for integer overflow
        if (req->size > UINT32_MAX / req->num_element)
            VACCEL_THROW_MSG(-EINVAL, "Info size overflow: size=%u, num_element=%u",
                             req->size, req->num_element);
        info_size = req->size * req->num_element;
        array_args.param = req->param;
        array_args.element_size = req->size;
        array_args.num_element = req->num_element;
        cmd = DRM_IOCTL_AMDXDNA_GET_ARRAY;
        pargs = &array_args;
    } else {
        info_size = req->size;
        args.param = req->param;
        args.buffer_size = req->size;
        cmd = DRM_IOCTL_AMDXDNA_GET_INFO;
        pargs = &args;
    }

    std::vector<uint8_t> info_buf(info_size);
    // Read argument data from resource
    res->read(0, info_buf.data(), info_size);
    if (req->num_element) {
        array_args.buffer = static_cast<uint64_t>(reinterpret_cast<uintptr_t>(info_buf.data()));
    } else {
        args.buffer = static_cast<uint64_t>(reinterpret_cast<uintptr_t>(info_buf.data()));
    }

    ret = ioctl(get_fd(), cmd, pargs);
    if (ret)
        VACCEL_THROW_MSG(-errno, "Get info failed ret %d, errno %d", ret, errno);

    if (cmd == DRM_IOCTL_AMDXDNA_GET_ARRAY) {
        rsp.num_element = array_args.num_element;
        rsp.size = array_args.element_size;
        if (array_args.element_size > 0 &&
            array_args.num_element > UINT32_MAX / array_args.element_size)
            VACCEL_THROW_MSG(-EINVAL, "Info size overflow: element_size=%u, num_element=%u",
                             array_args.element_size, array_args.num_element);
        info_size = array_args.element_size * array_args.num_element;
    } else {
        rsp.size = args.buffer_size;
        info_size = args.buffer_size;
    }

    res->write(0, info_buf.data(), info_size);
    rsp.hdr.base.len = sizeof(rsp);
    write_rsp(&rsp, sizeof(rsp), req->hdr.rsp_off);
}

void
vxdna_context::
read_sysfs(const struct amdxdna_ccmd_read_sysfs_req *req)
{
    struct amdxdna_ccmd_read_sysfs_rsp rsp = {};
    struct stat st = {};
    int ret;

    ret = fstat(get_fd(), &st);
    if (ret)
        VACCEL_THROW_MSG(-errno, "fstat failed ret %d, errno %d", ret, errno);

    std::ostringstream device_root_oss;
    device_root_oss << "/sys/dev/char/" << major(st.st_rdev) << ":" << minor(st.st_rdev) << "/device";
    std::string device_root = device_root_oss.str();

    std::ostringstream req_path_oss;
    req_path_oss << device_root << "/" << req->node_name;
    std::string req_path = req_path_oss.str();

    std::filesystem::path real_device_root_path, real_req_path;
    try {
        real_device_root_path = std::filesystem::canonical(device_root);
    } catch (const std::exception& e) {
        VACCEL_THROW_MSG(-EINVAL, "Failed to resolve device sysfs root: %s, error: %s", device_root.c_str(), e.what());
    }
    try {
        real_req_path = std::filesystem::canonical(req_path);
    } catch (const std::exception& e) {
        VACCEL_THROW_MSG(-EINVAL, "Failed to resolve requested sysfs path: %s, error: %s", req_path.c_str(), e.what());
    }

    // Ensure the resolved req_path is under device_root (including trailing slash)
    auto real_device_root_str = real_device_root_path.string();
    auto real_req_path_str = real_req_path.string();

    if (real_req_path_str.size() <= (real_device_root_str.size() + 1) ||
        real_req_path_str.compare(0, real_device_root_str.size(), real_device_root_str) != 0 ||
        real_req_path_str[real_device_root_str.size()] != '/') {
        VACCEL_THROW_MSG(-EINVAL, "Requested sysfs path %s is not under device sysfs root %s",
            real_req_path_str.c_str(), real_device_root_str.c_str());
    }

    // Open the sysfs file in binary mode and read the full contents into a buffer.
    std::ifstream file(real_req_path_str, std::ios::binary);
    if (!file.is_open())
        VACCEL_THROW_MSG(-ENOENT, "Failed to open sysfs file %s (file not found or permission denied)",
                         real_req_path_str.c_str());

    // Read all content into buffer
    std::vector<uint8_t> buffer((std::istreambuf_iterator<char>(file)),
                                std::istreambuf_iterator<char>());
    rsp.val_len = static_cast<int32_t>(buffer.size());
    rsp.hdr.base.len = sizeof(rsp) + rsp.val_len;
    write_rsp(&rsp, sizeof(rsp), req->hdr.rsp_off);
    write_rsp(buffer.data(), buffer.size(), req->hdr.rsp_off + sizeof(rsp));
}

void
vxdna_context::
write_err_rsp(int err)
{
    auto resp_res = get_resp_res();
    if (!resp_res)
        VACCEL_THROW_MSG(-EINVAL, "Resp resource not found for context %u", get_id());
    struct amdxdna_ccmd_rsp rsp = {};
    rsp.ret = err;
    rsp.base.len = sizeof(rsp);
    resp_res->write(0, &rsp, sizeof(rsp));
}

void
vxdna_context::
write_rsp(const void *rsp, size_t rsp_size, uint32_t rsp_off)
{
    auto resp_res = get_resp_res();
    if (!resp_res)
        VACCEL_THROW_MSG(-EINVAL, "Resp resource not found for context %u", get_id());
    resp_res->write(rsp_off, rsp, rsp_size);
}

int
vxdna_context::
get_blob_impl(const struct vaccel_create_resource_blob_args *args)
{
    vxdna_dbg("Getting blob: ctx_id=%u, ctx_fd=%d, blob_id=%ld, blob_size=%zu", get_id(), get_fd(), args->blob_id, args->size);
    struct amdxdna_drm_create_bo blob_args = {};
    blob_args.type = args->blob_id;//AMDXDNA_BO_SHMEM;
    blob_args.size = args->size;
    auto ret = ioctl(get_fd(), DRM_IOCTL_AMDXDNA_CREATE_BO, &blob_args);
    if (ret) {
        VACCEL_THROW_MSG(-errno, "Create blob failed ret %d, %d, %s, type %d, size %lld\n",
                         ret, -errno, strerror(errno), static_cast<uint32_t>(blob_args.type),
                         blob_args.size);
    }

    return blob_args.handle;
}

void
vxdna::
get_capset_info(uint32_t *max_version, uint32_t *max_size)
{
    /* Return max version if requested */
    if (max_version)
        *max_version = vxdna::capset.version_major;

    /* Return max size if requested */
    if (max_size)
        *max_size = sizeof(vxdna::capset);
}

void
vxdna::
fill_capset(uint32_t capset_size, void *capset_buf)
{
    if (capset_size < sizeof(vxdna::capset))
        VACCEL_THROW_MSG(-EINVAL, "Provided capset_size (%u) is smaller than expected (%zu)",
                         capset_size, sizeof(vxdna::capset));

    /* Copy the capset structure to user buffer */
    memcpy(capset_buf, &vxdna::capset, sizeof(vxdna::capset));
    vxdna_dbg("Capset structure filled for capset_id=%u, version=%u",
               get_capset_id(), vxdna::capset.version_major);
}

void
vxdna::
create_ctx(uint32_t ctx_id, [[maybe_unused]] uint32_t ctx_flags, uint32_t nlen,
           [[maybe_unused]] const char *name)
{
    vxdna_dbg("Creating execution ctx: ctx_id=%u, flags=0x%x, nlen=%u, name=%s",
              ctx_id, ctx_flags, nlen, name ? name : "(null)");
    // Pass reference to this device - context accesses cookie/callbacks through device
    auto ctx = std::make_shared<vxdna_context>(ctx_id, 8, *this);
#ifdef HAVE_DRM_SET_CLIENT_NAME
    if (name != nullptr && nlen > 0) {
        struct drm_set_client_name n = {
            .name_len = nlen,
            .name = reinterpret_cast<uint64_t>(name),
        };
        int ret = ioctl(ctx->get_fd(), DRM_IOCTL_SET_CLIENT_NAME, &n);
        if (ret < 0) {
            VACCEL_THROW_MSG(-errno, "Failed to set client name: ctx_id=%u", ctx_id);
        }
    }
#else
    // DRM_IOCTL_SET_CLIENT_NAME not available on this system
    if (name != nullptr && nlen > 0) {
        vxdna_info("DRM_IOCTL_SET_CLIENT_NAME not available on this system, ctx_id=%u, name=%s",
                  ctx_id, name);
    }
#endif
    add_ctx(ctx_id, std::move(ctx));
}

void
vxdna::
destroy_ctx(uint32_t ctx_id)
{
    vxdna_dbg("Destroying execution ctx: ctx_id=%u", ctx_id);
    remove_ctx(ctx_id);
}


void
vxdna::
create_resource_from_blob(const struct vaccel_create_resource_blob_args *args)
{
    auto ctx = get_ctx(args->ctx_id);
    if (!ctx)
        VACCEL_THROW_MSG(-EINVAL, "Context not found, ctx_id %u", args->ctx_id);
    int opaque_handle = ctx->get_blob(args);
    auto res = std::make_shared<vaccel_resource>(args->res_handle, args->size,
                                                 opaque_handle, args->ctx_id);
    add_resource(args->res_handle, std::move(res));
    vxdna_dbg("Created resource from blob: res_id=%u, opaque_handle=%d",
              args->res_handle, opaque_handle);
}

void
vxdna::
destroy_resource([[maybe_unused]] const std::shared_ptr<vaccel_resource> &res)
{
    // Required by vaccel<T>::destroy_resource
    // TODO: it is not required for now as guest xdna shim virtio
    // driver already ensures the sequence by first creating the resource blob
    // and then creating the BO, and it destroys them in reverse order.
}

// Forward declarations of handler functions (to be implemented elsewhere)
static void
vxdna_ccmd_nop([[maybe_unused]] vxdna &device,
               [[maybe_unused]] const std::shared_ptr<vxdna_context>& ctx,
               [[maybe_unused]] const void *hdr)
{
}

static void
vxdna_ccmd_init(vxdna &device, const std::shared_ptr<vxdna_context>& ctx,
                  const void *hdr)
{
    auto *req = static_cast<const struct amdxdna_ccmd_init_req *>(hdr);

    auto res = device.get_resource(req->rsp_res_id);
    if (!res)
        VACCEL_THROW_MSG(-EINVAL, "Resp resource not found");

    // Set the response resource for the context for the following ccmds to use
    ctx->set_resp_res(std::move(res));
}

static void
vxdna_ccmd_create_bo([[maybe_unused]] vxdna &device, const std::shared_ptr<vxdna_context>& ctx,
                     const void *hdr)
{
    auto *req = static_cast<const struct amdxdna_ccmd_create_bo_req *>(hdr);
    vxdna_ccmd_error_wrap(ctx, [&]() {
        ctx->create_bo(req);
    });
}

static void
vxdna_ccmd_destroy_bo([[maybe_unused]] vxdna &device, const std::shared_ptr<vxdna_context>& ctx,
                       const void *hdr)
{
    auto *req = static_cast<const struct amdxdna_ccmd_destroy_bo_req *>(hdr);

    vxdna_ccmd_error_wrap(ctx, [&]() {
        ctx->remove_bo(req->handle);
    });
}

static void
vxdna_ccmd_create_ctx([[maybe_unused]] vxdna &device, const std::shared_ptr<vxdna_context>& ctx,
                      const void *hdr)
{
    auto *req = static_cast<const struct amdxdna_ccmd_create_ctx_req *>(hdr);

    vxdna_ccmd_error_wrap(ctx, [&]() {
        ctx->create_hwctx(req);
    });
}

static void
vxdna_ccmd_destroy_ctx([[maybe_unused]] vxdna &device, const std::shared_ptr<vxdna_context>& ctx,
                       const void *hdr)
{
    auto *req = static_cast<const struct amdxdna_ccmd_destroy_ctx_req *>(hdr);

    vxdna_ccmd_error_wrap(ctx, [&]() {
        ctx->remove_hwctx(req->handle);
    });
}

static void
vxdna_ccmd_config_ctx([[maybe_unused]] vxdna &device, const std::shared_ptr<vxdna_context>& ctx,
                      const void *hdr)
{
    auto *req = static_cast<const struct amdxdna_ccmd_config_ctx_req *>(hdr);

    vxdna_ccmd_error_wrap(ctx, [&]() {
        ctx->config_hwctx(req);
    });
}

static void
vxdna_ccmd_exec_cmd([[maybe_unused]] vxdna &device, const std::shared_ptr<vxdna_context>& ctx,
                    const void *hdr)
{
    auto *req = static_cast<const struct amdxdna_ccmd_exec_cmd_req *>(hdr);

    vxdna_ccmd_error_wrap(ctx, [&]() {
        ctx->exec_cmd(req);
    });
}

static void
vxdna_ccmd_wait_cmd([[maybe_unused]] vxdna &device, const std::shared_ptr<vxdna_context>& ctx,
                    const void *hdr)
{
    auto *req = static_cast<const struct amdxdna_ccmd_wait_cmd_req *>(hdr);

    vxdna_ccmd_error_wrap(ctx, [&]() {
        ctx->wait_cmd(req);
    });
}

static void
vxdna_ccmd_get_info([[maybe_unused]] vxdna &device, const std::shared_ptr<vxdna_context>& ctx,
                    const void *hdr)
{
    auto *req = static_cast<const struct amdxdna_ccmd_get_info_req *>(hdr);
    vxdna_ccmd_error_wrap(ctx, [&]() {
        ctx->get_info(req);
    });
}

static void
vxdna_ccmd_read_sysfs([[maybe_unused]] vxdna &device, const std::shared_ptr<vxdna_context>& ctx,
                      const void *hdr)
{
    auto *req = static_cast<const struct amdxdna_ccmd_read_sysfs_req *>(hdr);
    vxdna_ccmd_error_wrap(ctx, [&]() {
        ctx->read_sysfs(req);
    });
}

// Definition of the CCMD handler type for AMDXDNA
using amdxdna_ccmd_handler_t = void(*)(vxdna &device,
    const std::shared_ptr<vxdna_context>& ctx,
    const void *hdr);

// Structure describing each command handler entry
struct amdxdna_ccmd_dispatch_entry {
    const char *name;
    amdxdna_ccmd_handler_t handler;
    uint32_t size;
};

// Macro to statically define and initialize amdxdna_ccmd_dispatch_entry with a command name.
// The macro accepts the command name (without quotes) and expands to:
// { #name, amdxdna_ccmd_<name>, sizeof(struct amdxdna_ccmd_<name>_req) }
#define AMD_CCMD_DISPATCH_ENTRY(name) \
    { #name, vxdna_ccmd_##name, sizeof(struct amdxdna_ccmd_##name##_req) }

constexpr size_t AMDXDNA_CCMD_COUNT = 11;
constexpr std::array<amdxdna_ccmd_dispatch_entry, AMDXDNA_CCMD_COUNT> amdxdna_ccmd_dispatch_table = {{
    AMD_CCMD_DISPATCH_ENTRY(nop),
    AMD_CCMD_DISPATCH_ENTRY(init),
    AMD_CCMD_DISPATCH_ENTRY(create_bo),
    AMD_CCMD_DISPATCH_ENTRY(destroy_bo),
    AMD_CCMD_DISPATCH_ENTRY(create_ctx),
    AMD_CCMD_DISPATCH_ENTRY(destroy_ctx),
    AMD_CCMD_DISPATCH_ENTRY(config_ctx),
    AMD_CCMD_DISPATCH_ENTRY(exec_cmd),
    AMD_CCMD_DISPATCH_ENTRY(wait_cmd),
    AMD_CCMD_DISPATCH_ENTRY(get_info),
    AMD_CCMD_DISPATCH_ENTRY(read_sysfs),
}};

void
vxdna::
dispatch_ccmd(std::shared_ptr<vxdna_context> &ctx, const struct vdrm_ccmd_req *hdr)
{
    if (!hdr->cmd || hdr->cmd > amdxdna_ccmd_dispatch_table.size())
        VACCEL_THROW_MSG(-EINVAL, "invalid cmd: %u", hdr->cmd);

    const struct amdxdna_ccmd_dispatch_entry *ccmd = &amdxdna_ccmd_dispatch_table[hdr->cmd - 1];

    if (!ccmd->handler) {
        VACCEL_THROW_MSG(-EINVAL, "no handler: %u", hdr->cmd);
    }

    if (hdr->len < ccmd->size)
        VACCEL_THROW_MSG(-EINVAL, "request length is smaller than the expected size: %u < %u",
                         hdr->len, ccmd->size);

    vxdna_dbg("%s: hdr={cmd=%u, len=%u, seqno=%u, rsp_off=0x%x)", ccmd->name, hdr->cmd,
              hdr->len, hdr->seqno, hdr->rsp_off);

    /* copy request to let ccmd handler patch command in-place */
    size_t ccmd_size = std::max(ccmd->size, hdr->len);
    std::vector<uint8_t> buf(ccmd_size);
    memcpy(buf.data(), hdr, hdr->len);

    /* Request length from the guest can be smaller than the expected
     * size, ie. newer host and older guest, we need to zero initialize
     * the new fields at the end.
     */
    if (ccmd->size > hdr->len)
        memset(&buf[hdr->len], 0, ccmd->size - hdr->len);

    struct vdrm_ccmd_req *ccmd_hdr = reinterpret_cast<struct vdrm_ccmd_req *>(buf.data());
    ccmd->handler(*this, ctx, static_cast<const void *>(ccmd_hdr));
}

void
vxdna::
submit_fence(uint32_t ctx_id, uint32_t flags, uint32_t ring_idx, uint64_t fence_id)
{
    vxdna_dbg("Submitting fence: ctx_id=%u, flags=0x%x, ring_idx=%u, fence_id=%lu",
              ctx_id, flags, ring_idx, fence_id);
    auto ctx = get_ctx(ctx_id);
    if (!ctx)
        VACCEL_THROW_MSG(-EINVAL, "Context not found");
    ctx->submit_fence(ring_idx, fence_id);
}

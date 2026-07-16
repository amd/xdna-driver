// SPDX-License-Identifier: MIT
// Copyright (C) 2025 - 2026, Advanced Micro Devices, Inc. All rights reserved.

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

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
#include <limits>
#include <unistd.h>
#include <sstream>
#include <sys/stat.h>
#include <system_error>
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

namespace {

/* Host driver notifies FW in dev_mem_size chunks (typically 64 MiB). UVA must align. */
constexpr size_t k_dev_heap_uva_align = 64UL << 20;

size_t
page_size()
{
    static size_t ps = 0;

    if (!ps) {
        long r = sysconf(_SC_PAGESIZE);

        ps = (r > 0) ? static_cast<size_t>(r) : 4096;
    }
    return ps;
}

size_t
page_roundup(size_t size)
{
    const size_t ps = page_size();

    return (size + ps - 1) & ~(ps - 1);
}

/*
 * Guest CCMD requests may carry inline payload after the fixed header.  The
 * dispatch path copies hdr.len bytes into host memory; param_val_size and
 * arg_offset/arg_count must stay within that snapshot or ioctl handlers would
 * copy_from_user() past the end of the request buffer.
 */
void
validate_config_ctx_inline_payload(const struct amdxdna_ccmd_config_ctx_req *req)
{
    constexpr size_t inline_off =
        offsetof(struct amdxdna_ccmd_config_ctx_req, param_val);
    const uint32_t hdr_len = req->hdr.len;
    const size_t avail = hdr_len - inline_off;

    if (req->param_val_size > avail)
        VACCEL_THROW_MSG(-EINVAL,
                         "config_ctx param_val_size %u exceeds inline payload %zu bytes "
                         "(hdr.len %u)",
                         req->param_val_size, avail, hdr_len);
}

void
validate_exec_cmd_inline_payload(const struct amdxdna_ccmd_exec_cmd_req *req)
{
    constexpr size_t inline_off =
        offsetof(struct amdxdna_ccmd_exec_cmd_req, cmds_n_args);
    const uint32_t hdr_len = req->hdr.len;
    const size_t ndwords = (hdr_len - inline_off) / sizeof(uint32_t);

    if (!req->cmd_count)
        VACCEL_THROW_MSG(-EINVAL, "exec_cmd cmd_count is zero (hdr.len %u)", hdr_len);

    if (req->cmd_count > ndwords)
        VACCEL_THROW_MSG(-EINVAL,
                         "exec_cmd cmd_count %u exceeds inline cmds_n_args dwords %zu "
                         "(hdr.len %u)",
                         req->cmd_count, ndwords, hdr_len);

    if (!req->arg_count)
        return;

    const uint64_t args_end = static_cast<uint64_t>(req->arg_offset) +
                              static_cast<uint64_t>(req->arg_count);

    if (args_end > ndwords)
        VACCEL_THROW_MSG(-EINVAL,
                         "exec_cmd arg_offset %u + arg_count %u exceeds inline dwords "
                         "%zu (hdr.len %u)",
                         req->arg_offset, req->arg_count, ndwords, hdr_len);
}

/*
 * VirtGPU registers device-wide blobs (response buffer, guest iovec backing for
 * userptr CREATE_BO, etc.) under ctx 0 at open / RESOURCE_CREATE_BLOB on the
 * platform DRM fd.  App CCMDs run on ring_idx >= 1.  Allow those platform
 * resources to be used from any execution context on the same device, but still
 * reject ids registered by another app context (ctx >= 1).
 */
static constexpr uint32_t k_platform_ctx_id = 0;

/*
 * Resources live in a single per-device table addressable by any context that
 * shares the cookie (e.g. multiple guest user processes inside the same VM).
 * Each resource records its registering ctx_id on creation; guest-controlled
 * lookups must reject ids owned by a different app context so one context
 * cannot install another context's iovec-backed buffer as its response buffer,
 * source/sink for GET_INFO, or backing for CREATE_BO.  Platform (ctx 0)
 * resources are shared by design.  On mismatch we throw -EACCES; the ccmd
 * error wrapper (or the C-API boundary for INIT) turns that into a logged
 * error response.
 */
std::shared_ptr<vaccel_resource>
lookup_resource_for_ctx(vxdna &device, uint32_t res_id, uint32_t caller_ctx_id,
                        const char *purpose)
{
    auto res = device.get_resource(res_id);
    if (!res)
        VACCEL_THROW_MSG(-ENOENT, "%s: resource %u not found (ctx %u)",
                         purpose, res_id, caller_ctx_id);

    const uint32_t owner_ctx_id = res->get_ctx_id();
    if (owner_ctx_id != caller_ctx_id &&
        owner_ctx_id != k_platform_ctx_id)
        VACCEL_THROW_MSG(-EACCES,
                         "%s: resource %u not owned by ctx %u (owner ctx %u)",
                         purpose, res_id, caller_ctx_id, owner_ctx_id);
    return res;
}

/*
 * The node_name flexible-array member has no built-in NUL guarantee.  When
 * hdr.len > sizeof(request), the dispatch copy fills the whole buffer with
 * guest bytes (no trailing zero pad), so streaming req->node_name into an
 * ostringstream would read past the request copy until it hit a stray 0 in
 * adjacent host heap.  Require an explicit terminator inside hdr.len.
 */
void
validate_read_sysfs_inline_payload(const struct amdxdna_ccmd_read_sysfs_req *req)
{
    constexpr size_t inline_off =
        offsetof(struct amdxdna_ccmd_read_sysfs_req, node_name);
    const uint32_t hdr_len = req->hdr.len;
    const size_t max_name = hdr_len - inline_off;

    if (max_name == 0)
        VACCEL_THROW_MSG(-EINVAL,
                         "read_sysfs node_name is empty (hdr.len %u)", hdr_len);

    if (::strnlen(req->node_name, max_name) == max_name)
        VACCEL_THROW_MSG(-EINVAL,
                         "read_sysfs node_name not NUL-terminated within %zu bytes "
                         "(hdr.len %u)",
                         max_name, hdr_len);
}

/*
 * Helpers for iov_table_overlaps(): detect whether the coalesce destination
 * [base, base+len) intersects any guest iovec before mremap(old_size=0).  Overlap
 * would make dest and source the same VA range; mremap would fail (typically
 * EINVAL) — we fail early with a clear error instead of inside mremap_dup_to_fixed.
 */
bool
uintptr_range_end(uintptr_t base, size_t len, uintptr_t *end_out)
{
    if (len > std::numeric_limits<uintptr_t>::max() || base > std::numeric_limits<uintptr_t>::max() - len)
        return false;
    *end_out = base + len;
    return true;
}

bool
uintptr_ranges_overlap(uintptr_t a0, uintptr_t a1, uintptr_t b0, uintptr_t b1)
{
    return a0 < b1 && b0 < a1;
}

/*
 * True if coalesce destination [base, base+len) intersects any iovec (mremap source).
 * Called from mmap_coalesce_backing() / mmap_aligned_coalesce_backing() immediately
 * after reserving the arena and before mremap_iovs_into_coalesce().  On arithmetic
 * overflow, returns true so callers fail closed.
 */
bool
iov_table_overlaps(uintptr_t base, size_t len, const struct iovec *iov, uint32_t n)
{
    uintptr_t end;

    if (!uintptr_range_end(base, len, &end))
        return true;

    for (uint32_t i = 0; i < n; i++) {
        uintptr_t a = reinterpret_cast<uintptr_t>(iov[i].iov_base);
        uintptr_t b;

        if (!uintptr_range_end(a, iov[i].iov_len, &b))
            return true;
        if (uintptr_ranges_overlap(base, end, a, b))
            return true;
    }
    return false;
}

void *
mmap_coalesce_backing(size_t total, const struct iovec *iov, uint32_t n)
{
    for (int attempt = 0; attempt < 24; attempt++) {
        void *p = mmap(nullptr, total, PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

        if (p == MAP_FAILED)
            VACCEL_THROW_MSG(-errno, "mmap for coalesced userptr BO failed");

        /* Pre-mremap: coalesce VA must not overlap any iov_base slice. */
        if (!iov_table_overlaps(reinterpret_cast<uintptr_t>(p), total, iov, n))
            return p;
        munmap(p, total);
    }
    VACCEL_THROW_MSG(-ENOMEM,
                     "Could not reserve VA for coalesced userptr BO without overlapping iovecs");
}

/*
 * Like mmap_coalesce_backing(), but after mmap trims to a @uva_align-aligned
 * subrange of length @total (head/tail munmap). Required for AMDXDNA_BO_DEV_HEAP
 * so MAP_HOST_BUFFER sees a 64 MiB-aligned user VA (matches kernel dev_mem_size).
 */
void *
mmap_aligned_coalesce_backing(size_t total, const struct iovec *iov, uint32_t n,
                               size_t uva_align)
{
    const size_t ps = page_size();

    if (uva_align < ps || (uva_align % ps) != 0)
        VACCEL_THROW_MSG(-EINVAL, "UVA alignment %zu must be a multiple of page size %zu",
                         uva_align, ps);

    const size_t slack = uva_align - 1;
    size_t map_sz = total + slack;

    if (map_sz < total)
        VACCEL_THROW_MSG(-EINVAL, "aligned coalesce map size overflow");

    map_sz = (map_sz + ps - 1) / ps * ps;

    void *p = mmap(nullptr, map_sz, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

    if (p == MAP_FAILED)
        VACCEL_THROW_MSG(-errno, "mmap for aligned coalesced userptr BO failed");

    const uintptr_t pb = reinterpret_cast<uintptr_t>(p);
    const uintptr_t aligned = (pb + uva_align - 1) & ~(uva_align - 1);

    if (aligned < pb || aligned + total < aligned ||
        aligned + total > pb + map_sz) {
        munmap(p, map_sz);
        VACCEL_THROW_MSG(-EINVAL, "aligned coalesce internal size error");
    }

    /* Pre-mremap: aligned coalesce window must not overlap any iov slice. */
    if (n && iov_table_overlaps(aligned, total, iov, n)) {
        munmap(p, map_sz);
        VACCEL_THROW_MSG(-ENOMEM,
                         "64MiB-aligned coalesce VA overlaps guest iovec mappings; retry BO create");
    }

    const uintptr_t tail = aligned + total;
    const uintptr_t end = pb + map_sz;

    if (aligned > pb) {
        if (munmap(p, aligned - pb) != 0) {
            munmap(p, map_sz);
            VACCEL_THROW_MSG(-errno, "munmap head trim for aligned coalesce failed");
        }
    }

    if (tail < end) {
        if (munmap(reinterpret_cast<void *>(tail), end - tail) != 0) {
            munmap(reinterpret_cast<void *>(aligned), end - aligned);
            VACCEL_THROW_MSG(-errno, "munmap tail trim for aligned coalesce failed");
        }
    }

    return reinterpret_cast<void *>(aligned);
}

void
mremap_dup_to_fixed(void *old_base, size_t len, void *new_base)
{
    /*
     * Only MAP_SHARED (or other shareable) sources are supported: old_size==0
     * duplicates the same physical pages at new_base while keeping the original
     * mapping. Private anonymous / bounce buffers fail with EINVAL (no fallback).
     */
    void *ret = mremap(old_base, 0, len, MREMAP_MAYMOVE | MREMAP_FIXED, new_base);

    if (ret == MAP_FAILED)
        VACCEL_THROW_MSG(-errno,
                         "mremap coalesce failed (need shareable mapping, old_size=0): "
                         "old=%p len=%zu new=%p",
                         old_base, len, new_base);
}

struct coalesce_backing {
    void *va;
    size_t len;
};

/*
 * Guest-backed userptr BOs (SHARE, CMD, …): one iovec uses backing UVA directly;
 * multiple iovs reserve one coalesced VMA and duplicate slices with mremap.
 * DEV_HEAP chunks use a slice of the context's 64 MiB-aligned arena instead.
 */
coalesce_backing
reserve_coalesce_backing(const struct iovec *iov, uint32_t n)
{
    if (!n)
        VACCEL_THROW_MSG(-EINVAL, "Resource has no iovecs for user-pointer BO create");

    const size_t ps = page_size();
    size_t total = 0;

    for (uint32_t i = 0; i < n; i++) {
        const uintptr_t base = reinterpret_cast<uintptr_t>(iov[i].iov_base);
        const size_t len = iov[i].iov_len;

        if ((base % ps) != 0 || (len % ps) != 0)
            VACCEL_THROW_MSG(-EINVAL,
                             "iovec %u must be page-aligned for userptr BO (base=0x%lx len=%zu)",
                             i, static_cast<unsigned long>(base), len);
        if (total + len < total)
            VACCEL_THROW_MSG(-EINVAL, "iovec total size overflows size_t");
        total += len;
    }

    void *va = mmap_coalesce_backing(total, iov, n);

    return { va, total };
}

void
mremap_iovs_into_coalesce(void *coalesce, const struct iovec *iov, uint32_t n)
{
    size_t off = 0;

    for (uint32_t i = 0; i < n; i++) {
        void *oldb = iov[i].iov_base;
        size_t len = iov[i].iov_len;
        void *newb = static_cast<char *>(coalesce) + off;

        mremap_dup_to_fixed(oldb, len, newb);
        off += len;
    }
}

void
close_gem_handle(int fd, uint32_t handle)
{
    if (handle != AMDXDNA_INVALID_BO_HANDLE) {
        struct drm_gem_close arg = {};
        arg.handle = handle;
        ioctl(fd, DRM_IOCTL_GEM_CLOSE, &arg);
    }
}

} // namespace

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
    m_iov_bytes = 0;
    m_map_offset = 0;
    m_vaddr = AMDXDNA_INVALID_ADDR;
    m_xdna_addr = AMDXDNA_INVALID_ADDR;

    if (m_bo_type != AMDXDNA_BO_DEV)
        VACCEL_THROW_MSG(-EINVAL,
                         "Device-local create supports AMDXDNA_BO_DEV only, not type %u",
                         m_bo_type);

    args.size = m_size;
    args.type = m_bo_type;
    vxdna_dbg("Create bo: ctx_fd=%d, type=%d, size=%lu", m_ctx_fd, m_bo_type, m_size);
    ret = ioctl(m_ctx_fd, DRM_IOCTL_AMDXDNA_CREATE_BO, &args);
    if (ret)
        VACCEL_THROW_MSG(-errno, "Create bo failed ret %d, errno %d, %s",
                         ret, errno, strerror(errno));

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

void *
vxdna_context::
ensure_heap_arena()
{
    if (m_heap_arena_va)
        return m_heap_arena_va;

    const size_t arena_cap = static_cast<size_t>(HEAP_MAX_SIZE);

    m_heap_arena_va = mmap_aligned_coalesce_backing(arena_cap, nullptr, 0,
                                                    k_dev_heap_uva_align);
    m_heap_arena_cap = arena_cap;
    vxdna_dbg("Context %u: heap arena at %p size 0x%zx", get_id(), m_heap_arena_va,
              m_heap_arena_cap);
    return m_heap_arena_va;
}

void
vxdna_context::
release_heap_arena() noexcept
{
    if (!m_heap_arena_va || !m_heap_arena_cap)
        return;
    if (munmap(m_heap_arena_va, m_heap_arena_cap) != 0)
        vxdna_err("munmap heap arena failed errno %d", errno);
    m_heap_arena_va = nullptr;
    m_heap_arena_cap = 0;
}

vxdna_bo::
vxdna_bo(const std::shared_ptr<vaccel_resource> &res, vxdna_context &ctx,
         const struct amdxdna_ccmd_create_bo_req *req)
         : m_opaque_handle(res->get_opaque_handle())
{
    struct amdxdna_drm_get_bo_info bo_info = {};
    int ret;

    m_ctx_fd = ctx.get_fd();
    m_bo_type = req->bo_type;
    m_size = req->size;
    m_iov_bytes = 0;
    m_map_offset = 0;
    m_vaddr = AMDXDNA_INVALID_ADDR;
    m_xdna_addr = AMDXDNA_INVALID_ADDR;

    if (m_bo_type == AMDXDNA_BO_DEV)
        VACCEL_THROW_MSG(-EINVAL,
                         "AMDXDNA_BO_DEV must use device-local create (no resource/iovec)");

    const struct iovec *iovecs = nullptr;
    auto num_iovs = res->get_iovecs(&iovecs);

    bool created_here = false;
    bool use_raw_iovs = false;
    if (m_opaque_handle == AMDXDNA_INVALID_BO_HANDLE) {
        const bool heap_chunk = (m_bo_type == AMDXDNA_BO_DEV_HEAP);
        void *coalesce = nullptr;
        size_t total = 0;

        for (uint32_t i = 0; i < num_iovs; i++) {
            if (total + iovecs[i].iov_len < total)
                VACCEL_THROW_MSG(-EINVAL, "iovec total size overflows size_t");
            total += iovecs[i].iov_len;
        }

        if (heap_chunk) {
            if (m_size != static_cast<uint64_t>(total))
                VACCEL_THROW_MSG(-EINVAL,
                                 "DEV_HEAP size 0x%lx must equal iovec total 0x%zx",
                                 static_cast<unsigned long>(m_size), total);

            void *arena = ctx.ensure_heap_arena();
            const uint64_t off = ctx.m_heap_committed;

            if (off + m_size > vxdna_context::HEAP_MAX_SIZE)
                VACCEL_THROW_MSG(-ENOSPC,
                                 "heap chunk at 0x%llx + 0x%llx exceeds arena 0x%llx",
                                 static_cast<unsigned long long>(off),
                                 static_cast<unsigned long long>(m_size),
                                 static_cast<unsigned long long>(
                                     vxdna_context::HEAP_MAX_SIZE));
            coalesce = static_cast<char *>(arena) + static_cast<size_t>(off);
        } else if (num_iovs == 1) {
            const uintptr_t base = reinterpret_cast<uintptr_t>(iovecs[0].iov_base);
            const size_t len = iovecs[0].iov_len;
            const size_t ps = page_size();

            if ((base % ps) != 0 || (len % ps) != 0)
                VACCEL_THROW_MSG(-EINVAL,
                                 "single iovec must be page-aligned (base=0x%lx len=%zu)",
                                 static_cast<unsigned long>(base), len);
            coalesce = iovecs[0].iov_base;
            total = len;
        } else {
            auto backing = reserve_coalesce_backing(iovecs, num_iovs);
            coalesce = backing.va;
            total = backing.len;
            m_coalesce_va = coalesce;
            m_coalesce_len = total;
        }

        const size_t pin_len = page_roundup(m_size);
        if (pin_len > total)
            VACCEL_THROW_MSG(-EINVAL,
                             "create_bo pin size 0x%zx exceeds resource backing 0x%zx "
                             "(bo size 0x%lx)",
                             pin_len, total, static_cast<unsigned long>(m_size));

        if (heap_chunk || num_iovs > 1) {
            try {
                mremap_iovs_into_coalesce(coalesce, iovecs, num_iovs);
            } catch (...) {
                if (m_coalesce_va && m_coalesce_len) {
                    munmap(m_coalesce_va, m_coalesce_len);
                    m_coalesce_va = nullptr;
                    m_coalesce_len = 0;
                }
                /*
                 * Coalescing needs shareable guest memory: mremap(old_size=0)
                 * only duplicates MAP_SHARED slices. When QEMU is started
                 * without share=on the slices are private-anon and mremap fails.
                 * Do not fail here -- for heap chunks too: fall back to handing
                 * the driver the raw scattered iovecs as a multi-entry va_tbl
                 * and let CREATE_BO be the arbiter. With an IOMMU (force_iova)
                 * the driver coalesces the pages into one device address -- for
                 * a heap into its reserved heap IOVA region; without one
                 * (SVA/PA) CREATE_BO fails and so does BO creation.
                 */
                use_raw_iovs = true;
                vxdna_dbg("coalesce failed (guest mem not shareable); falling "
                          "back to %u raw iovecs for BO create", num_iovs);
            }
        }
        m_iov_bytes = total;

        uint32_t n_entries = 1;
        if (use_raw_iovs) {
            /* Count entries needed to cover pin_len (truncate the last). */
            m_vaddr = AMDXDNA_INVALID_ADDR;
            size_t remaining = pin_len;
            n_entries = 0;
            for (uint32_t i = 0; i < num_iovs && remaining; i++) {
                size_t l = iovecs[i].iov_len < remaining ? iovecs[i].iov_len : remaining;
                remaining -= l;
                n_entries++;
            }
        } else {
            m_vaddr = static_cast<uint64_t>(reinterpret_cast<uintptr_t>(coalesce));
        }

        size_t buf_size = sizeof(amdxdna_drm_va_tbl) +
                          static_cast<size_t>(n_entries) * sizeof(amdxdna_drm_va_entry);
        // Back the va_tbl with uint64_t so the storage is 8-byte aligned for its
        // u64 fields; a uint8_t vector only guarantees byte alignment, and
        // reinterpreting it as amdxdna_drm_va_tbl would be UB on strict-align archs.
        std::vector<uint64_t> buf_vec((buf_size + sizeof(uint64_t) - 1) / sizeof(uint64_t));
        auto tbl = reinterpret_cast<amdxdna_drm_va_tbl *>(buf_vec.data());

        tbl->udma_fd = -1;
        tbl->num_entries = n_entries;
        if (use_raw_iovs) {
            size_t remaining = pin_len;
            for (uint32_t i = 0; i < n_entries; i++) {
                size_t l = iovecs[i].iov_len < remaining ? iovecs[i].iov_len : remaining;
                tbl->va_entries[i].vaddr =
                    static_cast<uint64_t>(reinterpret_cast<uintptr_t>(iovecs[i].iov_base));
                tbl->va_entries[i].len = static_cast<uint64_t>(l);
                remaining -= l;
            }
        } else {
            tbl->va_entries[0].vaddr =
                static_cast<uint64_t>(reinterpret_cast<uintptr_t>(coalesce));
            tbl->va_entries[0].len = static_cast<uint64_t>(pin_len);
        }

        struct amdxdna_drm_create_bo args = {};
        args.vaddr = static_cast<uint64_t>(reinterpret_cast<uintptr_t>(buf_vec.data()));
        args.size = m_size;
        args.type = m_bo_type;
        ret = ioctl(m_ctx_fd, DRM_IOCTL_AMDXDNA_CREATE_BO, &args);
        if (ret) {
            if (m_coalesce_va && m_coalesce_len) {
                munmap(m_coalesce_va, m_coalesce_len);
                m_coalesce_va = nullptr;
                m_coalesce_len = 0;
            }
            VACCEL_THROW_MSG(-errno, "Create bo failed ret %d, errno %d, %s", ret, errno, strerror(errno));
        }
        m_bo_handle = args.handle;
        created_here = true;
    } else {
        m_bo_handle = static_cast<uint32_t>(m_opaque_handle);
    }

    bo_info.handle = m_bo_handle;
    ret = ioctl(m_ctx_fd, DRM_IOCTL_AMDXDNA_GET_BO_INFO, &bo_info);
    if (ret) {
        if (created_here) {
            close_gem_handle(m_ctx_fd, m_bo_handle);
            if (m_coalesce_va && m_coalesce_len) {
                munmap(m_coalesce_va, m_coalesce_len);
                m_coalesce_va = nullptr;
                m_coalesce_len = 0;
            }
        }
        VACCEL_THROW_MSG(-errno, "Get bo info failed ret %d", ret);
    }

    m_map_offset = bo_info.map_offset;
    m_xdna_addr = bo_info.xdna_addr;

    /* Opaque import: CPU UVA from GET_BO_INFO. Created userptr BOs keep coalesce UVA. */
    if (!created_here) {
        m_vaddr = bo_info.vaddr;
        if (m_vaddr == AMDXDNA_INVALID_ADDR || m_vaddr == 0)
            VACCEL_THROW_MSG(-EINVAL,
                             "Pre-imported BO without CPU UVA from GET_BO_INFO: handle=%u, type=%u",
                             m_bo_handle, m_bo_type);
    }

    vxdna_dbg("Resource BO: res_id=%u, handle=%u, vaddr=0x%lx, xdna_addr=0x%lx, iov_bytes=%lu (coalesced UVA)",
              res->get_res_id(), m_bo_handle, m_vaddr, m_xdna_addr,
              static_cast<unsigned long>(m_iov_bytes));
}

vxdna_bo::
~vxdna_bo() noexcept
{
    vxdna_dbg("vxdna Destroying bo: ctx_fd=%d, handle=%u, vaddr=%lx, iov_bytes=%lu",
              m_ctx_fd, m_bo_handle, m_vaddr, static_cast<unsigned long>(m_iov_bytes));
    if (m_bo_handle != AMDXDNA_INVALID_BO_HANDLE) {
        struct drm_gem_close arg = {};
        arg.handle = m_bo_handle;
        vxdna_dbg("vxdna Close bo: ctx_fd=%d, handle=%u", m_ctx_fd, m_bo_handle);
        auto ret = ioctl(m_ctx_fd, DRM_IOCTL_GEM_CLOSE, &arg);
        if (ret)
            vxdna_err("Close vxdna bo failed ret %d", ret);
    }
    if (m_coalesce_va && m_coalesce_len > 0) {
        if (munmap(m_coalesce_va, m_coalesce_len) != 0)
            vxdna_err("munmap coalesce va failed errno %d", errno);
        m_coalesce_va = nullptr;
        m_coalesce_len = 0;
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
    auto rollback_created_hwctx = [&]() {
        /*
         * Roll back the kernel hwctx + syncobj acquired above before we
         * hand the failure back to the guest.  Member subobjects unwind
         * on their own when this constructor throws (the dtor itself is
         * not invoked on a partially-constructed object), but the DRM
         * handles are external state and must be released here.
         */
        struct drm_syncobj_destroy sync_arg = {};
        sync_arg.handle = m_syncobj_handle;
        ioctl(m_ctx_fd, DRM_IOCTL_SYNCOBJ_DESTROY, &sync_arg);

        struct amdxdna_drm_destroy_hwctx hwctx_arg = {};
        hwctx_arg.handle = m_hwctx_handle;
        ioctl(m_ctx_fd, DRM_IOCTL_AMDXDNA_DESTROY_HWCTX, &hwctx_arg);
    };

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
    } catch (const std::system_error &e) {
        rollback_created_hwctx();
        /*
         * pthread_create failure is reported as std::system_error; map the
         * errno (typically EAGAIN under RLIMIT_NPROC / pids.max) so the guest
         * can back off and retry instead of getting a generic -EIO.
         */
        int err = EAGAIN;
        if (e.code().category() == std::system_category())
            err = e.code().value();
        if (err <= 0)
            err = EAGAIN;
        VACCEL_THROW_MSG(-err,
                         "vxdna_hwctx ctor: failed to start polling thread: %s",
                         e.what());
    } catch (const std::bad_alloc &) {
        rollback_created_hwctx();
        VACCEL_THROW_MSG(-ENOMEM,
                         "vxdna_hwctx ctor: failed to start polling thread");
    } catch (const std::exception &e) {
        rollback_created_hwctx();
        VACCEL_THROW_MSG(-EIO,
                         "vxdna_hwctx ctor: failed to start polling thread: %s",
                         e.what());
    } catch (...) {
        rollback_created_hwctx();
        VACCEL_THROW_MSG(-EIO,
                         "vxdna_hwctx ctor: failed to start polling thread "
                         "(unknown exception)");
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
    validate_config_ctx_inline_payload(req);

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
    validate_exec_cmd_inline_payload(req);

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
            /*
             * Refuse to grow the pending queue past MAX_PENDING_FENCES.
             * The polling thread can only block on one syncobj_wait at a
             * time, so a guest that submits a fence with a never-reached
             * sync point pins the head and lets the queue grow on every
             * subsequent submit.  Throwing surfaces -ENOSPC up through
             * vaccel_error_wrap("vaccel_submit_fence") so QEMU can fail
             * the virtio command; m_has_sync_point stays asserted so the
             * next submit_fence retries cleanly once the queue drains.
             */
            if (m_pending_fences.size() >= MAX_PENDING_FENCES)
                VACCEL_THROW_MSG(-ENOSPC,
                                 "submit_fence: ctx %u hwctx %u pending queue full "
                                 "(%zu/%zu); fence_id=%lu rejected",
                                 m_ctx_id, m_hwctx_handle,
                                 m_pending_fences.size(),
                                 MAX_PENDING_FENCES,
                                 static_cast<unsigned long>(fence_id));

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
    if (m_heap_destroyed &&
        (req->bo_type == AMDXDNA_BO_DEV || req->bo_type == AMDXDNA_BO_DEV_HEAP))
        VACCEL_THROW_MSG(-EINVAL, "Heap destroyed, cannot allocate type %u", req->bo_type);

    if (req->bo_type == AMDXDNA_BO_DEV_HEAP) {
        if (!req->size || (req->size % k_dev_heap_uva_align) != 0)
            VACCEL_THROW_MSG(-EINVAL,
                             "DEV_HEAP size 0x%lx must be non-zero and 0x%zx aligned "
                             "(dev_mem_size)",
                             static_cast<unsigned long>(req->size), k_dev_heap_uva_align);
        if (req->size > HEAP_MAX_SIZE - m_heap_committed)
            VACCEL_THROW_MSG(-ENOSPC,
                             "Heap expansion rejected: size 0x%lx, remaining 0x%llx",
                             static_cast<unsigned long>(req->size),
                             static_cast<unsigned long long>(HEAP_MAX_SIZE -
                                                             m_heap_committed));
    }

    std::shared_ptr<vxdna_bo> xdna_bo;
    if (req->bo_type != AMDXDNA_BO_DEV) {
        auto res = lookup_resource_for_ctx(get_device(), req->res_id, get_id(),
                                           "create_bo");
        xdna_bo = std::make_shared<vxdna_bo>(res, *this, req);
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

    if (req->bo_type == AMDXDNA_BO_DEV_HEAP)
        m_heap_committed += req->size;
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
    auto bo = m_bo_table.lookup(handle);
    if (bo && bo->get_type() == AMDXDNA_BO_DEV_HEAP)
        m_heap_destroyed = true;
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
    auto res = lookup_resource_for_ctx(get_device(), req->info_res, get_id(),
                                       "get_info");

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

    /*
     * num_element / element_size / buffer_size are all kernel-mutable on
     * return (UAPI marks them in/out and on -ENOSPC the kernel reports the
     * size *needed*, not the size *written*).  Clamp to the host scratch
     * buffer we actually filled so a kernel-reported overshoot can't make
     * us copy uninitialised heap into the guest info resource.  Mirror the
     * clamp on rsp.{num_element,size} so the guest sees a self-consistent
     * "bytes written" tuple instead of a possibly larger "bytes needed".
     */
    if (info_size > info_buf.size()) {
        vxdna_err("get_info: kernel reported size %u exceeds host buffer %zu "
                  "(cmd %s); clamping",
                  info_size, info_buf.size(),
                  cmd == DRM_IOCTL_AMDXDNA_GET_ARRAY ? "GET_ARRAY" : "GET_INFO");
        info_size = static_cast<uint32_t>(info_buf.size());
        if (cmd == DRM_IOCTL_AMDXDNA_GET_ARRAY) {
            /* keep rsp.size (per-element) intact; clamp count and bytes written */
            if (rsp.size > 0) {
                rsp.num_element = info_size / rsp.size;
                info_size = rsp.num_element * rsp.size;
            } else {
                rsp.num_element = 0;
                info_size = 0;
            }
        } else {
            rsp.size = info_size;
        }
    }

    res->write(0, info_buf.data(), info_size);
    rsp.hdr.base.len = sizeof(rsp);
    write_rsp(&rsp, sizeof(rsp), req->hdr.rsp_off);
}

void
vxdna_context::
read_sysfs(const struct amdxdna_ccmd_read_sysfs_req *req)
{
    validate_read_sysfs_inline_payload(req);

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
    if (!resp_res) {
        vxdna_err("write_err_rsp: no resp resource for ctx %u, err %d dropped",
                  get_id(), err);
        return;
    }
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

    auto res = lookup_resource_for_ctx(device, req->rsp_res_id, ctx->get_id(),
                                       "init");
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

// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2025, Advanced Micro Devices, Inc. All rights reserved.

// Disable debug print in this file.
//#undef XDNA_SHIM_DEBUG

#include "buffer.h"
#include "shim_debug.h"
#include "core/common/config_reader.h"
#if defined(__x86_64__) || defined(_M_X64)
#include <x86intrin.h>
#endif

namespace {

uint8_t
use_to_fw_debug_type(uint8_t use)
{
  switch (use) {
  case XRT_BO_USE_DEBUG:
    return AMDXDNA_FW_BUF_DEBUG;
  case XRT_BO_USE_DTRACE:
    return AMDXDNA_FW_BUF_TRACE;
  case XRT_BO_USE_DEBUG_QUEUE:
    return AMDXDNA_FW_BUF_DBG_Q;
  case XRT_BO_USE_LOG:
    return AMDXDNA_FW_BUF_LOG;
  }
  throw;
}

const uint64_t page_size = sysconf(_SC_PAGESIZE);
const long cacheline_size = sysconf(_SC_LEVEL1_DCACHE_LINESIZE);

bool
is_power_of_two(size_t x)
{
  return (x > 0) && ((x & (x - 1)) == 0);
}

void *
next_aligned_addr(void *p, size_t align)
{
  if (!is_power_of_two(align))
    shim_err(EINVAL, "Alignment 0x%lx is not power of two", align);
  auto addr = reinterpret_cast<uint64_t>(p);
  return reinterpret_cast<void*>((addr + align - 1) & ~(align - 1));
}

bool
is_cacheline_aligned(void *ptr)
{
  return (ptr == next_aligned_addr(ptr, cacheline_size));
}

bool
is_page_aligned(void *ptr)
{
  return (ptr == next_aligned_addr(ptr, page_size));
}

void *
page_align(void *ptr)
{
  auto ap = reinterpret_cast<uintptr_t>(ptr);
  ap &= ~(page_size - 1);
  return reinterpret_cast<void*>(ap);
}

uint64_t
page_offset(void *ptr)
{
  if (!ptr)
    return 0;

  auto ap = reinterpret_cast<uintptr_t>(ptr);
  return ap & (page_size - 1);
}

size_t
page_size_roundup(size_t size)
{
  return (size + page_size - 1) & ~(page_size - 1);
}

std::string
type_to_name(int type, uint64_t flags)
{
  switch (type) {
  case AMDXDNA_BO_SHARE:
    if (xcl_bo_flags{flags}.use == XRT_BO_USE_DTRACE)
      return std::string("AMDXDNA_BO_UC_DTRACE");
    else if (xcl_bo_flags{flags}.use == XRT_BO_USE_LOG)
      return std::string("AMDXDNA_BO_UC_LOG");
    else if (xcl_bo_flags{flags}.use == XRT_BO_USE_DEBUG_QUEUE)
      return std::string("AMDXDNA_BO_UC_DEBUG_QUEUE");
    //else if (xcl_bo_flags{flags}.use == XRT_BO_USE_UC_DEBUG)
    //  return std::string("AMDXDNA_BO_UC_DEBUG_BUF");
    return std::string("AMDXDNA_BO_SHARE");
  case AMDXDNA_BO_DEV_HEAP:
    return std::string("AMDXDNA_BO_DEV_HEAP");
  case AMDXDNA_BO_DEV:
    return std::string("AMDXDNA_BO_DEV");
  case AMDXDNA_BO_CMD:
    return std::string("AMDXDNA_BO_CMD");
  }
  return std::string("BO_UNKNOWN");
}

std::string
to_hex_string(uint64_t num) {
  std::stringstream ss;
  ss << "0x" << std::hex << num;
  return ss.str();
}
 
inline void flush_cache_line(const char *cur)
{
#if defined(__x86_64__) || defined(_M_X64)
  _mm_clflush(cur);
#elif defined(__aarch64__)
  asm volatile(
    "DC CIVAC, %[addr]\n"  // Clean and invalidate data cache
    "DSB SY\n"             // Data Synchronization Barrier
    "ISB SY\n"             // Instruction Synchronization Barrier
    :
    : [addr] "r" (cur)
    : "memory"
  );
#endif
}

// flash cache line for non coherent memory
inline void
clflush_data(const void *base, size_t offset, size_t len)
{
  const char *cur = (const char *)base;
  cur += offset;
  uintptr_t lastline = (uintptr_t)(cur + len - 1) | (cacheline_size - 1);
  do {
    flush_cache_line(cur);
    cur += cacheline_size;
  } while (cur <= (const char *)lastline);
}

bool
is_driver_sync()
{
  static bool drv_sync =
    xrt_core::config::detail::get_bool_value("Debug.force_driver_sync", false);
  return drv_sync;
}

bool
is_driver_pin_arg_bo()
{
  static bool drv_pin =
    xrt_core::config::detail::get_bool_value("Debug.driver_pin_arg_bo", true);
  return drv_pin;
}

uint64_t
bo_addr_align(int type)
{
  // Device mem heap must align at 64MB boundary. Others can be byte aligned.
  return (type == AMDXDNA_BO_DEV_HEAP) ? 64ul * 1024 * 1024 : 1;
}

}

namespace shim_xdna {

//
// Impl for class mmap_ptr
//

mmap_ptr::
mmap_ptr(size_t size, size_t alignment)
  : m_size(page_size_roundup(size)) // Roundup size to page size
{
  if (!is_power_of_two(alignment))
    shim_err(EINVAL, "Alignment 0x%lx is not power of two", alignment);

  auto total_sz = m_size;
  // Mmap should automatically return at least page aligned address.
  if (alignment > page_size)
    total_sz += alignment;

  auto p = mmap(0, total_sz, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (p == MAP_FAILED)
    shim_err(-errno, "mmap_range(len=%ld) failed", size);
  if (!is_page_aligned(p))
    shim_err(EINVAL, "mmap_range is not page aligend");

  m_ptr = next_aligned_addr(p, alignment);
  auto pre_sz = reinterpret_cast<char*>(m_ptr) - reinterpret_cast<char*>(p);
  total_sz -= pre_sz;

  // Unmap prefix part
  if (p != m_ptr)
    munmap(p, pre_sz);
  // Unmap suffix part
  if (total_sz > m_size) {
    // coverity[bad_free]
    munmap(reinterpret_cast<char*>(m_ptr) + m_size, total_sz - m_size);
  }
}

mmap_ptr::
mmap_ptr(const pdev *dev, void *addr, uint64_t dev_offset, size_t size)
  : m_dev(dev), m_size(size)
{
  int flags = addr ? MAP_FIXED : 0;
  m_ptr = dev->mmap(addr, size, PROT_READ | PROT_WRITE,
    MAP_SHARED | MAP_LOCKED | flags, dev_offset);
}

mmap_ptr::
~mmap_ptr()
{
  if (!m_ptr)
    return;

  if (m_dev)
    m_dev->munmap(m_ptr, m_size);
  else
    munmap(m_ptr, m_size);
}

void *
mmap_ptr::
get() const
{
  return m_ptr;
}

std::unique_ptr<mmap_ptr>
mmap_ptr::
alloc(const pdev *dev, uint64_t dev_offset, size_t size)
{
  auto sz = page_size_roundup(size);
  if (sz > m_size)
    shim_err(ENOSPC, "mmap_alloc(len=%ld) failed", size);

  auto new_mmap = std::make_unique<mmap_ptr>(dev, m_ptr, dev_offset, sz);
  m_size -= sz;
  if (m_size == 0)
    m_ptr = nullptr;
  else
    m_ptr = reinterpret_cast<void*>(reinterpret_cast<char*>(m_ptr) + sz);
  return std::move(new_mmap);
}

//
// Impl for class drm_bo
//

drm_bo::
drm_bo(const pdev& pdev, size_t size, int type)
  : m_pdev(pdev), m_size(size)
{
  auto align = bo_addr_align(type);
  create_bo_arg arg = {
    .type = type,
    .size = m_size,
    .xdna_addr_align = (align == 1 ? 0 : align), 
  };
  m_pdev.drv_ioctl(drv_ioctl_cmd::create_bo, &arg);
  m_id = arg.bo;
  m_xdna_addr = arg.xdna_addr;
  m_map_offset = arg.map_offset;
}

drm_bo::
drm_bo(const pdev& pdev, size_t size, void *uptr)
  : m_pdev(pdev), m_size(size)
{
  create_uptr_bo_arg arg = {
    .buf = uptr,
    .size = m_size,
  };
  m_pdev.drv_ioctl(drv_ioctl_cmd::create_uptr_bo, &arg);
  m_id = arg.bo;
  m_xdna_addr = arg.xdna_addr;
  m_map_offset = arg.map_offset;
}

drm_bo::
drm_bo(const pdev& pdev, xrt_core::shared_handle::export_handle ehdl)
  : m_pdev(pdev)
{
  import_bo_arg arg = {
    .fd = ehdl,
  };
  m_pdev.drv_ioctl(drv_ioctl_cmd::import_bo, &arg);
  m_size = arg.size;
  m_id = arg.bo;
  m_xdna_addr = arg.xdna_addr;
  m_map_offset = arg.map_offset;
}

drm_bo::
~drm_bo()
{
  m_vaddr.reset();

  try {
    destroy_bo_arg arg = {
      .bo = m_id,
    };
    m_pdev.drv_ioctl(drv_ioctl_cmd::destroy_bo, &arg);
  } catch (const xrt_core::system_error& e) {
    // In case BO is exported and imported in the same process, the same BO
    // could be destroyed twice (once by exported BO, and once by imported BO).
    // The last BO destroy will see EINVAL error. Ignore it.
    if (e.get_code() != EINVAL) {
      std::cout << "Failed to destroy DRM BO "
        << std::to_string(m_id.handle)
        << ": " << e.what()
        << std::endl;
    }
  }
}

//
// Impl for class buffer
//

buffer::
buffer(const pdev& dev, size_t size, void *uptr)
  : buffer(dev, size, AMDXDNA_BO_SHARE, uptr)
{
}

buffer::
buffer(const pdev& dev, size_t size, int type)
  : buffer(dev, size, type, nullptr)
{
}

buffer::
buffer(const pdev& dev, size_t size, int type, void *uptr)
  : m_pdev(dev)
  , m_uptr(uptr)
  , m_type(type)
  , m_total_size(size)
  , m_cur_size(0)
{
  // CPU and device can't share cacheline, especially when the BO is output and
  // both CPU and device may write to it.
  // In case the BO is exported to other process, it has to be aligned on page
  // boundary so that we don't implicitly share more than we need.
  // Based on the above reasons, we'll enforce the pointer to be page aligned.
  if (!is_page_aligned(m_uptr))
    shim_err(EINVAL, "User pointer %p must be page aligned.", m_uptr);
  if (m_uptr && type != AMDXDNA_BO_SHARE)
    shim_err(EINVAL, "User pointer BO must be AMDXDNA_BO_SHARE type.");

  // Prepare the mmap range for the entire buffer
  m_range_addr = std::make_unique<mmap_ptr>(m_total_size, bo_addr_align(m_type));

  // Obtain the buffer
  expand(m_total_size);
  shim_debug("Created %s", describe().c_str());
}

buffer::
buffer(const pdev& dev, xrt_core::shared_handle::export_handle ehdl)
  : m_pdev(dev)
  , m_type(AMDXDNA_BO_SHARE)
{
  auto bo = std::make_unique<drm_bo>(dev, ehdl);

  m_total_size = m_cur_size = bo->m_size;
  // Prepare the mmap range for the entire buffer
  m_range_addr = std::make_unique<mmap_ptr>(m_total_size, bo_addr_align(m_type));

  mmap_drm_bo(bo.get());
  m_bos.push_back(std::move(bo));
  shim_debug("Imported %s", describe().c_str());
}

void
buffer::
expand(size_t size)
{
  auto cur_sz = m_cur_size;
  auto new_sz = size + m_cur_size;
  shim_debug("Expanding BO from %ld to %ld", cur_sz, new_sz);

  if (new_sz > m_total_size)
    shim_err(EINVAL, "Can't expand BO beyond total size %ld", m_total_size);

  std::unique_ptr<drm_bo> bo;
  if (m_uptr)
    bo = std::make_unique<drm_bo>(m_pdev, size, m_uptr);
  else
    bo = std::make_unique<drm_bo>(m_pdev, size, m_type);
  mmap_drm_bo(bo.get());

  m_bos.push_back(std::move(bo));
  m_cur_size += size;
  
  // Newly allocated buffer may contain dirty pages. If used as output buffer,
  // the data in cacheline will be flushed onto memory and pollute the output
  // from device. We perform a cache flush right after the BO is allocated to
  // avoid this issue.
  if (m_type == AMDXDNA_BO_SHARE)
    sync(direction::host2device, size, cur_sz);
}

buffer::
~buffer()
{
  shim_debug("Destroying %s", describe().c_str());
}

void
buffer::
mmap_drm_bo(drm_bo *bo)
{
  if (bo->m_map_offset == AMDXDNA_INVALID_ADDR) {
    if (m_type != AMDXDNA_BO_DEV)
      shim_err(EINVAL, "Non-DEV BO without mmap offset!");
    return;
  }
  bo->m_vaddr = m_range_addr->alloc(&m_pdev, bo->m_map_offset, bo->m_size);
}

void *
buffer::
map(map_type t)
{
  if (t != map_type::write)
    shim_err(EINVAL, "Not support map BO as readonly. Type must be bo::map_type::write");
  return vaddr();
}

void *
buffer::
vaddr() const
{
  if (m_uptr)
    return m_uptr;

  auto& bo = m_bos[0];
  if (bo->m_map_offset != AMDXDNA_INVALID_ADDR)
    return reinterpret_cast<char*>(bo->m_vaddr->get());

  // Must be DEV BO.
  auto base = static_cast<char*>(m_pdev.get_heap_vaddr());
  return base + (paddr() - m_pdev.get_heap_paddr());
}

size_t
buffer::
size() const
{
  return m_cur_size;
}

void
buffer::
unmap(void *addr)
{
  // Nothing to do.
}

buffer::properties
buffer::
get_properties() const 
{
  return { m_flags, size(), paddr(), id().handle };
}

std::unique_ptr<xrt_core::shared_handle>
buffer::
share() const 
{
  export_bo_arg arg = {
    .bo = id(),
    .fd = -1,
  };
  m_pdev.drv_ioctl(drv_ioctl_cmd::export_bo, &arg);

  shim_debug("Exported BO %d to fd %d", id().handle, arg.fd);
  return std::make_unique<shared>(arg.fd);
}

void
buffer::
bind_at(size_t pos, const buffer_handle* bh, size_t offset, size_t size)
{
  // Should only be supported for cmd_buffer.
  shim_not_supported_err(__func__);
}

bo_id
buffer::
id() const
{
  return id(0);
}

bo_id
buffer::
id(int index) const
{
  return m_bos[index]->m_id;
}

uint64_t
buffer::
paddr() const
{
  auto xdna_addr = m_bos[0]->m_xdna_addr;
  return (xdna_addr != AMDXDNA_INVALID_ADDR) ?
    xdna_addr : reinterpret_cast<uintptr_t>(m_bos[0]->m_vaddr->get());
}

void
buffer::
bind_hwctx(const hwctx& hwctx)
{
  // Nothing to do.
}

void
buffer::
unbind_hwctx()
{
  // Nothing to do.
}

void
buffer::
set_flags(uint64_t flags)
{
  m_flags = flags;
}

uint64_t
buffer::
get_flags() const
{
  return m_flags;
}

std::string
buffer::
describe() const
{
  std::string desc = bo_sub_type_name() + ": ";

  desc += "type=";
  desc += type_to_name(m_type, m_flags);
  desc += " ";
  desc += "hdl=";
  for (int i = 0; i < m_bos.size(); i++) {
    desc += std::to_string(id(i).handle);
    desc += " ";
  }

  desc += "sz=";
  desc += to_hex_string(size());

  desc += " ";
  desc += "paddr=";
  desc += to_hex_string(paddr());

  desc += " ";
  desc += "vaddr=";
  desc += to_hex_string(reinterpret_cast<uint64_t>(vaddr()));
  return desc;
}

void
buffer::
sync(direction, size_t sz, size_t offset)
{
  if (m_pdev.is_cache_coherent())
    return;

  if (offset + sz > size())
    shim_err(EINVAL, "Invalid BO offset and size for sync'ing: %ld, %ld", offset, sz);

  if (is_driver_sync()) {
    sync_bo_arg arg = {
      .bo = id(),
      .offset = offset,
      .size = sz,
    };
    m_pdev.drv_ioctl(drv_ioctl_cmd::sync_bo, &arg);
    return;
  }

  clflush_data(vaddr(), offset, sz); 
  shim_debug("Sync'ed BO %d: offset=%ld, size=%ld", id().handle, offset, sz);
}

std::set<bo_id>
buffer::
get_arg_bo_ids() const
{
  // For non-cmd BO, arg bo handles contains only its own handle.
  std::set<bo_id> ret = { id() };
  return ret;
}

std::string
buffer::
bo_sub_type_name() const
{
  return m_uptr ? "USER_PTR BO" : "Non-USER_PTR BO";
}

//
// Impl for class cmd_buffer
//

void
cmd_buffer::
mark_enqueued() const
{
  std::unique_lock<std::mutex> lg(m_submission_lock);
  m_submitted = false;
}

uint64_t
cmd_buffer::
wait_for_submitted() const
{
  std::unique_lock<std::mutex> lg(m_submission_lock);
  m_submission_cv.wait(lg, [this]() { return m_submitted; });
  return m_cmd_seq;
}

void
cmd_buffer::
mark_submitted(uint64_t seq) const
{
  std::unique_lock<std::mutex> lg(m_submission_lock);
  m_cmd_seq = seq;
  m_submitted = true;
  m_submission_cv.notify_all();
}

void
cmd_buffer::
bind_at(size_t pos, const buffer_handle* bh, size_t offset, size_t size)
{
  if (!is_driver_pin_arg_bo())
    return;

  auto boh = reinterpret_cast<const buffer*>(bh);
  std::lock_guard<std::mutex> lg(m_args_map_lock);

  // Hack for now. Should move to buffer_handle::reset() when it is available
  if (!pos)
    m_args_map.clear();

  m_args_map[pos] = boh->get_arg_bo_ids();

#ifdef XDNA_SHIM_DEBUG
  std::string bohs;
  auto s = boh->get_arg_bo_ids();
  for (const auto& bo : s)
    bohs += std::to_string(bo.handle) + " ";
  shim_debug("Added arg BO %s to cmd BO %d", bohs.c_str(), id().handle);
#endif
}

std::set<bo_id>
cmd_buffer::
get_arg_bo_ids() const
{
  std::set<bo_id> ret;
  // For cmd BO, arg bo handles contains everything in args_map.
  std::lock_guard<std::mutex> lg(m_args_map_lock);

  for (const auto& m : m_args_map)
    ret.insert(m.second.begin(), m.second.end());
  return ret;
}

std::string
cmd_buffer::
bo_sub_type_name() const
{
  return "EXEC_BUF BO";
}

//
// Impl for class dbg_buffer
//

void
dbg_buffer::
bind_hwctx(const hwctx& hwctx)
{
  m_ctx_id = hwctx.get_slotidx();
  try {
    config_debug_bo(false);
  } catch (...) {
    m_ctx_id = AMDXDNA_INVALID_CTX_HANDLE;
    throw;
  }
  shim_debug("Attached DEBUG BO %d to hwctx %d", id().handle, m_ctx_id);
}

void
dbg_buffer::
unbind_hwctx()
{
  try {
    config_debug_bo(true);
    m_ctx_id = AMDXDNA_INVALID_CTX_HANDLE;
  } catch (const xrt_core::system_error& e) {
    std::cout << "Failed to detach DEBUG BO " << std::to_string(id().handle)
      << " from hwctx " << std::to_string(m_ctx_id)
      << ": " << e.what() << std::endl;
  }
}

void
dbg_buffer::
config_debug_bo(bool is_detach)
{
  config_ctx_debug_bo_arg arg = {
    .ctx_handle = m_ctx_id,
    .is_detach = is_detach,
    .bo = id(),
  };
  m_pdev.drv_ioctl(drv_ioctl_cmd::config_ctx_debug_bo, &arg);
}

dbg_buffer::
~dbg_buffer()
{
  if (m_ctx_id == AMDXDNA_INVALID_CTX_HANDLE)
    return;

  try {
    config_debug_bo(true);
  } catch (const xrt_core::system_error& e) {
    std::cout << "Failed to detach DEBUG BO " << std::to_string(id().handle)
      << " from hwctx " << std::to_string(m_ctx_id)
      << ": " << e.what() << std::endl;
  }
}

std::string
dbg_buffer::
bo_sub_type_name() const
{
  return "DEBUG BO";
}

//
// Impl for class uc_dbg_buffer
//
void
uc_dbg_buffer::
config(xrt_core::hwctx_handle* hwctx, const std::map<uint32_t, size_t>& buf_sizes)
{
  auto meta_buf_size = offsetof(struct fw_buffer_metadata, uc_info)
     + buf_sizes.size() * sizeof(struct uc_info_entry);
  m_metadata_bo = std::make_unique<dbg_buffer>(m_pdev, meta_buf_size, AMDXDNA_BO_SHARE);
  auto metadata = reinterpret_cast<fw_buffer_metadata *>(m_metadata_bo->vaddr());
  metadata->bo_handle = id().handle;
  metadata->command_id = 0; //support this later
  auto f = xcl_bo_flags{get_flags()};
  metadata->buf_type = use_to_fw_debug_type(f.use);
  metadata->num_ucs = buf_sizes.size();
  int i = 0;
  for (const auto& pair : buf_sizes)
  {
    metadata->uc_info[i].size = pair.second;
    metadata->uc_info[i].index = pair.first;
    i++;
  }

  shim_debug("Config CMD BO %d (%s) for %d uC", id().handle,
    type_to_name(AMDXDNA_BO_SHARE, get_flags()).c_str(), i);

  auto ctx = static_cast<shim_xdna::hwctx *>(hwctx);
  m_metadata_bo->bind_hwctx(*ctx);
}

void
uc_dbg_buffer::
unconfig(xrt_core::hwctx_handle* hwctx)
{
  shim_debug("Unconfig CMD BO %d (%s)", id().handle,
    type_to_name(AMDXDNA_BO_SHARE, get_flags()).c_str());
  m_metadata_bo->unbind_hwctx();
}

}

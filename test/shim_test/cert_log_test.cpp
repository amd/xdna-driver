// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026, Advanced Micro Devices, Inc. All rights reserved.

#include "bo.h"
#include "hwctx.h"

#include "core/include/xrt/detail/xrt_mem.h"

#include <cerrno>
#include <iostream>
#include <map>
#include <memory>
#include <stdexcept>
#include <string>

using arg_type = const std::vector<uint64_t>;

namespace {

constexpr uint32_t aie4_max_num_certs = 6;  // AIE4_MAX_NUM_CERTS in aie4_msg_priv.h
constexpr size_t   payload_bo_size    = 64 * 1024;
constexpr uint32_t default_slice_size = 4096;

std::unique_ptr<buffer_handle>
alloc_log_bo(hw_ctx& ctx, size_t size)
{
  uint32_t ext_boflags = XRT_BO_USE_LOG << 4;
  return ctx.get()->alloc_bo(size, get_bo_flags(XRT_BO_FLAGS_CARVEOUT, ext_boflags));
}

void
expect_config_ok(buffer_handle* bo, hwctx_handle* ctx,
                 const std::map<uint32_t, size_t>& sizes, const std::string& tag)
{
  try {
    bo->config(ctx, sizes);
  } catch (const std::system_error& e) {
    // Accept -EOPNOTSUPP when firmware lacks CERT log support.
    if (e.code().value() == EOPNOTSUPP) {
      std::cout << "  " << tag << ": firmware unsupported, accepting as pass" << std::endl;
      return;
    }
    throw std::runtime_error(tag + ": config failed err=" + std::to_string(e.code().value()));
  }
}

void
expect_config_err(buffer_handle* bo, hwctx_handle* ctx,
                  const std::map<uint32_t, size_t>& sizes,
                  int expected, const std::string& tag)
{
  try {
    bo->config(ctx, sizes);
  } catch (const std::system_error& e) {
    if (e.code().value() == expected)
      return;
    throw std::runtime_error(tag + ": got err=" + std::to_string(e.code().value()) +
                             " expected " + std::to_string(expected));
  }
  throw std::runtime_error(tag + ": expected err=" + std::to_string(expected) +
                           " but config succeeded");
}

}

void
TEST_certlog_attach_detach(device::id_type id, std::shared_ptr<device>& sdev, arg_type& arg)
{
  hw_ctx ctx{sdev.get()};
  auto bo = alloc_log_bo(ctx, payload_bo_size);

  expect_config_ok(bo.get(), ctx.get(), {{0, default_slice_size}}, "attach LOG (1 uc)");
  bo->unconfig(ctx.get());
}

void
TEST_certlog_multi_uc(device::id_type id, std::shared_ptr<device>& sdev, arg_type& arg)
{
  hw_ctx ctx{sdev.get()};
  auto bo = alloc_log_bo(ctx, payload_bo_size);

  std::map<uint32_t, size_t> sizes;
  for (uint32_t i = 0; i < aie4_max_num_certs; i++)
    sizes[i] = default_slice_size;

  expect_config_ok(bo.get(), ctx.get(), sizes,
                   "attach LOG (" + std::to_string(aie4_max_num_certs) + " ucs)");
  bo->unconfig(ctx.get());
}

void
TEST_certlog_num_ucs_overflow(device::id_type id, std::shared_ptr<device>& sdev, arg_type& arg)
{
  hw_ctx ctx{sdev.get()};
  auto bo = alloc_log_bo(ctx, payload_bo_size);

  std::map<uint32_t, size_t> sizes;
  for (uint32_t i = 0; i <= aie4_max_num_certs; i++)
    sizes[i] = default_slice_size;

  expect_config_err(bo.get(), ctx.get(), sizes, EINVAL,
                    "num_ucs > AIE4_MAX_NUM_CERTS");
}

void
TEST_certlog_invalid_uc_index(device::id_type id, std::shared_ptr<device>& sdev, arg_type& arg)
{
  hw_ctx ctx{sdev.get()};
  auto bo = alloc_log_bo(ctx, payload_bo_size);

  expect_config_err(bo.get(), ctx.get(),
                    {{aie4_max_num_certs, default_slice_size}},
                    EINVAL, "uc_info index out of range");
}

void
TEST_certlog_payload_overflow(device::id_type id, std::shared_ptr<device>& sdev, arg_type& arg)
{
  hw_ctx ctx{sdev.get()};
  auto bo = alloc_log_bo(ctx, default_slice_size);

  expect_config_err(bo.get(), ctx.get(),
                    {{0, default_slice_size}, {1, default_slice_size}},
                    EINVAL, "cumulative slice size > payload BO size");
}

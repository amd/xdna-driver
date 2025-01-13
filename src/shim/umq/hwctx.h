// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2023-2024, Advanced Micro Devices, Inc. All rights reserved.

#ifndef _HWCTX_UMQ_H_
#define _HWCTX_UMQ_H_

#include "../hwctx.h"

namespace shim_xdna {

class hw_ctx_umq : public hw_ctx {
public:
  hw_ctx_umq(const device& dev, const xrt::xclbin& xclbin, const qos_type& qos);

  ~hw_ctx_umq();

  std::unique_ptr<xrt_core::buffer_handle>
  alloc_bo(void* userptr, size_t size, uint64_t flags) override;

private:
  #define LOG_MAGIC_NO 0x43455254

  enum umq_log_flag {
    UMQ_DEBUG_BUFFER = 0,
    UMQ_TRACE_BUFFER
  };

  struct umq_log_metadata {
    uint32_t magic_no;
    uint8_t major;
    uint8_t minor;
    uint8_t umq_log_flag;
    uint8_t num_cols;       // how many valid cols, up to 8 for now
    uint64_t col_paddr[8];  // device accessible address array for each valid col
    uint32_t col_size[8];    // bo size for each valid col
  };

  struct umq_log_metadata m_metadata;
  void *m_log_buf;

  void init_log_buf();
  void fini_log_buf();
  void set_metadata(int num_cols, size_t size, uint64_t bo_paddr, enum umq_log_flag flag);
};

} // shim_xdna

#endif // _HWCTX_UMQ_H_

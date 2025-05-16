// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2023-2025, Advanced Micro Devices, Inc. All rights reserved.

#ifndef FW_METADATA_H
#define FW_METADATA_H

namespace shim_xdna {

enum umq_fw_flag {
  UMQ_DEBUG_BUFFER = 0,
  UMQ_TRACE_BUFFER,
  UMQ_DBG_QUEUE,
  UMQ_LOG_BUFFER
};

struct umq_fw_metadata {
  uint16_t reserved;
  uint8_t umq_fw_flag;
  uint8_t num_ucs;       // how many valid ucs, up to 8 for now
  struct {
    uint64_t paddr : 57;  // device accessible address array for each valid uc
    uint64_t index : 7;  // uc index
    uint32_t size;    // bo size for each valid uc in words
  } uc_info[8];
};

}

#endif

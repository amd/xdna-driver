// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2024, Advanced Micro Devices, Inc. All rights reserved.

#ifndef _SHIMTEST_IO_H_
#define _SHIMTEST_IO_H_

#include "bo.h"

#include "core/common/device.h"
#include <memory>

enum io_test_bo_type {
  IO_TEST_BO_CMD = 0,
  IO_TEST_BO_INSTRUCTION,
  IO_TEST_BO_INPUT,
  IO_TEST_BO_PARAMETERS,
  IO_TEST_BO_OUTPUT,
  IO_TEST_BO_INTERMEDIATE,
  IO_TEST_BO_MC_CODE,
  IO_TEST_BO_MAX_TYPES
};

struct io_test_bo {
  size_t size;
  size_t init_offset;
  std::shared_ptr<bo> tbo;
};
using io_test_bo_set = std::array<io_test_bo, IO_TEST_BO_MAX_TYPES>;

void bo_set_sync_before_run(io_test_bo_set& io_test_bos);
void bo_set_sync_after_run(io_test_bo_set& io_test_bos);
void bo_set_init_cmd(io_test_bo_set& io_test_bos, xrt_core::cuidx_type idx, bool dump);
void bo_set_dump_content(io_test_bo_set& io_test_bos);
void bo_set_verify_result(io_test_bo_set& io_test_bos, const std::string& local_data_path);
io_test_bo_set create_bo_set(device* dev, const std::string& local_data_path);
const char* bo_set_type2name(int type);

#endif // _SHIMTEST_IO_H_

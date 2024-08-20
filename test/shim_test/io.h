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

class io_test_bo_set {
public:
  io_test_bo_set(device *dev, const std::string& data_path);

  void
  run();

  void
  run(bool no_check_result);

  void
  run(xrt_core::fence_handle* fence, bool no_check_result);

  void
  sync_before_run();

  void
  sync_after_run();

  void
  init_cmd(xrt_core::cuidx_type idx, bool dump);

  void
  dump_content();

  void
  verify_result();

  static const char *
  bo_type2name(int type);

  std::array<io_test_bo, IO_TEST_BO_MAX_TYPES>&
  get_bos();

private:
  std::array<io_test_bo, IO_TEST_BO_MAX_TYPES> m_bo_array;
  const std::string m_local_data_path;
  device *m_dev;

  void
  init_sizes();

  void
  alloc_bos();

  void
  init_args();
};

#endif // _SHIMTEST_IO_H_

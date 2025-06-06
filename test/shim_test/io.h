// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2024, Advanced Micro Devices, Inc. All rights reserved.

#ifndef _SHIMTEST_IO_H_
#define _SHIMTEST_IO_H_

#include "bo.h"
#include "dev_info.h"

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
  IO_TEST_BO_CTRL_PKT_PM,
  IO_TEST_BO_SCRATCH_PAD,
  IO_TEST_BO_SAVE_INSTRUCTION,
  IO_TEST_BO_RESTORE_INSTRUCTION,
  IO_TEST_BO_MAX_TYPES
};

struct io_test_bo {
  size_t size = 0;
  size_t init_offset = 0;
  std::vector<char> ubuf;
  std::shared_ptr<bo> tbo;
};

class io_test_bo_set_base
{
public:
  io_test_bo_set_base(device *dev, const std::string& xclbin_name);
  virtual ~io_test_bo_set_base()
  {
    // Do nothing, but allow destructor of inherited class to be called when destruction
    // happens through base
  }

  void
  run_no_check_result();

  void
  run();

  void
  run(const std::vector<xrt_core::fence_handle*>& wait_fences,
    const std::vector<xrt_core::fence_handle*>& signal_fences, bool no_check_result);

  void
  sync_before_run();

  void
  sync_after_run();

  virtual void
  init_cmd(xrt_core::cuidx_type idx, bool dump) = 0;

  void
  dump_content();

  virtual void
  verify_result() = 0;

  static const char *
  bo_type2name(int type);

  std::array<io_test_bo, IO_TEST_BO_MAX_TYPES>&
  get_bos();

protected:
  std::array<io_test_bo, IO_TEST_BO_MAX_TYPES> m_bo_array;
  const std::string m_xclbin_name;
  const std::string m_local_data_path;
  device *m_dev;
};

class io_test_bo_set : public io_test_bo_set_base
{
public:
  io_test_bo_set(device *dev, const std::string& xclbin_name, bool use_ubuf);
  io_test_bo_set(device *dev);
  io_test_bo_set(device *dev, bool use_ubuf);

  void
  init_cmd(xrt_core::cuidx_type idx, bool dump) override;

  void
  verify_result() override;
};

class elf_io_test_bo_set : public io_test_bo_set_base
{
public:
  elf_io_test_bo_set(device *dev, const std::string& xclbin_name);

  void
  init_cmd(xrt_core::cuidx_type idx, bool dump) override;

  void
  verify_result() override;

private:
  const xrt::elf m_elf;
};

class elf_preempt_io_test_bo_set : public io_test_bo_set_base
{
public:
  elf_preempt_io_test_bo_set(device *dev, const std::string& xclbin_name);

  ~elf_preempt_io_test_bo_set() {
    --m_total_cmds;
  }

  void
  init_cmd(xrt_core::cuidx_type idx, bool dump) override;

  void
  verify_result() override;

private:
  const xrt::elf m_elf;
  int m_user_tid = -1;
  std::vector<std::pair<int, uint64_t>> m_fine_preemptions;
  unsigned long m_total_fine_preemption_checkpoints;
  static unsigned long m_total_cmds;
};

#endif // _SHIMTEST_IO_H_

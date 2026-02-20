// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2024-2026, Advanced Micro Devices, Inc. All rights reserved.

#ifndef _SHIMTEST_IO_H_
#define _SHIMTEST_IO_H_

#include "bo.h"
#include "hwctx.h"
#include "dev_info.h"
#include "exec_buf.h"

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
  IO_TEST_BO_2ND_PARAMETERS,
  IO_TEST_BO_PDI,
  IO_TEST_BO_MAX_TYPES
};

struct io_test_bo {
  size_t init_offset = 0;
  std::vector<char> ubuf;
  std::shared_ptr<bo> tbo;
};

class io_test_bo_set_base
{
public:
  io_test_bo_set_base(device *dev, const std::string& tag = "", const flow_type* flow = nullptr);
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
  init_cmd(hw_ctx& hwctx, bool dump);

  void
  dump_content();

  virtual void
  verify_result();

  static const char *
  bo_type2name(int type);

  void
  reset_cmd_header();

  std::array<io_test_bo, IO_TEST_BO_MAX_TYPES>&
  get_bos();

  virtual unsigned long
  get_preemption_checkpoints();

protected:
  std::array<io_test_bo, IO_TEST_BO_MAX_TYPES> m_bo_array;
  const std::string m_tag;
  const std::string m_local_data_path;
  device *m_dev;
  const flow_type* m_flow = nullptr;  /* nullptr = lookup by tag/default only; non-null = lookup by tag + flow */
  xrt::elf m_elf = {};
  uint32_t m_kernel_index;
  uint32_t m_cached_header = 0;
  const int m_FLAG_USR_BUF =  1 << 0;
  const int m_FLAG_OPT =      1 << 1;
  const int m_FLAG_NO_FILL =  1 << 2;
  const int m_FLAG_DEV_BUF =  1 << 3;

  void
  create_data_bo_from_file(io_test_bo& ibo, const std::string filename, int flags);

  void
  create_ctrl_bo_from_elf(io_test_bo& ibo, xrt_core::elf_patcher::buf_type type);

  xrt_core::cuidx_type
  get_cu_idx(hw_ctx& hwctx);

private:
  void
  cache_cmd_header();
};

class io_test_bo_set : public io_test_bo_set_base
{
public:
  io_test_bo_set(device *dev, const std::string& tag = "", bool use_ubuf = false, const flow_type* flow = nullptr);
  io_test_bo_set(device *dev, const std::string& tag, const flow_type* flow);
  io_test_bo_set(device *dev, bool use_ubuf);

  void
  init_cmd(hw_ctx& hwctx, bool dump) override;

  void
  verify_result() override;
};

class elf_io_test_bo_set : public io_test_bo_set_base
{
public:
  elf_io_test_bo_set(device *dev, const std::string& tag = "", const flow_type* flow = nullptr);

  void
  init_cmd(hw_ctx& hwctx, bool dump) override;
};

class elf_full_io_test_bo_set : public io_test_bo_set_base
{
public:
  elf_full_io_test_bo_set(device *dev, const std::string& tag = "", const flow_type* flow = nullptr);

  void
  init_cmd(hw_ctx& hwctx, bool dump) override;
};

class elf_preempt_io_test_bo_set : public io_test_bo_set_base
{
public:
  elf_preempt_io_test_bo_set(device *dev, const std::string& tag = "", const flow_type* flow = nullptr);

  void
  init_cmd(hw_ctx& hwctx, bool dump) override;

  unsigned long
  get_preemption_checkpoints() override;

private:
  bool m_is_full_elf;
  unsigned long m_total_fine_preemption_checkpoints;
};

class elf_io_negative_test_bo_set : public io_test_bo_set_base
{
public:
  elf_io_negative_test_bo_set(device *dev, const std::string& tag,
    const std::string& elf_name, uint32_t exp_status, uint32_t exp_txn_op_idx);

  void
  init_cmd(hw_ctx& hwctx, bool dump) override;

  void
  verify_result() override;

private:
  uint32_t m_expect_txn_op_idx;
  uint32_t m_expect_cmd_status;
};

class async_error_io_test_bo_set : public io_test_bo_set_base
{
public:
  async_error_io_test_bo_set(device *dev);

  void
  init_cmd(hw_ctx& hwctx, bool dump) override;

  void
  verify_result() override;

private:
  uint64_t m_expect_err_code;
  uint64_t m_last_err_timestamp;
  static const std::map<uint32_t, enum xrtErrorNum> m_shim_event_err_num_map;
};

class async_error_aie4_io_test_bo_set : public io_test_bo_set_base
{
public:
  async_error_aie4_io_test_bo_set(device *dev, const std::string& tag);

  void
  init_cmd(hw_ctx& hwctx, bool dump) override;

  void
  verify_result() override;

private:
  uint64_t m_expect_err_code;
  uint64_t m_last_err_timestamp;
};

class elf_io_gemm_test_bo_set : public io_test_bo_set_base
{
public:
  elf_io_gemm_test_bo_set(device *dev, const std::string& tag,
    const std::string& elf_name);

  void
  init_cmd(hw_ctx& hwctx, bool dump) override;

  void
  verify_result() override;

private:
  std::unique_ptr<xrt_core::buffer_handle> m_dbo;
};

class elf_io_aie_debug_test_bo_set : public io_test_bo_set_base
{
public:
  elf_io_aie_debug_test_bo_set(device *dev, const std::string& tag,
    const flow_type* flow = nullptr);

  void
  init_cmd(hw_ctx& hwctx, bool dump) override;

  void
  verify_result() override;

private:
  bool m_is_full_elf = false;
};

#endif // _SHIMTEST_IO_H_

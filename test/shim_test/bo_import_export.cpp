// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2024-2026, Advanced Micro Devices, Inc. All rights reserved.

#include "bo.h"
#include "io.h"
#include "2proc.h"
#include "dev_info.h"

#include "core/common/system.h"

namespace {

using namespace xrt_core;

class test_2proc_export_import_bo : public test_2proc
{
public:
  test_2proc_export_import_bo(device::id_type id) : test_2proc(id)
  {}

private:
  struct ipc_data {
    pid_t pid;
    shared_handle::export_handle hdl;
  };

  void
  run_test_parent() override
  {
    msg("test started...");

    bool success = true;
    ipc_data idata = {};
    if (!recv_ipc_data(&idata, sizeof(idata)))
      return;

    msg("Received fd %d from PID %d", idata.hdl, idata.pid);

    // Create IO test BO set and replace input BO with the one from child
    auto sdev = get_userpf_device(get_dev_id());
    auto dev = sdev.get();

    auto boset = create_bo_set_for_device(dev);
    boset->get_bos()[IO_TEST_BO_INPUT].tbo = std::make_shared<bo>(dev, idata.pid, idata.hdl);
    boset->run();
    send_ipc_data(&success, sizeof(success));
  }

  void
  run_test_child() override
  {
    msg("test started...");

    // Create IO test BO set and share input BO with parent
    auto dev = get_userpf_device(get_dev_id());
    auto boset = create_bo_set_for_device(dev.get());
    auto& input_bo = boset->get_bos()[IO_TEST_BO_INPUT].tbo;
    if (!input_bo)
      throw std::runtime_error("BO set has no input BO, export test requires IO_TEST_BO_INPUT");
    auto share = input_bo->get()->share();
    ipc_data idata = { getpid(), share->get_export_handle() };
    send_ipc_data(&idata, sizeof(idata));
    bool success;
    recv_ipc_data(&success, sizeof(success));
  }
};

}

void
TEST_export_import_bo(device::id_type id, std::shared_ptr<device>& sdev, const std::vector<uint64_t>& arg)
{
  // Can't fork with opened device.
  sdev.reset();

  test_2proc_export_import_bo t2p(id);
  t2p.run_test();
}

void
TEST_export_import_bo_single_proc(device::id_type id, std::shared_ptr<device>& sdev, const std::vector<uint64_t>& arg)
{
  auto dev = sdev.get();

  // Create IO test BO set and share input BO with same process
  auto boset1 = create_bo_set_for_device(dev);
  auto& input_bo1 = boset1->get_bos()[IO_TEST_BO_INPUT].tbo;
  if (!input_bo1)
    throw std::runtime_error("BO set has no input BO, export test requires IO_TEST_BO_INPUT");
  auto share = input_bo1->get()->share();

  // Create IO test BO set and replace input BO with the one from above and execute it
  auto boset2 = create_bo_set_for_device(dev);
  auto& input_bo2 = boset2->get_bos()[IO_TEST_BO_INPUT].tbo;
  if (!input_bo2)
    throw std::runtime_error("BO set has no input BO, export test requires IO_TEST_BO_INPUT");
  boset2->get_bos()[IO_TEST_BO_INPUT].tbo = std::make_shared<bo>(dev, getpid(), share->get_export_handle());
  boset2->run();
}

void
TEST_export_bo_then_close_device(device::id_type id, std::shared_ptr<device>& sdev, const std::vector<uint64_t>& arg)
{
  auto dev = sdev.get();
  std::unique_ptr<xrt_core::shared_handle> share;

  // Create IO test BO set and export input BO
  {
    auto boset1 = create_bo_set_for_device(dev);
    auto& input_bo = boset1->get_bos()[IO_TEST_BO_INPUT].tbo;
    if (!input_bo)
      throw std::runtime_error("BO set has no input BO, export test requires IO_TEST_BO_INPUT");
    share = input_bo->get()->share();
  }
  // Close device fd while holding onto the exported BO
  sdev.reset();
  // Exported BO is freed here
}

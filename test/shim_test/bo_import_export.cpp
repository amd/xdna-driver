// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2024, Advanced Micro Devices, Inc. All rights reserved.

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

    msg("Received BO %d from PID %d", idata.hdl, idata.pid);

    // Create IO test BO set and replace input BO with the one from child
    auto sdev = get_userpf_device(get_dev_id());
    auto dev = sdev.get();
    auto wrk = get_xclbin_workspace(dev);
    auto xclbin = get_xclbin_name(dev);

    io_test_bo_set boset{dev, wrk + "/data/"};
    boset.get_bos()[IO_TEST_BO_INPUT].tbo = std::make_shared<bo>(dev, idata.pid, idata.hdl);
    boset.run(xclbin);
    send_ipc_data(&success, sizeof(success));
  }

  void
  run_test_child() override
  {
    msg("test started...");

    // Create IO test BO set and share input BO with parent
    auto dev = get_userpf_device(get_dev_id());
    auto wrk = get_xclbin_workspace(dev.get());
    io_test_bo_set boset{dev.get(), wrk + "/data/"};
    auto share = boset.get_bos()[IO_TEST_BO_INPUT].tbo->get()->share();
    ipc_data idata = { getpid(), share->get_export_handle() };
    send_ipc_data(&idata, sizeof(idata));
    bool success;
    recv_ipc_data(&success, sizeof(success));
  }
};

}

void
TEST_export_import_bo(device::id_type id, std::shared_ptr<device> sdev, const std::vector<uint64_t>& arg)
{
  // Can't fork with opened device.
  sdev.reset();

  test_2proc_export_import_bo t2p(id);
  t2p.run_test();
}

void
TEST_export_import_bo_single_proc(device::id_type id, std::shared_ptr<device> sdev, const std::vector<uint64_t>& arg)
{
  auto dev = sdev.get();
  auto wrk = get_xclbin_workspace(dev);
  auto xclbin = get_xclbin_name(dev);

  // Create IO test BO set and share input BO with same process
  io_test_bo_set boset1{sdev.get(), wrk + "/data/"};
  auto share = boset1.get_bos()[IO_TEST_BO_INPUT].tbo->get()->share();

  // Create IO test BO set and replace input BO with the one from above and execute it
  io_test_bo_set boset2{sdev.get(), wrk + "/data/"};
  boset2.get_bos()[IO_TEST_BO_INPUT].tbo = std::make_shared<bo>(sdev.get(), getpid(), share->get_export_handle());
  boset2.run(xclbin);
}

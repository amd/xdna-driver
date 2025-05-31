// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2024, Advanced Micro Devices, Inc. All rights reserved.

#include "bo.h"
#include "io.h"
#include "hwctx.h"
#include "2proc.h"
#include "dev_info.h"
#include "exec_buf.h"
#include "io_config.h"

#include "core/common/system.h"
#include "core/common/shim/fence_handle.h"
#include <algorithm>

namespace {

using namespace xrt_core;
using arg_type = const std::vector<uint64_t>;

class test_2proc_cmd_fence_host : public test_2proc
{
public:
  test_2proc_cmd_fence_host(device::id_type id) : test_2proc(id)
  {}

private:
  struct ipc_data {
    pid_t pid;
    shared_handle::export_handle shdl; // for signaling
    shared_handle::export_handle whdl; // for waiting
  };

  void
  run_test_parent() override
  {
    msg("user fence test started...");

    ipc_data idata = {};
    if (!recv_ipc_data(&idata, sizeof(idata)))
      return;
    msg("Received cmd fence fd %d %d from pid %d", idata.shdl, idata.whdl, idata.pid);

    auto dev = get_userpf_device(get_dev_id());
    auto wfence = dev->import_fence(idata.pid, idata.whdl);
    auto sfence = dev->import_fence(idata.pid, idata.shdl);

    wfence->wait(0);
    sfence->signal();
    wfence->wait(0);
    sfence->signal();
    wfence->wait(0);
    sfence->signal();

    bool success = true;
    send_ipc_data(&success, sizeof(success));
  }

  void
  run_test_child() override
  {
    msg("user fence test started...");

    auto dev = get_userpf_device(get_dev_id());
    auto sfence = dev->create_fence(fence_handle::access_mode::process);
    auto wfence = dev->create_fence(fence_handle::access_mode::process);
    auto sshare = sfence->share();
    auto wshare = wfence->share();
    ipc_data idata = { getpid(), sshare->get_export_handle(), wshare->get_export_handle() };
    send_ipc_data(&idata, sizeof(idata));

    wfence->signal();
    sfence->wait(0);
    wfence->signal();
    sfence->wait(0);
    wfence->signal();
    sfence->wait(0);

    bool success;
    recv_ipc_data(&success, sizeof(success));
  }
};

class test_2proc_cmd_fence_device : public test_2proc
{
public:
  test_2proc_cmd_fence_device(device::id_type id) : test_2proc(id)
  {}

private:
  struct ipc_data {
    pid_t pid;
    shared_handle::export_handle hdl;
  };

  void
  run_test_parent() override
  {
    msg("device fence test started...");

    ipc_data idata = {};
    if (!recv_ipc_data(&idata, sizeof(idata)))
      return;
    msg("Received cmd fence fd %d from pid %d", idata.hdl, idata.pid);

    auto dev = get_userpf_device(get_dev_id());
    auto fence = dev->import_fence(idata.pid, idata.hdl);
    const std::vector<xrt_core::fence_handle*> wfences{fence.get()};
    const std::vector<xrt_core::fence_handle*> sfences{};

    io_test_bo_set boset{dev.get()};
    boset.run(wfences, sfences, false);
    boset.run(wfences, sfences, false);
    boset.run(wfences, sfences, false);

    bool success = true;
    send_ipc_data(&success, sizeof(success));
  }

  void
  run_test_child() override
  {
    msg("device fence test started...");

    auto dev = get_userpf_device(get_dev_id());
    auto fence = dev->create_fence(fence_handle::access_mode::process);
    const std::vector<xrt_core::fence_handle*> sfences{fence.get()};
    const std::vector<xrt_core::fence_handle*> wfences{};
    auto share = fence->share();
    ipc_data idata = { getpid(), share->get_export_handle() };
    send_ipc_data(&idata, sizeof(idata));

    hw_ctx hwctx{dev.get()};
    auto hwq = hwctx.get()->get_hw_queue();

    try {
      hwq->submit_signal(fence.get());
    } catch(...) {
      fence->signal();
      throw;
    }

    io_test_bo_set boset{dev.get()};
    boset.run(wfences, sfences, false);
    boset.run(wfences, sfences, false);

    bool success;
    recv_ipc_data(&success, sizeof(success));
  }
};

}

void
TEST_cmd_fence_host(device::id_type id, std::shared_ptr<device>& sdev, arg_type& arg)
{
  // Can't fork with opened device.
  sdev.reset();

  test_2proc_cmd_fence_host t2p(id);
  t2p.run_test();
}

void
TEST_cmd_fence_device(device::id_type id, std::shared_ptr<device>& sdev, arg_type& arg)
{
  // Can't fork with opened device.
  sdev.reset();

  test_2proc_cmd_fence_device t2p(id);
  t2p.run_test();
}

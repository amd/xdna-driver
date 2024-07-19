// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2024, Advanced Micro Devices, Inc. All rights reserved.

#include "2proc.h"
#include "bo.h"

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

  const uint8_t m_buf_char = 0x55;

  void
  run_test_parent() override
  {
    std::cout << "Running parent test..." << std::endl;

    ipc_data idata = {};
    recv_ipc_data(&idata, sizeof(idata));
    std::cout << "Received BO " << idata.hdl << " from PID " << idata.pid << std::endl;

    bool success = true;
    auto dev = get_userpf_device(get_dev_id());
    bo imp_bo{dev.get(), idata.pid, idata.hdl};
    char *imp_p = reinterpret_cast<char *>(imp_bo.map());
    for (int i = 0; i < imp_bo.size(); i++) {
      if (imp_p[i] != m_buf_char) {
        std::cout << "Imported BO content mis-match" << std::endl;
        success = false;
        break;
      }
    }
    send_ipc_data(&success, sizeof(success));
  }

  void
  run_test_child() override
  {
    std::cout << "Running child test..." << std::endl;

    auto dev = get_userpf_device(get_dev_id());
    bo exp_bo{dev.get(), 4096ul};
    auto exp_p = exp_bo.map();
    std::memset(exp_p, m_buf_char, exp_bo.size());
    auto share = exp_bo.get()->share();
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

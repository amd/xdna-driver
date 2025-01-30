// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2025, Advanced Micro Devices, Inc. All rights reserved.

#ifndef _MULTI_THREADS_H_
#define _MULTI_THREADS_H_

#include <thread>

#include "core/common/device.h"

using namespace xrt_core;
using arg_type = const std::vector<uint64_t>;

typedef void (*func)(device::id_type id, std::shared_ptr<device> dev, arg_type& arg);

class multi_thread {
public:
  multi_thread(int num_thread, func test) :
    m_total_threads(num_thread),
    m_test(test)
  {
    std::cout << "Total threads " << m_total_threads << std::endl;
  }

  ~multi_thread()
  {
  }

  void run_test(xrt_core::device::id_type id, std::shared_ptr<device> dev, arg_type& arg)
  {
    for (int i = 0; i < m_total_threads; i++) {
      m_threads.push_back(std::thread([&](int i){
          std::cout << "Thread " << i << " started" << std::endl;
	  m_test(id, dev ,arg);
	}, i)
      );
    }

    for (int i = 0; i < m_total_threads; i++)
      m_threads[i].join();
  }

private:
  int m_total_threads;
  std::vector<std::thread> m_threads;
  func m_test;
};

#endif // _MULTI_THREADS_H_

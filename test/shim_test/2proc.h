// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2024, Advanced Micro Devices, Inc. All rights reserved.

#ifndef _SHIMTEST_2PROC_H_
#define _SHIMTEST_2PROC_H_

#include "core/common/device.h"

#include <signal.h>
#include <sys/wait.h>

class test_2proc {
public:
  test_2proc(xrt_core::device::id_type id) : m_id(id)
  {
    int p_pipefd[2] = {-1, -1};
    int c_pipefd[2] = {-1, -1};

    if (pipe(p_pipefd) < 0 || pipe(c_pipefd) < 0) {
      std::cout << "Can't create pipes" << std::endl;
      // Just quit on these fundamental issues and let OS clean it up.
      _exit(EXIT_FAILURE);
    }
    auto pid = fork();
    if (pid == -1) {
      std::cout << "Can't fork" << std::endl;
      // Just quit on these fundamental issues and let OS clean it up.
      _exit(EXIT_FAILURE);
    }
    // We want to handle pipe comm issue ourselves.
    signal(SIGPIPE, SIG_IGN);

    m_is_parent = !!pid;

    if (m_is_parent) {
      m_read_fd = p_pipefd[0];
      close(p_pipefd[1]);
      m_write_fd = c_pipefd[1];
      close(c_pipefd[0]);
    } else {
      m_read_fd = c_pipefd[0];
      close(c_pipefd[1]);
      m_write_fd = p_pipefd[1];
      close(p_pipefd[0]);
    }

    std::cout << (m_is_parent ? "Parent" : "Child") << " started: " << getpid() << std::endl;
  }

  ~test_2proc()
  {
    close(m_read_fd);
    close(m_write_fd);
    if (m_is_parent)
      wait(nullptr);
    else
      _exit(m_child_failed ? EXIT_FAILURE : EXIT_SUCCESS);
  }

  void
  run_test()
  {
    if (m_is_parent) {
      run_test_parent();
      wait_for_child();
    } else {
      try {
        run_test_child();
      } catch (const std::exception& ex) {
        std::cout << "Child failed: " << ex.what() << std::endl;
        m_child_failed = true;
        return;
      }
      m_child_failed = false;
    }
  }

protected:
  void
  send_ipc_data(const void *buf, size_t size)
  {
    if (write(m_write_fd, buf, size) != size) {
      if (!m_is_parent)
        throw std::runtime_error("Failed to send IPC data to parent");
      else
        std::cout << "Failed to send IPC data to child" << std::endl;
    }
  }

  void
  recv_ipc_data(void *buf, size_t size)
  {
    if (read(m_read_fd, buf, size) != size) {
      if (!m_is_parent)
        throw std::runtime_error("Failed to read IPC data from parent");
      else
        std::cout << "Failed to read IPC data from child" << std::endl;
    }
  }

  xrt_core::device::id_type
  get_dev_id()
  {
    return m_id;
  }

private:
  virtual void
  run_test_parent() = 0;

  virtual void
  run_test_child() = 0;

  void
  wait_for_child()
  {
    int status = 0;

    wait(&status);
    if (!WIFEXITED(status) || WEXITSTATUS(status) != EXIT_SUCCESS)
      throw std::runtime_error("Child did not complete successfully");
  }

  bool m_is_parent = false;
  bool m_child_failed = true;
  int m_read_fd = -1;
  int m_write_fd = -1;
  xrt_core::device::id_type m_id;
};

#endif // _SHIMTEST_2PROC_H_

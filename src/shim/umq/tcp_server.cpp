// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2025, Advanced Micro Devices, Inc. All rights reserved.

#include <netinet/in.h>
#include <sys/socket.h>
#include <chrono>
#include <thread>

#include "tcp_server.h"

namespace shim_xdna {

tcp_server::
tcp_server(const device& dev, hwctx* hwctx)
  : m_dbg_umq(dev)
  , m_def_size(16)
  , m_ctrl_buf(nullptr)
  , m_ctrl_paddr(0)
  , m_aie_attached(false)
  , m_pdev(dev.get_pdev())
{
  m_hwctx = hwctx;
  auto def_buf_size = m_def_size * sizeof(uint32_t);
  m_data_bo = std::make_unique<buffer>(m_pdev, def_buf_size, AMDXDNA_BO_SHARE);
  m_data_buf = m_data_bo->vaddr();
  m_data_paddr = m_data_bo->paddr();
  m_srv_stop = 0;

  // issue ioctl to attach the dbg hsa queue
  std::map<uint32_t, size_t> buf_sizes;
  buf_sizes[0] = 32; // we don't care size

  m_dbg_umq.get_dbg_umq_bo()->config(m_hwctx, buf_sizes);
  shim_debug("TCP server ioctl: debugger attach\n");
}

tcp_server::
~tcp_server()
{
  shim_debug("TCP server destructor");
}

void
tcp_server::
sigusr1_handler(int sig)
{
  if (sig == SIGUSR1)
  {
    shim_debug("SIGUSR1 received!");
    m_srv_stop = 1;
  }
}

void
tcp_server::
start()
{
  struct sigaction sa;
  sa.sa_handler = tcp_server::sigusr1_handler;
  sigemptyset(&sa.sa_mask);
  sa.sa_flags = 0;
  sigaction(SIGUSR1, &sa, nullptr);

  int serverSocket = socket(AF_INET, SOCK_STREAM, 0);
  
  if (serverSocket < 0)
  {
    shim_debug("tcp server socket creation failed");
    return;
  }

  // specifying the address
  sockaddr_in serverAddress; 
  serverAddress.sin_family = AF_INET;
  serverAddress.sin_port = htons(6666);
  serverAddress.sin_addr.s_addr = INADDR_ANY;
  
  // binding socket. 
  int ret = bind(serverSocket, (struct sockaddr*)&serverAddress, sizeof(serverAddress));
  if (ret == -1)
  {
    shim_debug("tcp server socket bind failed");
    close(serverSocket);
    return;
  }
  
  // listening to the assigned socket
  // we allow only one debugger running
  listen(serverSocket, 1); 
  int flags = fcntl(serverSocket, F_GETFL, 0);
  if (flags == -1)
  {
    shim_debug("F_GETFL over tcp server socket failed: %d", errno);
    close(serverSocket);
    return;
  }
  ret = fcntl(serverSocket, F_SETFL, flags | O_NONBLOCK);
  if (ret == -1)
  {
    shim_debug("F_SETFL over tcp server socket failed: %d", errno);
    close(serverSocket);
    return;
  }

  shim_debug("Waiting for incoming connection...\n");
  while (!m_srv_stop)
  { 
    // accepting connection request
    int clientSocket = accept(serverSocket, nullptr, nullptr);
    if (clientSocket < 0)
    { 
      if (errno == EINTR && m_srv_stop == 1)
      { 
        shim_debug("Tcp thread exit!\n");
        break;
      }
      else if (errno == EAGAIN || errno == EWOULDBLOCK)
      {
        std::this_thread::sleep_for(std::chrono::seconds(1));
        continue;
      }
      else
      {
        throw;
      }
    }

    bool loop = true;
    while (loop)
    {
      int length = 0;
      ssize_t n = recv(clientSocket, &length, sizeof(int), MSG_DONTWAIT);

      if (n == 0)
      {
        // connection closed, we detach.
        shim_debug("Tcp connection lost!\n");
        handle_detach();
        loop = false;
        break;
      }
      else if (n < 0)
      {
        if (errno == EAGAIN || errno == EWOULDBLOCK)
        {
          std::this_thread::sleep_for(std::chrono::seconds(1));
          continue;
        }
        else if (errno == EINTR && m_srv_stop == 1)
        {
          shim_debug("Tcp connection exit!\n");
          loop = false;
          break;
        }
      }

      //we don't expect front end read/write longer than 64k in one cmd
      //and length must be multiple of word
      if (length <= 0 || length > 0x10000 ||
        (length % sizeof(uint32_t) != 0))
      {
        shim_debug("tcp server recv() length failure\n");
        break;
      }
      std::vector<uint32_t> buffer(length >> 2);
      n = recv(clientSocket, buffer.data(), length, 0);
      if (n <= 0)
      {
        shim_debug("tcp server recv() data failure\n");
        break;
      }

      auto cmd = reinterpret_cast<aie_debugger_cmd *>(buffer.data());
      switch (cmd->type)
      {
        case ATTACH_CMD:
        {
          uint32_t status = handle_attach(cmd->cmd.attach.uc_index);
          std::vector<uint32_t> ret;
          ret.push_back(sizeof(uint32_t));
          ret.push_back(status);
          n = send(clientSocket, ret.data(), ret.size() * sizeof(uint32_t), 0);
          break;
        }
        case READ_MEM_CMD:
        {
          auto data = handle_read_mem(cmd->cmd.read_mem.aie_addr, cmd->cmd.read_mem.length);
          std::vector<uint32_t> ret;
          ret.push_back(sizeof(uint32_t) * (cmd->cmd.read_mem.length + 1));
          ret.insert(ret.end(), data->begin(), data->end());

          n = send(clientSocket, ret.data(), ret.size() * sizeof(uint32_t), 0);
          break;
        }
        case WRITE_MEM_CMD:
        {
          std::vector<uint32_t> data = {buffer.begin() + 2, buffer.end()};
          uint32_t status = handle_write_mem(cmd->cmd.write_mem.aie_addr, data);
          std::vector<uint32_t> ret;
          ret.push_back(sizeof(uint32_t));
          ret.push_back(status);
          n = send(clientSocket, ret.data(), ret.size() * sizeof(uint32_t), 0);
          break;
        }
        case DETACH_CMD:
          handle_detach();
          loop = false;
          break;
        default:
          break;
      }

      if (n <= 0)
      {// if we can't send back data to front, something wrong happen
       // just detach from cert
        shim_debug("tcp server: failed to send data back to front");
        handle_detach();
        loop = false;
        break;
      }
    }
    // closing the client socket.
    close(clientSocket);
  }

  // closing the server socket.
  close(serverSocket);
}

std::unique_ptr<std::vector<uint32_t>> 
tcp_server::
handle_read_mem(uint32_t addr, uint32_t length)
{
  //we return one extra word to front end
  //1st word returned is the status
  std::vector<uint32_t> data(length + 1);

  if (!m_aie_attached)
  {
    data[0] = AIE_DBG_NOT_ATTACHED;
    return std::make_unique<std::vector<uint32_t>>(data);
  }

  if (length > m_def_size)
  {
    buffer_extend(length); 
  }

  struct rw_mem rw;
  rw.host_addr_high = m_data_paddr >> 32;
  rw.host_addr_low = m_data_paddr & 0xffffffff;
  rw.aie_addr = addr;
  rw.length = length;

  uint32_t ret = m_dbg_umq.issue_rw_cmd(rw, DBG_CMD_READ);
  if (ret != DBG_PKT_SUCCESS)
  {
    data[0] = ret;
  }
  else
  {
    data[0] = AIE_DBG_SUCCESS;
    std::memcpy(data.data() + 1,
      const_cast<void *>(m_data_buf),
      length * sizeof (uint32_t));
  }
  shim_debug("TCP server read mem: addr (0x%x) length (%dW)\n", addr, length);

  return std::make_unique<std::vector<uint32_t>>(data);
}

uint32_t
tcp_server::
handle_write_mem(uint32_t addr, std::vector<uint32_t> &data)
{
  if (!m_aie_attached)
  {
    return AIE_DBG_NOT_ATTACHED;
  }

  if (data.size() > m_def_size)
  {
    buffer_extend(data.size()); 
  }

  struct rw_mem rw;
  rw.host_addr_high = m_data_paddr >> 32;
  rw.host_addr_low = m_data_paddr & 0xffffffff;
  rw.aie_addr = addr;
  rw.length = data.size();

  std::memcpy(const_cast<void *>(m_data_buf),
    data.data(), 
    data.size() * sizeof(uint32_t));
  uint32_t ret = m_dbg_umq.issue_rw_cmd(rw, DBG_CMD_WRITE);

  shim_debug("TCP server write mem: addr (0x%x)\n", addr);
  return ret != DBG_PKT_SUCCESS ? ret : AIE_DBG_SUCCESS;
}

void
tcp_server::
buffer_extend(size_t new_size)
{
    shim_debug("TCP server buffer extend to (%dW)\n", new_size);
    auto n_buf_size = new_size * sizeof(uint32_t);
    m_data_bo = std::make_unique<buffer>(m_pdev, n_buf_size, AMDXDNA_BO_SHARE);
    m_data_buf = m_data_bo->vaddr();
    m_data_paddr = m_data_bo->paddr();
}

uint32_t
tcp_server::
handle_attach(uint32_t uc_index)
{
  // Idea was the q can be attached to any uc, but now to simplify,
  // always attach to uc0
  // issue ioctl to attach the dbg hsa queue
  // std::map<uint32_t, size_t> buf_sizes;
  // buf_sizes[uc_index] = 0; //we don't care size

  // m_dbg_umq.get_dbg_umq_bo()->config(m_hwctx, buf_sizes);
  // shim_debug("TCP server ioctl: debugger attach\n");

  m_aie_attached = true;
  return AIE_DBG_SUCCESS;
}

void
tcp_server::
handle_detach()
{
  m_dbg_umq.issue_exit_cmd();
  // issue ioctl to detach the dbg hsa queue
  // m_dbg_umq.get_dbg_umq_bo()->unconfig(m_hwctx);

  m_aie_attached = false;
  shim_debug("TCP server ioctl: debugger queue detach\n");
}

} // shim_xdna

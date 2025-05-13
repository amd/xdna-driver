// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2025, Advanced Micro Devices, Inc. All rights reserved.

#include <signal.h>
#include <thread>
#include <netinet/in.h>
#include <sys/socket.h>

#include "tcp_server.h"

namespace shim_xdna {

tcp_server::
tcp_server(const device &dev) :
m_aie_attached(false), m_dbg_umq(dev) {}, m_def_size(16)
{
  auto def_buf_size = m_def_size * sizeof(uint32_t);
  auto def_bo = alloc_bo(def_buf_size, XCL_BO_FLAGS_EXECBUF);
  m_def_bo = std::unique_ptr<buffer>(static_cast<buffer*>(def_bo.release()));
  m_def_buf = m_def_bo->vaddr();
  m_def_paddr = m_def_bo->paddr();
}

tcp_server::
~tcp_server()
{
}

void
tcp_server::
start()
{
  int serverSocket = socket(AF_INET, SOCK_STREAM, 0);
  
  // specifying the address
  sockaddr_in serverAddress; 
  serverAddress.sin_family = AF_INET;
  serverAddress.sin_port = htons(6666);
  serverAddress.sin_addr.s_addr = INADDR_ANY;
  
  // binding socket. 
  bind(serverSocket, (struct sockaddr*)&serverAddress, sizeof(serverAddress));
  
  // listening to the assigned socket
  // we allow only one debugger running
  listen(serverSocket, 1);
  
  while (1)
  { 
    shim_debug("Waiting for incoming connection...\n");

    // accepting connection request
    int clientSocket = accept(serverSocket, nullptr, nullptr);
    if (clientSocket < 0)
    { 
      if (errno == EINTR)
      { 
        shim_debug("Tcp thread exit!\n");
        break;
      }
    }

    bool loop = true;
    while (loop)
    {
      int length = 0;
      recv(clientSocket, &length, sizeof(int), 0);

      if (!length)
      {
          break;
      }
      std::vector<uint32_t> buffer(length >> 2);
      recv(clientSocket, buffer.data(), length, 0);
      switch (buffer[0])
      {
        case ATTACH_CMD:
        {
          uint32_t status = handle_attach();
          std::vector<uint32_t> ret;
          ret.push_back(sizeof(uint32_t));
          ret.push_back(status);
          send(clientSocket, ret.data(), ret[0] + sizeof(uint32_t), 0);
          break;
        }
        case READ_MEM_CMD:
        {
          auto data = handle_read_mem(buffer[1], buffer[2]);
          std::vector<uint32_t> ret;
          ret.push_back(sizeof(uint32_t) * (buffer[2] + 1));
          ret.insert(ret.end(), data->begin(), data->end());

          send(clientSocket, ret.data(), ret[0] + sizeof(uint32_t), 0);
          break;
        }
        case WRITE_MEM_CMD:
        {
          std::vector<uint32_t> data = {buffer.begin() + 2, buffer.end()};
          uint32_t status = handle_write_mem(buffer[1], data);
          std::vector<uint32_t> ret;
          ret.push_back(sizeof(uint32_t));
          ret.push_back(status);
          send(clientSocket, ret.data(), ret[0] + sizeof(uint32_t), 0);
          break;
        }
        case DETACH_CMD:
          handle_detach();
          loop = false;
          break;
        default:
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
  rw.host_addr_high = m_def_paddr >> 32;
  rw.host_addr_low = m_def_paddr & 0xffffffff;
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
    std::memcpy(data.data() + 1, m_def_buf, length * sizeof (uint32_t));
  }

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
  rw.host_addr_high = m_def_paddr >> 32;
  rw.host_addr_low = m_def_paddr & 0xffffffff;
  rw.aie_addr = addr;
  rw.length = data.size();

  std::memcpy(m_def_buf, data.data(), data.size() * sizeof(uint32_t));
  uint32_t ret = m_dbg_umq.issue_rw_cmd(rw, DBG_CMD_WRITE);

  return ret != DBG_PKT_SUCCESS ? ret : AIE_DBG_SUCCESS;
}

void
tcp_server::
buffer_extend(size_t new_size)
{
    auto n_buf_size = new_size * sizeof(uint32_t);
    auto n_bo = alloc_bo(n_buf_size, XCL_BO_FLAGS_EXECBUF);
    m_def_bo = std::move(std::unique_ptr<buffer>(static_cast<buffer*>(n_bo.release())));
    m_def_buf = m_def_bo->vaddr();
    m_def_paddr = m_def_bo->paddr();
}

uint32_t
tcp_server::
handle_attach()
{ 
  // issue ioctl to attach the dbg hsa queue
  // send a DBG_CMD_TEST opcode
  m_aie_attached = true;
  return AIE_DBG_SUCCESS;
}

void
tcp_server::
handle_detach()
{
  issue_exit_cmd();
  // issue ioctl to detach the dbg hsa queue
  m_aie_attached = false;
}

} // shim_xdna

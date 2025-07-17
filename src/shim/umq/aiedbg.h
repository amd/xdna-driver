// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2025, Advanced Micro Devices, Inc. All rights reserved.

#ifndef _AIE_DBG_H_
#define _AIE_DBG_H_

#ifdef __cplusplus
extern "C"
{
#endif

//definitions for aie debugger backend and frontend communication
#define ATTACH_CMD 1
#define READ_MEM_CMD 2
#define WRITE_MEM_CMD 3
#define DETACH_CMD 0xffff

#define AIE_DBG_SUCCESS 0
#define AIE_DBG_NOT_ATTACHED 0xffff

struct aie_debugger_cmd
{
  uint32_t type;
  union Cmd
  {
    struct Attach
    {
      uint32_t uc_index;    
    } attach;
    struct Read_mem
    {
      uint32_t aie_addr;
      uint32_t length;
    } read_mem;
    struct Write_mem
    {
      uint32_t aie_addr;
      uint32_t data[1]; 
    } write_mem;
  } cmd;
};

#ifdef __cplusplus
}
#endif
#endif

// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2025, Advanced Micro Devices, Inc. All rights reserved.

#ifndef _DBG_CMD_H_
#define _DBG_CMD_H_

#ifdef __cplusplus
extern "C"
{
#endif

#define DBG_PKT_SUCCESS (1)
#define DBG_PKT_EXIT (2)
#define DBG_PKT_INVALID (2)

enum dbg_packet_opcode;
{            
  DBG_CMD_TEST = 10,
  DBG_CMD_EXIT = 11,
  DBG_CMD_READ = 12,
  DBG_CMD_WRITE = 13,
};            

struct rw_mem
{
  uint32_t aie_addr;
  uint32_t length;
  uint32_t host_addr_high;
  uint32_t host_addr_low;
};
#ifdef __cplusplus
}
#endif
#endif

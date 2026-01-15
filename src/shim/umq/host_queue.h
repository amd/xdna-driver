// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2023-2026, Advanced Micro Devices, Inc. All rights reserved.

#ifndef _HOST_QUEUE_H_
#define _HOST_QUEUE_H_

#define HSA_PKT_SUCCESS (0)
/*
 * 32-bit return code in completion of HSA pkt back to host.
 * The low 4 bits should match ert_cmd_state as defined in ert.h since host user code
 * will check them on all devices/platforms.
 * HSA specific error code will be on high 28 bits.
 */ 
enum hsa_cmd_state
{ // ert_cmd_state essentially
  HSA_CMD_STATE_NEW = 1,
  HSA_CMD_STATE_QUEUED = 2,
  HSA_CMD_STATE_RUNNING = 3,
  HSA_CMD_STATE_COMPLETED = 4,
  HSA_CMD_STATE_ERROR = 5,
  HSA_CMD_STATE_ABORT = 6,
  HSA_CMD_STATE_SUBMITTED = 7,
  HSA_CMD_STATE_TIMEOUT = 8,
  HSA_CMD_STATE_NORESPONSE = 9,
  HSA_CMD_STATE_SKERROR = 10,
  HSA_CMD_STATE_SKCRASHED = 11,
};
#define HSA_COMP_SUCCESS          HSA_CMD_STATE_COMPLETED // Host user code will check this
#define HSA_PKT_PAGE_CONT         10 // cert internal status
#define HSA_ERR(e)                (((e) << 4) | HSA_CMD_STATE_ERROR)
#define HSA_EXIT_PKT              HSA_ERR(0)
#define HSA_PDI_LOAD_NO_MAPPING   HSA_ERR(self_id * 100 + 1)
#define HSA_PDI_LOAD_FAILURE      HSA_ERR(self_id * 100 + 2)
#define HSA_INVALID_OPCODE        HSA_ERR(self_id * 100 + 3)
#define HSA_INVALID_PKT           HSA_ERR(4)
#define HSA_INVALID_PAGE          HSA_ERR(self_id * 100 + 5)
#define HSA_PKT_TIMEOUT           HSA_ERR(self_id * 100 + 6)
#define HSA_MAX_LEVEL1_INDIRECT_ENTRIES (6)

#define LAST_CMD (0)
#define NOT_LAST_CMD (1)

enum host_queue_packet_opcode
{            
  HOST_QUEUE_PACKET_EXEC_BUF = 1,
  HOST_QUEUE_PACKET_TEST = 2,
  HOST_QUEUE_PACKET_EXIT = 3,
};            

/*
 * hsa pkt payload of exec_buf
 * dpu_control_code_host_addr* is used to load control code interpreted by
 * the job runner in CERT
 * args contains the info of input/output frame, parameter of network
 * etc, which are all transparent to CERT 
 */ 
struct exec_buf
{
  uint32_t reserved0;
  uint32_t dpu_control_code_host_addr_low;
  uint32_t dpu_control_code_host_addr_high;
  uint16_t args_len;
  uint16_t reserved1;
  uint32_t args_host_addr_low;
  uint32_t args_host_addr_high;
};

struct host_queue_header
{
  uint64_t read_index;
  struct
  {
    uint16_t major;
    uint16_t minor;
  }
  version;
  uint32_t capacity; //Queue capacity, must be a power of two.
  uint64_t write_index;
  uint64_t data_address;
};


enum host_queue_packet_type
{            
  HOST_QUEUE_PACKET_TYPE_VENDOR_SPECIFIC = 0,
  HOST_QUEUE_PACKET_TYPE_INVALID = 1,
}; 

/*
 * 8 Bytes common header of hsa pkt used in CERT.
 * first 2 Bytes are header defined in HSA spec for all pkt types.
 * CERT so far only supports vendor specific pkt type. This type
 * has pkt header of 16 Bytes, which contains first 8 Bytes of this
 * common header, and 8 Bytes of completion_signal.
 * 'count' specifies the number of valid bytes in the hsa pkt after the
 * vendor specific header (16B) --
 * for 'direct', 'count' is the payload length of , eg, exec_buf
 * for 'indirect', 'count' is used to calc the number of indirect pkt entry,
 * see below
 */ 
struct common_header
{
  union {
    struct {
      uint16_t type: 8;
      uint16_t barrier: 1;
      uint16_t acquire_fence_scope: 2;    
      uint16_t release_fence_scope: 2;
    };    
    uint16_t header;
  };
  uint8_t opcode;
  uint8_t chain_flag;
  uint16_t count;
  uint8_t distribute;
  uint8_t indirect;
};

struct xrt_packet_header
{
  struct common_header common_header;	
  uint64_t completion_signal;
};

/*
 * format of indirect pkt. multiple-indirect-level is supported
 * there is vendor specific header (common header plus completion_signal) in 1st indirect level
 * there is common header in all the remaining indirect levels
 */ 
struct host_indirect_packet_entry
{
  uint32_t host_addr_low;
  uint32_t host_addr_high:25;
  uint32_t uc_index:7;
};

#define INVALID_INDIRECT_ADDR (0xffffffff)
/*
 * hsa pkt format -- 64Bytes fixed length
 *
 * case 1 -- direct exec_buf on one column
 * xrt_packet_header:
 *   type: 0 (vendor specific)
 *   opcode: 1 (exec_buf)
 *   count: 24 (sizeof(struct exec_buf))
 *   distribute: 0
 *   indirect: 0
 *   completion_signal: xxx
 * data:
 *   struct exec_buf
 *
 * case 2 -- indirect config_cu 
 * xrt_packet_header:
 *   type: 0 (vendor specific)
 *   opcode: 0 (config_cu)
 *   count: 12 (1 * sizeof(struct host_indirect_packet_entry))
 *   distribute: 0
 *   indirect: 1 // common header of indirect
 *   completion_signal: xxx
 * data:
 *   struct host_indirect_packet_entry:
 *     column_index: index of lead uc
 *     host_addr*: host addr of next level
 *       common_header:
 *         type: 0 (vendor specific)
 *         opcode: 0 (config_cu)
 *         count: 72 (config_cu with 16 entries)) //10 entry config_cu can fit in direct pkt
 *         indirect: 0 // common header of direct
 *       payload:
 *         struct config_cu: 16 entries of mapping table
 *
 * case 3 -- indirect exec_buf on 4 column partition
 * xrt_packet_header:
 *   type: 0 (vendor specific)
 *   opcode: 1 (exec_buf)
 *   count: 48 (6 *sizeof(struct host_indirect_packet_entry))
 *   distribute: 1
 *   indirect: 1 // common header of indirect
 *   completion_signal: xxx
 * data:
 *   struct host_indirect_packet_entry:
 *     column_index: index of lead uc
 *     host_addr*: host addr of next level
 *       common_header:
 *         type: 0 (vendor specific)
 *         opcode: 1 (exec_buf)
 *         count: 24 (sizeof(struct exec_buf))
 *         indirect: 0 // common header of direct
 *       payload:
 *          struct exec_buf 
 *   struct host_indirect_packet_entry:
 *     column_index: index of slave1
 *     host_addr*: host addr of next level
 *       common_header:
 *          type: 0 (vendor specific)
 *          opcode: 1 (exec_buf)
 *          count: 24 (struct sizeof(exec_buf))
 *          indirect: 0 // common header of direct
 *       payload:
 *          struct exec_buf
 *   struct host_indirect_packet_entry:
 *     slave2,3,etc...
 *
 * case 4 -- indirect exec_buf on 8 column partition 
 * xrt_packet_header:
 *   type: 0 (vendor specific)
 *   opcode: 1 (exec_buf)
 *   count: 12 (sizeof(struct host_indirect_packet_entry))
 *   distribute: 1
 *   indirect: 1 // common_header of level-1 indirect
 *   completion_signal: xxx
 * data:
 *   struct host_indirect_packet_entry:
 *     column_index: index of lead uc
 *     host_addr*: host addr of next level
 *       common_header:
 *         type: 0 (vendor specific)
 *         opcode: 1 (exec_buf)
 *         count: 12*8 (12 * sizeof(struct host_indirect_packet_entry))
 *         distribute: 1
 *         indirect: 1 // common header of level-2 indirect
 *       indirect_payload: 
 *         struct host_indirect_packet_entry:
 *           column_index: index of lead uc
 *           host_addr*: host addr of next level
 *             common_header:
 *               type: 0 (vendor specific)
 *               opcode: 1 (exec_buf)
 *               count: 24 (sizeof(struct exec_buf))
 *               distribute: 1
 *               indirect: 0  // common_header of direct
 *             payload: 
 *               struct exec_buf
 *         struct host_indirect_packet_entry:
 *           column_index: index of slave1
 *           host_addr*: host addr of next level
 *             common_header:
 *               type: 0 (vendor specific)
 *               opcode: 1 (exec_buf)
 *               count: 24 (sizeof(struct exec_buf))
 *               distribute: 1
 *               indirect: 0 // common_header of direct
 *             payload: 
 *               struct exec_buf
 *         struct host_indirect_packet_entry:
 *           slave2,3,etc...
 */ 
struct host_queue_packet
{
  struct xrt_packet_header xrt_header;	
  uint32_t data[12];
};

struct host_indirect_data {
  struct common_header header;
  struct exec_buf  payload;
};

/*
 * xrt pkt with random length.
 */ 
struct xrt_packet
{
  struct xrt_packet_header xrt_header;	
  uint64_t xrt_payload_host_addr;
};

struct host_queue
{
  uint64_t address;
};

#endif

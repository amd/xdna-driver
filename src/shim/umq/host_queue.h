/*  (c) Copyright 2014 - 2022 Xilinx, Inc. All rights reserved.
   
    This file contains confidential and proprietary information
    of Xilinx, Inc. and is protected under U.S. and
    international copyright and other intellectual property
    laws.
   
    DISCLAIMER
    This disclaimer is not a license and does not grant any
    rights to the materials distributed herewith. Except as
    otherwise provided in a valid license issued to you by
    Xilinx, and to the maximum extent permitted by applicable
    law: (1) THESE MATERIALS ARE MADE AVAILABLE "AS IS" AND
    WITH ALL FAULTS, AND XILINX HEREBY DISCLAIMS ALL WARRANTIES
    AND CONDITIONS, EXPRESS, IMPLIED, OR STATUTORY, INCLUDING
    BUT NOT LIMITED TO WARRANTIES OF MERCHANTABILITY, NON-
    INFRINGEMENT, OR FITNESS FOR ANY PARTICULAR PURPOSE; and
    (2) Xilinx shall not be liable (whether in contract or tort,
    including negligence, or under any other theory of
    liability) for any loss or damage of any kind or nature
    related to, arising under or in connection with these
    materials, including for any direct, or any indirect,
    special, incidental, or consequential loss or damage
    (including loss of data, profits, goodwill, or any type of
    loss or damage suffered as a result of any action brought
    by a third party) even if such damage or loss was
    reasonably foreseeable or Xilinx had been advised of the
    possibility of the same.
   
    CRITICAL APPLICATIONS
    Xilinx products are not designed or intended to be fail-
    safe, or for use in any application requiring fail-safe
    performance, such as life-support or safety devices or
    systems, Class III medical devices, nuclear facilities,
    applications related to the deployment of airbags, or any
    other applications that could lead to death, personal
    injury, or severe property or environmental damage
    (individually and collectively, "Critical
    Applications"). Customer assumes the sole risk and
    liability of any use of Xilinx products in Critical
    Applications, subject only to applicable laws and
    regulations governing limitations on product liability.
   
    THIS COPYRIGHT NOTICE AND DISCLAIMER MUST BE RETAINED AS
    PART OF THIS FILE AT ALL TIMES.                       */

#ifndef _HOST_QUEUE_H_
#define _HOST_QUEUE_H_

#include <stdbool.h>
#include <stdint.h>

#define SHIM_USER_EVENT_0_ID 0xb6
#define DOORBELL_EVENT_ID SHIM_USER_EVENT_0_ID

#define PDI_TABLE_SIZE 64

#define HSA_PKT_SUCCESS (0)
/*
 * 32-bit return code in completion of HSA pkt back to host.
 * The low 4 bits should match ert_cmd_state as defined in ert.h since host user code
 * will check them on all devices/platforms.
 * HSA specific error code will be on high 28 bits.
 */ 
enum hsa_cmd_state { // ert_cmd_state essentially
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
#define HSA_ERR(e)                (((e) << 4) | HSA_CMD_STATE_ERROR)
#define HSA_EXIT_PKT              HSA_ERR(0)
#define HSA_PDI_LOAD_NO_MAPPING   HSA_ERR(column_index_rel * 100 + 1)
#define HSA_PDI_LOAD_FAILURE      HSA_ERR(column_index_rel * 100 + 2)
#define HSA_INVALID_OPCODE        HSA_ERR(column_index_rel * 100 + 3)
#define HSA_INVALID_PKT           HSA_ERR(4)
#define HSA_INVALID_PAGE          HSA_ERR(column_index_rel * 100 + 5)

typedef enum     
{            
  HOST_QUEUE_PACKET_EXEC_BUF = 1,
  HOST_QUEUE_PACKET_TEST = 2,
  HOST_QUEUE_PACKET_EXIT = 3,
}            
host_queue_packet_opcode_t;

/*
 * cu_config contains cu <-> pdi mapping info
 *
 * due to memory footprint limitation, the pdi info (host address) is not saved in CERT
 * if num_mappings == 1, then pdi_info_host_addr contains the host addr of the pdi
 * if num_mappings > 1, then pdi_info_host_addr contains the host addr of a table, in which
 * the host addr of all the pdi are saved.
 *
 * note: both cu_index and pdi_index should be start from 0
 * e.g mapping[0] = 0, mapping[1] = 1, mapping[2] = 0,
 * means,
 * cu0 <-> pdi0
 * cu1 <-> pdi1
 * cu2 <-> pdi0
 * there are 3 mappings, and 2 pdi in pdi_info_host_addr table 
 */
typedef struct
{
  uint32_t num_mappings;
  uint32_t pdi_info_host_addr_low;
  uint32_t pdi_info_host_addr_high;
  uint8_t mapping[PDI_TABLE_SIZE];
}
config_cu_t;

#define INVALID_PDI_ID (0xFF)

/*
 * Maximum number of exec buf args in 4B
 */ 
#define EXEC_BUF_ARGS_MAX_LEN (20)

/*
 * hsa pkt payload of exec_buf
 * this cmd has to be after the cu_config cmd, with which the cu_index in
 * this cmd can locate the pdi info corresponding to the cu, CERT then can
 * decide whether pdi load is required.
 * dpu_control_code_host_addr* is used to load control code interpreted by
 * the job runner in CERT
 * args contains the info of input/output frame, parameter of network
 * etc, which are all transparent to CERT 
 */ 
typedef struct
{
  uint16_t cu_index;
  uint16_t reserved0;
  uint32_t dpu_control_code_host_addr_low;
  uint32_t dpu_control_code_host_addr_high;
  uint16_t args_len;
  uint16_t reserved1;
  uint32_t args_host_addr_low;
  uint32_t args_host_addr_high;
}
exec_buf_t;


typedef struct
{
  uint64_t read_index;
  
  uint32_t reserved;
  
  //! @note Queue capacity, must be a power of two.
  uint32_t capacity;

  uint64_t write_index;
  
  uint64_t data_address;
  
  // TODO Ready signal?
}
host_queue_header_t;


typedef enum     
{            
  HOST_QUEUE_PACKET_TYPE_VENDOR_SPECIFIC = 0,
  HOST_QUEUE_PACKET_TYPE_INVALID = 1,
}            
host_queue_packet_type_t;

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
typedef struct
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
  uint16_t opcode;
  uint16_t count;
  uint8_t distribute;
  uint8_t indirect;
}
common_header_t;

typedef struct
{
  common_header_t common_header;	
  uint64_t completion_signal;
}
xrt_packet_header_t;

/*
 * format of indirect pkt. multiple-indirect-level is supported
 * there is vendor specific header (common header plus completion_signal) in 1st indirect level
 * there is common header in all the remaining indirect levels
 */ 
typedef struct
{
  uint16_t column_index;
  uint16_t reserved;
  uint32_t host_addr_low;
  uint32_t host_addr_high;
}
host_indirect_packet_entry_t;

/*
 * hsa pkt format -- 64Bytes fixed length
 *
 * case 1 -- direct exec_buf on one column
 * xrt_packet_header:
 *   type: 0 (vendor specific)
 *   opcode: 1 (exec_buf)
 *   count: 24 (sizeof(exec_buf_t))
 *   distribute: 0
 *   indirect: 0
 *   completion_signal: xxx
 * data:
 *   exec_buf_t
 *
 * case 2 -- indirect config_cu 
 * xrt_packet_header:
 *   type: 0 (vendor specific)
 *   opcode: 0 (config_cu)
 *   count: 12 (1 * sizeof(host_indirect_packet_entry_t))
 *   distribute: 0
 *   indirect: 1 // common header of indirect
 *   completion_signal: xxx
 * data:
 *   host_indirect_packet_entry_t:
 *     column_index: index of lead uc
 *     host_addr*: host addr of next level
 *       common_header:
 *         type: 0 (vendor specific)
 *         opcode: 0 (config_cu)
 *         count: 72 (config_cu with 16 entries)) //10 entry config_cu can fit in direct pkt
 *         indirect: 0 // common header of direct
 *       payload:
 *         config_cu_t: 16 entries of mapping table
 *
 * case 3 -- indirect exec_buf on 4 column partition
 * xrt_packet_header:
 *   type: 0 (vendor specific)
 *   opcode: 1 (exec_buf)
 *   count: 48 (4 *sizeof(host_indirect_packet_entry_t))
 *   distribute: 1
 *   indirect: 1 // common header of indirect
 *   completion_signal: xxx
 * data:
 *   host_indirect_packet_entry_t:
 *     column_index: index of lead uc
 *     host_addr*: host addr of next level
 *       common_header:
 *         type: 0 (vendor specific)
 *         opcode: 1 (exec_buf)
 *         count: 24 (sizeof(exec_buf_t))
 *         indirect: 0 // common header of direct
 *       payload:
 *          exec_buf_t 
 *   host_indirect_packet_entry_t:
 *     column_index: index of slave1
 *     host_addr*: host addr of next level
 *       common_header:
 *          type: 0 (vendor specific)
 *          opcode: 1 (exec_buf)
 *          count: 24 (sizeof(exec_buf_t))
 *          indirect: 0 // common header of direct
 *       payload:
 *          exec_buf_t
 *   host_indirect_packet_entry_t:
 *     slave2,3,etc...
 *
 * case 4 -- indirect exec_buf on 8 column partition 
 * xrt_packet_header:
 *   type: 0 (vendor specific)
 *   opcode: 1 (exec_buf)
 *   count: 12 (sizeof(host_indirect_packet_entry_t))
 *   distribute: 1
 *   indirect: 1 // common_header of level-1 indirect
 *   completion_signal: xxx
 * data:
 *   host_indirect_packet_entry_t:
 *     column_index: index of lead uc
 *     host_addr*: host addr of next level
 *       common_header:
 *         type: 0 (vendor specific)
 *         opcode: 1 (exec_buf)
 *         count: 12*8 (12 * sizeof(host_indirect_packet_entry_t))
 *         distribute: 1
 *         indirect: 1 // common header of level-2 indirect
 *       indirect_payload: 
 *         host_indirect_packet_entry_t:
 *           column_index: index of lead uc
 *           host_addr*: host addr of next level
 *             common_header:
 *               type: 0 (vendor specific)
 *               opcode: 1 (exec_buf)
 *               count: 24 (sizeof(exec_buf_t))
 *               distribute: 1
 *               indirect: 0  // common_header of direct
 *             payload: 
 *               exec_buf_t
 *         host_indirect_packet_entry_t:
 *           column_index: index of slave1
 *           host_addr*: host addr of next level
 *             common_header:
 *               type: 0 (vendor specific)
 *               opcode: 1 (exec_buf)
 *               count: 24 (sizeof(exec_buf_t))
 *               distribute: 1
 *               indirect: 0 // common_header of direct
 *             payload: 
 *               exec_buf_t
 *         host_indirect_packet_entry_t:
 *           slave2,3,etc...
 */ 
typedef struct
{
  xrt_packet_header_t xrt_header;	
  uint32_t data[12];
}
host_queue_packet_t;

/*
 * xrt pkt with random length.
 */ 
typedef struct
{
  xrt_packet_header_t xrt_header;	
  uint64_t xrt_payload_host_addr;
}
xrt_packet_t;

#define XRT_PKT_TYPE(p) ((p)->xrt_header.common_header.type)
#define XRT_PKT_OPCODE(p) ((p)->xrt_header.common_header.opcode)
#define XRT_PKT_LEN(p) ((p)->xrt_header.common_header.count)
#define XRT_PKT_DISTRIBUTE(p) ((p)->xrt_header.common_header.distribute)
#define XRT_PKT_INDIRECT(p) ((p)->xrt_header.common_header.indirect)
#define XRT_PKT_COMPLETION(p) ((p)->xrt_header.completion_signal)
#define XRT_PKT_PAYLOAD(p) ((p)->xrt_payload_host_addr)

#define ADDR_HIGH(x)        ((x) >> 32)
#define ADDR_LOW(x)         ((x) & 0xFFFFFFFF)
#define MOD_POW2(x, y)      ((x) & ((y) - 1)) 

typedef struct
{
  uint64_t address;
}
host_queue_t;

void host_queue_init(host_queue_t *queue, uint64_t address);

xrt_packet_t *host_queue_pop(host_queue_t *queue, bool block);

void host_queue_finish_packet(host_queue_t *queue, xrt_packet_t *packet, uint32_t completion);

#endif

/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2026, Advanced Micro Devices, Inc.
 */

#ifndef _AIE4_MSG_PRIV_H_
#define _AIE4_MSG_PRIV_H_

#include <linux/types.h>

enum aie4_msg_opcode {
	AIE4_MSG_OP_SUSPEND                          = 0x10003,
	AIE4_MSG_OP_ATTACH_WORK_BUFFER               = 0x1000D,
	AIE4_MSG_OP_CREATE_VFS                       = 0x20001,
	AIE4_MSG_OP_DESTROY_VFS                      = 0x20002,
};

enum aie4_msg_status {
	AIE4_MSG_STATUS_SUCCESS = 0x0,
	AIE4_MSG_STATUS_ERROR = 0x1,
	AIE4_MSG_STATUS_NOTSUPP = 0x2,
	MAX_AIE4_MSG_STATUS_CODE = 0x4,
};

struct aie4_msg_suspend_req {
	__u32 rsvd;
} __packed;

struct aie4_msg_suspend_resp {
	enum aie4_msg_status status;
} __packed;

struct aie4_msg_create_vfs_req {
	__u32 vf_cnt;
} __packed;

struct aie4_msg_create_vfs_resp {
	enum aie4_msg_status status;
} __packed;

struct aie4_msg_destroy_vfs_req {
	__u32 rsvd;
} __packed;

struct aie4_msg_destroy_vfs_resp {
	enum aie4_msg_status status;
} __packed;

union aie4_msg_pasid {
	__u32 raw;
	struct {
		__u32 pasid     : 20;
		__u32 rsvd      : 11;
		__u32 pasid_vld : 1;
	} f;
} __packed;

#define AIE4_WORK_BUFFER_MIN_SIZE	(4 * 1024 * 1024) /* 4 MB */

struct aie4_msg_attach_work_buffer_req {
	__u64 buff_addr;
	union aie4_msg_pasid pasid;
	__u32 buff_size;
} __packed;

struct aie4_msg_attach_work_buffer_resp {
	enum aie4_msg_status status;
} __packed;

#endif /* _AIE4_MSG_PRIV_H_ */

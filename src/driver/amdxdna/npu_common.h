/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2023-2024, Advanced Micro Devices, Inc.
 */

#ifndef _NPU_COMMON_H
#define _NPU_COMMON_H

#include "amdxdna_drv.h"
#include "amdxdna_ctx.h"
#include "npu_mailbox.h"
#include "npu_solver.h"

#define TX_TIMEOUT 2000 /* miliseconds */
#define RX_TIMEOUT 5000 /* miliseconds */

struct npu_notify {
	struct completion       comp;
	u32			*data;
	size_t			size;
	int			error;
};

#define DECLARE_NPU_MSG_COMMON(name, op, status)		\
	struct name##_req	req = { 0 };			\
	struct name##_resp	resp = { status	};		\
	struct npu_notify	hdl = {				\
		.error = 0,					\
		.data = (u32 *)&resp,				\
		.size = sizeof(resp),				\
		.comp = COMPLETION_INITIALIZER(hdl.comp),	\
	};							\
	struct xdna_mailbox_msg msg = {				\
		.send_data = (u8 *)&req,			\
		.send_size = sizeof(req),			\
		.handle = &hdl,					\
		.opcode = op,					\
		.notify_cb = npu_msg_cb,			\
	}

void npu_msg_cb(void *handle, const u32 *data, size_t size);
int npu_send_msg_wait(struct amdxdna_dev *xdna,
		      struct mailbox_channel *chann,
		      struct xdna_mailbox_msg *msg);

void npu_default_xrs_cfg(struct amdxdna_dev *xdna, struct init_config *xrs_cfg);
int npu_alloc_resource(struct amdxdna_hwctx *hwctx);
void npu_release_resource(struct amdxdna_hwctx *hwctx);

#endif /* _NPU_COMMON_H */

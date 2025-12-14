/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2023-2025, Advanced Micro Devices, Inc.
 */

#ifndef _AIE4_MSG_H_
#define _AIE4_MSG_H_

#include "amdxdna_pci_drv.h"
#include "amdxdna_ctx.h"
#include "amdxdna_mailbox.h"

struct xdna_notify {
	struct completion       comp;
	u32			*data;
	size_t			size;
	int			error;
};

#define DECLARE_XDNA_MSG_COMMON(name, op, status)		\
	struct name##_req	req = { 0 };			\
	struct name##_resp	resp = { status	};		\
	struct xdna_notify	hdl = {				\
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
		.notify_cb = aie4_xdna_msg_cb,			\
	}

#define DECLARE_AIE4_MSG(name, op) \
	DECLARE_XDNA_MSG_COMMON(name, op, -1)

/* aie4_message.c */
int aie4_xdna_msg_cb(void *handle, void __iomem *data, size_t size);
int aie4_send_msg_wait(struct amdxdna_dev_hdl *ndev, struct xdna_mailbox_msg *msg);

#endif /* _AIE4_MSG_H_ */

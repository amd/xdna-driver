/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2023-2024, Advanced Micro Devices, Inc.
 */

#ifndef _AMDXDNA_MAILBOX_HELPER_H
#define _AMDXDNA_MAILBOX_HELPER_H

#include "amdxdna_drv.h"
#include "amdxdna_ctx.h"
#include "amdxdna_mailbox.h"

#define TX_TIMEOUT 2000 /* miliseconds */
#define RX_TIMEOUT 5000 /* miliseconds */

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
		.notify_cb = xdna_msg_cb,			\
	}

static int xdna_msg_cb(void *handle, const u32 *data, size_t size)
{
	struct xdna_notify *cb_arg = handle;
	int ret;

	if (unlikely(!data))
		goto out;

	if (unlikely(cb_arg->size != size)) {
		cb_arg->error = -EINVAL;
		goto out;
	}

	print_hex_dump_debug("resp data: ", DUMP_PREFIX_OFFSET,
			     16, 4, data, cb_arg->size, true);
	memcpy(cb_arg->data, data, cb_arg->size);
out:
	ret = cb_arg->error;
	complete(&cb_arg->comp);
	return ret;
}

static int xdna_send_msg_wait(struct amdxdna_dev *xdna,
			      struct mailbox_channel *chann,
			      struct xdna_mailbox_msg *msg)
{
	struct xdna_notify *hdl = msg->handle;
	int ret;

	ret = xdna_mailbox_send_msg(chann, msg, TX_TIMEOUT);
	if (ret) {
		XDNA_ERR(xdna, "Send message failed, ret %d", ret);
		return ret;
	}

	ret = wait_for_completion_timeout(&hdl->comp,
					  msecs_to_jiffies(RX_TIMEOUT));
	if (!ret) {
		XDNA_ERR(xdna, "Wait for completion timeout");
		return -ETIME;
	}

	return hdl->error;
}

#endif /* _AMDXDNA_MAILBOX_HELPER_H */
